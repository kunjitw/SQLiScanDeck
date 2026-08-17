"""
Parse a pasted raw HTTP request (Burp-style) into a structured object and
extract every testable parameter.

Accepts either:
  * a full raw request (request line + headers + optional body), or
  * a single bare URL line (http://host/path?a=1).

Locations map onto sqlmap/ghauri places: GET, POST, JSON, COOKIE, HEADER, URI.
"""
import json
import re
from urllib.parse import urlsplit, parse_qsl, urlunsplit, unquote

# Headers that are commonly worth offering as injectable points.
INTERESTING_HEADERS = ("user-agent", "referer", "x-forwarded-for", "x-forwarded-host", "origin")


def _split_head_body(raw):
    # Normalise newlines, then split on the first blank line.
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    return head, body


def _flatten_json(obj, prefix=""):
    """Collect leaf values with dotted names, e.g. user.name -> value."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = "{}.{}".format(prefix, k) if prefix else str(k)
            out.extend(_flatten_json(v, name))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            name = "{}[{}]".format(prefix, i)
            out.extend(_flatten_json(v, name))
    else:
        out.append((prefix, obj))
    return out


def parse_request(raw, force_ssl=False):
    """
    Returns a dict describing the request plus a `params` list. Never raises on
    malformed input -- it degrades to whatever it could extract.
    """
    result = {
        "ok": True,
        "method": "GET",
        "scheme": "https" if force_ssl else "http",
        "host": "",
        "path": "/",
        "url": "",
        "http_version": "HTTP/1.1",
        "headers": {},
        "cookies": {},
        "content_type": "",
        "body": "",
        "params": [],
        "warnings": [],
        "raw": raw,
    }
    try:
        raw = (raw or "").strip()
        if not raw:
            result["ok"] = False
            result["warnings"].append("空的請求內容")
            return result

        # Bare-URL shortcut.
        first_line = raw.splitlines()[0].strip()
        if len(raw.splitlines()) == 1 and re.match(r"^https?://", first_line, re.I):
            return _parse_bare_url(first_line, result, force_ssl)

        head, body = _split_head_body(raw)
        lines = head.split("\n")
        request_line = lines[0].strip()
        header_lines = lines[1:]

        # --- request line ---
        m = re.match(r"^([A-Z]+)\s+(\S+)\s+(HTTP/\d(?:\.\d)?)\s*$", request_line)
        if m:
            result["method"] = m.group(1).upper()
            target = m.group(2)
            result["http_version"] = m.group(3)
        else:
            # Tolerate "METHOD target" with no version, or just a target.
            bits = request_line.split()
            if len(bits) >= 2 and bits[0].isupper():
                result["method"], target = bits[0], bits[1]
            elif bits:
                target = bits[0]
            else:
                target = "/"
            result["warnings"].append("請求行格式不標準,已盡量解析")

        # --- headers ---
        for hl in header_lines:
            if not hl.strip() or ":" not in hl:
                continue
            name, _, value = hl.partition(":")
            name = name.strip()
            value = value.strip()
            result["headers"][name] = value
            low = name.lower()
            if low == "cookie":
                for pair in value.split(";"):
                    if "=" in pair:
                        ck, cv = pair.split("=", 1)
                        result["cookies"][ck.strip()] = cv.strip()
            elif low == "content-type":
                result["content_type"] = value

        host_hdr = ""
        for k, v in result["headers"].items():
            if k.lower() == "host":
                host_hdr = v.strip()
                break

        # --- resolve absolute vs origin form target ---
        if re.match(r"^https?://", target, re.I):
            parts = urlsplit(target)
            # take host/path/query from the absolute URL, but let the caller's force_ssl
            # (the HTTPS/HTTP selector) decide the SCHEME -- otherwise a pasted https:// line
            # would pin the scheme and make the selector silently do nothing.
            result["host"] = parts.netloc or host_hdr
            path = parts.path or "/"
            query = parts.query
        else:
            result["host"] = host_hdr
            sp = urlsplit(target if target.startswith("/") else "/" + target)
            path = sp.path or "/"
            query = sp.query

        result["path"] = path
        full_query = "?" + query if query else ""
        result["url"] = urlunsplit((result["scheme"], result["host"], path, query, ""))
        result["body"] = body

        # --- parameters ---
        params = []
        # GET
        for name, value in parse_qsl(query, keep_blank_values=True):
            params.append({"name": name, "location": "GET", "value": value})
        # COOKIE
        for name, value in result["cookies"].items():
            params.append({"name": name, "location": "COOKIE", "value": value})
        # BODY
        ctype = result["content_type"].lower()
        if body.strip():
            if "application/json" in ctype or _looks_json(body):
                try:
                    obj = json.loads(body)
                    for name, value in _flatten_json(obj):
                        if not name:   # bare scalar / unnamed leaf -> not targetable
                            continue
                        params.append({"name": name, "location": "JSON",
                                       "value": "" if value is None else str(value)})
                except Exception:
                    result["warnings"].append("Content-Type 是 JSON 但解析失敗,已略過 body 參數")
            elif "multipart/form-data" in ctype:
                mp = _parse_multipart(body, result["content_type"])
                if mp:
                    params.extend(mp)
                    nfile = sum(1 for x in mp if x.get("is_file"))
                    if nfile:
                        result["warnings"].append(
                            "multipart:拆出 {} 個欄位,其中 {} 個檔案上傳欄位已標記為不做 SQLi".format(len(mp), nfile))
                else:
                    result["warnings"].append("multipart 表單解析失敗(找不到 boundary 或格式異常)")
            else:
                # default: urlencoded form
                for name, value in parse_qsl(body, keep_blank_values=True):
                    params.append({"name": name, "location": "POST", "value": value})
        # HEADER (offer interesting ones, unselected by default upstream)
        for k, v in result["headers"].items():
            if k.lower() in INTERESTING_HEADERS:
                params.append({"name": k, "location": "HEADER", "value": v})

        result["params"] = _dedupe_params(params)
        return result
    except Exception as e:  # absolute safety net
        result["ok"] = False
        result["warnings"].append("解析發生例外:{}".format(e))
        return result


def _multipart_filename(cd):
    """Best-effort display filename from a Content-Disposition line: quoted filename,
    RFC 5987 filename* (percent-decoded), or a bare token. Detection of file-ness is
    separate (any filename/filename* presence) -- this is only for display."""
    m = re.search(r'(?i)\bfilename\s*=\s*"([^"]*)"', cd)
    if m:
        return m.group(1)
    m = re.search(r"(?i)\bfilename\*\s*=\s*[^']*''([^;\r\n]+)", cd)
    if m:
        try:
            return unquote(m.group(1))
        except Exception:
            return m.group(1)
    m = re.search(r'(?i)\bfilename\s*=\s*([^;\r\n]+)', cd)
    return m.group(1).strip().strip('"') if m else ""


def _multipart_boundary(content_type):
    # anchor before 'boundary=' to a param delimiter so a decoy like 'myboundary=Z'
    # (or a vendor 'x-boundary=') can't be picked ahead of the real boundary=.
    m = re.search(r'(?:^|[;\s])boundary=(?:"([^"]+)"|([^";]+))', content_type or "", re.I)
    return (m.group(1) or m.group(2)).strip() if m else None


def _parse_multipart(body, content_type):
    """Extract multipart/form-data parts. TEXT fields become testable POST params;
    parts carrying a filename (file uploads) are flagged is_file so they are SHOWN
    but skipped from SQLi fuzzing -- and their raw bytes are never surfaced (only a
    filename/type/size summary). Best-effort: returns [] on any trouble."""
    boundary = _multipart_boundary(content_type)
    if not boundary:
        return []
    out = []
    for seg in (body or "").split("--" + boundary):
        s = seg.strip("\r\n")
        if not s or s == "--":                       # preamble / closing delimiter
            continue
        parts = re.split(r"\r?\n\r?\n", s, maxsplit=1)
        head = parts[0]
        content = parts[1] if len(parts) > 1 else ""
        cd, part_ct = "", ""
        for hl in head.split("\n"):
            hl = hl.rstrip("\r")
            low = hl.lower()
            if low.startswith("content-disposition:"):
                cd = hl
            elif low.startswith("content-type:"):
                part_ct = hl.split(":", 1)[1].strip()
        name_m = re.search(r'(?i)\bname\s*=\s*"([^"]*)"', cd)
        if not name_m or not name_m.group(1):
            continue
        name = name_m.group(1)
        # File field? Robust, fail-toward-skip:
        #  - a `filename=` OR `filename*=` attribute (RFC 5987 unicode), any case /
        #    quoting / whitespace -- the canonical marker; OR
        #  - a per-part Content-Type that isn't text/* or application/json (browsers
        #    only attach a Content-Type to file parts; text fields normally have none).
        has_fn = re.search(r'(?i)\bfilename\*?\s*=', cd) is not None
        ct_low = part_ct.lower()
        # A per-part Content-Type only marks a file when it is a KNOWN-BINARY media type.
        # Textual types (application/xml, x-www-form-urlencoded, graphql, soap+xml,
        # ld+json, ...) are legit INJECTABLE form fields -- never misclassify them as
        # uploads. (filename= above stays the primary, reliable file signal.)
        ct_file = ct_low.startswith(("image/", "audio/", "video/", "font/", "model/")) \
            or "octet-stream" in ct_low \
            or ct_low in ("application/pdf", "application/zip", "application/gzip",
                          "application/x-7z-compressed", "application/x-rar-compressed",
                          "application/x-tar", "application/msword", "application/vnd.ms-excel")
        if has_fn or ct_file:
            fn = _multipart_filename(cd)
            summary = "檔案上傳:{}{} · {} bytes".format(
                fn or "(未命名/未選檔)", " · " + part_ct if part_ct else "", len(content))
            out.append({"name": name, "location": "FILE", "value": summary,
                        "is_file": True, "filename": fn, "part_ctype": part_ct})
        else:
            out.append({"name": name, "location": "POST", "value": content.strip("\r\n")})
    return out


def _parse_bare_url(url, result, force_ssl=False):
    parts = urlsplit(url)
    result["method"] = "GET"
    # host/path come from the URL, but the SCHEME follows the caller's force_ssl (the HTTPS/HTTP
    # selector) so the toggle can override a pasted https:// -- the frontend syncs the toggle to
    # the URL's scheme on parse, then the user can still flip it.
    result["scheme"] = "https" if force_ssl else "http"
    result["host"] = parts.netloc
    result["path"] = parts.path or "/"
    result["url"] = url
    result["headers"] = {"Host": parts.hostname or ""}
    params = [{"name": n, "location": "GET", "value": v}
              for n, v in parse_qsl(parts.query, keep_blank_values=True)]
    result["params"] = _dedupe_params(params)
    if not params:
        result["warnings"].append("這個 URL 沒有查詢參數;可加上 ?id=1 之類再測")
    return result


def _looks_json(body):
    b = body.strip()
    return (b.startswith("{") and b.endswith("}")) or (b.startswith("[") and b.endswith("]"))


def _dedupe_params(params):
    seen = set()
    out = []
    for p in params:
        key = (p["location"], p["name"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out

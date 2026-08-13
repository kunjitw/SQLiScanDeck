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
from urllib.parse import urlsplit, parse_qsl, urlunsplit

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
            return _parse_bare_url(first_line, result)

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
            result["scheme"] = parts.scheme.lower()
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
                        params.append({"name": name, "location": "JSON",
                                       "value": "" if value is None else str(value)})
                except Exception:
                    result["warnings"].append("Content-Type 是 JSON 但解析失敗,已略過 body 參數")
            elif "multipart/form-data" in ctype:
                result["warnings"].append("multipart 表單暫不自動拆解 body 參數")
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


def _parse_bare_url(url, result):
    parts = urlsplit(url)
    result["method"] = "GET"
    result["scheme"] = parts.scheme.lower()
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

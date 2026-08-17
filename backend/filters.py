"""
Rule engine. One matcher serves two purposes (rule.purpose):

  * "filter" -> the parameter is "not worth testing" and is auto-deselected
    (analytics/tracking/CSRF/encrypted-framework tokens). The user can override.
  * "advise" -> the parameter is a CANDIDATE for another test class (e.g. a value
    that decodes to a .NET serialized blob -> insecure deserialization). This is a
    heuristic HINT only; it never changes selection.

A rule matches by parameter NAME or VALUE, optionally scoped to a location
(COOKIE/GET/POST/...), optionally after a pipeline of built-in decoders
(rule.transform, e.g. base64decode -> match magic bytes). Transforms are a fixed
whitelist of code in THIS module; rules only reference them by name -- a rule can
never carry executable code (the rules DB + editor are local/unauthenticated, so
an eval-able rule would be a self-inflicted RCE).

Rules live in the DB (global or per-project); this module only evaluates them and
supplies the built-in defaults (DEFAULT_RULES + advise_catalog.json).
"""
import re
import os
import json
import base64
import zlib
from urllib.parse import unquote_plus


# Defaults seeded (and topped-up) on start. These are parameters that are
# either purely client-side (analytics/tracking cookies never touch the DB) or
# actively harmful to fuzz (anti-CSRF/anti-forgery tokens reject-on-mismatch, so
# every payload 403s -> sqlmap gets false negatives + wasted time). Matching
# only DESELECTS a parameter -- the user can always tick it back on.
#
# `enabled: False` entries are seeded switched-OFF (borderline items such as
# session ids: usually opaque randoms, but occasionally injectable, and fuzzing
# them can invalidate the session -- left to the user to enable).
DEFAULT_RULES = [
    # --- Google Analytics / Ads / Tag Manager (GA4 _ga_XXXX, _ga, _gat*, _gid) ---
    # NB: anchored to the real cookie shapes so we don't eat legit params that
    # merely start with "_ga" (e.g. _gallery / _gateway / _gaps).
    {"kind": "name", "mode": "regex", "pattern": r"^_ga$|^_ga_|^_gat($|_)", "note": "Google Analytics (_ga / _ga_* / _gat*)"},
    {"kind": "name", "mode": "regex", "pattern": r"^_gid", "note": "Google Analytics _gid"},
    {"kind": "name", "mode": "regex", "pattern": r"^_gcl", "note": "Google Ads (_gcl_au/aw/dc)"},
    {"kind": "name", "mode": "regex", "pattern": r"^_gac", "note": "Google Ads conversion"},
    {"kind": "name", "mode": "regex", "pattern": r"^_dc_gtm", "note": "Google Tag Manager"},
    {"kind": "name", "mode": "regex", "pattern": r"^__utm", "note": "Urchin / GA legacy"},
    {"kind": "name", "mode": "regex", "pattern": r"^__gads$|^__gpi$|^__eoi$", "note": "Google AdSense / Ad Manager"},
    # --- other analytics / tracking / consent (client-side only) ---
    {"kind": "name", "mode": "regex", "pattern": r"^_fbp$|^_fbc$|^fr$|^fbclid$", "note": "Facebook / Meta pixel"},
    {"kind": "name", "mode": "regex", "pattern": r"^_hj", "note": "Hotjar"},
    {"kind": "name", "mode": "regex", "pattern": r"^_clck$|^_clsk$", "note": "Microsoft Clarity"},
    {"kind": "name", "mode": "regex", "pattern": r"^_uet", "note": "Microsoft / Bing UET (_uetsid/_uetvid/_uetmsclkid)"},
    {"kind": "name", "mode": "regex", "pattern": r"^MUID$", "note": "Microsoft advertising MUID"},
    {"kind": "name", "mode": "regex", "pattern": r"^_pk_", "note": "Matomo / Piwik"},
    # Mixpanel cookie is mp_<projecttoken>_mixpanel — require that shape (was ^mp_, which ate mp_weight etc.)
    {"kind": "name", "mode": "regex", "pattern": r"^mp_.+_mixpanel$", "note": "Mixpanel"},
    {"kind": "name", "mode": "regex", "pattern": r"^ajs_", "note": "Segment"},
    # Amplitude uses amplitude_id_* (legacy) and AMP_* / AMP_MKTG_* (current). Dropped lowercase ^amp_ (ate amp_hours).
    {"kind": "name", "mode": "regex", "pattern": r"^amplitude|^AMP_", "note": "Amplitude"},
    {"kind": "name", "mode": "regex", "pattern": r"^intercom-", "note": "Intercom"},
    {"kind": "name", "mode": "regex", "pattern": r"^_ym", "note": "Yandex Metrica"},
    {"kind": "name", "mode": "regex", "pattern": r"^(bcookie|bscookie|lidc|li_gc|li_mc|UserMatchHistory|AnalyticsSyncHistory)$", "note": "LinkedIn"},
    {"kind": "name", "mode": "regex", "pattern": r"^AMCV_|^s_cc$|^s_sq$|^s_vi$|^s_fid$|^mbox$", "note": "Adobe Analytics / Target"},
    {"kind": "name", "mode": "regex", "pattern": r"^__cf", "note": "Cloudflare (__cf_bm / __cfduid)"},
    {"kind": "name", "mode": "regex", "pattern": r"^__hs|^hubspotutk$", "note": "HubSpot (__hstc/__hssc/__hssrc/hubspotutk)"},
    {"kind": "name", "mode": "regex", "pattern": r"^_vwo|^_vis_opt", "note": "VWO A/B testing"},
    {"kind": "name", "mode": "regex", "pattern": r"^optimizely", "note": "Optimizely A/B testing"},
    {"kind": "name", "mode": "regex", "pattern": r"^_omappv", "note": "OptinMonster"},
    # --- social pixels (TikTok / Snapchat / Pinterest / Reddit / Twitter) ---
    {"kind": "name", "mode": "regex", "pattern": r"^_ttp$|^_tt_enable_cookie$|^ttwid$", "note": "TikTok pixel"},
    {"kind": "name", "mode": "regex", "pattern": r"^_scid$|^sc_at$|^_schn$", "note": "Snapchat pixel"},
    {"kind": "name", "mode": "regex", "pattern": r"^_pin_|^_epik$|^_derived_epik$|^_pinterest", "note": "Pinterest"},
    {"kind": "name", "mode": "regex", "pattern": r"^_rdt_", "note": "Reddit pixel"},
    {"kind": "name", "mode": "regex", "pattern": r"^personalization_id$|^guest_id|^muc_ads$", "note": "Twitter / X tracking"},
    # --- cookie-consent / privacy signals (CMP + IAB TCF/GPP/US-Privacy) ---
    {"kind": "name", "mode": "regex", "pattern": r"^(OptanonConsent|OptanonAlertBoxClosed|CookieConsent|euconsent-v2)$|^cookielawinfo", "note": "Cookie-consent / CMP"},
    {"kind": "name", "mode": "regex", "pattern": r"^usprivacy$|^addtl_consent$|^eupubconsent|^__gpp", "note": "Privacy consent signals (US-Privacy / GPP / TCF)"},
    # --- anti-CSRF / anti-forgery (fuzzing them just 403s every request) ---
    {"kind": "name", "mode": "contains", "pattern": "csrf", "note": "CSRF token"},
    {"kind": "name", "mode": "contains", "pattern": "xsrf", "note": "CSRF token"},
    {"kind": "name", "mode": "regex", "pattern": r"^authenticity_token$", "note": "Rails anti-forgery"},
    {"kind": "name", "mode": "regex", "pattern": r"^csrfmiddlewaretoken$", "note": "Django CSRF"},
    {"kind": "name", "mode": "regex", "pattern": r"^__RequestVerificationToken", "note": "ASP.NET MVC anti-forgery"},
    {"kind": "name", "mode": "regex", "pattern": r"^nonce$|_nonce$|^wpnonce$|^_wpnonce$", "note": "nonce (single-use)"},
    # CAPTCHA responses are single-use & reject-on-mismatch, exactly like CSRF.
    {"kind": "name", "mode": "contains", "pattern": "captcha", "note": "CAPTCHA response (single-use)"},
    # --- ASP.NET WebForms postback plumbing (opaque, not injectable) ---
    {"kind": "name", "mode": "regex", "pattern": r"^__VIEWSTATE|^__EVENTVALIDATION$|^__EVENTTARGET$|^__EVENTARGUMENT$|^__PREVIOUSPAGE$", "note": "ASP.NET WebForms postback"},
    # --- framework plumbing / cache-busters (not real inputs) ---
    {"kind": "name", "mode": "regex", "pattern": r"^_$", "note": "jQuery cache-buster (_=timestamp)"},
    {"kind": "name", "mode": "regex", "pattern": r"^utf8$", "note": "Rails utf8 checkmark (always ✓)"},
    {"kind": "name", "mode": "regex", "pattern": r"^_method$", "note": "HTTP method override (Rails / Laravel)"},
    # --- value-based backups (in case a tracker is oddly named) ---
    {"kind": "value", "mode": "regex", "pattern": r"^GA\d\.", "note": "GA cookie value (GA1.*)"},
    {"kind": "value", "mode": "regex", "pattern": r"^GS\d\.", "note": "GA4 session value (GS2.1.*)"},
    {"kind": "value", "mode": "prefix", "pattern": "gcl", "note": "Google click-id value"},

    # --- ASP.NET Core framework cookies (Data Protection = authenticated encryption):
    #     the value is unforgeable/unmodifiable, so it is NOT an injection surface and
    #     fuzzing it breaks the session. Name rules cover the DEFAULT names; a COOKIE-
    #     scoped CfDJ8 value rule catches app-RENAMED cookies (e.g. GC.Session) whose
    #     name we cannot know. Scoped to COOKIE so it never hides a testable GET/POST
    #     param that merely carries a DP token (password-reset ?code=CfDJ8..., etc.). ---
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Antiforgery\.", "note": "ASP.NET Core 反 CSRF cookie(加密框架 token)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Session$", "note": "ASP.NET Core session cookie(加密)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Cookies($|C[0-9]+$)", "note": "ASP.NET Core auth cookie(含分塊)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Identity\.", "note": "ASP.NET Core Identity cookie(加密)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Mvc\.CookieTempDataProvider$", "note": "ASP.NET Core TempData cookie(加密)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.Correlation\.", "note": "OIDC correlation cookie(值恆為 N)"},
    {"kind": "name", "mode": "regex", "pattern": r"^\.AspNetCore\.OpenIdConnect\.Nonce\.", "note": "OIDC nonce cookie"},
    {"kind": "value", "mode": "prefix", "pattern": "CfDJ8", "location": "COOKIE", "note": "ASP.NET Core Data Protection 加密 cookie(認證加密,非注入面)"},
    {"kind": "value", "mode": "regex", "pattern": r"^chunks-[0-9]+$", "location": "COOKIE", "note": "ASP.NET Core 分塊 cookie 父節點"},

    # --- borderline: seeded OFF (enable if you want to skip them) ---
    {"kind": "name", "mode": "regex", "pattern": r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|sid|session)$", "note": "Session id (borderline)", "enabled": False},
    {"kind": "name", "mode": "regex", "pattern": r"^(access_token|id_token|refresh_token)$|^Authorization$", "note": "Auth/bearer token (borderline)", "enabled": False},
    # First-party Google/YouTube cookies — only seen when the target IS google/youtube. OFF to avoid clutter.
    {"kind": "name", "mode": "regex", "pattern": r"^(NID|DSID|IDE|1P_JAR|CONSENT|SOCS|AEC|PREF|YSC|VISITOR_INFO1_LIVE|__Secure-3PSID|__Secure-3PAPISID)$", "note": "Google/YouTube first-party cookie (borderline)", "enabled": False},
    # First-party Facebook cookies — only on facebook.com; c_user/xs are auth (fuzzing logs you out).
    {"kind": "name", "mode": "regex", "pattern": r"^(datr|c_user|xs|sb|wd)$", "note": "Facebook first-party cookie (borderline; c_user/xs are auth)", "enabled": False},
]


def _match(mode, pattern, text):
    """String match modes on a plain string."""
    if text is None:
        text = ""
    try:
        if mode == "equals":
            return text == pattern
        if mode == "iequals":
            return text.lower() == pattern.lower()
        if mode == "prefix":
            return text.startswith(pattern)
        if mode == "contains":
            return pattern.lower() in text.lower()
        if mode == "regex":
            return re.search(pattern, text) is not None
    except re.error:
        return False
    except Exception:
        return False
    return False


# --- transform pipeline: a FIXED whitelist of decoders. Rules reference these by
#     name only; a rule can never carry executable code. Each is fail-safe (returns
#     None on bad input) and size-capped (zip-bomb / runaway guard). ----------------
_MAX_DECODE = 1 << 20   # 1 MiB cap on any single decoded/decompressed output


def _t_urldecode(v):
    return unquote_plus(v) if isinstance(v, str) else None


def _t_base64decode(v):
    if not isinstance(v, str):
        return None
    s = v.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        out = base64.b64decode(s, validate=False)
    except Exception:
        return None
    return out if out and len(out) <= _MAX_DECODE else None


def _t_hexdecode(v):
    if not isinstance(v, str):
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", v)
    if not s or len(s) % 2:
        return None
    try:
        return bytes.fromhex(s)
    except Exception:
        return None


def _t_gunzip(v):
    if not isinstance(v, (bytes, bytearray)):
        return None
    try:
        # bounded, incremental: cap OUTPUT at _MAX_DECODE so a zip bomb can never
        # materialize gigabytes before a post-hoc size check (which gzip.decompress
        # would). 16 + MAX_WBITS = gzip-wrapped stream.
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(bytes(v), _MAX_DECODE)
        if d.unconsumed_tail:        # more than _MAX_DECODE would decompress -> reject
            return None
        return out
    except Exception:
        return None


def _t_json(v):
    s = v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else v
    if not isinstance(s, str):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _t_decode(enc):
    return lambda v: (v.decode(enc, "ignore") if isinstance(v, (bytes, bytearray)) else v)


_TRANSFORMS = {
    "urldecode": _t_urldecode,
    "base64decode": _t_base64decode,
    "hexdecode": _t_hexdecode,
    "gunzip": _t_gunzip,
    "json": _t_json,
    "utf8": _t_decode("utf-8"),
    "latin1": _t_decode("latin-1"),
}


def _parse_transform(t):
    if not t:
        return []
    if isinstance(t, list):
        return t
    if isinstance(t, str):
        s = t.strip()
        if not s:
            return []
        if s.startswith("["):
            try:
                return list(json.loads(s))
            except Exception:
                return []
        return [p.strip() for p in s.split(",") if p.strip()]
    return []


def _apply_transforms(value, transforms):
    data = value
    for t in transforms[:8]:              # cap chain depth
        if data is None:
            return None
        if not isinstance(t, str):        # a non-string token -> fail safe, never crash
            return None
        m = re.match(r"^split-dot\[(\d+)\]$", t)
        if m:
            n = int(m.group(1))
            data = data.split(".")[n] if isinstance(data, str) and n < len(data.split(".")) else None
            continue
        fn = _TRANSFORMS.get(t)
        if fn is None:                    # unknown transform -> fail safe, never run code
            return None
        data = fn(data)
    return data


def _json_has_key(obj, pattern):
    """True if any key in the (possibly nested) object equals `pattern`, or -- when
    pattern is '$*' -- any key starts with '$' (Mongo operator injection tell)."""
    want_dollar = pattern == "$*"
    def walk(o):
        if isinstance(o, dict):
            for k, val in o.items():
                if isinstance(k, str) and ((want_dollar and k.startswith("$")) or k == pattern):
                    return True
                if walk(val):
                    return True
        elif isinstance(o, list):
            return any(walk(it) for it in o)
        return False
    return walk(obj)


def _match_data(mode, pattern, data):
    """Match a (possibly transformed) value that may be str, bytes, or a parsed obj."""
    try:
        if mode in ("equals", "iequals", "prefix", "contains", "regex"):
            if isinstance(data, (bytes, bytearray)):
                text = bytes(data).decode("latin-1", "ignore")
            elif isinstance(data, str):
                text = data
            else:
                text = json.dumps(data, ensure_ascii=False) if data is not None else ""
            return _match(mode, pattern, text)
        if mode == "magic":
            b = data if isinstance(data, (bytes, bytearray)) else (
                data.encode("latin-1", "ignore") if isinstance(data, str) else None)
            if b is None:
                return False
            magic = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", pattern))
            return bool(magic) and bytes(b).startswith(magic)
        if mode == "json-key":
            obj = data if isinstance(data, (dict, list)) else _t_json(data)
            return _json_has_key(obj, pattern)
        if mode == "len-mod":
            if not isinstance(data, (bytes, bytearray)):
                return False
            mods = [int(x) for x in re.findall(r"\d+", pattern) if int(x)]
            return bool(mods) and any(len(data) % m == 0 for m in mods)
    except Exception:
        return False
    return False


def _rule_matches(param, rule):
    """Core matcher shared by filter + advise: location scope -> transform -> match.
    Fully fail-safe: any error evaluating ONE rule yields no-match and never
    propagates, so a single malformed rule can't 500 the whole /parse."""
    try:
        loc = (rule.get("location") or "").strip().upper()
        if loc and loc != "ANY" and loc != (param.get("location") or "").upper():
            return False
        kind = rule.get("kind", "value")
        base = param.get("name", "") if kind == "name" else param.get("value", "")
        transforms = _parse_transform(rule.get("transform"))
        data = _apply_transforms(base, transforms) if transforms else base
        if transforms and data is None:
            return False
        return _match_data(rule.get("mode", "contains"), rule.get("pattern", ""), data)
    except Exception:
        return False


def evaluate(param, rules):
    """
    Return (filtered: bool, reason: str|None) for a single param dict
    {name, location, value} against the FILTER rules. Only enabled rules count.
    """
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if (rule.get("purpose") or "filter") != "filter":
            continue
        if not rule.get("pattern"):
            continue
        if _rule_matches(param, rule):
            kind = rule.get("kind")
            label = rule.get("note") or "{} {} {}".format(kind, rule.get("mode"), rule.get("pattern"))
            reason = "規則命中:{}({}={})".format(label, kind, rule.get("pattern"))
            return True, reason
    return False, None


def apply_filters(params, rules):
    """
    Annotate each param with `filtered` and `filter_reason`; default `selected`
    to the opposite of filtered (header params are never auto-selected).
    """
    annotated = []
    for p in params:
        if p.get("is_file"):   # multipart file-upload field: show it, but NEVER SQLi-fuzz it
            item = dict(p)
            item["filtered"] = True
            item["filter_reason"] = "檔案上傳欄位(檔名/內容),不做 SQLi 注入測試(可另行測上傳漏洞)"
            item["selected"] = False
            annotated.append(item)
            continue
        filtered, reason = evaluate(p, rules)
        item = dict(p)
        item["filtered"] = filtered
        item["filter_reason"] = reason
        # header params default off (noisy); others default on unless filtered
        default_on = (p.get("location") != "HEADER") and not filtered
        item["selected"] = default_on
        annotated.append(item)
    return annotated


def advise(param, rules):
    """Return the list of ADVISE-rule hits for one param -- candidate test classes,
    each {vuln_class, why, tool, confidence, source}. Heuristic hints only; this
    never changes selection or the filter verdict."""
    hits = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if rule.get("purpose") != "advise":
            continue
        if not rule.get("pattern"):
            continue
        if _rule_matches(param, rule):
            hits.append({
                "vuln_class": rule.get("vuln_class", ""),
                "why": rule.get("note", ""),
                "tool": rule.get("tool", ""),
                "confidence": rule.get("confidence", ""),
                "source": rule.get("source", ""),
            })
    return hits


def apply_advice(params, rules):
    """Attach an `advice` list to each param (computed, not stored)."""
    for p in params:
        p["advice"] = advise(p, rules)
    return params


_ADVISE_CATALOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "advise_catalog.json")


def load_advise_catalog():
    """Built-in 'advise' rules (parameter fingerprint -> candidate test class),
    kept as DATA in advise_catalog.json so the research catalog is editable, not
    code. Never raises; returns [] if the file is missing/broken."""
    try:
        with open(_ADVISE_CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("rules") or []
        # require the fields the seed dereferences (kind/mode/pattern) so a hand-edited
        # entry missing one is SKIPPED, not crash-at-startup when it reaches the seeder.
        return [r for r in data if isinstance(r, dict)
                and r.get("pattern") and r.get("kind") and r.get("mode")]
    except Exception:
        return []


_RECON_CATALOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "recon_catalog.json")


def load_recon_catalog():
    """Built-in 'recon' rules (request signature -> target intel: backend language,
    framework, CDN/WAF, CMS). Data, not code; never raises."""
    try:
        with open(_RECON_CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("rules") or []
        return [r for r in data if isinstance(r, dict)
                and r.get("pattern") and r.get("kind") and r.get("mode")]
    except Exception:
        return []


_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def recon(params, rules):
    """Aggregate recon-rule hits over the request's params (cookies / param names /
    headers / a synthetic PATH pseudo-param) into per-conclusion intel:
    [{category, reveals, confidence, note, source, evidence:[names]}], deduped by
    `reveals`. Confidence is the strongest single hit, bumped to 'high' when >= 2
    distinct signals corroborate the same reveal (wafw00f-style). Purely informational
    -- request-only, so it characterizes the submitted request, never proves the server."""
    agg = {}
    for rule in rules:
        if not rule.get("enabled", True) or rule.get("purpose") != "recon":
            continue
        if not rule.get("pattern"):
            continue
        reveals = rule.get("reveals", "") or rule.get("note", "")
        if not reveals:
            continue                        # no label -> can't aggregate; skip (avoids a blank '' bucket)
        for p in params:
            if not _rule_matches(p, rule):
                continue
            a = agg.setdefault(reveals, {
                "reveals": reveals, "category": rule.get("category", ""),
                "note": rule.get("note", ""), "source": rule.get("source", ""),
                "confs": [], "evidence": [],
            })
            a["confs"].append(rule.get("confidence", "low") or "low")
            ev = p.get("name", "") or p.get("location", "")
            if ev and ev not in a["evidence"]:
                a["evidence"].append(ev)
            break                          # one contribution per rule
    out = []
    for a in agg.values():
        best = min(a["confs"], key=lambda c: _CONF_RANK.get(c, 2)) if a["confs"] else "low"
        if len(a["evidence"]) >= 2 and best != "high":
            best = "high"                  # corroborated by independent signals
        out.append({"category": a["category"], "reveals": a["reveals"],
                    "confidence": best, "note": a["note"], "source": a["source"],
                    "evidence": a["evidence"]})
    out.sort(key=lambda x: (x["category"], _CONF_RANK.get(x["confidence"], 2)))
    return out

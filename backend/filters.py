"""
Filter-rule engine: decide which parameters are "not worth testing" and should
be auto-deselected (the user can always override in the UI).

A rule matches by parameter NAME or by parameter VALUE, using one of a few
match modes. Matching a rule marks the parameter filtered with a reason.

Rules live in the DB (global or per-project); this module only evaluates them.
"""
import re


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

    # --- borderline: seeded OFF (enable if you want to skip them) ---
    {"kind": "name", "mode": "regex", "pattern": r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|sid|session)$", "note": "Session id (borderline)", "enabled": False},
    {"kind": "name", "mode": "regex", "pattern": r"^(access_token|id_token|refresh_token)$|^Authorization$", "note": "Auth/bearer token (borderline)", "enabled": False},
    # First-party Google/YouTube cookies — only seen when the target IS google/youtube. OFF to avoid clutter.
    {"kind": "name", "mode": "regex", "pattern": r"^(NID|DSID|IDE|1P_JAR|CONSENT|SOCS|AEC|PREF|YSC|VISITOR_INFO1_LIVE|__Secure-3PSID|__Secure-3PAPISID)$", "note": "Google/YouTube first-party cookie (borderline)", "enabled": False},
    # First-party Facebook cookies — only on facebook.com; c_user/xs are auth (fuzzing logs you out).
    {"kind": "name", "mode": "regex", "pattern": r"^(datr|c_user|xs|sb|wd)$", "note": "Facebook first-party cookie (borderline; c_user/xs are auth)", "enabled": False},
]


def _match(mode, pattern, text):
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


def evaluate(param, rules):
    """
    Return (filtered: bool, reason: str|None) for a single param dict
    {name, location, value} against an iterable of rule dicts.
    Only enabled rules are considered.
    """
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        kind = rule.get("kind")
        mode = rule.get("mode", "contains")
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        target = param.get("name", "") if kind == "name" else param.get("value", "")
        if _match(mode, pattern, target):
            label = rule.get("note") or "{} {} {}".format(kind, mode, pattern)
            reason = "規則命中:{}({}={})".format(label, kind, pattern)
            return True, reason
    return False, None


def apply_filters(params, rules):
    """
    Annotate each param with `filtered` and `filter_reason`; default `selected`
    to the opposite of filtered (header params are never auto-selected).
    """
    annotated = []
    for p in params:
        filtered, reason = evaluate(p, rules)
        item = dict(p)
        item["filtered"] = filtered
        item["filter_reason"] = reason
        # header params default off (noisy); others default on unless filtered
        default_on = (p.get("location") != "HEADER") and not filtered
        item["selected"] = default_on
        annotated.append(item)
    return annotated

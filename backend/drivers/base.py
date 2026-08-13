"""
Shared driver helpers: turning selected params + options into tool arguments,
and reading a finished/streaming log to decide "vulnerable?" + extract findings.
"""
import re


def selected_names(params):
    # unique names that are selected in AT LEAST ONE location
    return sorted({p["name"] for p in params if p.get("selected")})


def deselected_names(params):
    # A name is only a "skip" candidate if it is NOT selected anywhere. Otherwise
    # a name present in two locations (e.g. GET id + COOKIE id) with mixed
    # selection would land in BOTH testParameter and skip -- contradictory,
    # since sqlmap/ghauri filter by NAME, not by location.
    sel = {p["name"] for p in params if p.get("selected")}
    return sorted({p["name"] for p in params
                   if not p.get("selected") and p["name"] not in sel})


# --- vulnerability / result parsing ---------------------------------------
_VULN_MARKERS = (
    "is vulnerable",
    "the following injection point",
    "sqlmap identified the following injection",
    "injection point(s) with a total",
    "appears to be injectable",
    "parameter appears to be",
    "the parameter is vulnerable",
)

_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_PARAM_RE = re.compile(r"^\s*Parameter:\s*(.+)$", re.I | re.M)
_TYPE_RE = re.compile(r"^\s*Type:\s*(.+)$", re.I | re.M)
_TITLE_RE = re.compile(r"^\s*Title:\s*(.+)$", re.I | re.M)
_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+)$", re.I | re.M)


def looks_vulnerable(log_text):
    low = (log_text or "").lower()
    return any(m in low for m in _VULN_MARKERS)


def extract_findings(log_text):
    """Best-effort structured findings from the raw log text."""
    text = log_text or ""
    findings = {
        "dbms": None,
        "parameters": [],
        "types": [],
        "titles": [],
        "payloads": [],
    }
    m = _DBMS_RE.search(text)
    if m:
        findings["dbms"] = m.group(1).strip()
    findings["parameters"] = [x.strip() for x in _PARAM_RE.findall(text)]
    findings["types"] = [x.strip() for x in _TYPE_RE.findall(text)]
    findings["titles"] = [x.strip() for x in _TITLE_RE.findall(text)]
    findings["payloads"] = [x.strip() for x in _PAYLOAD_RE.findall(text)]
    return findings

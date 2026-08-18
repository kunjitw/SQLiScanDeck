"""
Shared driver helpers: turning selected params + options into tool arguments,
and reading a finished/streaming log to decide "vulnerable?" + extract findings.
"""
import re


def _is_testable(p):
    # a multipart file-upload field (is_file / location FILE) is NEVER a SQLi test
    # target, no matter what the UI/client selected -- enforced here so the "files are
    # never fuzzed" guarantee holds on every path (parse, scan, preview), not just the
    # parse-time default.
    return bool(p.get("selected")) and not p.get("is_file") and p.get("location") != "FILE"


def selected_names(params):
    # unique names that are selected (and testable) in AT LEAST ONE location
    return sorted({p["name"] for p in params if _is_testable(p)})


def deselected_names(params):
    # A name is only a "skip" candidate if it is NOT testable-selected anywhere.
    # Otherwise a name present in two locations (e.g. GET id + COOKIE id) with mixed
    # selection would land in BOTH testParameter and skip -- contradictory, since
    # sqlmap/ghauri filter by NAME, not by location. File fields are always here.
    sel = {p["name"] for p in params if _is_testable(p)}
    return sorted({p["name"] for p in params
                   if not _is_testable(p) and p["name"] not in sel})


def display_cmd(parts):
    """Shell-quote a command list FOR DISPLAY ONLY. The real run passes a list to
    subprocess (no shell), so quoting is NOT needed for execution -- but the
    logged 指令 line should be safe to copy into a shell, e.g. a parameter like
    conditions[like-institutionName] whose brackets a shell would glob-expand."""
    out = []
    for p in parts:
        s = str(p)
        if s == "" or re.search(r"""[\s"'\[\]()&|;<>*?$`\\]""", s):
            out.append('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"')
        else:
            out.append(s)
    return " ".join(out)


# --- vulnerability / result parsing ---------------------------------------
# Markers below are matched case-insensitively as substrings. IMPORTANT: the
# 【判定】 annotation text emitted by append_verdict() must never contain an
# English marker from these lists as literal scaffolding -- only interpolate the
# matched keyword/evidence, and only AFTER the verdict was computed from
# read_log(), so re-appending the block can't change this scan's verdict.

_VULN_MARKERS = (
    # CONFIRMED signals ONLY. "appears to be ... injectable" is TENTATIVE: sqlmap prints
    # it before the false-positive check and then may retract it ("false positive ... does
    # not seem to be injectable"). Counting the tentative phrasing here caused false
    # positives -- a confirmed injection always prints one of the lines below.
    "is vulnerable",
    "the following injection point",
    "sqlmap identified the following injection",
    "injection point(s) with a total",
    "the parameter is vulnerable",
)

# The target was never actually reached/tested. BOTH sqlmap and ghauri exit 0
# in most of these cases, so returncode alone can't tell a real "clean" result
# from "never connected" -> without these, a dead/blocked target would be
# recorded as "tested, no vuln" and poison the "tested before?" dedup history.
_FAILURE_MARKERS = (
    # -- sqlmap phrasings --
    "can't establish ssl connection",               # TLS handshake failed (e.g. --force-ssl on an http/localhost target)
    "unable to connect to the target url",
    "connection timed out to the target url",
    "connection timed out while trying",
    "connection reset to the target url",
    "connection dropped or unknown http",
    "connection was forcibly closed",
    "unable to retrieve page content",
    "not authorized, try to provide right http",   # 401 aborts the scan
    # -- ghauri phrasings (different wording, also exits 0) --
    "was not able to establish connection",
    "target url is not responding",
    "connection attempt to the target url was",     # aborted / refused / reset
    "connection timeout, target is very slow to respond",
    # -- setup / "nothing was actually tested" (both tools, exit 0) --
    "does not contain a usable http request",       # ghauri: bad -r / no params
    "no parameter(s) found for testing",            # sqlmap: nothing testable
)

# The POSITIVE "it really ran, tested every param, found nothing" signal. A run
# that hit a transient retry (leaving a _FAILURE_MARKER substring in the log)
# but then RECOVERED and completed prints this -> use it to keep such a run from
# being mislabeled 'error'. Substring covers sqlmap's "all tested parameters do
# not appear to be injectable" and ghauri's identical phrasing.
_CLEAN_MARKERS = (
    "do not appear to be injectable",
)

# WAF/IPS detection -- not a hard failure, but a strong caveat that a "clean"
# result may be a false negative (payloads blocked). Surfaced in the verdict.
_WAF_MARKERS = (
    "waf/ips identified as",
    "protected by some kind of waf/ips",
    "is dropping 'suspicious' requests",
    "is resetting 'suspicious' requests",
    "filtered out by some sort of waf/ids",   # ghauri's wording (note: IDS, not IPS)
)

_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_DBMS_IS_RE = re.compile(r"the back-end DBMS is\s+(?!not\b)(.+)", re.I)   # ghauri prints "...is not X" while eliminating candidates -> skip those, keep the confirmation
# our append_log() prefixes every line with "[YYYY-MM-DD HH:MM:SS] ", which defeats a
# plain ^-anchor -> line-anchored regexes MUST allow that optional prefix.
_TS = r"(?:\[[^\]]*\]\s*)?"
_PARAM_RE = re.compile(r"^" + _TS + r"Parameter:\s*(.+)$", re.I | re.M)
_TYPE_RE = re.compile(r"^" + _TS + r"\s*Type:\s*(.+)$", re.I | re.M)
_TITLE_RE = re.compile(r"^" + _TS + r"\s*Title:\s*(.+)$", re.I | re.M)
_PAYLOAD_RE = re.compile(r"^" + _TS + r"\s*Payload:\s*(.+)$", re.I | re.M)
# post-detection enumeration (sqlmap AND ghauri use the same 'label: value' wording)
_BANNER_RE = re.compile(r"banner:\s*'([^']+)'", re.I)
_CURUSER_RE = re.compile(r"current user:\s*'([^']+)'", re.I)
_CURDB_RE = re.compile(r"current database(?:[^:]*)?:\s*'([^']+)'", re.I)   # label suffix varies
_HOSTNAME_RE = re.compile(r"hostname:\s*'([^']+)'", re.I)
_ISDBA_RE = re.compile(r"current user is DBA:\s*(true|false)", re.I)
_DBS_RE = re.compile(r"available databases \[(\d+)\]", re.I)
_WEBTECH_RE = re.compile(r"web application technology:\s*(.+)", re.I)
# --dbs / --users NAMES: a "header [N]:" line followed by one or more "[*] <name>" lines
_DBS_NAMES_RE = re.compile(r"available databases \[\d+\][^\n]*\n((?:" + _TS + r"\[\*\][^\n]*\n?)+)", re.I)
_USERS_NAMES_RE = re.compile(r"database management system users \[\d+\][^\n]*\n((?:" + _TS + r"\[\*\][^\n]*\n?)+)", re.I)
_STAR_ITEM_RE = re.compile(r"\[\*\]\s*(.+)")
# --tables / --columns / --dump: counts (un-anchored is safe) + the Database:/Table: labels
_TABLES_CNT_RE = re.compile(r"\[(\d+)\s+tables?\]", re.I)
_COLS_CNT_RE = re.compile(r"\[(\d+)\s+columns?\]", re.I)
_ENTRIES_CNT_RE = re.compile(r"\[(\d+)\s+entr(?:y|ies)\]", re.I)
_TABLE_LABEL_RE = re.compile(r"^" + _TS + r"\s*Table:\s*(.+)$", re.I | re.M)
_PWHASH_RE = re.compile(r"password hash:\s*(.+)", re.I)
# sqlmap's positive heuristic (tentative, informational only -- NOT a verdict input)
_HEUR_SQLI_RE = re.compile(r"parameter '([^']+)' might be injectable", re.I)

# explicit PER-PARAMETER verdict lines the tools print, e.g.
#   "GET parameter 'id' is vulnerable"                    (sqlmap, confirmed)
#   "the parameter 'id' is injectable with error-based"   (ghauri, confirmed)
#   "GET parameter 'id' appears to be 'boolean-based blind' injectable"  (ghauri)
#   "GET parameter 'id' does not seem to be injectable"   (both, clean)
# CONFIRMED per-param vuln: "is vulnerable" / "is injectable" / "is 'TECHNIQUE' injectable".
_PP_CONFIRMED_RES = (
    re.compile(r"parameter '([^']+)' is vulnerable", re.I),
    re.compile(r"parameter '([^']+)' is (?:'[^']*' )?injectable", re.I),
)
# TENTATIVE: "appears to be '...' injectable" -- provisional, may be retracted (below).
_PP_TENTATIVE_RE = re.compile(r"parameter '([^']+)' appears to be '[^']*' injectable", re.I)
_PP_CLEAN_RE = re.compile(r"parameter '([^']+)' does not seem to be injectable", re.I)
# The ONE line both engines print for every param they actually fuzz -- emitted BEFORE
# the verdict, for clean AND vulnerable outcomes, and never for a param they skip (place/
# level gates, --skip, anti-CSRF, is_file all `continue` before it). Our definitive
# "was actually tested" oracle (sqlmap controller.py:604, ghauri ghauri.py:704).
_PP_TESTED_RE = re.compile(r"testing for SQL injection on .*?parameter '([^']+)'", re.I)

# bonus non-SQLi heuristic findings sqlmap surfaces during a SQLi run
_XSS_RE = re.compile(r"parameter '([^']+)' might be vulnerable to cross-site scripting", re.I)
_FI_RE = re.compile(r"parameter '([^']+)' might be vulnerable to file inclusion", re.I)

# reliability caveats -> (lowercase substring, human note). Informational only;
# they explain WHY a result may be unreliable (esp. a false "clean").
_CAVEAT_MARKERS = (
    ("target url content is not stable", "頁面內容不穩定,偵測較易誤判(改用序列比對)"),
    ("appears to be too dynamic", "頁面過於動態,已切換純文字比對,準確度下降"),
    ("heavily dynamic", "頁面高度動態,偵測準確度可能下降"),
    ("redirect to '", "偵測到 HTTP 轉址(可能被導向登入頁,測試結果可能無效)"),
    ("there is a dbms error found in the http response body", "回應原本就含 DBMS 錯誤訊息,可能干擾比對"),
    ("responded with an http error code", "基準請求收到 HTTP 錯誤碼,影響可靠度"),
    ("http error codes detected during run", "掃描期間出現多個 HTTP 錯誤碼(大量錯誤常代表被阻擋)"),
    ("continuous problem with connection to the target", "與目標連線持續有問題,結果不可靠"),
)


def _first_marker(text, markers):
    """(marker, verbatim_line) for the EARLIEST marker hit in text, else
    (None, None). Lets callers show WHICH keyword/line drove a verdict."""
    low = (text or "").lower()
    best = None
    for m in markers:
        i = low.find(m)
        if i != -1 and (best is None or i < best[0]):
            best = (i, m)
    if best is None:
        return None, None
    i, marker = best
    ls = text.rfind("\n", 0, i) + 1
    le = text.find("\n", i)
    le = len(text) if le == -1 else le
    return marker, text[ls:le].strip()


def vuln_evidence(log_text):
    return _first_marker(log_text or "", _VULN_MARKERS)


def fail_evidence(log_text):
    return _first_marker(log_text or "", _FAILURE_MARKERS)


def waf_evidence(log_text):
    return _first_marker(log_text or "", _WAF_MARKERS)


# thin boolean wrappers over the evidence finders -> the SAME marker sets and
# case-folding, so what counts as vulnerable / failed is unchanged.
def looks_vulnerable(log_text):
    return vuln_evidence(log_text)[0] is not None


def looks_failed(log_text):
    return fail_evidence(log_text)[0] is not None


def looks_clean(log_text):
    low = (log_text or "").lower()
    return any(m in low for m in _CLEAN_MARKERS)


def merge_vuln(vuln_marker, findings):
    """The scan is vulnerable if a scan-level _VULN_MARKER hit OR any explicit
    per-parameter 'vulnerable' verdict (per_param_verdicts matches phrasings the
    scan-level markers don't, e.g. ghauri's "parameter 'x' is injectable"). Keeps
    the scan card and the per-param badge from ever disagreeing. Returns
    (vulnerable_bool, marker_for_the_verdict_annotation)."""
    if vuln_marker is not None:
        return True, vuln_marker
    hit = [n for n, v in (findings.get("per_param") or {}).items() if v == "vulnerable"]
    if hit:
        return True, "逐參數確認可注入:" + "、".join(hit)
    return False, None


def caveats(log_text):
    """Reliability caveats present in the log. Each -> {marker, note}. Purely
    informational (explains why a 'clean' result might be a false negative)."""
    low = (log_text or "").lower()
    return [{"marker": m, "note": note} for m, note in _CAVEAT_MARKERS if m in low]


# The subset of caveats SEVERE enough to invalidate a "clean" verdict: the run
# never got a usable baseline (base request errored), drowned in HTTP errors, or
# lost the connection. When one is present, a "nothing injectable" result is NOT
# trustworthy -> the scan is 測不準 (inconclusive), not 無洞. Milder caveats
# (e.g. "content is not stable") stay informational: sqlmap still tests via the
# sequence matcher, so they don't by themselves void the result.
_SEVERE_CAVEAT_MARKERS = (
    ("responded with an http error code", "基準請求就收到 HTTP 錯誤碼,無法建立可靠的比較基準"),
    ("continuous problem with connection to the target", "與目標連線持續有問題,結果不可靠"),
)

# sqlmap prints "HTTP error codes detected during run:" whenever kb.httpErrorCodes
# is non-empty -- i.e. after even ONE 4xx/5xx (a single 500 to a quote-containing
# probe is common on perfectly clean targets). So this marker alone must NOT void a
# clean verdict; only a STORM does. We sum the "<code> (...) - N times" counts and
# require a threshold before treating it as severe.
_ERROR_STORM_MARKER = "http error codes detected during run"
_ERROR_STORM_MIN = 20                       # total 4xx/5xx across the run to count as a storm
_ERROR_COUNT_RE = re.compile(r"-\s*(\d+)\s*times?", re.I)


def _error_storm_note(log_text):
    """Human note if the run had a STORM of HTTP errors (many, not just one), else None."""
    text = log_text or ""
    i = text.lower().find(_ERROR_STORM_MARKER)
    if i == -1:
        return None
    block = text[i:i + 600]                 # the code/count lines follow the marker
    total = sum(int(m.group(1)) for m in _ERROR_COUNT_RE.finditer(block))
    if total >= _ERROR_STORM_MIN:
        return "掃描期間出現大量 HTTP 錯誤碼(共 {} 次),回應無法可靠比較".format(total)
    return None


def severe_reliability(log_text):
    """(marker, note) for the first SEVERE reliability problem that makes a
    'clean' verdict untrustworthy, else (None, None)."""
    low = (log_text or "").lower()
    for marker, note in _SEVERE_CAVEAT_MARKERS:
        if marker in low:
            return marker, note
    storm = _error_storm_note(log_text)
    if storm:
        return _ERROR_STORM_MARKER, storm
    return None, None


def _tested_param_names(findings):
    """Bare names of params the tool actually produced per-parameter EVIDENCE for:
    an explicit clean/vulnerable/tentative verdict, a confirmed injection point, OR the
    "testing for SQL injection on ... parameter X" START line (findings['tested']) that
    both engines print for every param they fuzz. SAFETY: this is only ever consulted
    (via clean_covers_selected) once clean_hit is true, and both engines emit the
    "do not appear to be injectable" aggregate that sets clean_hit ONLY after the whole
    per-param loop finishes -- so a START line here always has its matching conclusion,
    and a skipped param has neither. Don't consult it in a path where clean_hit isn't
    already established, or a half-tested START could masquerade as covered."""
    per = (findings or {}).get("per_param") or {}
    names = set(per.keys())
    names.update((findings or {}).get("tested") or [])
    for p in (findings or {}).get("parameters") or []:
        names.add(str(p).split(" (")[0].strip())
    return names


def clean_covers_selected(selected_names, findings, had_selection=False):
    """True only if the tool's per-parameter evidence covers what the USER chose
    to test. Without this, a "nothing injectable" line about the URL path ('#1*')
    or a param the tool silently skipped (e.g. a Cookie at --level 1) would be
    mistaken for 'the selected params are clean'.

    `selected_names` must already be the TESTABLE set (base.selected_names -- file/
    non-testable fields removed). `had_selection` says whether the user selected
    anything at all: a genuine bare-URL scan (had_selection False) lets any tested
    point count, but a scan where the user DID select params that all dropped as
    non-testable (e.g. only a file-upload field) has an untested intended target and
    must NOT be called covered."""
    tested = _tested_param_names(findings)
    sel = list(selected_names or [])
    if sel:
        return all(n in tested for n in sel)
    return False if had_selection else bool(tested)


def decide_status(returncode, vulnerable, clean_hit, selected_names, findings, log_text, had_selection=False):
    """Single source of truth for a scan's terminal status, shared by both
    engines so sqlmap and ghauri never diverge. Evidence-based:
      - vulnerable       -> 'done'  (the red verdict rides the `vulnerable` flag)
      - never really ran -> 'error' (rc != 0, or no positive 'nothing injectable' signal)
      - ran but the "clean" can't be trusted -> 'inconclusive' (測不準):
          * a SEVERE reliability problem (HTTP-error storm / base request errored /
            persistent connection failure), OR
          * a coverage gap: the selected params were never actually tested
      - ran clean, reliably, covering the selected params -> 'done' (無洞/green)
    """
    if vulnerable:
        return "done"
    if returncode != 0 or not clean_hit:
        return "error"
    if severe_reliability(log_text)[0] is not None:
        return "inconclusive"
    if not clean_covers_selected(selected_names, findings, had_selection):
        return "inconclusive"
    return "done"


def inconclusive_reason(selected_names, findings, log_text, had_selection=False):
    """Human note explaining WHY a scan came out 測不準, for the 【判定】 block."""
    _m, note = severe_reliability(log_text)
    if note:
        return note
    tested = _tested_param_names(findings)
    missing = [n for n in (selected_names or []) if n not in tested]
    if missing:
        return "所選參數未被實際測試(工具日誌未對其下任何結論):" + "、".join(missing)
    if had_selection and not list(selected_names or []):
        return "所選欄位皆不可測 SQLi(例如檔案上傳欄位),未實際測試"
    if not list(selected_names or []):
        return "沒有可測的參數,未取得任何逐參數結論"
    return "未取得足夠證據可判定為「無洞」"


def per_param_verdicts(log_text):
    """Explicit per-parameter verdicts, keyed by param NAME: {name: 'vulnerable'|'clean'}.
    Precedence (weak -> strong): a merely TENTATIVE "appears to be ... injectable" is
    provisional; an explicit rejection "does not seem to be injectable" (sqlmap's
    false-positive retraction) overrides it; a CONFIRMED "is vulnerable/injectable" wins
    outright. This stops a tentative hit that the tool LATER rejects from being recorded
    as a confirmed injection (which used to poison the dedup history)."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "")   # strip ANSI so colour-wrapped names match
    verdicts = {}
    for m in _PP_TENTATIVE_RE.finditer(text):
        verdicts.setdefault(m.group(1), "tentative")    # provisional ONLY -- NOT counted as
                                                        # vulnerable by merge_vuln, so an
                                                        # interrupted scan can't record a false
                                                        # confirmed injection off a tentative hit
    for m in _PP_CLEAN_RE.finditer(text):
        verdicts[m.group(1)] = "clean"                  # rejection overrides a tentative
    for rx in _PP_CONFIRMED_RES:
        for m in rx.finditer(text):
            verdicts[m.group(1)] = "vulnerable"         # confirmation wins outright
    return verdicts


def extract_findings(log_text):
    """Best-effort structured findings scraped from the raw log text. Every field
    is informational (surfaced to the user); none of it changes the vulnerable
    verdict."""
    # strip ANSI colour codes first (ghauri 1.4.3 has no --disable-coloring, and can wrap
    # a param name in colour escapes -> would corrupt every quoted-name match otherwise).
    text = re.sub(r"\x1b\[[0-9;]*m", "", log_text or "")
    findings = {
        "dbms": None,
        "parameters": [],
        "types": [],
        "titles": [],
        "payloads": [],
        # explicit per-parameter verdicts {name: 'vulnerable'|'clean'|'tentative'}
        "per_param": {},
        # enumeration (present only when the user asked for --banner /
        # --current-user / --current-db / --hostname / --is-dba / --dbs AND the
        # run got that far). Both tools print these with identical wording.
        "banner": None,
        "current_user": None,
        "current_db": None,
        "hostname": None,
        "is_dba": None,
        "databases_count": None,
        "databases": [],          # actual DB names from --dbs
        "db_users": [],           # --users names (sqlmap only)
        "password_hashes": [],    # --passwords hashes (sqlmap only)
        "tables_count": None,     # --tables
        "table_names": [],        # Table: <name> labels seen
        "columns_count": None,    # --columns
        "entries_count": None,    # --dump rows
        "web_tech": None,
        # bonus non-SQLi heuristic hits + reliability caveats (informational)
        "heuristic_sqli": [],     # sqlmap "might be injectable" (tentative, informational)
        "heuristic_xss": [],
        "heuristic_fi": [],
        "caveats": [],
    }
    m = _DBMS_RE.search(text) or _DBMS_IS_RE.search(text)
    if m:
        val = m.group(1).strip()
        # ghauri/sqlmap can append an interactive prompt on the same line, e.g.
        # "the back-end DBMS is 'MySQL'. Do you want to skip ...? [Y/n] Y" -> keep
        # only the DBMS name/version, drop the prompt tail.
        cuts = [val.find(x) for x in (". Do you want", " Do you want", " [", "? ", "?")]
        cuts = [i for i in cuts if i >= 0]
        if cuts:
            val = val[:min(cuts)]
        findings["dbms"] = val.strip(" '\".")
    findings["parameters"] = [x.strip() for x in _PARAM_RE.findall(text)]
    findings["types"] = [x.strip() for x in _TYPE_RE.findall(text)]
    findings["titles"] = [x.strip() for x in _TITLE_RE.findall(text)]
    findings["payloads"] = [x.strip() for x in _PAYLOAD_RE.findall(text)]

    def _one(rx):
        mm = rx.search(text)
        return mm.group(1).strip() if mm else None

    findings["banner"] = _one(_BANNER_RE)
    findings["current_user"] = _one(_CURUSER_RE)
    findings["current_db"] = _one(_CURDB_RE)
    findings["hostname"] = _one(_HOSTNAME_RE)
    dba = _one(_ISDBA_RE)
    if dba is not None:
        findings["is_dba"] = (dba.lower() == "true")
    dbs = _one(_DBS_RE)
    if dbs is not None:
        try:
            findings["databases_count"] = int(dbs)
        except ValueError:
            findings["databases_count"] = None
    findings["web_tech"] = _one(_WEBTECH_RE)

    # --dbs / --users NAMES (header "[N]:" then "[*] <name>" lines). Both tools reuse
    # "[*]" for START/END banners, so drop "starting @ .."/"ending @ ..".
    def _star_names(block_re):
        blk = block_re.search(text)
        if not blk:
            return []
        return [n.strip() for n in _STAR_ITEM_RE.findall(blk.group(1))
                if not re.match(r"(?:starting|ending)\s+@", n.strip(), re.I)]
    findings["databases"] = _star_names(_DBS_NAMES_RE)
    findings["db_users"] = _star_names(_USERS_NAMES_RE)
    findings["password_hashes"] = [m.group(1).strip() for m in _PWHASH_RE.finditer(text)]
    findings["table_names"] = sorted({m.strip() for m in _TABLE_LABEL_RE.findall(text)})

    def _cnt(rx):
        mm = rx.search(text)
        try:
            return int(mm.group(1)) if mm else None
        except ValueError:
            return None
    findings["tables_count"] = _cnt(_TABLES_CNT_RE)
    findings["columns_count"] = _cnt(_COLS_CNT_RE)
    findings["entries_count"] = _cnt(_ENTRIES_CNT_RE)
    findings["heuristic_sqli"] = sorted({m.group(1) for m in _HEUR_SQLI_RE.finditer(text)})

    findings["per_param"] = per_param_verdicts(text)
    findings["tested"] = sorted({m.group(1) for m in _PP_TESTED_RE.finditer(text)})  # actually-fuzzed params
    findings["heuristic_xss"] = sorted({m.group(1) for m in _XSS_RE.finditer(text)})
    findings["heuristic_fi"] = sorted({m.group(1) for m in _FI_RE.finditer(text)})
    findings["caveats"] = caveats(text)
    return findings


def append_verdict(ctx, *, tool, vulnerable, vuln_marker, vuln_line,
                   status, returncode, fail_marker, fail_line,
                   clean_hit, waf_marker, findings, recorded_history,
                   inconclusive_note=None):
    """Emit a compact, machine-parseable 【判定】 block that explains HOW the app
    judged this scan: each conclusion + the exact evidence it rests on. MUST be
    called AFTER the verdict is computed from read_log(), so quoting an English
    marker here can never re-trigger the matchers for this scan."""
    L = ctx.append_log
    L("──── 【判定】自動判讀依據 ────")

    # 1) vulnerable? A "否" (clean) verdict is only claimed on a POSITIVE completion
    #    (status=='done' -> the driver required a clean_hit). error AND killed both fall
    #    to "無法判定" -- never a clean conclusion drawn merely from status != error.
    if vulnerable:
        L("【判定】有漏洞:是 ← 命中關鍵字「{}」".format(vuln_marker))
        if vuln_line:
            L("【判定】  依據行:{}".format(vuln_line))
    elif status == "done":
        L("【判定】有漏洞:否 ← 已測完所選參數、命中「無可注入」完成訊號")
    elif status == "inconclusive":
        L("【判定】有漏洞:測不準 ← 雖有「無可注入」訊號,但結果不可信,不能當作「無洞」")
        if inconclusive_note:
            L("【判定】  原因:{}".format(inconclusive_note))
    else:
        L("【判定】有漏洞:無法判定 ← 掃描未正常完成或未出現「無可注入」完成訊號(狀態:{}),此結果不代表「無洞」".format(status))

    # 2) status + the reason it was reached
    if returncode is None:
        L("【判定】狀態:{}(使用者中止,不記錄參數歷史)".format(status))
    elif status == "error" and returncode != 0:
        L("【判定】狀態:error ← returncode={}(非 0:程序異常/崩潰)".format(returncode))
    elif status == "error" and fail_marker:
        L("【判定】狀態:error ← returncode=0,但命中「連線/存取失敗」關鍵字「{}」(目標未實際受測)".format(fail_marker))
        if fail_line:
            L("【判定】  依據行:{}".format(fail_line))
    elif status == "error":
        L("【判定】狀態:error ← returncode=0,但未出現「測試完成」訊號(疑似連線/SSL 失敗或掃描中斷)—— 目標未實際測完,不能當作「無洞」")
    elif status == "inconclusive":
        L("【判定】狀態:inconclusive(測不準)← returncode={}、有「無可注入」訊號,但{}".format(
            returncode, inconclusive_note or "結果不可信"))
    elif clean_hit:
        L("【判定】狀態:done ← returncode={}、命中「已測完但無可注入參數」完成訊號".format(returncode))
    elif fail_marker:
        L("【判定】狀態:done ← returncode={}(註:log 曾出現失敗字樣「{}」,但已{}完成)".format(
            returncode, fail_marker, "確認漏洞並" if vulnerable else ""))
    else:
        L("【判定】狀態:done ← returncode={}、未命中失敗關鍵字".format(returncode))

    # 3) WAF/IPS + reliability caveats
    if waf_marker:
        L("【判定】WAF/IPS:偵測到防護 ← 命中「{}」(「無洞」可能為誤判,建議加 --tamper 重測)".format(waf_marker))
    for c in (findings.get("caveats") or []):
        L("【判定】注意:{} ← 命中「{}」".format(c.get("note", ""), c.get("marker", "")))

    # 3b) bonus non-SQLi heuristic findings surfaced during the SQLi run
    if findings.get("heuristic_xss"):
        L("【判定】附帶發現・疑似 XSS:參數 {}(非 SQLi,heuristic 提示,建議另行驗證)".format(
            "、".join(findings["heuristic_xss"])))
    if findings.get("heuristic_fi"):
        L("【判定】附帶發現・疑似檔案包含 FI:參數 {}(非 SQLi,heuristic 提示)".format(
            "、".join(findings["heuristic_fi"])))

    # 4) findings surfaced
    if findings.get("dbms"):
        L("【判定】DBMS:{}".format(findings["dbms"]))
    if findings.get("parameters"):
        L("【判定】可注入參數:{}".format(" / ".join(findings["parameters"])))
    if findings.get("types"):
        L("【判定】注入技法:{}".format(" / ".join(dict.fromkeys(findings["types"]))))
    enum_fields = [
        ("banner", "banner"),
        ("current_user", "current user"),
        ("current_db", "current db"),
        ("hostname", "hostname"),
        ("web_tech", "web tech"),
    ]
    enum = ["{}={}".format(label, findings[key]) for key, label in enum_fields
            if findings.get(key) is not None]
    if findings.get("is_dba") is not None:
        enum.append("is DBA={}".format(findings["is_dba"]))
    if findings.get("databases"):
        enum.append("databases[{}]={}".format(len(findings["databases"]), "、".join(findings["databases"])))
    elif findings.get("databases_count") is not None:
        enum.append("databases={}".format(findings["databases_count"]))
    if findings.get("db_users"):
        enum.append("db users={}".format("、".join(findings["db_users"])))
    if findings.get("password_hashes"):
        enum.append("password hashes={}".format(len(findings["password_hashes"])))
    if findings.get("tables_count") is not None:
        enum.append("tables={}".format(findings["tables_count"]))
    if findings.get("columns_count") is not None:
        enum.append("columns={}".format(findings["columns_count"]))
    if findings.get("entries_count") is not None:
        enum.append("dump entries={}".format(findings["entries_count"]))
    if enum:
        L("【判定】列舉:{}".format("、".join(enum)))
    if findings.get("table_names"):
        L("【判定】資料表:{}".format(" / ".join(findings["table_names"])))
    if findings.get("heuristic_sqli"):
        L("【判定】附帶提示・heuristic 疑似可注入:參數 {}(暫定,非確認)".format("、".join(findings["heuristic_sqli"])))
    if findings.get("is_dba") is True:
        L("【判定】權限:目前資料庫帳號具 DBA 權限(影響程度高)")

    # 5) what actually got written into the dedup history
    if recorded_history is None:
        L("【判定】參數歷史:未寫入(僅 status=done 才記錄,避免污染去重)")
    elif recorded_history:
        L("【判定】參數歷史:已記錄 {}".format(
            "、".join("{}={}".format(n, s) for n, s in recorded_history)))
    else:
        L("【判定】參數歷史:無已勾選參數可記錄")

    L("──── 【判定】結束 ────")

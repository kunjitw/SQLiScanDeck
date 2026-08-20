"""
ghauri driver -- ghauri has no REST API, so we wrap the CLI as a subprocess and
stream its stdout into the scan log. Run with the *portable* python via
`python -m ghauri`, so we never touch the user's system python.

Runs synchronously inside a worker thread; a background reader thread pumps
output so cancellation stays responsive.
"""
import os
import queue
import subprocess
import threading

import config
import proc_guard
from drivers import base

TOOL = "ghauri"


def build_args(ctx):
    """
    Build ghauri CLI args. Flags verified against ghauri source
    (ghauri/scripts/ghauri.py). NOTE: ghauri has NO --tamper and NO --risk.
    """
    args = ["-r", ctx.request_file, "--batch"]
    o = ctx.options or {}

    sel = base.selected_names(ctx.params)
    desel = base.deselected_names(ctx.params)
    if sel and desel:                       # only narrow if user narrowed
        args += ["-p", ",".join(sel)]

    # NOTE: ghauri already defaults to https for -r requests, and its --force-ssl
    # only toggles TLS CERT VERIFICATION (default: accept any cert). We deliberately
    # do NOT pass it: enabling verification would break self-signed / bad-cert
    # targets (common in authorized testing). The "強制 HTTPS" toggle is effectively
    # a no-op for ghauri (it's https regardless), so mapping it here would only harm.
    if o.get("random_agent"):
        args += ["--random-agent"]
    if o.get("text_only"):
        args += ["--text-only"]

    # value options (only if provided)
    def add(flag, key, cast=str):
        v = o.get(key)
        if v is None or v == "":   # keep 0 (retries=0 / delay=0 are meaningful)
            return
        args.extend([flag, str(cast(v))])

    add("--level", "level", int)
    add("--dbms", "dbms")
    add("--technique", "technique")
    add("--threads", "threads", int)
    add("--timeout", "timeout", int)
    add("--time-sec", "time_sec", int)
    add("--retries", "retries", int)
    add("--delay", "delay", int)
    add("--prefix", "prefix")
    add("--suffix", "suffix")
    add("--proxy", "proxy")
    # detection tuning + request control (ghauri supports these; NOT skip/regexp/auth/csrf)
    _hdr = o.get("headers")
    if _hdr not in (None, ""):   # textarea: one header per line -> literal \n
        args.extend(["--headers", str(_hdr).replace("\r\n", "\n").replace("\n", "\\n")])
    add("--ignore-code", "ignore_code")
    add("--string", "test_string")
    add("--not-string", "not_string")
    add("--code", "code", int)

    # enumeration flags (store_true)
    for key, flag in (("get_banner", "--banner"),
                      ("get_current_user", "--current-user"),
                      ("get_current_db", "--current-db"),
                      ("get_hostname", "--hostname"),
                      ("get_dbs", "--dbs"),
                      ("dump", "--dump")):
        if o.get(key):
            args.append(flag)
    return args


def _ensure_http_referer(ctx):
    """ghauri defaults -r requests to HTTPS and has NO flag to force http; its only
    documented downgrade is a matching 'Referer: http://<host>/'. So when the target
    is http, inject one — otherwise ghauri tries https and dies with 'target URL is
    not responding' on any plain-http / localhost target."""
    if ctx.scheme == "https":
        return
    try:
        with open(ctx.request_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
            raw = f.read()
    except Exception:
        return
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    host = ""
    for ln in lines:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
            break
    if not host:
        return
    if any(ln.lower().startswith("referer:") and "http://" in ln.lower() for ln in lines):
        return                                  # already has an http Referer
    referer = "Referer: http://{}/".format(host)
    out, inserted = [], False
    for ln in lines:
        if ln.lower().startswith("referer:"):   # drop EVERY existing (non-http) Referer, no duplicates
            continue
        out.append(ln)
        if ln.lower().startswith("host:") and not inserted:   # insert the single canonical one after Host
            out.append(referer)
            inserted = True
    if not inserted:                            # defensive: no Host line matched -> put it right after the request line
        out.insert(1, referer)
    try:
        with open(ctx.request_file, "w", encoding="utf-8", errors="ignore", newline="") as f:
            f.write("\r\n".join(out))
        ctx.append_log("備忘・已注入 {} 讓 ghauri 走 http(ghauri 對 -r 預設 https、無強制 http 旗標)".format(referer))
    except Exception:
        pass


def _pump(pipe, q):
    try:
        for line in iter(pipe.readline, ""):
            q.put(line)
    except Exception:
        pass
    finally:
        q.put(None)  # sentinel: stream closed


def run(ctx):
    ctx.append_log("=== ghauri 掃描開始 ===")
    ctx.append_log("目標:{} {}".format(ctx.method, ctx.url))
    if ctx.restrict_ip:
        # audit/memo only -- ghauri cannot bind an outbound source IP, so this
        # is a note, not an enforced restriction.
        ctx.append_log("備忘・允許測試來源 IP:{}".format(ctx.restrict_ip))

    _ensure_http_referer(ctx)   # make ghauri use http on plain-http targets (it defaults https)
    args = build_args(ctx)
    # Run ghauri from its GitHub source (tools/ghauri) via our launcher, using
    # the portable python. ghauri itself is NOT pip-installed.
    cmd = [ctx.python_exe, config.GHAURI_LAUNCH] + args + ctx.extra_flag_list()
    ctx.append_log("指令:{}".format(base.display_cmd(cmd)))

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    # Isolate ghauri's session DB per scan. ghauri stores it at
    # expanduser('~')/.ghauri/<host>/session.sqlite with NO flag to relocate it, so two
    # concurrent scans on the same host would share (and cross-contaminate / lock) one
    # session.sqlite -- risking a param reported vulnerable off another run's cached hit.
    # Point HOME/USERPROFILE at a per-scan dir (ntpath.expanduser honors USERPROFILE first).
    scan_home = os.path.join(config.DATA_DIR, "ghauri_home", str(ctx.id))
    try:
        os.makedirs(scan_home, exist_ok=True)
    except Exception:
        pass
    env["USERPROFILE"] = scan_home
    env["HOME"] = scan_home

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            bufsize=1,
            env=env,
            cwd=config.DATA_DIR,   # ghauri writes session/output here, not into its source
        )
    except FileNotFoundError:
        ctx.append_log("!! 找不到可攜帶 python 或 ghauri 模組,請先執行 bootstrap.bat")
        ctx.fail("ghauri 啟動失敗:找不到 python/ghauri")
        return
    except Exception as e:
        ctx.append_log("!! ghauri 啟動失敗:{}".format(e))
        ctx.fail("ghauri 啟動失敗:{}".format(e))
        return

    ctx.engine_proc = proc
    proc_guard.assign(proc.pid)   # so a HARD-killed backend takes this scanner down with it
    q = queue.Queue()
    reader = threading.Thread(target=_pump, args=(proc.stdout, q), daemon=True)
    reader.start()

    killed = False
    while True:
        if ctx.should_stop():
            try:
                proc.terminate()
            except Exception:
                pass
            ctx.append_log("== 使用者中止掃描 ==")
            killed = True
            break
        try:
            line = q.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None:
                # process ended; let the reader enqueue the tail + sentinel, then drain
                reader.join(timeout=2)
                _drain(q, ctx)
                break
            continue
        if line is None:  # stream closed
            break
        ctx.append_log(line.rstrip("\n"))

    try:
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # Compute the verdict from the pre-annotation log, THEN append the 【判定】
    # block (so quoting an English marker in the block can't re-flip this scan).
    log_text = ctx.read_log()
    vuln_marker, vuln_line = base.vuln_evidence(log_text)
    findings = base.extract_findings(log_text)
    vulnerable, vuln_marker = base.merge_vuln(vuln_marker, findings)  # fold per-param confirmation in
    waf_marker, _waf_line = base.waf_evidence(log_text)
    # stamp reliability BEFORE the killed/done split (see sqlmap_driver) so a killed+vuln
    # run can't record a co-param 'clean' against an untrustworthy baseline.
    findings["reliability_ok"] = base.severe_reliability(log_text)[0] is None

    if killed:
        recorded = ctx.finish(status="killed", vulnerable=vulnerable, findings=findings)
        base.append_verdict(ctx, tool="ghauri", vulnerable=vulnerable,
                            vuln_marker=vuln_marker, vuln_line=vuln_line,
                            status="killed", returncode=None,
                            fail_marker=None, fail_line=None, clean_hit=False,
                            waf_marker=waf_marker, findings=findings,
                            recorded_history=recorded)
    else:
        rc = proc.returncode
        ctx.append_log("=== ghauri 掃描結束 (returncode={}) ===".format(rc))
        # Count as a real "done" only if the target was actually reached & tested.
        # ghauri exits 0 even on connection failure AND phrases the failure very
        # differently from sqlmap, so this relies on base._FAILURE_MARKERS also
        # covering ghauri's wording. clean_hit overrides a stray retry substring;
        # a found vuln is preserved via the vulnerable flag regardless.
        fail_marker, fail_line = base.fail_evidence(log_text)
        clean_hit = base.looks_clean(log_text)
        # coverage LHS must be the exact set sent to -p: base.selected_names drops file /
        # non-testable fields, so a 'selected' file field can't force a false 測不準.
        # had_selection guards the "user selected ONLY non-testable fields" edge.
        selected_names = base.selected_names(getattr(ctx, "params", []))
        had_selection = any(p.get("selected") for p in getattr(ctx, "params", []))
        # Three-outcome verdict, shared with sqlmap via base.decide_status so the two
        # engines never diverge: 有洞 / 無洞 / 失敗. A low-confidence clean (error storm
        # or coverage gap) stays 無洞 -- its reason becomes an advisory ⚠ caveat below.
        status = base.decide_status(rc, vulnerable, clean_hit)
        # A low-confidence clean stays 無洞; its reason rides along as an advisory ⚠
        # caveat (findings['caveat']) for the UI, never as its own verdict.
        caveat = (base.clean_caveat(selected_names, findings, log_text, had_selection)
                  if (status == "done" and not vulnerable) else None)
        findings["caveat"] = caveat
        recorded = ctx.finish(status=status, vulnerable=vulnerable, findings=findings)
        base.append_verdict(ctx, tool="ghauri", vulnerable=vulnerable,
                            vuln_marker=vuln_marker, vuln_line=vuln_line,
                            status=status, returncode=rc,
                            fail_marker=fail_marker, fail_line=fail_line,
                            clean_hit=clean_hit, waf_marker=waf_marker,
                            findings=findings, recorded_history=recorded,
                            caveat_note=caveat)


def _drain(q, ctx):
    while True:
        try:
            line = q.get_nowait()
        except queue.Empty:
            return
        if line is None:
            return
        ctx.append_log(line.rstrip("\n"))

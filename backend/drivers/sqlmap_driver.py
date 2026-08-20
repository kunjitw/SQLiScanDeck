"""
sqlmap driver -- run sqlmap's CLI (sqlmap.py) directly, ONE subprocess per scan,
streaming its stdout into the scan log. Same model as the ghauri driver (no REST
API). Launched on the portable python via sqlmap_launch.py so sqlmap can import
its own `lib`. Cancellation terminates the process.
"""
import os
import queue
import subprocess
import threading

import config
import proc_guard
from drivers import base

TOOL = "sqlmap"


def build_args(ctx):
    """sqlmap CLI args. Flags verified against sqlmap-1.10/lib/parse/cmdline.py."""
    args = ["-r", ctx.request_file, "--batch", "--disable-coloring"]
    o = ctx.options or {}

    sel = base.selected_names(ctx.params)
    desel = base.deselected_names(ctx.params)
    if sel and desel:                       # only narrow if the user narrowed
        args += ["-p", ",".join(sel)]

    if ctx.scheme == "https" or o.get("force_ssl"):
        args += ["--force-ssl"]
    if o.get("random_agent"):
        args += ["--random-agent"]
    if o.get("text_only"):
        args += ["--text-only"]

    def add(flag, key, cast=str):
        v = o.get(key)
        if v is None or v == "":            # keep 0 (retries=0 / delay=0 are meaningful)
            return
        try:
            args.append("{}={}".format(flag, cast(v)))
        except Exception:
            args.append("{}={}".format(flag, v))

    add("--level", "level", int)
    add("--risk", "risk", int)
    add("--technique", "technique")
    add("--dbms", "dbms")
    add("--threads", "threads", int)
    add("--tamper", "tamper")
    add("--timeout", "timeout", float)
    add("--time-sec", "time_sec", int)
    add("--delay", "delay", float)
    add("--retries", "retries", int)
    add("--prefix", "prefix")
    add("--suffix", "suffix")
    add("--proxy", "proxy")
    # detection tuning + request control + auth/CSRF (flags audited to exist)
    _hdr = o.get("headers")
    if _hdr not in (None, ""):   # textarea: one header per line -> literal \n
        args.append("--headers={}".format(str(_hdr).replace("\r\n", "\n").replace("\n", "\\n")))
    add("--ignore-code", "ignore_code")
    add("--string", "test_string")
    add("--not-string", "not_string")
    add("--regexp", "regexp")
    add("--code", "code", int)
    add("--skip", "skip")
    add("--auth-type", "auth_type")
    add("--auth-cred", "auth_cred")
    add("--csrf-token", "csrf_token")
    add("--csrf-url", "csrf_url")
    # danger zone (interactive shells --os-shell/--sql-shell intentionally NOT
    # exposed: they'd block on stdin in a background subprocess)
    add("--sql-query", "sql_query")
    add("--os-cmd", "os_cmd")
    add("--file-read", "file_read")
    add("--file-write", "file_write")
    add("--file-dest", "file_dest")

    for key, flag in (("get_banner", "--banner"),
                      ("get_current_user", "--current-user"),
                      ("get_current_db", "--current-db"),
                      ("get_hostname", "--hostname"),
                      ("get_dbs", "--dbs"),
                      ("is_dba", "--is-dba"),
                      ("dump", "--dump"),
                      ("dump_all", "--dump-all"),
                      ("passwords", "--passwords")):
        if o.get(key):
            args.append(flag)

    # per-scan output dir -> fully isolates sqlmap's per-target state
    # (session.sqlite HashDB, target.txt, dump/), so concurrent scans -- even
    # against the SAME host -- never share files. sqlmap nests
    # <output-dir>/<hostname>/ beneath this; ctx.id is unique per scan.
    args.append("--output-dir={}".format(
        os.path.join(config.DATA_DIR, "sqlmap_output", str(ctx.id))))
    return args


def _pump(pipe, q):
    try:
        for line in iter(pipe.readline, ""):
            q.put(line)
    except Exception:
        pass
    finally:
        q.put(None)  # sentinel: stream closed


def run(ctx):
    ctx.append_log("=== sqlmap 掃描開始 ===")
    ctx.append_log("目標:{} {}".format(ctx.method, ctx.url))
    if ctx.restrict_ip:
        # audit/memo only -- neither sqlmap nor ghauri can bind an outbound
        # source IP, so this is a note, not an enforced restriction.
        ctx.append_log("備忘・允許測試來源 IP:{}".format(ctx.restrict_ip))

    args = build_args(ctx)
    cmd = [ctx.python_exe, config.SQLMAP_LAUNCH] + args + ctx.extra_flag_list()
    ctx.append_log("指令:{}".format(base.display_cmd(cmd)))

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

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
            cwd=config.DATA_DIR,
        )
    except FileNotFoundError:
        ctx.append_log("!! 找不到攜帶版 python 或 sqlmap,請先執行 bootstrap.bat")
        ctx.fail("sqlmap 啟動失敗:找不到 python/sqlmap")
        return
    except Exception as e:
        ctx.append_log("!! sqlmap 啟動失敗:{}".format(e))
        ctx.fail("sqlmap 啟動失敗:{}".format(e))
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
                reader.join(timeout=2)   # let the reader enqueue the tail + sentinel
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
    # stamp reliability BEFORE the killed/done split: a killed+vulnerable run also records
    # param history, so without this its co-params' "clean" lines would be recorded against
    # an untrustworthy baseline (reliability_ok would default True), defeating the guard.
    findings["reliability_ok"] = base.severe_reliability(log_text)[0] is None

    if killed:
        recorded = ctx.finish(status="killed", vulnerable=vulnerable, findings=findings)
        base.append_verdict(ctx, tool="sqlmap", vulnerable=vulnerable,
                            vuln_marker=vuln_marker, vuln_line=vuln_line,
                            status="killed", returncode=None,
                            fail_marker=None, fail_line=None, clean_hit=False,
                            waf_marker=waf_marker, findings=findings,
                            recorded_history=recorded)
    else:
        rc = proc.returncode
        ctx.append_log("=== sqlmap 掃描結束 (returncode={}) ===".format(rc))
        # Count as a real "done" only if the target was actually reached & tested.
        # rc!=0 (crash) OR a connection/access failure in the log (sqlmap exits 0
        # even when it never connected) => "error", so finish() won't record the
        # params as "tested, no vuln" and poison dedup. clean_hit (the positive
        # "tested, nothing injectable" signal) overrides a stray failure substring
        # left by a transient retry that recovered. A found vuln is preserved via
        # the vulnerable flag regardless.
        fail_marker, fail_line = base.fail_evidence(log_text)
        clean_hit = base.looks_clean(log_text)
        # coverage LHS must be the exact set sent to -p: base.selected_names drops file /
        # non-testable fields, so a 'selected' file field can't force a false 測不準.
        # had_selection guards the "user selected ONLY non-testable fields" edge.
        selected_names = base.selected_names(getattr(ctx, "params", []))
        had_selection = any(p.get("selected") for p in getattr(ctx, "params", []))
        # Three-outcome verdict (shared via base.decide_status): 有洞 / 無洞 / 失敗.
        # A low-confidence clean (error storm, or a coverage gap like cookies at
        # --level 1 / the URI '#1*' fallback) is STILL 無洞 -- its reason becomes an
        # advisory ⚠ caveat below, not a separate status.
        status = base.decide_status(rc, vulnerable, clean_hit)
        # A low-confidence clean stays 無洞; its reason rides along as an advisory ⚠
        # caveat (findings['caveat']) for the UI, never as its own verdict.
        caveat = (base.clean_caveat(selected_names, findings, log_text, had_selection)
                  if (status == "done" and not vulnerable) else None)
        findings["caveat"] = caveat
        recorded = ctx.finish(status=status, vulnerable=vulnerable, findings=findings)
        base.append_verdict(ctx, tool="sqlmap", vulnerable=vulnerable,
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

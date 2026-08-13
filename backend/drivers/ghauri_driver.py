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

    if ctx.scheme == "https" or o.get("force_ssl"):
        args += ["--force-ssl"]
    if o.get("random_agent"):
        args += ["--random-agent"]

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

    # enumeration flags (store_true)
    for key, flag in (("get_banner", "--banner"),
                      ("get_current_user", "--current-user"),
                      ("get_current_db", "--current-db"),
                      ("get_hostname", "--hostname"),
                      ("get_dbs", "--dbs")):
        if o.get(key):
            args.append(flag)
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
    ctx.append_log("=== ghauri 掃描開始 ===")
    ctx.append_log("目標:{} {}".format(ctx.method, ctx.url))
    if ctx.restrict_ip:
        ctx.append_log("限制測試來源 IP:{}".format(ctx.restrict_ip))

    args = build_args(ctx)
    # Run ghauri from its GitHub source (tools/ghauri) via our launcher, using
    # the portable python. ghauri itself is NOT pip-installed.
    cmd = [ctx.python_exe, config.GHAURI_LAUNCH] + args + ctx.extra_flag_list()
    ctx.append_log("指令:{}".format(" ".join(cmd)))

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
                # process ended; drain remaining
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

    log_text = ctx.read_log()
    vulnerable = base.looks_vulnerable(log_text)
    findings = base.extract_findings(log_text)

    if killed:
        ctx.finish(status="killed", vulnerable=vulnerable, findings=findings)
    else:
        rc = proc.returncode
        ctx.append_log("=== ghauri 掃描結束 (returncode={}) ===".format(rc))
        ctx.finish(status="done", vulnerable=vulnerable, findings=findings)


def _drain(q, ctx):
    while True:
        try:
            line = q.get_nowait()
        except queue.Empty:
            return
        if line is None:
            return
        ctx.append_log(line.rstrip("\n"))

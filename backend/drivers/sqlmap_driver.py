"""
sqlmap driver -- talks to the sqlmap REST API (sqlmapapi.py -s).

Each scan is a *task* in a separate sqlmap process, so many can run at once
without blocking each other. We stream the task log into the scan's log file
and read /scan/<id>/data at the end for structured findings.

Runs synchronously inside a worker thread (the scan manager owns concurrency);
cancellation is cooperative via ctx.should_stop().
"""
import json
import time
import urllib.request
import urllib.error

from drivers import base

TOOL = "sqlmap"


def _req(url, payload=None, timeout=15):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers,
                               method="POST" if payload is not None else "GET")
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "ignore")
    try:
        return json.loads(raw)
    except Exception:
        return {"success": False, "raw": raw}


def build_options(ctx):
    """Map our scan options + request file onto sqlmap API option names."""
    # Option (dest) names verified against sqlmap-1.10/lib/parse/cmdline.py.
    o = ctx.options or {}
    opts = {
        "batch": True,
        "requestFile": ctx.request_file,      # faithful raw request => handles GET/POST/JSON/cookies/headers
    }
    if ctx.scheme == "https" or o.get("force_ssl"):
        opts["forceSSL"] = True

    sel = base.selected_names(ctx.params)
    desel = base.deselected_names(ctx.params)
    # Only constrain if the user actually narrowed the set.
    if sel and desel:
        opts["testParameter"] = ",".join(sel)
    if desel:
        opts["skip"] = ",".join(desel)

    if o.get("random_agent"):
        opts["randomAgent"] = True

    # value options: our key -> (sqlmap dest, caster)
    value_map = {
        "level": ("level", int), "risk": ("risk", int),
        "technique": ("technique", str), "dbms": ("dbms", str),
        "threads": ("threads", int), "tamper": ("tamper", str),
        "timeout": ("timeout", float), "time_sec": ("timeSec", int),
        "delay": ("delay", float), "retries": ("retries", int),
        "prefix": ("prefix", str), "suffix": ("suffix", str),
        "proxy": ("proxy", str),
    }
    for our, (dest, cast) in value_map.items():
        v = o.get(our)
        # keep 0 -- retries=0 / delay=0 / time_sec=0 are meaningful choices.
        # (the old `v not in (None,"",False)` dropped them because 0 == False)
        if v is None or v == "":
            continue
        try:
            opts[dest] = cast(v)
        except Exception:
            opts[dest] = v

    # enumeration toggles (store_true)
    enum_map = {
        "get_banner": "getBanner", "get_current_user": "getCurrentUser",
        "get_current_db": "getCurrentDb", "get_hostname": "getHostname",
        "get_dbs": "getDbs", "is_dba": "isDba",
    }
    for our, their in enum_map.items():
        if o.get(our):
            opts[their] = True
    return opts


def run(ctx):
    base_url = ctx.sqlmapapi_base
    ctx.append_log("=== sqlmap 掃描開始 ===")
    ctx.append_log("目標:{} {}".format(ctx.method, ctx.url))
    if ctx.restrict_ip:
        ctx.append_log("限制測試來源 IP:{}".format(ctx.restrict_ip))

    # 1) new task
    try:
        resp = _req(base_url + "/task/new")
        taskid = resp.get("taskid")
        if not taskid:
            raise RuntimeError("sqlmap API 未回傳 taskid:{}".format(resp))
    except Exception as e:
        ctx.append_log("!! 無法建立 sqlmap 任務(REST API 沒啟動?):{}".format(e))
        ctx.fail("sqlmap API 連線失敗:{}".format(e))
        return
    ctx.engine_task_id = taskid
    ctx.append_log("sqlmap task id = {}".format(taskid))

    # 2) start scan with options
    opts = build_options(ctx)
    ctx.append_log("選項:{}".format(json.dumps(opts, ensure_ascii=False)))
    try:
        start = _req(base_url + "/scan/{}/start".format(taskid), payload=opts)
    except Exception as e:
        ctx.append_log("!! 啟動掃描失敗:{}".format(e))
        ctx.fail("啟動掃描失敗:{}".format(e))
        return
    # A failed start (bad option etc.) never enters 'running', so the poll loop
    # below would spin forever waiting for 'terminated'. Treat it as fatal.
    if not start.get("success", True) and "engineid" not in start:
        ctx.append_log("!! 啟動掃描回應異常,任務未開始:{}".format(start))
        try:
            _req(base_url + "/task/{}/delete".format(taskid))
        except Exception:
            pass
        ctx.fail("sqlmap 未能啟動掃描(選項可能無效):{}".format(start))
        return

    # 3) poll log + status
    last = 0
    killed = False
    seen_running = False
    idle = 0
    while True:
        if ctx.should_stop():
            try:
                _req(base_url + "/scan/{}/kill".format(taskid))
            except Exception:
                pass
            ctx.append_log("== 使用者中止掃描 ==")
            killed = True
            break
        try:
            log = _req(base_url + "/scan/{}/log".format(taskid))
            entries = log.get("log", []) or []
            for e in entries[last:]:
                ctx.append_log("[{}] [{}] {}".format(
                    e.get("time", ""), e.get("level", ""), e.get("message", "")))
            last = len(entries)
        except Exception as e:
            ctx.append_log("(讀取 log 暫時失敗:{})".format(e))

        try:
            status = _req(base_url + "/scan/{}/status".format(taskid))
        except Exception as e:
            status = {"status": "running"}
            ctx.append_log("(讀取狀態暫時失敗:{})".format(e))

        st = status.get("status")
        if st == "running":
            seen_running = True
            idle = 0
        elif st == "terminated":
            break
        elif st == "not running":
            # finished after running -> done; never ran -> bail so we don't spin
            if seen_running:
                break
            idle += 1
            if idle >= 8:  # ~10s and it never entered 'running'
                ctx.append_log("!! sqlmap 任務長時間未進入執行狀態,判定啟動失敗。")
                break
        time.sleep(1.2)

    # 4) collect data + decide vulnerable
    log_text = ctx.read_log()
    vulnerable = base.looks_vulnerable(log_text)
    findings = base.extract_findings(log_text)
    try:
        data = _req(base_url + "/scan/{}/data".format(taskid))
        if data.get("data"):
            findings["api_data"] = data.get("data")
            # presence of injection data is a strong signal
            for d in data.get("data", []):
                if d.get("type") in (1,) and d.get("value"):
                    vulnerable = True
    except Exception:
        pass

    # 5) cleanup task
    try:
        _req(base_url + "/task/{}/delete".format(taskid))
    except Exception:
        pass

    if killed:
        ctx.finish(status="killed", vulnerable=vulnerable, findings=findings)
    else:
        ctx.append_log("=== sqlmap 掃描結束 ===")
        ctx.finish(status="done", vulnerable=vulnerable, findings=findings)

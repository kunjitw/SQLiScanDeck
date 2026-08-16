"""
FastAPI backend + static frontend host.

Run directly with the portable python:  python backend\app.py
It serves the web UI and the JSON API on http://127.0.0.1:8776 by default.
"""
import os
import sys
import json
import threading
import webbrowser

# make sibling modules importable when launched as a script
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import config          # noqa: E402
import db              # noqa: E402
import request_parser  # noqa: E402
import filters as filters_mod  # noqa: E402
import ip_utils        # noqa: E402
from scan_manager import manager  # noqa: E402

from fastapi import FastAPI, Body, HTTPException  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

WEB_DIR = os.path.join(config.ROOT_DIR, "web")

app = FastAPI(title="sqlmap_auto", version="1.0")


@app.on_event("startup")
def _startup():
    config.ensure_dirs()
    manager.start()


@app.on_event("shutdown")
def _shutdown():
    manager.shutdown()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _annotate_params(parsed, project_id):
    """Attach filter status + prior-test status to each detected parameter."""
    rules = db.list_rules(project_id)
    annotated = filters_mod.apply_filters(parsed.get("params", []), rules)

    signature, sig_endpoint, endpoint = manager.prepare_target(parsed)
    prior = {}
    for ph in db.param_history(project_id, sig_endpoint):
        prior[(ph["location"], ph["name"])] = ph
    for p in annotated:
        hist = prior.get((p["location"], p["name"]))
        if hist:
            p["prior_status"] = hist["status"]
            p["prior_vulnerable"] = bool(hist["vulnerable"])
            p["prior_test_count"] = hist["test_count"]
        else:
            p["prior_status"] = None
            p["prior_vulnerable"] = False
            p["prior_test_count"] = 0
    return annotated, signature, sig_endpoint, endpoint


# --------------------------------------------------------------------------
# meta / ip / settings
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"ok": True, "sqlmap_present": os.path.isfile(config.SQLMAPAPI_PY)}


@app.get("/api/ip")
def api_ip():
    s = manager.settings
    return ip_utils.get_ip_info(
        want_public=s.get("public_ip_lookup", True),
        public_timeout=s.get("public_ip_timeout", 2.5),
    )


@app.get("/api/settings")
def get_settings():
    return manager.settings


@app.post("/api/settings")
def update_settings(payload: dict = Body(...)):
    merged = config.save_settings({**manager.settings, **(payload or {})})
    manager.reload_settings()
    return merged


# --------------------------------------------------------------------------
# projects
# --------------------------------------------------------------------------
@app.get("/api/projects")
def list_projects():
    return db.list_projects()


@app.post("/api/projects")
def create_project(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "專案名稱不可為空")
    return db.create_project(name, payload.get("note", ""), payload.get("restrict_ip", ""))


@app.patch("/api/projects/{pid}")
def patch_project(pid: int, payload: dict = Body(...)):
    return db.update_project(pid, **(payload or {}))


@app.delete("/api/projects/{pid}")
def del_project(pid: int):
    db.delete_project(pid)
    return {"ok": True}


# --------------------------------------------------------------------------
# filter rules
# --------------------------------------------------------------------------
@app.get("/api/rules")
def list_rules(project_id: int = None):
    return db.list_rules(project_id)


@app.post("/api/rules")
def create_rule(payload: dict = Body(...)):
    kind = payload.get("kind")
    mode = payload.get("mode")
    pattern = payload.get("pattern")
    if kind not in ("name", "value"):
        raise HTTPException(400, "kind 必須是 name 或 value")
    if mode not in ("equals", "iequals", "prefix", "contains", "regex"):
        raise HTTPException(400, "不支援的 mode")
    if not pattern:
        raise HTTPException(400, "pattern 不可為空")
    return db.create_rule(kind, mode, pattern, payload.get("note", ""),
                          payload.get("project_id"), payload.get("enabled", True))


@app.patch("/api/rules/{rid}")
def patch_rule(rid: int, payload: dict = Body(...)):
    db.update_rule(rid, **(payload or {}))
    return {"ok": True}


@app.delete("/api/rules/{rid}")
def del_rule(rid: int):
    db.delete_rule(rid)
    return {"ok": True}


# --------------------------------------------------------------------------
# scan templates (reusable presets; one may be auto-applied default)
# --------------------------------------------------------------------------
@app.get("/api/templates")
def list_templates():
    return db.list_templates()


@app.get("/api/templates/default")
def default_template(tool: str = None):
    return db.get_default_template(tool) or {}


@app.post("/api/templates")
def create_template(payload: dict = Body(...)):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "範本名稱不可為空")
    data = payload.get("data", {}) or {}
    tool = payload.get("tool") or data.get("tool") or ""
    return db.create_template(name, data, bool(payload.get("is_default", False)), tool)


@app.patch("/api/templates/{tid}")
def patch_template(tid: int, payload: dict = Body(...)):
    return db.update_template(tid, **(payload or {}))


@app.delete("/api/templates/{tid}")
def del_template(tid: int):
    db.delete_template(tid)
    return {"ok": True}


# --------------------------------------------------------------------------
# parse (paste request -> params + filters + history)
# --------------------------------------------------------------------------
@app.post("/api/parse")
def parse(payload: dict = Body(...)):
    raw = payload.get("raw", "")
    force_ssl = bool(payload.get("force_ssl", False))
    project_id = payload.get("project_id")
    parsed = request_parser.parse_request(raw, force_ssl=force_ssl)
    annotated, signature, sig_endpoint, endpoint = _annotate_params(parsed, project_id)
    parsed["params"] = annotated
    history = manager.history_for(project_id, signature, sig_endpoint)
    return {
        "parsed": parsed,
        "signature": signature,
        "sig_endpoint": sig_endpoint,
        "endpoint": endpoint,
        "history": history,
    }


# --------------------------------------------------------------------------
# scans
# --------------------------------------------------------------------------
@app.post("/api/scans")
def create_scans(payload: dict = Body(...)):
    raw = payload.get("raw", "")
    force_ssl = bool(payload.get("force_ssl", False))
    project_id = payload.get("project_id")
    if project_id is None:
        raise HTTPException(400, "必須先選擇或建立一個專案才能掃描")
    if db.get_project(project_id) is None:
        raise HTTPException(400, "指定的專案不存在")
    options = payload.get("options", {}) or {}
    params = payload.get("params", []) or []
    extra_flags = payload.get("extra_flags", "") or ""
    restrict_ip = payload.get("restrict_ip", "") or ""
    note = payload.get("note", "") or ""

    tools = payload.get("tools")
    if not tools:
        tools = [payload.get("tool", "sqlmap")]
    tools = [t for t in tools if t in ("sqlmap", "ghauri")]
    if not tools:
        raise HTTPException(400, "請選擇工具 sqlmap 或 ghauri")

    parsed = request_parser.parse_request(raw, force_ssl=force_ssl)
    if not parsed.get("ok"):
        raise HTTPException(400, "請求解析失敗:{}".format("; ".join(parsed.get("warnings", []))))

    # Reconcile the client's selection against the request we ACTUALLY parse here
    # (this parse is the source of the -r file). If the raw request was edited
    # after the UI parsed it, stale param names would otherwise be tested. Carry
    # the user's checkbox choices onto the freshly-parsed params by (name,
    # location); vanished params drop out, brand-new ones default to unselected.
    sel_map = {(p.get("name"), p.get("location")): bool(p.get("selected")) for p in params}
    params = [dict(p, selected=sel_map.get((p.get("name"), p.get("location")), False))
              for p in parsed.get("params", [])]

    # Guard the all-deselected case the UI already blocks (direct API clients):
    # sqlmap would get skip=<every name> and abort "all parameters were skipped".
    if params and not any(p.get("selected") for p in params):
        raise HTTPException(400, "請至少勾選一個要測試的參數")

    launched = []
    for tool in tools:
        row = manager.create_scan(parsed, tool, options, params,
                                  project_id=project_id, extra_flags=extra_flags,
                                  restrict_ip=restrict_ip, note=note)
        manager.launch(row)
        launched.append(row)
    return {"launched": launched, "count": len(launched)}


@app.post("/api/scans/stop_all")
def scans_stop_all(project_id: int = None):
    return {"stopped": manager.stop_all(project_id)}


@app.get("/api/scans")
def list_scans(project_id: int = None, status: str = None, limit: int = 200, slim: bool = False):
    return db.list_scans(project_id=project_id, status=status, limit=limit, slim=slim)


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    row = db.get_scan(sid)
    if not row:
        raise HTTPException(404, "找不到掃描")
    if row.get("result_json"):
        row["result"] = json.loads(row["result_json"])
    # the raw request (from the -r file) so the UI can re-load this scan's exact
    # request + settings back into the composer ("以此設定重新配置"). The raw
    # request contains the TARGET's cookies / auth headers, so only expose it when
    # the server is bound to loopback -- never hand captured credentials to a
    # non-local client on a 0.0.0.0 bind.
    host = str(manager.settings.get("host", "127.0.0.1")).lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        try:
            with open(os.path.join(config.REQ_DIR, "req_{}.txt".format(sid)),
                      "r", encoding="utf-8", errors="ignore") as f:
                row["raw"] = f.read()
        except Exception:
            row["raw"] = ""
    else:
        row["raw"] = ""
    return row


@app.get("/api/scans/{sid}/log")
def scan_log(sid: int, offset: int = 0):
    data = manager.get_log(sid, offset=offset)
    if data is None:
        raise HTTPException(404, "找不到掃描")
    return data


@app.get("/api/scans/{sid}/related")
def scan_related(sid: int):
    row = db.get_scan(sid)
    if not row:
        raise HTTPException(404, "找不到掃描")
    return manager.history_for(row["project_id"], row["signature"], row["sig_endpoint"])


@app.get("/api/param-tests")
def param_tests(project_id: int = None, sig_endpoint: str = "",
                name: str = "", location: str = ""):
    """Full per-scan test timeline for ONE parameter (for the drill-down)."""
    return db.param_test_log(project_id, sig_endpoint, name, location)


@app.get("/api/param-history")
def param_history(project_id: int = None, sig_endpoint: str = ""):
    """Aggregate latest per-parameter status for an endpoint. Lets the composer
    refresh the 測過/無洞/有漏洞 badges live without re-pasting + re-parsing."""
    return db.param_history(project_id, sig_endpoint)


@app.post("/api/scans/{sid}/stop")
def scan_stop(sid: int):
    ok = manager.stop_scan(sid)
    return {"ok": ok}


@app.delete("/api/scans/{sid}")
def scan_delete(sid: int):
    ok = manager.delete_scan(sid)
    if not ok:
        raise HTTPException(404, "找不到掃描")
    return {"ok": True}


# --------------------------------------------------------------------------
# static frontend (mounted last so /api/* wins)
# --------------------------------------------------------------------------
@app.middleware("http")
async def _revalidate_static(request, call_next):
    """Force browsers to revalidate the frontend assets instead of serving them
    from cache heuristically. StaticFiles already sends ETag/Last-Modified, so a
    reload becomes a cheap 304 when unchanged and a fresh 200 right after an edit
    -- no more manual Ctrl+F5 to pick up CSS/JS changes."""
    resp = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".css", ".js", ".html")):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


def _open_browser(url):
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    import uvicorn
    settings = config.load_settings()
    host = settings["host"]
    port = int(settings["port"])
    url = "http://{}:{}".format("127.0.0.1" if host in ("0.0.0.0", "") else host, port)
    print("=" * 60)
    print(" sqlmap_auto 已啟動:{}".format(url))
    print(" 按 Ctrl+C 可停止")
    print("=" * 60)
    if settings.get("auto_open_browser", True):
        threading.Timer(1.2, _open_browser, args=(url,)).start()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()

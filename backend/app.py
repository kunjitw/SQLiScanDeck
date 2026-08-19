"""
FastAPI backend + static frontend host.

Run directly with the portable python:  python backend\app.py
It serves the web UI and the JSON API on http://127.0.0.1:8776 by default.
"""
import os
import sys
import json
import shlex
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
from drivers import sqlmap_driver, ghauri_driver, base as drv_base  # noqa: E402

from fastapi import FastAPI, Body, HTTPException  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse  # noqa: E402
import hashlib  # noqa: E402
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
    # heuristic "worth another test class" hints (deserialization/XSS/SSRF/...),
    # computed from the SAME rules (purpose=advise); never changes selection.
    filters_mod.apply_advice(annotated, rules)

    # target intel (recon): fingerprint backend / framework / CDN / WAF from the
    # REQUEST alone. Matched over the params + a synthetic PATH pseudo-param so
    # path-extension rules (.php/.aspx/...) can fire. Request-only, so it only
    # characterizes the submitted request, never proves the server.
    path = parsed.get("path") or parsed.get("url") or ""
    recon_targets = list(annotated)
    if path:
        recon_targets.append({"name": path, "location": "PATH", "value": path})
    recon = filters_mod.recon(recon_targets, rules)

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
    return annotated, signature, sig_endpoint, endpoint, recon


# --------------------------------------------------------------------------
# meta / ip / settings
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"ok": True, "sqlmap_present": os.path.isfile(config.SQLMAPAPI_PY)}


@app.get("/api/meta")
def api_meta():
    # Opaque per-dataset id (born with data/, travels with it). The web UI scopes its
    # per-dataset localStorage by this so a fresh clone / swapped data/ can never restore
    # another dataset's cached compose tabs. Just a random token -> no loopback gating.
    return {"dataset_id": db.get_dataset_id()}


@app.get("/api/ip")
def api_ip():
    s = manager.settings
    info = ip_utils.get_ip_info(
        want_public=s.get("public_ip_lookup", True),
        public_timeout=s.get("public_ip_timeout", 2.5),
        preferred_ip=s.get("preferred_local_ip", ""),
    )
    # NIC adapter names are reconnaissance-grade intel; withhold them from non-loopback
    # (0.0.0.0) clients, exactly like get_scan/_gate_tabs withhold the raw request/tabs.
    if not _is_loopback():
        info["interfaces"] = []
    return info


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
_BOUND_HOST = None   # address uvicorn ACTUALLY bound to (set once in main()); the loopback gate
                     # keys off THIS, not the mutable settings host, so a runtime settings write
                     # (POST /api/settings {"host":"127.0.0.1"}) can't flip the gate off.


def _is_loopback():
    host = _BOUND_HOST if _BOUND_HOST is not None else manager.settings.get("host", "127.0.0.1")
    return str(host).lower() in ("127.0.0.1", "localhost", "::1")


# fields on a scan row that carry captured secrets, withheld from non-loopback clients:
# params_json = the target's cookie/session VALUES; options_json = --auth-cred/--proxy;
# extra_flags = operator-entered; raw = the full request; result_json/result = --dump'd data.
_SENSITIVE_SCAN_KEYS = ("raw", "extra_flags", "params_json", "options_json", "result_json", "result")


def _gate_scan(row):
    if isinstance(row, dict) and not _is_loopback():
        for k in _SENSITIVE_SCAN_KEYS:
            if k in row:
                row[k] = None   # withheld sentinel; frontend treats null as absent (no JSON.parse)
    return row


def _gate_scans(rows):
    if isinstance(rows, list):
        for r in rows:
            _gate_scan(r)
    return rows


def _gate_tabs(projs):
    """tabs_json embeds the pasted raw request (Cookie/Authorization) -> withhold it from
    non-loopback clients, exactly like get_scan withholds a scan's raw request on a 0.0.0.0 bind."""
    if _is_loopback():
        return projs
    for p in (projs if isinstance(projs, list) else [projs]):
        if isinstance(p, dict) and "tabs_json" in p:
            p["tabs_json"] = ""
    return projs


@app.get("/api/projects")
def list_projects():
    return _gate_tabs(db.list_projects())


@app.post("/api/projects")
def create_project(payload: dict = Body(...)):
    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "專案名稱不可為空")
    return db.create_project(name, payload.get("note", ""), payload.get("restrict_ip", ""))


@app.patch("/api/projects/{pid}")
def patch_project(pid: int, payload: dict = Body(...)):
    return _gate_tabs(db.update_project(pid, **(payload or {})))


@app.post("/api/projects/{pid}/tabs")
def save_project_tabs(pid: int, payload: dict = Body(...)):
    # persist the composer tab set into the DB (survives a data/ move); POST so the page can
    # flush it via navigator.sendBeacon on unload. Fire-and-forget: never error the client.
    try:
        db.update_project(pid, tabs_json=str(payload.get("tabs_json") or ""))
    except Exception:
        pass
    return {"ok": True}


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
    if mode not in ("equals", "iequals", "prefix", "contains", "regex",
                    "magic", "json-key", "len-mod"):
        raise HTTPException(400, "不支援的 mode")
    if (payload.get("purpose") or "filter") not in ("filter", "advise", "recon"):
        raise HTTPException(400, "purpose 必須是 filter / advise / recon")
    if not pattern:
        raise HTTPException(400, "pattern 不可為空")
    if mode == "regex":
        import re as _re
        if len(str(pattern)) > 300:
            raise HTTPException(400, "regex pattern 太長(上限 300 字元)")
        try:
            _re.compile(pattern)
        except Exception as e:
            raise HTTPException(400, "regex 無效:{}".format(e))
    return db.create_rule(
        kind, mode, pattern, payload.get("note", ""),
        payload.get("project_id"), payload.get("enabled", True),
        purpose=payload.get("purpose", "filter"),
        location=payload.get("location", ""),
        transform=payload.get("transform", ""),
        vuln_class=payload.get("vuln_class", ""),
        tool=payload.get("tool", ""),
        confidence=payload.get("confidence", ""),
        source=payload.get("source", ""),
        reveals=payload.get("reveals", ""),
        category=payload.get("category", ""),
    )


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
    name = str(payload.get("name") or "").strip()
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
    annotated, signature, sig_endpoint, endpoint, recon = _annotate_params(parsed, project_id)
    parsed["params"] = annotated
    history = manager.history_for(project_id, signature, sig_endpoint)
    if isinstance(history, dict):
        _gate_scans(history.get("related_scans"))   # withhold related scans' secrets off-loopback
    return {
        "parsed": parsed,
        "signature": signature,
        "sig_endpoint": sig_endpoint,
        "endpoint": endpoint,
        "history": history,
        "recon": recon,
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
    params = payload.get("params") if isinstance(payload.get("params"), list) else []
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
    # a selection that is ALL non-testable (e.g. only a file-upload field) would emit no -p
    # and let sqlmap/ghauri silently fuzz every UNCHECKED param -> reject it explicitly.
    if params and any(p.get("selected") for p in params) and not drv_base.selected_names(params):
        raise HTTPException(400, "所選欄位皆不可測 SQLi(例如檔案上傳欄位),請改勾其他參數")

    launched = []
    for tool in tools:
        row = manager.create_scan(parsed, tool, options, params,
                                  project_id=project_id, extra_flags=extra_flags,
                                  restrict_ip=restrict_ip, note=note)
        manager.launch(row)
        launched.append(row)
    return {"launched": launched, "count": len(launched)}


class _PreviewCtx:
    """Minimal ScanContext stand-in so a driver's build_args() can produce the EXACT
    CLI args without creating/launching a scan -- the preview and the real run share
    one source of truth (build_args), so the UI command can't drift from reality."""
    def __init__(self, options, params, scheme, extra_flags):
        self.options = options or {}
        self.params = params or []
        self.scheme = scheme
        self.extra_flags = extra_flags or ""
        self.id = "N"                  # real scans use their DB id in --output-dir
        self.request_file = "req.txt"  # real run uses req_<id>.txt

    def extra_flag_list(self):
        try:
            toks = shlex.split(self.extra_flags) if self.extra_flags else []
        except Exception:
            toks = (self.extra_flags or "").split()
        from scan_manager import filter_extra_flags
        return filter_extra_flags(toks)   # preview must match the real run (host-side flags stripped)


@app.post("/api/preview")
def preview_cmd(payload: dict = Body(...)):
    """Build the 'what will run' command via the SAME build_args() the launcher uses,
    so the on-screen preview is guaranteed to match the real command. Creates nothing."""
    tool = payload.get("tool", "sqlmap")
    if tool not in ("sqlmap", "ghauri"):
        return {"ok": False, "cmd": "", "warning": "請選擇工具 sqlmap 或 ghauri"}
    raw = payload.get("raw", "")
    force_ssl = bool(payload.get("force_ssl", False))
    options = payload.get("options", {}) or {}
    params = payload.get("params") if isinstance(payload.get("params"), list) else []
    extra_flags = payload.get("extra_flags", "") or ""

    parsed = request_parser.parse_request(raw, force_ssl=force_ssl)
    if not parsed.get("ok"):
        return {"ok": False, "cmd": "", "warning": "請求解析失敗:{}".format("; ".join(parsed.get("warnings", [])))}
    # reconcile the client's checkbox selection onto the freshly-parsed params by
    # (name, location) -- identical to create_scans so -p matches the real run.
    sel_map = {(p.get("name"), p.get("location")): bool(p.get("selected")) for p in params}
    rparams = [dict(p, selected=sel_map.get((p.get("name"), p.get("location")), False))
               for p in parsed.get("params", [])]

    ctx = _PreviewCtx(options, rparams, parsed.get("scheme", "http"), extra_flags)
    driver = sqlmap_driver if tool == "sqlmap" else ghauri_driver
    try:
        args = driver.build_args(ctx) + ctx.extra_flag_list()
    except Exception as e:
        return {"ok": False, "cmd": "", "warning": "產生指令失敗:{}".format(e)}
    return {"ok": True, "cmd": drv_base.display_cmd([tool] + args)}


@app.post("/api/scans/stop_all")
def scans_stop_all(project_id: int = None):
    return {"stopped": manager.stop_all(project_id)}


@app.get("/api/scans")
def list_scans(project_id: int = None, status: str = None, limit: int = 200, slim: bool = False):
    return _gate_scans(db.list_scans(project_id=project_id, status=status, limit=limit, slim=slim))


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    row = db.get_scan(sid)
    if not row:
        raise HTTPException(404, "找不到掃描")
    row["raw"] = ""
    # non-loopback client -> withhold raw/params_json/options_json/result (target cookies,
    # --auth-cred/--proxy, --dump'd data). Only a local operator gets the full row.
    if not _is_loopback():
        return _gate_scan(row)
    if row.get("result_json"):
        try:
            row["result"] = json.loads(row["result_json"])
        except Exception:
            row["result"] = None
    # raw request (from the -r file) so the composer can re-load this scan ("以此設定重新配置")
    try:
        with open(os.path.join(config.REQ_DIR, "req_{}.txt".format(sid)),
                  "r", encoding="utf-8", errors="ignore") as f:
            row["raw"] = f.read()
    except Exception:
        row["raw"] = ""
    return row


@app.get("/api/scans/{sid}/log")
def scan_log(sid: int, offset: int = 0):
    data = manager.get_log(sid, offset=offset)
    if data is None:
        raise HTTPException(404, "找不到掃描")
    if not _is_loopback():
        # the log's "指令:" line embeds --auth-cred/--proxy/extra_flags, and result holds
        # any --dump'd databases/passwords -> withhold from non-loopback clients.
        data["chunk"] = ""
        data["result"] = None
        data["error"] = None
    return data


@app.get("/api/scans/{sid}/related")
def scan_related(sid: int):
    row = db.get_scan(sid)
    if not row:
        raise HTTPException(404, "找不到掃描")
    hist = manager.history_for(row["project_id"], row["signature"], row["sig_endpoint"])
    if isinstance(hist, dict):
        _gate_scans(hist.get("related_scans"))
    return hist


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
    """Never let the browser cache the frontend assets: no-store means every reload is a
    fresh 200 (no conditional 304), and the index route additionally cache-busts app.js/
    style.css with a ?v=<content-hash>. Together they kill stale-JS/CSS after an edit."""
    resp = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".css", ".js", ".html")):
        # no-store = never keep a copy at all (stronger than no-cache, which some browsers
        # ignore for entries cached before the header existed). Combined with the ?v= hash
        # on the includes, the frontend can never go stale.
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


def _asset_ver(fn):
    """8-char content hash used to cache-bust app.js/style.css."""
    try:
        with open(os.path.join(WEB_DIR, fn), "rb") as f:
            return hashlib.md5(f.read()).hexdigest()[:8]
    except Exception:
        return "0"


@app.get("/")
def index():
    # Append a content-hash ?v= to the JS/CSS includes so the browser is FORCED to fetch a
    # fresh copy whenever either file changes -- kills the recurring stale-app.js confusion
    # (a plain no-cache header doesn't help a browser that cached the file before it existed).
    try:
        with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
    except Exception:
        return FileResponse(os.path.join(WEB_DIR, "index.html"))
    html = html.replace('href="/style.css"', 'href="/style.css?v=%s"' % _asset_ver("style.css"))
    html = html.replace('src="/app.js"', 'src="/app.js?v=%s"' % _asset_ver("app.js"))
    return HTMLResponse(html)


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
    global _BOUND_HOST
    _BOUND_HOST = host                 # authoritative for the loopback gate (see _is_loopback)
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

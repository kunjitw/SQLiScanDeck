"""
Scan manager: the orchestration core.

 * owns the sqlmap REST API server process (started lazily, once)
 * runs scans in a bounded thread pool so MANY can run concurrently while
   extras queue instead of blocking the UI ("don't wait for the previous one")
 * gives each scan a ScanContext that streams a full timestamped log to disk
   and persists process / result / timing records to SQLite
 * updates per-parameter history so we can answer "was this tested before?"
"""
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import config
import db
import signature as sig_mod
from drivers import sqlmap_driver, ghauri_driver


def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _now_ms():
    return int(time.time() * 1000)


def _vuln_param_names(findings):
    """Exact param names the engine flagged as injectable. Log lines read like
    'Parameter: userid (GET)' -> take the name before the '(...)'. A SET of exact
    names avoids the substring bug where a clean 'id' matched vulnerable 'userid'."""
    names = set()
    for entry in (findings or {}).get("parameters", []) or []:
        m = re.match(r"^\s*(.+?)\s*(?:\([^)]*\))?\s*$", entry or "")
        name = (m.group(1) if m else entry).strip()
        if name:
            names.add(name)
    return names


# --------------------------------------------------------------------------
# per-scan context handed to drivers
# --------------------------------------------------------------------------
class ScanContext:
    def __init__(self, scan_row, settings):
        self.scan = scan_row
        self.id = scan_row["id"]
        self.tool = scan_row["tool"]
        self.method = scan_row["method"]
        self.url = scan_row["url"]
        self.scheme = "https" if (scan_row["url"] or "").lower().startswith("https") else "http"
        self.endpoint = scan_row["endpoint"]
        self.sig_endpoint = scan_row["sig_endpoint"]
        self.project_id = scan_row["project_id"]
        self.restrict_ip = scan_row["restrict_ip"] or ""
        self.options = json.loads(scan_row["options_json"] or "{}")
        self.params = json.loads(scan_row["params_json"] or "[]")
        self.extra_flags = scan_row["extra_flags"] or ""
        self.request_file = os.path.join(config.REQ_DIR, "req_{}.txt".format(self.id))
        self.log_path = os.path.join(config.LOG_DIR, "scan_{}.log".format(self.id))

        self.python_exe = config.PYTHON_EXE
        self.tools_dir = config.TOOLS_DIR
        self.sqlmapapi_base = "http://{}:{}".format(
            settings["sqlmapapi_host"], settings["sqlmapapi_port"])

        self.engine_task_id = None   # sqlmap task id
        self.engine_proc = None      # ghauri subprocess
        self.deleted = False         # set when the scan is deleted mid-run
        self._stop = threading.Event()
        self._log_lock = threading.Lock()

    # --- control ---
    def request_stop(self):
        self._stop.set()

    def should_stop(self):
        return self._stop.is_set()

    def extra_flag_list(self):
        try:
            return shlex.split(self.extra_flags) if self.extra_flags else []
        except Exception:
            return self.extra_flags.split()

    # --- logging (source of truth for live streaming) ---
    def append_log(self, text):
        if self.deleted:          # scan was deleted -> don't recreate its log file
            return
        line = "[{}] {}\n".format(_ts(), text)
        with self._log_lock:
            try:
                with open(self.log_path, "a", encoding="utf-8", errors="ignore") as f:
                    f.write(line)
            except Exception:
                pass

    def read_log(self):
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""

    # --- terminal states ---
    def fail(self, message):
        if self.deleted:
            return
        ended = _now_ms()
        started = self.scan.get("started_at") or ended
        db.update_scan(self.id, status="error", error=message,
                       ended_at=ended, duration_ms=ended - started)

    def finish(self, status, vulnerable, findings):
        if self.deleted:          # deleted mid-run -> skip all DB writes (no orphans)
            return
        ended = _now_ms()
        started = self.scan.get("started_at") or ended
        db.update_scan(
            self.id,
            status=status,
            vulnerable=1 if vulnerable else 0,
            result_json=json.dumps(findings, ensure_ascii=False),
            ended_at=ended,
            duration_ms=ended - started,
        )
        # Only a genuine completion tells us anything about the params. A killed
        # / stopped / error scan must NOT record them as "clean" -- that would
        # poison the "have I tested this before?" dedup with false negatives.
        if status == "done":
            self._record_param_history(vulnerable, findings)

    def _record_param_history(self, vulnerable, findings):
        vuln_names = _vuln_param_names(findings) if vulnerable else set()
        for p in self.params:
            if not p.get("selected"):
                continue  # only record params we actually tested
            is_vuln = bool(vulnerable and p.get("name") in vuln_names)
            status = "vulnerable" if is_vuln else "clean"
            try:
                db.upsert_param_status(
                    self.project_id, self.sig_endpoint, self.endpoint,
                    p["name"], p.get("location", "?"), status, is_vuln, self.id)
            except Exception:
                pass


# --------------------------------------------------------------------------
# manager
# --------------------------------------------------------------------------
class ScanManager:
    def __init__(self):
        self.settings = config.load_settings()
        # clamp to a sane positive int so a bad settings.json (0 / negative /
        # non-int) can't crash the whole backend at import time.
        try:
            workers = int(self.settings.get("max_concurrent", 8))
        except (TypeError, ValueError):
            workers = 8
        workers = max(1, min(64, workers))
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.contexts = {}          # scan_id -> ScanContext
        self._ctx_lock = threading.Lock()
        self._api_proc = None
        self._api_started = False
        self._api_lock = threading.Lock()

    # ---- lifecycle ----
    def start(self):
        db.init_db()
        # sqlmap API is started lazily on first sqlmap scan (see ensure_sqlmapapi)

    def shutdown(self):
        # stop the flag AND actually kill any live ghauri/sqlmap engine process,
        # so Ctrl+C never orphans a scanner still hitting the target.
        for ctx in list(self.contexts.values()):
            ctx.request_stop()
            proc = getattr(ctx, "engine_proc", None)
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        if self._api_proc and self._api_proc.poll() is None:
            try:
                self._api_proc.terminate()
            except Exception:
                pass

    def reload_settings(self):
        self.settings = config.load_settings()

    # ---- sqlmap REST API server ----
    def _api_alive(self):
        base = "http://{}:{}".format(self.settings["sqlmapapi_host"],
                                     self.settings["sqlmapapi_port"])
        try:
            with urllib.request.urlopen(base + "/version", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def ensure_sqlmapapi(self):
        with self._api_lock:
            if self._api_alive():
                return True
            if not os.path.isfile(config.SQLMAPAPI_PY):
                return False
            # go through the launcher so SQLMAP_DIR is on sys.path (embeddable
            # python's ._pth won't add it -> sqlmapapi.py can't `import lib`)
            cmd = [config.PYTHON_EXE, config.SQLMAPAPI_LAUNCH, "-s",
                   "-H", self.settings["sqlmapapi_host"],
                   "-p", str(self.settings["sqlmapapi_port"])]
            # keep the API's output in a log so a startup failure stays visible
            # (it used to go to DEVNULL, which hid exactly this kind of crash)
            try:
                config.ensure_dirs()
                logf = open(os.path.join(config.LOG_DIR, "sqlmapapi.log"),
                            "a", encoding="utf-8", errors="ignore")
            except Exception:
                logf = subprocess.DEVNULL
            try:
                self._api_proc = subprocess.Popen(
                    cmd, cwd=config.SQLMAP_DIR,
                    stdout=logf, stderr=subprocess.STDOUT)
            except Exception:
                return False
            # wait up to ~10s for it to come up
            for _ in range(20):
                if self._api_alive():
                    self._api_started = True
                    return True
                time.sleep(0.5)
            return self._api_alive()

    # ---- launching scans ----
    def prepare_target(self, parsed):
        """Compute signatures + endpoint label from a parsed request."""
        names = [p["name"] for p in parsed.get("params", [])]
        signature, endpoint = sig_mod.build_signature(
            parsed["method"], parsed["url"], names)
        sig_endpoint, _ = sig_mod.endpoint_signature(parsed["method"], parsed["url"])
        return signature, sig_endpoint, endpoint

    def history_for(self, project_id, signature, sig_endpoint):
        related = db.scans_by_signature(signature, sig_endpoint, project_id=project_id)
        params = db.param_history(project_id, sig_endpoint)
        return {"related_scans": related, "param_history": params,
                "tested_before": len(related) > 0}

    def create_scan(self, parsed, tool, options, params, project_id=None,
                    extra_flags="", restrict_ip=""):
        signature, sig_endpoint, endpoint = self.prepare_target(parsed)
        row = db.create_scan({
            "project_id": project_id,
            "tool": tool,
            "method": parsed["method"],
            "url": parsed["url"],
            "endpoint": endpoint,
            "signature": signature,
            "sig_endpoint": sig_endpoint,
            "options": options,
            "params": params,
            "extra_flags": extra_flags,
            "restrict_ip": restrict_ip,
        })
        # write the raw request file used by -r (faithful reconstruction)
        config.ensure_dirs()
        raw = build_raw_request(parsed)
        req_path = os.path.join(config.REQ_DIR, "req_{}.txt".format(row["id"]))
        try:
            with open(req_path, "w", encoding="utf-8", errors="ignore", newline="\r\n") as f:
                f.write(raw)
        except Exception:
            pass
        return row

    def launch(self, scan_row):
        ctx = ScanContext(scan_row, self.settings)
        with self._ctx_lock:
            self.contexts[ctx.id] = ctx
        self.pool.submit(self._run, ctx)
        return ctx.id

    def _run(self, ctx):
        # If it was stopped while still queued, never start the engine at all.
        if ctx.should_stop():
            ctx.append_log("== 掃描在開始前已被中止(佇列中取消)==")
            now = _now_ms()
            db.update_scan(ctx.id, status="killed", started_at=now,
                           ended_at=now, duration_ms=0)
            with self._ctx_lock:
                self.contexts.pop(ctx.id, None)
            return
        started = _now_ms()
        db.update_scan(ctx.id, status="running", started_at=started)
        ctx.scan["started_at"] = started
        try:
            if ctx.tool == "sqlmap":
                if not self.ensure_sqlmapapi():
                    ctx.append_log("!! 無法啟動 sqlmap REST API(tools/sqlmap 不存在或啟動失敗)")
                    ctx.append_log("   請先執行 bootstrap.bat 下載 sqlmap。")
                    ctx.fail("sqlmap REST API 無法啟動")
                    return
                sqlmap_driver.run(ctx)
            elif ctx.tool == "ghauri":
                ghauri_driver.run(ctx)
            else:
                ctx.fail("未知的工具:{}".format(ctx.tool))
        except Exception as e:
            ctx.append_log("!! 掃描發生未預期例外:{}".format(e))
            ctx.fail("未預期例外:{}".format(e))
        finally:
            with self._ctx_lock:
                self.contexts.pop(ctx.id, None)
            # if it was deleted mid-run, re-clean any file recreated during the
            # kill window (append_log is guarded, but be defensive about races)
            if ctx.deleted:
                self._remove_scan_files(ctx.id)

    def stop_scan(self, scan_id):
        """Request a real kill. The driver actually terminates the engine and
        only then marks the scan killed -- so the UI never shows 'stopped'
        while the process is still alive."""
        with self._ctx_lock:
            ctx = self.contexts.get(scan_id)
        if ctx:
            ctx.request_stop()
            return True
        row = db.get_scan(scan_id)
        if row and row["status"] in ("queued",):
            db.update_scan(scan_id, status="killed", ended_at=_now_ms())
            return True
        return False

    def _remove_scan_files(self, scan_id):
        for path in (os.path.join(config.LOG_DIR, "scan_{}.log".format(scan_id)),
                     os.path.join(config.REQ_DIR, "req_{}.txt".format(scan_id))):
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass

    def delete_scan(self, scan_id):
        """Remove a scan entirely. If still live, mark its context deleted (so the
        worker stops writing log/DB rows -> no orphan log file or param_status)
        and kill the engine; the worker's finally re-cleans anything recreated
        during the kill window. Returns False if unknown."""
        row = db.get_scan(scan_id)
        if not row:
            return False
        with self._ctx_lock:
            ctx = self.contexts.get(scan_id)
        if ctx:
            ctx.deleted = True   # suppress further append_log / finish / history
            ctx.request_stop()   # kill the live engine
        db.delete_scan(scan_id)
        self._remove_scan_files(scan_id)
        return True

    def stop_all(self, project_id=None):
        """Force-stop every running/queued scan (optionally within a project)."""
        with self._ctx_lock:
            ctxs = list(self.contexts.values())
        count = 0
        for ctx in ctxs:
            if project_id is None or ctx.project_id == project_id:
                ctx.request_stop()
                count += 1
        return count

    def get_log(self, scan_id, offset=0):
        row = db.get_scan(scan_id)
        if not row:
            return None
        path = os.path.join(config.LOG_DIR, "scan_{}.log".format(scan_id))
        text = ""
        new_offset = max(int(offset or 0), 0)
        try:
            if os.path.isfile(path):
                size = os.path.getsize(path)
                start = min(new_offset, size)
                # binary seek so a UTF-8 multibyte char is never split mid-way
                with open(path, "rb") as f:
                    f.seek(start)
                    raw = f.read()               # may read past `size` if it grew
                text = raw.decode("utf-8", "ignore")
                # report the ACTUAL end of what we returned, not the pre-read
                # size -- otherwise bytes appended between getsize() and read()
                # get re-sent next poll and the live log shows duplicate lines.
                new_offset = start + len(raw)
        except Exception:
            pass
        return {
            "id": scan_id,
            "status": row["status"],
            "vulnerable": bool(row["vulnerable"]),
            "offset": new_offset,
            "chunk": text,
            "duration_ms": row["duration_ms"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "error": row["error"],
        }


# --------------------------------------------------------------------------
# raw request reconstruction for `-r`
# --------------------------------------------------------------------------
def build_raw_request(parsed):
    """
    Prefer the ORIGINAL pasted request VERBATIM (only normalising line endings to
    CRLF). This is what sqlmap/ghauri receive via -r, so they test exactly what
    the user captured -- parsing is used only to enumerate/select parameters and
    build the dedup signature, never to rebuild the request. A minimal request is
    synthesised ONLY for bare-URL input (nothing else to send).
    """
    raw = parsed.get("raw") or ""
    stripped = raw.strip()
    is_bare_url = bool(re.match(r"^https?://\S+$", stripped)) and ("\n" not in stripped)

    if stripped and not is_bare_url:
        text = raw.replace("\r\n", "\n").replace("\r", "\n")
        if "\n\n" not in text:               # guarantee a header/body separator
            text = text.rstrip("\n") + "\n\n"
        return text.replace("\n", "\r\n")

    # bare URL (or empty) -> synthesise a minimal GET request
    from urllib.parse import urlsplit
    parts = urlsplit(parsed.get("url", "") or stripped)
    target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    host = parsed.get("host") or parts.netloc or ""
    return "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(
        parsed.get("method", "GET"), target, host)


# module-level singleton
manager = ScanManager()

"""
Scan manager: the orchestration core.

 * runs each scan as ONE direct CLI subprocess (sqlmap.py / ghauri), no REST API
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
import shutil
import threading
import time
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

        self.engine_proc = None      # ghauri / sqlmap subprocess
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
        """Persist the terminal result. Returns the list of (param_name, status)
        pairs actually written to the dedup history (so the driver's 【判定】 block
        can report the truth), or None when nothing was recorded."""
        if self.deleted:          # deleted mid-run -> skip all DB writes (no orphans)
            return None
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
        # Record per-param history on any completion we drew evidence from: a clean
        # 'done', an 'inconclusive' run (records ONLY the params the tool actually
        # judged -- see below), or any CONFIRMED vuln even if the run then errored/was
        # killed (never lose a real injection). A killed/error scan with NO vuln records
        # nothing, so it can't poison the dedup history with false negatives.
        if status in ("done", "inconclusive") or vulnerable:
            return self._record_param_history(vulnerable, findings)
        return None

    def _record_param_history(self, vulnerable, findings):
        summary_vuln = _vuln_param_names(findings) if vulnerable else set()
        explicit = (findings or {}).get("per_param") or {}   # {name: vulnerable|clean}
        recorded = []
        for p in self.params:
            name = p["name"]
            location = p.get("location", "?")
            if not p.get("selected"):
                # parsed but the user chose NOT to test it -> record 'skipped'
                # (distinct from never-seen 'untested'); never downgrades a real
                # result and doesn't count as a test.
                try:
                    db.mark_param_skipped(self.project_id, self.sig_endpoint,
                                          self.endpoint, name, location, self.id)
                except Exception:
                    pass
                continue
            # EVIDENCE-ONLY per-param verdict -- a param is coloured only from a log
            # line that NAMED it:
            #  - in the injection summary OR explicit "is vulnerable" -> vulnerable
            #  - explicit "does not seem to be injectable"           -> clean
            #  - explicit tentative "appears to be ... injectable"   -> 'tested' (疑似,未定案)
            #  - NO line mentioned this param                        -> record nothing
            # The last case is the fix: a scan that only tested the URI '#1*' (or
            # skipped cookies at --level 1) leaves those selected params with no row,
            # so they stay 未測 instead of being painted a groundless 'clean'. The old
            # `or not vulnerable` fallback (which greened every selected param on any
            # non-vuln completion) is deliberately gone.
            if name in summary_vuln or explicit.get(name) == "vulnerable":
                status, is_vuln = "vulnerable", True
            elif explicit.get(name) == "clean":
                status, is_vuln = "clean", False
            elif explicit.get(name) == "tentative":
                status, is_vuln = "tested", False
            else:
                continue
            try:
                # latest aggregate (drives the parse-screen badges)
                db.upsert_param_status(
                    self.project_id, self.sig_endpoint, self.endpoint,
                    name, location, status, is_vuln, self.id)
                # append to the immutable per-scan timeline (drives the drill-down)
                db.add_param_test(
                    self.project_id, self.sig_endpoint, self.endpoint,
                    name, location, self.id, self.tool, status, is_vuln)
                recorded.append((name, status))
            except Exception:
                pass
        return recorded


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

    # ---- lifecycle ----
    def start(self):
        db.init_db()
        # a previous run's in-flight scans can't resume (their processes are
        # gone) -> mark leftover running/queued as killed so the UI is honest
        db.reset_stale_scans()

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

    def reload_settings(self):
        self.settings = config.load_settings()

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
                    extra_flags="", restrict_ip="", note=""):
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
            "note": note,
        })
        # write the raw request file used by -r (faithful reconstruction)
        config.ensure_dirs()
        raw = build_raw_request(parsed)
        req_path = os.path.join(config.REQ_DIR, "req_{}.txt".format(row["id"]))
        try:
            # build_raw_request already emits CRLF; write VERBATIM (newline="") so the
            # text-mode layer does not translate \n again and produce \r\r\n. sqlmap
            # tolerates the doubled CR but ghauri rejects it ("does not contain a
            # usable HTTP request"), which broke every ghauri -r scan on Windows.
            with open(req_path, "w", encoding="utf-8", errors="ignore", newline="") as f:
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
                sqlmap_driver.run(ctx)   # direct CLI subprocess (no REST API)
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
        # per-scan sqlmap output tree (session.sqlite, target.txt, dump/, ...)
        sqlmap_dir = os.path.join(config.DATA_DIR, "sqlmap_output", str(scan_id))
        try:
            if os.path.isdir(sqlmap_dir):
                shutil.rmtree(sqlmap_dir, ignore_errors=True)
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

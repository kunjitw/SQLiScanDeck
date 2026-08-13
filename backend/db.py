"""
SQLite data layer. One portable file at data/sqlmap_auto.db.

Guarded by a single lock so it is safe to call from both async handlers and
threadpool workers. Keeps everything the tool needs: projects, filter rules,
scans (with full process/result/timing records) and per-parameter test history
used for the dedup / "have I tested this before?" feature.
"""
import json
import sqlite3
import threading
import time

import config
import filters as filters_mod

_conn = None
_lock = threading.RLock()


def _now():
    # Wall-clock millis. (Date.now() etc. are fine in normal Python runtime.)
    return int(time.time() * 1000)


def _connect():
    global _conn
    config.ensure_dirs()
    _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL;")
    _conn.execute("PRAGMA foreign_keys=ON;")
    return _conn


def init_db():
    with _lock:
        conn = _connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                note TEXT DEFAULT '',
                restrict_ip TEXT DEFAULT '',
                archived INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS filter_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,            -- NULL = global
                kind TEXT NOT NULL,            -- name | value
                mode TEXT NOT NULL,            -- equals|iequals|prefix|contains|regex
                pattern TEXT NOT NULL,
                note TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                tool TEXT NOT NULL,            -- sqlmap | ghauri
                method TEXT,
                url TEXT,
                endpoint TEXT,                 -- human readable METHOD host/{id}
                signature TEXT,                -- exact (endpoint + param names)
                sig_endpoint TEXT,             -- loose (endpoint only)
                options_json TEXT,             -- scan options chosen
                params_json TEXT,              -- [{name,location,value,selected}]
                extra_flags TEXT DEFAULT '',
                restrict_ip TEXT DEFAULT '',
                status TEXT NOT NULL,          -- queued|running|done|error|killed|stopped
                vulnerable INTEGER DEFAULT 0,
                result_json TEXT,              -- parsed findings
                log_path TEXT,
                error TEXT DEFAULT '',
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                ended_at INTEGER,
                duration_ms INTEGER,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS param_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                sig_endpoint TEXT NOT NULL,
                endpoint TEXT,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                status TEXT NOT NULL,          -- tested|vulnerable|clean|skipped
                vulnerable INTEGER DEFAULT 0,
                last_scan_id INTEGER,
                test_count INTEGER DEFAULT 0,
                updated_at INTEGER NOT NULL,
                UNIQUE(project_id, sig_endpoint, name, location)
            );

            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tool TEXT DEFAULT '',           -- sqlmap | ghauri (templates are per-tool)
                is_default INTEGER DEFAULT 0,   -- one default PER TOOL
                data_json TEXT NOT NULL,        -- saved composer config (tool + options)
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_sig ON scans(signature);
            CREATE INDEX IF NOT EXISTS idx_scans_sigep ON scans(sig_endpoint);
            CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
            CREATE INDEX IF NOT EXISTS idx_pstatus_ep ON param_status(project_id, sig_endpoint);
            """
        )
        # migrate older DBs that predate the templates.tool column
        try:
            conn.execute("ALTER TABLE templates ADD COLUMN tool TEXT DEFAULT ''")
        except Exception:
            pass
        conn.commit()
        _seed_default_rules()
        _seed_default_templates()


def _seed_default_rules():
    """Top-up: insert any built-in default global rule that isn't present yet
    (matched by kind+mode+pattern). This seeds a fresh DB AND upgrades an
    existing one when new defaults are added, without duplicating. User-created
    rules and user toggles on existing defaults are left untouched."""
    now = _now()
    for r in filters_mod.DEFAULT_RULES:
        exists = _conn.execute(
            "SELECT 1 FROM filter_rules WHERE project_id IS NULL AND kind=? AND mode=? AND pattern=?",
            (r["kind"], r["mode"], r["pattern"]),
        ).fetchone()
        if not exists:
            _conn.execute(
                "INSERT INTO filter_rules(project_id,kind,mode,pattern,note,enabled,created_at)"
                " VALUES(NULL,?,?,?,?,?,?)",
                (r["kind"], r["mode"], r["pattern"], r.get("note", ""),
                 1 if r.get("enabled", True) else 0, now),
            )
    _conn.commit()


def _seed_default_templates():
    """Seed ONE example template (sqlmap, marked default) on a fresh DB so there's
    a working reference to copy. Only when the table is empty -> never clobbers a
    user's own templates and never re-appears after they delete it."""
    n = _conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
    if n:
        return
    example = {
        "tool": "sqlmap",
        "options": {
            "level": 1, "risk": 1, "random_agent": True,
            "get_banner": True, "get_current_user": True, "get_current_db": True,
        },
    }
    _conn.execute(
        "INSERT INTO templates(name,tool,is_default,data_json,created_at) VALUES(?,?,?,?,?)",
        ("範例 · 基本偵測(系統預設)", "sqlmap", 1,
         json.dumps(example, ensure_ascii=False), _now()),
    )
    _conn.commit()


def _row(r):
    return dict(r) if r is not None else None


def _rows(rs):
    return [dict(r) for r in rs]


# --------------------------------------------------------------------------
# projects
# --------------------------------------------------------------------------
def create_project(name, note="", restrict_ip=""):
    with _lock:
        cur = _conn.execute(
            "INSERT INTO projects(name,note,restrict_ip,created_at) VALUES(?,?,?,?)",
            (name, note, restrict_ip, _now()),
        )
        _conn.commit()
        return get_project(cur.lastrowid)


def list_projects(include_archived=False):
    with _lock:
        q = "SELECT * FROM projects"
        if not include_archived:
            q += " WHERE archived=0"
        q += " ORDER BY created_at DESC"
        return _rows(_conn.execute(q).fetchall())


def get_project(pid):
    with _lock:
        return _row(_conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())


def update_project(pid, **fields):
    allowed = {"name", "note", "restrict_ip", "archived"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return get_project(pid)
    with _lock:
        cols = ", ".join("{}=?".format(k) for k in sets)
        _conn.execute("UPDATE projects SET {} WHERE id=?".format(cols),
                      list(sets.values()) + [pid])
        _conn.commit()
        return get_project(pid)


def delete_project(pid):
    with _lock:
        _conn.execute("DELETE FROM projects WHERE id=?", (pid,))
        _conn.commit()


# --------------------------------------------------------------------------
# filter rules
# --------------------------------------------------------------------------
def list_rules(project_id=None):
    """Global rules always; plus this project's rules when project_id given."""
    with _lock:
        if project_id is None:
            rs = _conn.execute(
                "SELECT * FROM filter_rules WHERE project_id IS NULL ORDER BY id"
            ).fetchall()
        else:
            rs = _conn.execute(
                "SELECT * FROM filter_rules WHERE project_id IS NULL OR project_id=? ORDER BY id",
                (project_id,),
            ).fetchall()
        out = _rows(rs)
        for r in out:
            r["enabled"] = bool(r["enabled"])
        return out


def create_rule(kind, mode, pattern, note="", project_id=None, enabled=True):
    with _lock:
        cur = _conn.execute(
            "INSERT INTO filter_rules(project_id,kind,mode,pattern,note,enabled,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (project_id, kind, mode, pattern, note, 1 if enabled else 0, _now()),
        )
        _conn.commit()
        return _row(_conn.execute("SELECT * FROM filter_rules WHERE id=?",
                                  (cur.lastrowid,)).fetchone())


def update_rule(rule_id, **fields):
    allowed = {"kind", "mode", "pattern", "note", "enabled"}
    sets = {k: (1 if k == "enabled" and v else 0 if k == "enabled" else v)
            for k, v in fields.items() if k in allowed}
    if not sets:
        return
    with _lock:
        cols = ", ".join("{}=?".format(k) for k in sets)
        _conn.execute("UPDATE filter_rules SET {} WHERE id=?".format(cols),
                      list(sets.values()) + [rule_id])
        _conn.commit()


def delete_rule(rule_id):
    with _lock:
        _conn.execute("DELETE FROM filter_rules WHERE id=?", (rule_id,))
        _conn.commit()


# --------------------------------------------------------------------------
# scans
# --------------------------------------------------------------------------
def create_scan(scan):
    with _lock:
        cur = _conn.execute(
            """INSERT INTO scans(project_id,tool,method,url,endpoint,signature,sig_endpoint,
                    options_json,params_json,extra_flags,restrict_ip,status,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan.get("project_id"),
                scan.get("tool"),
                scan.get("method"),
                scan.get("url"),
                scan.get("endpoint"),
                scan.get("signature"),
                scan.get("sig_endpoint"),
                json.dumps(scan.get("options", {}), ensure_ascii=False),
                json.dumps(scan.get("params", []), ensure_ascii=False),
                scan.get("extra_flags", ""),
                scan.get("restrict_ip", ""),
                "queued",
                _now(),
            ),
        )
        _conn.commit()
        return get_scan(cur.lastrowid)


def get_scan(sid):
    with _lock:
        return _row(_conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone())


# columns the board/tree actually render — lets the 1.5s poll skip the heavy
# options_json / params_json / result_json blobs on every cycle
_SCAN_SLIM_COLS = ("id, project_id, tool, method, url, endpoint, status, "
                   "vulnerable, duration_ms, created_at, started_at, ended_at")


def list_scans(project_id=None, status=None, limit=200, slim=False):
    with _lock:
        q = "SELECT {} FROM scans".format(_SCAN_SLIM_COLS if slim else "*")
        conds, args = [], []
        if project_id is not None:
            conds.append("project_id=?")
            args.append(project_id)
        if status:
            conds.append("status=?")
            args.append(status)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        return _rows(_conn.execute(q, args).fetchall())


def update_scan(sid, **fields):
    allowed = {"status", "vulnerable", "result_json", "log_path", "error",
               "started_at", "ended_at", "duration_ms"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    with _lock:
        cols = ", ".join("{}=?".format(k) for k in sets)
        _conn.execute("UPDATE scans SET {} WHERE id=?".format(cols),
                      list(sets.values()) + [sid])
        _conn.commit()


def delete_scan(sid):
    with _lock:
        _conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        _conn.commit()


def scans_by_signature(signature, sig_endpoint, project_id=None, exclude_id=None, limit=50):
    """Related history: exact signature OR same endpoint."""
    with _lock:
        q = ("SELECT * FROM scans WHERE (signature=? OR sig_endpoint=?)")
        args = [signature, sig_endpoint]
        if project_id is not None:
            q += " AND project_id=?"
            args.append(project_id)
        if exclude_id is not None:
            q += " AND id<>?"
            args.append(exclude_id)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        return _rows(_conn.execute(q, args).fetchall())


# --------------------------------------------------------------------------
# per-parameter history
# --------------------------------------------------------------------------
def upsert_param_status(project_id, sig_endpoint, endpoint, name, location,
                        status, vulnerable, scan_id):
    with _lock:
        now = _now()
        existing = _conn.execute(
            "SELECT id,test_count FROM param_status WHERE "
            "project_id IS ? AND sig_endpoint=? AND name=? AND location=?",
            (project_id, sig_endpoint, name, location),
        ).fetchone()
        if existing:
            _conn.execute(
                "UPDATE param_status SET status=?, vulnerable=?, last_scan_id=?, "
                "endpoint=?, test_count=test_count+1, updated_at=? WHERE id=?",
                (status, 1 if vulnerable else 0, scan_id, endpoint, now, existing["id"]),
            )
        else:
            _conn.execute(
                "INSERT INTO param_status(project_id,sig_endpoint,endpoint,name,location,"
                "status,vulnerable,last_scan_id,test_count,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,1,?)",
                (project_id, sig_endpoint, endpoint, name, location,
                 status, 1 if vulnerable else 0, scan_id, now),
            )
        _conn.commit()


def param_history(project_id, sig_endpoint):
    with _lock:
        rs = _conn.execute(
            "SELECT * FROM param_status WHERE project_id IS ? AND sig_endpoint=? "
            "ORDER BY name",
            (project_id, sig_endpoint),
        ).fetchall()
        out = _rows(rs)
        for r in out:
            r["vulnerable"] = bool(r["vulnerable"])
        return out


# --------------------------------------------------------------------------
# scan templates (reusable presets; one may be the auto-applied default)
# --------------------------------------------------------------------------
def _template_row(r):
    if r is None:
        return None
    d = dict(r)
    d["is_default"] = bool(d["is_default"])
    try:
        d["data"] = json.loads(d["data_json"] or "{}")
    except Exception:
        d["data"] = {}
    return d


def list_templates():
    with _lock:
        rs = _conn.execute(
            "SELECT * FROM templates ORDER BY is_default DESC, name"
        ).fetchall()
        return [_template_row(r) for r in rs]


def get_template(tid):
    with _lock:
        return _template_row(
            _conn.execute("SELECT * FROM templates WHERE id=?", (tid,)).fetchone())


def get_default_template(tool=None):
    # There is one default PER TOOL, so a bare is_default=1 is ambiguous. Require
    # a tool for a precise answer; without one, pick deterministically by tool.
    with _lock:
        if tool:
            r = _conn.execute(
                "SELECT * FROM templates WHERE is_default=1 AND tool=? LIMIT 1", (tool,)
            ).fetchone()
        else:
            r = _conn.execute(
                "SELECT * FROM templates WHERE is_default=1 ORDER BY tool LIMIT 1"
            ).fetchone()
        return _template_row(r)


def create_template(name, data, is_default=False, tool=""):
    with _lock:
        if is_default:
            # only one default PER TOOL
            _conn.execute("UPDATE templates SET is_default=0 WHERE tool=?", (tool,))
        cur = _conn.execute(
            "INSERT INTO templates(name,tool,is_default,data_json,created_at) VALUES(?,?,?,?,?)",
            (name, tool, 1 if is_default else 0,
             json.dumps(data or {}, ensure_ascii=False), _now()),
        )
        _conn.commit()
        return get_template(cur.lastrowid)


def update_template(tid, **fields):
    sets = {}
    if "name" in fields:
        sets["name"] = fields["name"]
    if "tool" in fields:
        sets["tool"] = fields["tool"] or ""
    if "data" in fields:
        sets["data_json"] = json.dumps(fields["data"] or {}, ensure_ascii=False)
    with _lock:
        if fields.get("is_default"):
            row = _conn.execute("SELECT tool FROM templates WHERE id=?", (tid,)).fetchone()
            tool = fields.get("tool", row["tool"] if row else "")
            _conn.execute("UPDATE templates SET is_default=0 WHERE tool=?", (tool,))
            sets["is_default"] = 1
        elif "is_default" in fields:
            sets["is_default"] = 0
        if sets:
            cols = ", ".join("{}=?".format(k) for k in sets)
            _conn.execute("UPDATE templates SET {} WHERE id=?".format(cols),
                          list(sets.values()) + [tid])
            _conn.commit()
        return get_template(tid)


def delete_template(tid):
    with _lock:
        _conn.execute("DELETE FROM templates WHERE id=?", (tid,))
        _conn.commit()

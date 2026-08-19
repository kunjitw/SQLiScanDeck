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
                tabs_json TEXT DEFAULT '',      -- composer tab set (drafts; detail tabs = scanId ref) so it survives a data/ move
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS filter_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,            -- NULL = global
                kind TEXT NOT NULL,            -- name | value
                mode TEXT NOT NULL,            -- equals|iequals|prefix|contains|regex|magic|json-key|len-mod
                pattern TEXT NOT NULL,
                note TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                purpose TEXT DEFAULT 'filter', -- filter (auto-deselect) | advise (suggest a test class)
                location TEXT DEFAULT '',      -- '' / ANY = any location; else GET|POST|COOKIE|JSON|HEADER|PATH
                transform TEXT DEFAULT '',     -- JSON list of decoders applied before match, e.g. ["base64decode"]
                vuln_class TEXT DEFAULT '',    -- advise: candidate test class
                tool TEXT DEFAULT '',          -- advise: recommended tool/technique
                confidence TEXT DEFAULT '',    -- advise/recon: high|medium|low
                source TEXT DEFAULT '',        -- advise/recon: authoritative reference URL
                reveals TEXT DEFAULT '',       -- recon: what the signal reveals (e.g. backend=PHP)
                category TEXT DEFAULT '',      -- recon: language|framework|server|waf|cdn|cms|...
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
                note TEXT DEFAULT '',          -- user's free-text note for this run
                status TEXT NOT NULL,          -- queued|running|done|inconclusive|error|killed|stopped
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

            -- append-only per-(scan,param) log so we can show a parameter's full
            -- test timeline (param_status above keeps only the LATEST aggregate).
            CREATE TABLE IF NOT EXISTS param_test (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                sig_endpoint TEXT NOT NULL,
                endpoint TEXT,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                scan_id INTEGER NOT NULL,
                tool TEXT,
                status TEXT NOT NULL,           -- vulnerable | clean | tested
                vulnerable INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
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
            CREATE INDEX IF NOT EXISTS idx_ptest_ep ON param_test(project_id, sig_endpoint, name, location);
            CREATE INDEX IF NOT EXISTS idx_ptest_scan ON param_test(scan_id);

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,   -- dataset_id: random id born with this data/ dir, travels with the DB
                value TEXT
            );
            """
        )
        # migrate older DBs that predate the templates.tool column
        try:
            conn.execute("ALTER TABLE templates ADD COLUMN tool TEXT DEFAULT ''")
        except Exception:
            pass
        # migrate older DBs that predate the scans.note column
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN note TEXT DEFAULT ''")
        except Exception:
            pass
        # migrate older DBs that predate the projects.tabs_json column
        try:
            conn.execute("ALTER TABLE projects ADD COLUMN tabs_json TEXT DEFAULT ''")
        except Exception:
            pass
        # migrate older DBs that predate the filter_rules advise/transform columns
        for _col, _decl in (
            ("purpose", "TEXT DEFAULT 'filter'"),
            ("location", "TEXT DEFAULT ''"),
            ("transform", "TEXT DEFAULT ''"),
            ("vuln_class", "TEXT DEFAULT ''"),
            ("tool", "TEXT DEFAULT ''"),
            ("confidence", "TEXT DEFAULT ''"),
            ("source", "TEXT DEFAULT ''"),
            ("reveals", "TEXT DEFAULT ''"),
            ("category", "TEXT DEFAULT ''"),
        ):
            try:
                conn.execute("ALTER TABLE filter_rules ADD COLUMN {} {}".format(_col, _decl))
            except Exception:
                pass
        conn.commit()
        get_dataset_id()   # stamp a random dataset_id at DB birth (RLock is reentrant)
        _seed_default_rules()
        _seed_default_templates()
        _seed_preset_templates()
        _migrate_preset_desc()


def get_dataset_id():
    """Random id identifying THIS data/ dir. Generated once, stored in the DB, so it
    travels with the DB (a moved data/ keeps its id; a fresh clone gets a new one).

    The web UI scopes its per-dataset localStorage -- compose tabs (which embed that
    dataset's raw requests/cookies) and the last-opened project -- by this id. That
    way a fresh clone or a swapped data/ can never restore ANOTHER dataset's cached
    tabs just because both happen to have a numeric project id 1."""
    import uuid
    with _lock:
        conn = _conn or _connect()   # reuse the existing connection (init_db already set it)
        row = conn.execute("SELECT value FROM meta WHERE key='dataset_id'").fetchone()
        if row and row["value"]:
            return row["value"]
        did = uuid.uuid4().hex
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('dataset_id', ?)", (did,))
        conn.commit()
        return did


def _seed_default_rules():
    """Top-up: insert any built-in default global rule that isn't present yet
    (matched by kind+mode+pattern). This seeds a fresh DB AND upgrades an
    existing one when new defaults are added, without duplicating. User-created
    rules and user toggles on existing defaults are left untouched."""
    now = _now()
    defaults = ([dict(r, purpose="filter") for r in filters_mod.DEFAULT_RULES]
                + [dict(r, purpose="advise") for r in filters_mod.load_advise_catalog()]
                + [dict(r, purpose="recon") for r in filters_mod.load_recon_catalog()])
    for r in defaults:
        loc = r.get("location", "") or ""
        # dedup on the full conclusion (vuln_class for advise, reveals for recon) so
        # distinct rules sharing a pattern still both seed.
        exists = _conn.execute(
            "SELECT 1 FROM filter_rules WHERE project_id IS NULL AND purpose=? "
            "AND kind=? AND mode=? AND pattern=? AND IFNULL(location,'')=? "
            "AND IFNULL(vuln_class,'')=? AND IFNULL(reveals,'')=?",
            (r["purpose"], r["kind"], r["mode"], r["pattern"], loc,
             r.get("vuln_class", "") or "", r.get("reveals", "") or ""),
        ).fetchone()
        if not exists:
            _conn.execute(
                "INSERT INTO filter_rules(project_id,kind,mode,pattern,note,enabled,"
                "purpose,location,transform,vuln_class,tool,confidence,source,reveals,category,created_at)"
                " VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["kind"], r["mode"], r["pattern"], r.get("note", ""),
                 1 if r.get("enabled", True) else 0, r["purpose"], loc,
                 _dump_transform(r.get("transform")), r.get("vuln_class", ""),
                 r.get("tool", ""), r.get("confidence", ""), r.get("source", ""),
                 r.get("reveals", ""), r.get("category", ""), now),
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


# Curated scenario presets (option keys match the composer / drivers exactly).
# Values validated against each tool: sqlmap level 1-5 / risk 1-3 / technique
# BEUSTQ / tamper+is_dba allowed; ghauri level 1-3 / technique B,E,S,T only (no U)
# / NO risk, tamper, is_dba.
# (name, tool, options, danger) -- danger: safe | normal | high (display + warn)
# The "安全預設(唯讀)" per tool is a genuinely SAFE default (研究-grounded): lowest
# intrusiveness (level 1 / risk 1), READ-ONLY technique (drops S=stacked so no
# multi-statement writes), random_agent (near pure-upside: dodges the trivially-
# blocked default UA, one UA per session so page comparison stays consistent),
# and NO enumeration. It is marked each tool's default.
_PRESET_TEMPLATES = [
    # (name, tool, options, danger, description)
    ("安全預設(唯讀)", "sqlmap", {"level": 1, "risk": 1, "technique": "BEUTQ", "random_agent": True}, "safe",
     "最低侵入性、唯讀起手式:level 1、risk 1、technique 去掉堆疊(BEUTQ)保證不改資料、隨機 UA。日常首選。"),
    ("安全預設(唯讀)", "ghauri", {"level": 1, "technique": "BET", "random_agent": True}, "safe",
     "最低侵入、唯讀:level 1、technique BET(去堆疊查詢)、隨機 UA。日常首選。"),
    # sqlmap scenarios
    ("快速冒煙", "sqlmap", {"technique": "BEU", "threads": 5, "retries": 2, "timeout": 15}, "safe",
     "只用 B/E/U 快技法、砍掉最慢的時間盲注,threads 5、timeout 15。大量端點初篩,寧漏要快。"),
    ("標準偵測", "sqlmap", {"level": 2, "threads": 5}, "normal",
     "level 2(加測 Cookie)、threads 5、完整 technique;合理覆蓋但先不列舉。單一目標常規偵測。"),
    ("深度高覆蓋", "sqlmap", {"level": 5, "risk": 3, "threads": 5}, "high",
     "level 5 + risk 3,最大偵測率;⚠ risk 3 的 OR-based 可能影響多列資料,僅在明確授權且可接受風險時用。"),
    ("純偵測不改資料", "sqlmap", {"level": 2, "technique": "BEUTQ", "threads": 3}, "safe",
     "technique BEUTQ 移除堆疊查詢(S),從技術上保證唯讀不寫入;level 2。生產環境用。"),
    ("疑似有 WAF", "sqlmap", {"random_agent": True, "tamper": "space2comment,between,randomcase",
                              "threads": 1, "delay": 1, "time_sec": 8}, "normal",
     "random-agent + tamper(space2comment/between/randomcase)+ threads 1 + delay 1,規避 UA/簽章/速率封鎖。"),
    ("確認後列舉", "sqlmap", {"get_banner": True, "get_current_user": True, "get_current_db": True,
                             "is_dba": True, "get_dbs": True, "threads": 3}, "normal",
     "已確認可注入後,抓 banner / current-user / current-db / is-dba / dbs,取報告必要證據。"),
    ("盲注專用", "sqlmap", {"technique": "BT", "time_sec": 10, "threads": 1, "retries": 3}, "normal",
     "只用 B(布林)+T(時間),time-sec 10、單執行緒穩定時間量測;無回顯、UNION/報錯皆失敗時用。"),
    # ghauri scenarios
    ("快速冒煙", "ghauri", {"level": 1, "technique": "BE", "threads": 5, "timeout": 15, "retries": 1}, "safe",
     "level 1、technique BE、threads 5、retries 1;幾秒內拿到 yes/no。"),
    ("標準偵測", "ghauri", {"level": 2, "threads": 3}, "normal",
     "level 2、threads 3、預設 BEST;速度與覆蓋平衡的起手式。"),
    ("深度偵測", "ghauri", {"level": 3, "technique": "BEST", "time_sec": 8, "retries": 4}, "normal",
     "level 3(上限)、technique BEST、time-sec 8、retries 4;逼出隱藏或難觸發的注入。"),
    ("純偵測不改資料", "ghauri", {"level": 2, "technique": "BET"}, "safe",
     "technique BET 移除堆疊查詢(S),唯讀不寫入;level 2。"),
    ("慢速避偵測", "ghauri", {"level": 1, "technique": "BT", "threads": 1, "delay": 4,
                             "retries": 2, "random_agent": True}, "safe",
     "delay 4、threads 1、random-agent、technique BT;壓低請求頻率與指紋,避 WAF/速率限制。"),
    ("確認後列舉", "ghauri", {"level": 2, "get_banner": True, "get_current_user": True,
                             "get_current_db": True, "get_dbs": True}, "normal",
     "已確認可注入後,抓 banner / current-user / current-db / dbs。"),
]

_DEFAULT_PRESET_BY_TOOL = {"sqlmap": "安全預設(唯讀)", "ghauri": "安全預設(唯讀)"}


def _seed_preset_templates():
    """Add the curated scenario presets ONCE, guarded by PRAGMA user_version so
    existing DBs also receive them, but deleting one never brings it back. Marks
    each tool's SAFE preset as that tool's default (both tools get a default)."""
    ver = _conn.execute("PRAGMA user_version").fetchone()[0]
    if ver >= 1:
        return
    for name, tool, opts, danger, desc in _PRESET_TEMPLATES:
        exists = _conn.execute(
            "SELECT 1 FROM templates WHERE name=? AND tool=?", (name, tool)).fetchone()
        if not exists:
            _conn.execute(
                "INSERT INTO templates(name,tool,is_default,data_json,created_at)"
                " VALUES(?,?,0,?,?)",
                (name, tool,
                 json.dumps({"tool": tool, "danger": danger, "desc": desc, "options": opts},
                            ensure_ascii=False), _now()),
            )
    # give each tool the SAFE preset as its default -- but ONLY when there is no
    # default yet, or the only default is the seeded example. Never clobber a
    # default the user chose for their own template.
    for tool, defname in _DEFAULT_PRESET_BY_TOOL.items():
        cur = _conn.execute(
            "SELECT name FROM templates WHERE tool=? AND is_default=1 LIMIT 1",
            (tool,)).fetchone()
        if cur is None or cur["name"] == "範例 · 基本偵測(系統預設)":
            _conn.execute("UPDATE templates SET is_default=0 WHERE tool=?", (tool,))
            _conn.execute("UPDATE templates SET is_default=1 WHERE tool=? AND name=?",
                          (tool, defname))
    _conn.execute("PRAGMA user_version = 1")
    _conn.commit()


def _migrate_preset_desc():
    """v1 presets were seeded before descriptions existed. Backfill data_json.desc
    (and danger) for the built-in presets still missing it -> user_version 2. Only
    touches presets that lack a desc, so a user's own edits are left alone."""
    ver = _conn.execute("PRAGMA user_version").fetchone()[0]
    if ver >= 2:
        return
    for name, tool, opts, danger, desc in _PRESET_TEMPLATES:
        row = _conn.execute(
            "SELECT id,data_json FROM templates WHERE name=? AND tool=?",
            (name, tool)).fetchone()
        if not row:
            continue
        try:
            data = json.loads(row["data_json"] or "{}")
        except Exception:
            data = {}
        if not data.get("desc"):
            data["desc"] = desc
            data.setdefault("danger", danger)
            _conn.execute("UPDATE templates SET data_json=? WHERE id=?",
                          (json.dumps(data, ensure_ascii=False), row["id"]))
    _conn.execute("PRAGMA user_version = 2")
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
    allowed = {"name", "note", "restrict_ip", "archived", "tabs_json"}
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


def _dump_transform(t):
    """Store the transform pipeline as a JSON array string. Accepts a list, a
    JSON string, or a comma-separated string; returns '' for empty."""
    if not t:
        return ""
    if isinstance(t, str):
        s = t.strip()
        if not s:
            return ""
        if s.startswith("["):
            return s
        return json.dumps([p.strip() for p in s.split(",") if p.strip()])
    try:
        return json.dumps(list(t))
    except Exception:
        return ""


def create_rule(kind, mode, pattern, note="", project_id=None, enabled=True,
                purpose="filter", location="", transform="", vuln_class="",
                tool="", confidence="", source="", reveals="", category=""):
    with _lock:
        cur = _conn.execute(
            "INSERT INTO filter_rules(project_id,kind,mode,pattern,note,enabled,"
            "purpose,location,transform,vuln_class,tool,confidence,source,reveals,category,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (project_id, kind, mode, pattern, note, 1 if enabled else 0,
             purpose or "filter", location or "", _dump_transform(transform),
             vuln_class or "", tool or "", confidence or "", source or "",
             reveals or "", category or "", _now()),
        )
        _conn.commit()
        return _row(_conn.execute("SELECT * FROM filter_rules WHERE id=?",
                                  (cur.lastrowid,)).fetchone())


def update_rule(rule_id, **fields):
    allowed = {"kind", "mode", "pattern", "note", "enabled", "purpose",
               "location", "transform", "vuln_class", "tool", "confidence", "source",
               "reveals", "category"}
    if "transform" in fields:
        fields["transform"] = _dump_transform(fields["transform"])
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
                    options_json,params_json,extra_flags,restrict_ip,note,status,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                scan.get("note", ""),
                "queued",
                _now(),
            ),
        )
        _conn.commit()
        return get_scan(cur.lastrowid)


def get_scan(sid):
    with _lock:
        r = _row(_conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone())
    if r:
        try:
            res = json.loads(r.get("result_json") or "{}") or {}
        except Exception:
            res = {}
        r["reliability_ok"] = res.get("reliability_ok", True)
        r["caveat"] = res.get("caveat") or ""   # advisory ⚠ note on a 無洞 result
    return r


# columns the board/tree actually render — lets the 1.5s poll skip the heavy
# options_json / params_json / result_json blobs on every cycle
# slim fetches the param/result blobs too, but only to derive the compact `pouts`
# (tested-param outcomes for the sidebar card); the heavy blobs are dropped before return.
_SCAN_SLIM_COLS = ("id, project_id, tool, method, url, endpoint, status, "
                   "vulnerable, duration_ms, created_at, started_at, ended_at, "
                   "params_json, result_json")


def _param_outcomes(row):
    """Compact per-parameter outcome for the sidebar card: only the params actually
    TESTED (selected), each as {n: name, v: has_injection_point}. Skipped params omitted."""
    try:
        params = json.loads(row.get("params_json") or "[]") or []
    except Exception:
        params = []
    try:
        res = json.loads(row.get("result_json") or "{}") or {}
    except Exception:
        res = {}
    # res["parameters"] holds the raw log form "id (GET)"; params_json names are bare
    # ("id"), so strip the "(location)" suffix before comparing or a vulnerable param
    # renders as clean on multi-param scans.
    vuln = {str(p).split(" (")[0].strip() for p in (res.get("parameters") or [])}
    per = res.get("per_param") or {}
    scan_vuln = bool(row.get("vulnerable"))
    reliable = res.get("reliability_ok", True)   # False on a severe-reliability 測不準 run
    out = []
    for p in params:
        if not p.get("selected"):
            continue
        name = p.get("name")
        pv = per.get(name)
        # EVIDENCE-BASED, never default-to-clean: 'clean' needs a per-parameter signal
        # that named THIS param ("... parameter 'X' does not seem to be injectable"). A
        # selected param the tool never mentioned -- errored, half-run, or simply not
        # tested (the URI '#1*' fallback / a cookie at --level 1) -- is 'unknown' (未測),
        # NOT 無洞. The scan-level status is deliberately NOT used to infer per-param clean.
        if name in vuln or pv == "vulnerable":
            st = "vuln"
        elif pv == "tentative":
            st = "tentative"                       # unresolved tentative -> 疑似, never silently clean
        elif pv == "clean":
            st = "clean"                           # tool explicitly cleared THIS param
        else:
            st = "unknown"                         # selected but no per-param evidence -> 未測
        # low-confidence: the tool DID judge this param but the baseline was untrustworthy
        # (error storm / connection issue) -> show the real outcome + a ⚠, not a blank 未測.
        lc = (not reliable) and st in ("clean", "tentative")
        out.append({"n": name, "st": st, "v": st == "vuln", "lc": lc})
    # single-param inference: scan is vulnerable but the tool named no param (common with
    # ghauri) and exactly one param was tested -> that param is the injectable one.
    if scan_vuln and len(out) == 1 and out[0]["st"] != "vuln":
        out[0]["st"] = "vuln"
        out[0]["v"] = True
    return out


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
        rows = _rows(_conn.execute(q, args).fetchall())
        if slim:
            for r in rows:
                r["pouts"] = _param_outcomes(r)
                try:
                    res = json.loads(r.get("result_json") or "{}") or {}
                except Exception:
                    res = {}
                r["reliability_ok"] = res.get("reliability_ok", True)
                r["caveat"] = res.get("caveat") or ""   # advisory ⚠ note on a 無洞 result (低可信原因)
                r.pop("params_json", None)
                r.pop("result_json", None)
        return rows


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
        # drop this scan's rows from the per-parameter timeline too, so the
        # drill-down never links to a now-missing scan (param_status aggregate is
        # a summary and is intentionally left as-is).
        _conn.execute("DELETE FROM param_test WHERE scan_id=?", (sid,))
        _conn.commit()


def reset_stale_scans():
    """Any scan still 'running' or 'queued' at startup is a leftover from a
    previous run whose process is gone -> it can't resume/start, so mark it
    killed with a note. Keeps the board/tree honest instead of showing a
    zombie 'running'/'queued' that never progresses."""
    with _lock:
        now = _now()
        cur = _conn.execute(
            "UPDATE scans SET status='killed', "
            "ended_at=COALESCE(ended_at, ?), "
            "duration_ms=CASE WHEN started_at IS NOT NULL THEN ? - started_at ELSE duration_ms END, "
            "error=CASE WHEN COALESCE(error,'')='' THEN '伺服器重啟時中斷' ELSE error END "
            "WHERE status IN ('running','queued')",
            (now, now),
        )
        _conn.commit()
        return cur.rowcount


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
            "SELECT id,vulnerable,status FROM param_status WHERE "
            "project_id IS ? AND sig_endpoint=? AND name=? AND location=?",
            (project_id, sig_endpoint, name, location),
        ).fetchone()
        if existing:
            # NEVER downgrade a confirmed injection: once a param was vulnerable it
            # stays flagged (badge = 曾有漏洞), even if a later/flaky re-run doesn't
            # reproduce it. Still bump test_count / last_scan_id for the re-test.
            if existing["vulnerable"] and not vulnerable:
                status, vulnerable = "vulnerable", True
            # An inconclusive 'tested' must not downgrade a definitive 'clean': with
            # --batch the tool may skip re-testing this param after a hit in another
            # one, which is not evidence the earlier clean result was wrong.
            elif existing["status"] == "clean" and status == "tested":
                status = "clean"
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


def mark_param_skipped(project_id, sig_endpoint, endpoint, name, location, scan_id):
    """Record that a parsed parameter was SEEN but not selected this run -> mark
    it 'skipped' (distinct from never-seen 'untested'). Never downgrades a param
    that was actually tested (vulnerable/clean/tested), and does NOT bump
    test_count (it wasn't tested)."""
    with _lock:
        now = _now()
        existing = _conn.execute(
            "SELECT id,status FROM param_status WHERE "
            "project_id IS ? AND sig_endpoint=? AND name=? AND location=?",
            (project_id, sig_endpoint, name, location),
        ).fetchone()
        if existing:
            if existing["status"] in ("vulnerable", "clean", "tested"):
                return  # keep the real result; don't downgrade to skipped
            _conn.execute(
                "UPDATE param_status SET status='skipped', last_scan_id=?, "
                "endpoint=?, updated_at=? WHERE id=?",
                (scan_id, endpoint, now, existing["id"]),
            )
        else:
            _conn.execute(
                "INSERT INTO param_status(project_id,sig_endpoint,endpoint,name,location,"
                "status,vulnerable,last_scan_id,test_count,updated_at)"
                " VALUES(?,?,?,?,?,'skipped',0,?,0,?)",
                (project_id, sig_endpoint, endpoint, name, location, scan_id, now),
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


def add_param_test(project_id, sig_endpoint, endpoint, name, location,
                   scan_id, tool, status, vulnerable):
    """Append one immutable record of THIS scan's verdict for THIS parameter, so
    a per-parameter timeline can be shown (param_status keeps only the latest)."""
    with _lock:
        _conn.execute(
            "INSERT INTO param_test(project_id,sig_endpoint,endpoint,name,location,"
            "scan_id,tool,status,vulnerable,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (project_id, sig_endpoint, endpoint, name, location,
             scan_id, tool, status, 1 if vulnerable else 0, _now()),
        )
        _conn.commit()


def param_test_log(project_id, sig_endpoint, name, location):
    """Full chronological test history for one parameter (newest first), joined
    to each scan's url/status for display + linking."""
    with _lock:
        rs = _conn.execute(
            "SELECT pt.*, s.url AS scan_url, s.status AS scan_status "
            "FROM param_test pt LEFT JOIN scans s ON s.id = pt.scan_id "
            "WHERE pt.project_id IS ? AND pt.sig_endpoint=? AND pt.name=? AND pt.location=? "
            "ORDER BY pt.created_at DESC, pt.id DESC",
            (project_id, sig_endpoint, name, location),
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

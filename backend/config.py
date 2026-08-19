"""
Central configuration and path resolution.

Everything is resolved relative to the *app root* (the folder that contains
start.bat), so the whole thing can be copied anywhere and stay portable.
No absolute machine-specific paths are baked in.
"""
import os
import re
import sys
import json

# backend/  ->  app root is one level up
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)

# --- interpreter for scanner subprocesses ---------------------------------
PYTHON_DIR = os.path.join(ROOT_DIR, "python")     # legacy pre-uv embeddable; may linger on upgraded checkouts
_BUNDLED_PY = os.path.join(PYTHON_DIR, "python.exe")
# uv now owns the runtime: the backend runs inside the uv-managed .venv, whose
# interpreter (sys.executable) already has every dependency from uv.lock -- including
# ghauri's runtime libs. So sqlmap/ghauri subprocesses MUST reuse sys.executable, not a
# leftover .\python\ (which uv never manages and whose pinned deps drift out of sync).
# Fall back to the old bundled interpreter only if sys.executable is somehow unavailable.
PYTHON_EXE = sys.executable or _BUNDLED_PY

TOOLS_DIR = os.path.join(ROOT_DIR, "tools")


def resolve_tool_dir(canonical_name, marker_parts):
    """
    Find a bundled tool directory under tools/, tolerant of version-suffixed
    folder names. So all of these are accepted:  tools/sqlmap,
    tools/sqlmap-1.10, tools/ghauri, tools/ghauri-1.4.3 ...

    `canonical_name` is the preferred/bootstrap name (checked first);
    `marker_parts` is the relative file that must exist inside a valid dir
    (e.g. ["sqlmapapi.py"] or ["ghauri","scripts","ghauri.py"]).
    Returns the canonical path as a fallback even if nothing is found yet.
    """
    canonical = os.path.join(TOOLS_DIR, canonical_name)
    if os.path.isfile(os.path.join(canonical, *marker_parts)):
        return canonical
    matches = []
    try:
        for entry in sorted(os.listdir(TOOLS_DIR)):
            full = os.path.join(TOOLS_DIR, entry)
            if (os.path.isdir(full)
                    and entry.lower().startswith(canonical_name.lower())
                    and os.path.isfile(os.path.join(full, *marker_parts))):
                matches.append(full)
    except Exception:
        pass
    if matches:
        # pick the highest version NUMERICALLY (so sqlmap-1.10 beats sqlmap-1.9,
        # which a plain lexicographic sort gets wrong: '1.10' < '1.9' as strings)
        def _ver_key(path):
            nums = re.findall(r"\d+", os.path.basename(path))
            return [int(n) for n in nums] or [0]
        return max(matches, key=_ver_key)
    return canonical            # not present yet; keep canonical for messages


# sqlmap: run from vendored source as a direct CLI subprocess. No third-party deps.
SQLMAP_DIR = resolve_tool_dir("sqlmap", ["sqlmapapi.py"])
SQLMAP_PY = os.path.join(SQLMAP_DIR, "sqlmap.py")
SQLMAPAPI_PY = os.path.join(SQLMAP_DIR, "sqlmapapi.py")
# launcher that puts SQLMAP_DIR on sys.path first (embeddable python's ._pth
# won't, so sqlmap.py can't `import lib` when run directly). We run the CLI
# (sqlmap.py) directly, one subprocess per scan (no REST API).
SQLMAP_LAUNCH = os.path.join(BACKEND_DIR, "sqlmap_launch.py")

# ghauri: GitHub SOURCE run directly (NOT pip-installed); only its dependency
# libraries are pip-installed. Launched via backend/ghauri_launch.py.
GHAURI_DIR = resolve_tool_dir("ghauri", ["ghauri", "scripts", "ghauri.py"])
GHAURI_LAUNCH = os.path.join(BACKEND_DIR, "ghauri_launch.py")
GHAURI_ENTRY = os.path.join(GHAURI_DIR, "ghauri", "scripts", "ghauri.py")

# --- data (created at runtime) --------------------------------------------
DATA_DIR = os.path.join(ROOT_DIR, "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
REQ_DIR = os.path.join(DATA_DIR, "requests")   # saved raw .req files for -r
DB_PATH = os.path.join(DATA_DIR, "sqlmap_auto.db")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")

# --- defaults -------------------------------------------------------------
DEFAULTS = {
    "host": "127.0.0.1",
    "port": 8776,             # web UI port
    "max_concurrent": 3,      # how many scans may run at once (pool size; needs restart)
    "public_ip_lookup": True, # try to also show the public IP (best-effort)
    "public_ip_timeout": 2.5, # seconds; failure is non-fatal
    "ip_refresh_seconds": 60,  # how often the UI auto-refreshes the IP display
    "preferred_local_ip": "",  # user-picked NIC IP to show as 內網 (empty = auto-detect by route)
    "scan_refresh_seconds": 2, # how often the board/tree/log poll for updates
    "auto_open_browser": True,
    "default_tool": "sqlmap", # which tool the composer pre-selects (sqlmap | ghauri)
    "default_scan_mode": "advanced",  # composer's default mode every time (advanced | basic)
    # keys shown in the pinned "常用設置" quick strip above the command preview. Empty
    # list is a valid explicit choice (hide the strip); the frontend supplies the default
    # set when this key is absent. Persisted verbatim as a JSON list.
    "pinned_common": ["force_ssl", "random_agent"],
    # which raw-output view a scan detail opens on: "highlighted" (our verdict/enum
    # highlighting) or "original" (terminal-style, tool's own log colours).
    "default_log_view": "highlighted",
}


def ensure_dirs():
    for d in (DATA_DIR, LOG_DIR, REQ_DIR):
        os.makedirs(d, exist_ok=True)


def load_settings():
    """Merge on-disk settings over DEFAULTS. Never raises on a bad file."""
    settings = dict(DEFAULTS)
    try:
        if os.path.isfile(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings.update(json.load(f) or {})
    except Exception:
        pass
    return settings


def save_settings(settings):
    ensure_dirs()
    merged = dict(DEFAULTS)
    merged.update(settings or {})
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    return merged

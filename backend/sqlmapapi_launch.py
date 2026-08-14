"""
Launch sqlmap's REST API (sqlmapapi.py) from the vendored source using the
portable/embeddable Python.

Why a launcher: the embeddable Python ships a `pythonXX._pth` file that PINS
sys.path and does NOT add the script's own directory (and ignores PYTHONPATH).
sqlmapapi.py does `import lib...` expecting its folder on sys.path, so run
directly it dies with `ModuleNotFoundError: No module named 'lib'`. We put the
sqlmap source dir on sys.path first (same trick as ghauri_launch.py), then run
sqlmapapi.py as __main__.

Usage:  python backend/sqlmapapi_launch.py -s -H 127.0.0.1 -p 8775
"""
import os
import sys
import runpy

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config  # resolves the sqlmap source dir (tolerates tools/sqlmap-<ver>)

_SQLMAP_DIR = config.SQLMAP_DIR
if os.path.isdir(_SQLMAP_DIR) and _SQLMAP_DIR not in sys.path:
    sys.path.insert(0, _SQLMAP_DIR)

_api = config.SQLMAPAPI_PY
if not os.path.isfile(_api):
    sys.stderr.write(
        "找不到 sqlmapapi.py:{}\n已解析的 sqlmap 目錄:{}\n"
        "請先執行 bootstrap.bat 下載 sqlmap。\n".format(_api, _SQLMAP_DIR))
    sys.exit(2)

# sqlmapapi.py parses sys.argv -- make it look like it was invoked directly.
sys.argv = [_api] + sys.argv[1:]
runpy.run_path(_api, run_name="__main__")

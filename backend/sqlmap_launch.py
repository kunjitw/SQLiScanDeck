"""
Run sqlmap's CLI (sqlmap.py) straight from the vendored source with the
portable/embeddable Python -- no REST API, one subprocess per scan (same model
as ghauri_launch.py).

Why a launcher: the embeddable Python's `pythonXX._pth` pins sys.path and won't
add the script's own directory, so sqlmap.py can't `import lib`. We put the
sqlmap source dir on sys.path first, then run sqlmap.py as __main__.

Usage:  python backend/sqlmap_launch.py -r <req> --batch <sqlmap args...>
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

_py = config.SQLMAP_PY
if not os.path.isfile(_py):
    sys.stderr.write(
        "找不到 sqlmap.py:{}\n已解析的 sqlmap 目錄:{}\n"
        "請先執行 bootstrap.bat 下載 sqlmap。\n".format(_py, _SQLMAP_DIR))
    sys.exit(2)

sys.argv = [_py] + sys.argv[1:]
runpy.run_path(_py, run_name="__main__")

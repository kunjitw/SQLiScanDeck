"""
Run ghauri straight from its GitHub source checkout at tools/ghauri, WITHOUT
pip-installing ghauri itself (only its dependency libraries are pip-installed).

This keeps ghauri on the latest GitHub source. We put tools/ghauri on sys.path
and call the same entry point pip would (`ghauri.scripts.ghauri:main`).

Usage:  python backend/ghauri_launch.py <ghauri args...>
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config  # resolves the ghauri source dir (tolerates tools/ghauri-<ver>)

_GHAURI_DIR = config.GHAURI_DIR
if os.path.isdir(_GHAURI_DIR) and _GHAURI_DIR not in sys.path:
    sys.path.insert(0, _GHAURI_DIR)

try:
    from ghauri.scripts.ghauri import main
except Exception as e:  # pragma: no cover
    sys.stderr.write(
        "無法從原始碼載入 ghauri({}).\n"
        "已解析的 ghauri 目錄:{}\n"
        "請確認 tools\\ghauri(或 tools\\ghauri-<版本>)存在,且其相依已安裝"
        "(tldextract colorama requests chardet ua_generator)。\n".format(e, _GHAURI_DIR))
    sys.exit(2)

if __name__ == "__main__":
    main()

# SQLiScanDeck

English · [繁體中文](README.md)

SQLiScanDeck is a local web UI for the sqlmap and ghauri command-line tools. Paste an HTTP request or a URL; it extracts the testable parameters, runs concurrent scans in the background, and stores every run in SQLite.

![SQLiScanDeck main screen: scan queue on the left, request composer in the middle, test-history tree on the right](docs/demo.png)

> ⚠️ Only test targets you have written authorization for. Unauthorized scanning may be illegal, and the responsibility is yours. This is a local tool: it binds to `127.0.0.1` by default and has no built-in login. Never upload `data/` — it holds real requests and cookies.

Requirements: Windows 10/11. The first `bootstrap` needs internet to download. It never touches your system Python.

## Install

1. First time: connect to the internet and double-click `bootstrap.bat`. It downloads an embedded Python, sqlmap, and ghauri. You only do this once.
2. Every time after: double-click `start.bat`. It opens your browser at `http://127.0.0.1:8776`.

You can copy the whole folder to another machine that has already been bootstrapped and just run `start.bat`. Scan history and tabs live in `data/`, so they move with the folder.

## Try it

The project ships a practice target so you can do a full run with zero risk.

```
python testlab\vuln_server.py          # deliberately vulnerable target, binds to 127.0.0.1:5000
```

In the UI, paste `http://127.0.0.1:5000/product?id=1`, pick a tool, and press Start scan. After a few seconds the queue turns red (vulnerable); open it to see the live log, the evidence behind the verdict, and the payload.

There is also a MySQL / MariaDB target: double-click `testlab\start_mysql_lab.bat`, which binds to `127.0.0.1:5001`. Both targets are intentionally vulnerable and must stay bound to localhost.

## How to use

1. Paste a raw request or a URL and press Parse. Parameters split into three groups: main (checked by default), Header, and auto-skipped.
2. Pick a tool: sqlmap or ghauri.
3. Pick a mode: Basic applies a template and is read-only; Advanced lets you change every option.
4. When needed, use the quick-settings strip at the bottom to change the scheme (HTTP / HTTPS), random User-Agent, and other common flags. To edit the whole command directly, press Edit.
5. Press Start scan. Watch the status colors in the left queue, click a scan for its live log, and the tree on the right builds up history.

## Features

- Paste a request or URL and it extracts GET / POST / JSON / Cookie / Header parameters.
- Built-in noise filters (GA, FB pixel, CSRF, ViewState, and so on) leave matched values unchecked by default; you can re-check them by hand.
- Scans run concurrently in the background without freezing the UI. Status is color-coded: red = vulnerable, green = clean, orange = running, gray = stopped or other.
- The command preview at the bottom is exactly what runs, because the frontend and backend share the same command-building code.
- Every scan stores its command, log, and result in SQLite. Re-testing the same endpoint warns you that it was tested before, or was vulnerable.
- A scan's log can switch between highlighted and raw output, and can be exported as a PNG for reports.
- The test-history tree on the right is arranged by path hierarchy and can be filtered by outcome.
- Separate targets into projects; composer tabs are stored in the database, so they survive moving the whole folder to another machine.

## License and safety

Licensed under [GNU AGPL-3.0](LICENSE) (© 2026 kunjitw). Free to use, study, and modify; but any modified, distributed, or network-served version must also be open-sourced under AGPL with attribution, and cannot be relicensed as closed-source proprietary software.

- Only test targets you have explicit written authorization for. Unauthorized scanning may be illegal in your jurisdiction.
- Binds to `127.0.0.1` with no built-in auth by default. If you expose it, add your own access control.
- Never upload `data/` — it holds real requests, cookies, and logs. `.gitignore` already excludes `data/`, `python/`, and `tools/`.
- The `testlab/` targets are intentionally vulnerable and must stay bound to localhost.
- This project orchestrates [sqlmap](https://github.com/sqlmapproject/sqlmap) (GPLv2) and [ghauri](https://github.com/r0oth3x49/ghauri) (MIT) as separate processes, fetched by `bootstrap` and not redistributed here.

<details>
<summary>📸 Screenshots</summary>

Request composer: pick tool, mode, template, and options; the quick-settings strip and the exact command run at the bottom.

![sqlmap scan options with the command preview at the bottom](docs/compose.png)

Scan detail: the verdict evidence, per-parameter results, the raw request, and a live log that switches between highlighted and raw.

![scan detail where ghauri found a MySQL injection](docs/detail.png)

Image export: drag to select rows, toggle colors, edit, then save as PNG or copy to the clipboard.

![the image-export dialog](docs/export.png)

</details>

<details>
<summary>🧠 Three things worth knowing</summary>

- Signature dedup only affects display. IDs in a path are normalized to `{id}` just to group history and draw the tree; the scan sends your original text, and the path is not changed.
- Filters only uncheck things for you; you can re-check any of them. Gray-area values (session ids, Authorization, first-party cookies) are off by default because testing them can break your own session.
- A template is just a set of scan options, stored per tool. Once set as default, it is applied automatically each time.

</details>

<details>
<summary>⚙️ Settings</summary>

| Item | Notes |
|---|---|
| Max concurrent scans | How many run at once (default 3, needs restart) |
| Web port | Default 8776 (needs restart) |
| Default tool | Pre-selects sqlmap or ghauri on load |
| Default scan mode | Opens in Basic or Advanced each time |
| Pinned quick settings | Which flags show in the strip above the command (default: force HTTPS, random User-Agent) |
| Default log view | Opens a scan detail in highlighted or raw |
| IP refresh (seconds) | How often the header IP badge updates |
| Try to show public IP | Turn off for a faster intranet (it calls ipify and similar) |
| Open browser on start | — |

</details>

<details>
<summary>🏗️ Architecture</summary>

```
backend/   FastAPI backend, runs on the embedded Python
  app.py            API routes, static frontend, /api/preview command preview, loopback gate
  scan_manager.py   concurrency queue, live log streaming, persistence, force-stop and delete
  drivers/          sqlmap / ghauri drivers; build_args is the single source of the command
  db.py             SQLite: projects, scans, param history, rules, templates, tabs
  request_parser.py / filters.py / signature.py / ip_utils.py / config.py
web/       single-page frontend (index.html / style.css / app.js, no framework)
testlab/   vuln_server.py and vuln_mysql_server.py, two practice targets, bound to 127.0.0.1
python/    embedded portable Python (bootstrap downloads it, .gitignore)
tools/     sqlmap / ghauri source (.gitignore)
data/      created at runtime: DB, logs/, requests/, settings.json (.gitignore)
```

- Both engines run as separate subprocesses with `-r <request file>`, so the scan tests exactly what you pasted.
- The frontend preview and the real run share the backend `build_args()`, so they can't drift apart.
- Sensitive fields such as the raw request and tab contents are only returned when bound to `127.0.0.1 / localhost / ::1`.
- Force-stop actually kills the engine process before marking the scan as killed.

</details>

<details>
<summary>🔧 Manual install (intranet, or when bootstrap can't run)</summary>

1. Put a portable Python in `python\`, then run `python\python.exe -m pip install -r backend\requirements.txt`.
2. Put the sqlmap source in `tools\sqlmap\` (must contain `sqlmap.py`, `sqlmapapi.py`).
3. Put the ghauri source in `tools\ghauri\` (must contain `ghauri\scripts\ghauri.py`), then install its deps: `pip install tldextract colorama requests chardet ua_generator`.
4. Run `start.bat`, or `python backend\app.py` directly.

</details>

<details>
<summary>❓ FAQ</summary>

- Engine light is red: `tools\sqlmap` or `tools\ghauri` isn't ready. Re-run `bootstrap.bat`.
- Command preview is blank or wrong: the backend was updated. Restart the server, then hard-refresh.
- Pressing F5 inside a project: it stays in that project instead of returning to the list.
- MySQL target won't start: the first run downloads MariaDB and needs internet. If it hangs, run `stop_mysql_lab.bat`, then `start_mysql_lab.bat` again.
- IP shows "not detected": this machine can't reach the internet. It doesn't affect scanning; you can turn off the public-IP lookup in settings.
- Changed concurrency or port and nothing happened: it needs a restart.

</details>

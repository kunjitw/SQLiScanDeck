@echo off
REM ===========================================================================
REM  SQLiScanDeck launcher -- fully self-contained via uv.
REM  Double-click to run. First run downloads uv + a managed Python + deps,
REM  ALL inside this folder. Nothing is installed on the system, PATH is never
REM  changed. Delete the folder = zero residue.
REM  (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
REM ===========================================================================
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%"

REM --- keep EVERY uv artifact inside the project folder; touch nothing global ---
set "UV_UNMANAGED_INSTALL=%ROOT%\.tools"
set "UV_PYTHON_INSTALL_DIR=%ROOT%\.python-managed"
set "UV_PROJECT_ENVIRONMENT=%ROOT%\.venv"
set "UV_CACHE_DIR=%ROOT%\.uv-cache"
set "UV_PYTHON_PREFERENCE=only-managed"
set "UV_PYTHON=3.11"
set "UV_NO_MODIFY_PATH=1"
REM never inherit a colleague's python packages / interpreter
set "PYTHONPATH="
set "PYTHONHOME="

set "UV=%ROOT%\.tools\uv.exe"

echo %ROOT%| find " " >nul && echo [start] NOTE: this path has a space; if anything misbehaves, move the folder to a path with no spaces (e.g. C:\SQLiScanDeck).

REM --- 1) ensure uv.exe (download once into .tools, or copy from an intranet share) ---
if not exist "%UV%" (
  if defined SQLISCANDECK_UV_SRC (
    if exist "%SQLISCANDECK_UV_SRC%" (
      echo [start] copying uv.exe from share: %SQLISCANDECK_UV_SRC%
      if not exist "%ROOT%\.tools" mkdir "%ROOT%\.tools"
      copy /y "%SQLISCANDECK_UV_SRC%" "%UV%" >nul
    )
  )
)
if not exist "%UV%" (
  echo [start] first run: downloading uv into .tools ^(no PATH/profile changes^) ...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:UV_UNMANAGED_INSTALL='%ROOT%\.tools'; $env:UV_NO_MODIFY_PATH='1'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://astral.sh/uv/install.ps1 | iex"
)
if not exist "%UV%" (
  echo.
  echo [start] ERROR: could not obtain uv.exe.
  echo         Intranet with no GitHub access? Put a copy of uv.exe on a share and
  echo         set SQLISCANDECK_UV_SRC to its full path, then run start.bat again.
  echo         ^(or just drop uv.exe into .tools\ by hand.^)
  pause
  exit /b 1
)

REM --- 2) ensure the ENGINES (sqlmap + ghauri SOURCE). uv cannot fetch these:
REM        they run from source, not PyPI. Accept version-suffixed dirs (sqlmap-1.10,
REM        ghauri-1.4.3, ...) exactly like config.resolve_tool_dir. bootstrap.ps1 is idempotent. ---
set "SQLMAP_OK="
for /d %%D in ("%ROOT%\tools\sqlmap*") do if exist "%%D\sqlmapapi.py" set "SQLMAP_OK=1"
set "GHAURI_OK="
for /d %%D in ("%ROOT%\tools\ghauri*") do if exist "%%D\ghauri\scripts\ghauri.py" set "GHAURI_OK=1"
if defined SQLMAP_OK if defined GHAURI_OK goto ENGINES_OK
echo [start] fetching sqlmap + ghauri source ^(one-time^) ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bootstrap.ps1"
if errorlevel 1 (
  echo [start] engine fetch failed. See the error above. On an intranet you can copy
  echo         tools\sqlmap\ and tools\ghauri\ from another machine.
  pause
  exit /b 1
)
:ENGINES_OK

REM --- 3) sync Python + deps from the committed uv.lock (exact, reproducible) ---
echo [start] syncing environment via uv ...
"%UV%" sync --frozen --project "%ROOT%"
if errorlevel 1 (
  echo [start] uv sync failed. See the error above.
  pause
  exit /b 1
)

REM --- 4) launch the web UI (opens your browser; Ctrl+C to stop) ---
echo [start] starting SQLiScanDeck ... press Ctrl+C to stop.
"%UV%" run --frozen --project "%ROOT%" backend
pause

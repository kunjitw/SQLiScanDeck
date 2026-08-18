@echo off
REM Optional pre-fetch of the scanners (sqlmap + ghauri source) into .\tools.
REM You normally do NOT need to run this -- start.bat fetches the engines on first
REM run and then handles Python + deps via uv. Run this only to pre-stage the
REM engines (e.g. before going offline).
REM (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
setlocal
echo === SQLiScanDeck: fetch scanner engines (sqlmap + ghauri) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1"
if errorlevel 1 (
  echo.
  echo [bootstrap] Engine fetch did NOT complete. See the error above.
  pause
  exit /b 1
)
echo.
echo [bootstrap] Done. Now run  start.bat  to launch the web UI.
pause

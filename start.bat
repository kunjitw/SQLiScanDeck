@echo off
REM Launch sqlmap_auto on the PORTABLE python. Opens the web UI in your browser.
REM (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
setlocal
set "PYEXE=%~dp0python\python.exe"

if not exist "%PYEXE%" (
  echo [start] Portable Python not found: "%PYEXE%"
  echo [start] Please run  bootstrap.bat  first to complete one-time setup.
  pause
  exit /b 1
)

echo [start] Starting sqlmap_auto ... press Ctrl+C to stop.
"%PYEXE%" "%~dp0backend\app.py"
pause

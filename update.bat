@echo off
REM ===========================================================================
REM  SQLiScanDeck updater -- pull the latest code from GitHub. NO git required.
REM  Double-click. It downloads the latest release zip and overlays the CODE
REM  only: your data\ (scan history, settings, saved requests), the engines in
REM  tools\, and the whole uv runtime (.venv / .tools / ...) are NEVER touched.
REM  (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
REM ===========================================================================
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

echo [update] checking for updates ... (nothing is changed until you confirm)
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\update.ps1"
if errorlevel 1 (
  echo.
  echo [update] Update did NOT complete -- see the error above. Your install was NOT changed.
  pause
  exit /b 1
)
echo.
echo [update] Done. If the app is currently running, close it ^(Ctrl+C in its window^)
echo          and double-click start.bat again to run the new version.
pause

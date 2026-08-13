@echo off
REM One-time setup: fetches a portable Python + sqlmap + ghauri into this folder.
REM Needs internet only for this first run. Re-runnable (skips finished steps).
REM (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
setlocal
echo === sqlmap_auto first-time setup ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1"
if errorlevel 1 (
  echo.
  echo [bootstrap] Setup did NOT complete. See the error above.
  pause
  exit /b 1
)
echo.
pause

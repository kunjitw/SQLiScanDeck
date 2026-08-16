@echo off
REM ============================================================================
REM  SQLiScanDeck - one-click portable MySQL/MariaDB test lab
REM  Uses your system Python (3.8+ on PATH) + pip. First run downloads a
REM  portable MariaDB (~90MB) into testlab\mariadb (gitignored); nothing is
REM  installed as a service and nothing outside testlab\ is touched.
REM  (ASCII-only on purpose: non-ASCII in .bat breaks cmd.exe on CJK codepages.)
REM ============================================================================
setlocal
cd /d "%~dp0.."

where python >nul 2>nul
if errorlevel 1 (
  echo [mysql-lab] Python not found on PATH. Install Python 3 and retry.
  pause & exit /b 1
)

echo [mysql-lab] ensuring pymysql is installed ...
python -m pip install --quiet pymysql
if errorlevel 1 ( echo [mysql-lab] pip install pymysql failed & pause & exit /b 1 )

echo [mysql-lab] starting MariaDB ^(first run downloads ~90MB^) ...
python testlab\mysql_lab.py up
if errorlevel 1 ( echo [mysql-lab] lab bring-up failed & pause & exit /b 1 )

echo [mysql-lab] launching the vulnerable MySQL app in a new window ...
start "VulnLab-MySQL :5001" python testlab\vuln_mysql_server.py 127.0.0.1 5001

echo.
echo [mysql-lab] Ready. Point SQLiScanDeck at  http://127.0.0.1:5001
echo [mysql-lab] Stop the database later with:  stop_mysql_lab.bat
echo.
pause

@echo off
REM Shut down the portable MariaDB test lab (leaves the data dir intact).
setlocal
cd /d "%~dp0.."
where python >nul 2>nul || ( echo [mysql-lab] Python not found on PATH. & pause & exit /b 1 )
python testlab\mysql_lab.py down
echo [mysql-lab] (the vulnerable app window, if open, can be closed manually)
pause

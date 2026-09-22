@echo off
setlocal
echo ========================================================
echo             MailTrace AI - Stopping All Services
echo ========================================================
echo.

echo Stopping servers on ports 8000, 5173, 5174...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 "') do (
    taskkill /F /PID %%a >nul 2>&1
)

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173 "') do (
    taskkill /F /PID %%a >nul 2>&1
)

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5174 "') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo All MailTrace AI servers (Backend, User Webmail, Security SOC) have been STOPPED!
echo ========================================================
echo.
pause

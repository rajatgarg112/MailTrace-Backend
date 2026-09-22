@echo off
setlocal enabledelayedexpansion
title MailTrace AI - Auto Launcher

echo ========================================================
echo       MailTrace AI - Smart Multi-Service Launcher
echo ========================================================
echo.

cd /d "%~dp0"

:: ---------------------------------------------------------
:: 1. Auto-Detect Backend Directory
:: ---------------------------------------------------------
set "BACKEND_DIR="
if exist "%~dp0app\main.py" (
    set "BACKEND_DIR=%~dp0"
) else if exist "%~dp0backend\app\main.py" (
    set "BACKEND_DIR=%~dp0backend"
) else if exist "%~dp0MailTrace-Backend\app\main.py" (
    set "BACKEND_DIR=%~dp0MailTrace-Backend"
) else if exist "%~dp0..\backend\app\main.py" (
    set "BACKEND_DIR=%~dp0..\backend"
) else if exist "%~dp0..\MailTrace-Backend\app\main.py" (
    set "BACKEND_DIR=%~dp0..\MailTrace-Backend"
) else if exist "%~dp0..\app\main.py" (
    set "BACKEND_DIR=%~dp0.."
)

:: ---------------------------------------------------------
:: 2. Auto-Detect Frontend Directory
:: ---------------------------------------------------------
set "FRONTEND_DIR="
if exist "%~dp0package.json" (
    set "FRONTEND_DIR=%~dp0"
) else if exist "%~dp0frontend\package.json" (
    set "FRONTEND_DIR=%~dp0frontend"
) else if exist "%~dp0MailTrace-Frontend\package.json" (
    set "FRONTEND_DIR=%~dp0MailTrace-Frontend"
) else if exist "%~dp0..\frontend\package.json" (
    set "FRONTEND_DIR=%~dp0..\frontend"
) else if exist "%~dp0..\MailTrace-Frontend\package.json" (
    set "FRONTEND_DIR=%~dp0..\MailTrace-Frontend"
) else if exist "%~dp0..\package.json" (
    set "FRONTEND_DIR=%~dp0.."
)

:: ---------------------------------------------------------
:: 3. Validation & Environment Checks
:: ---------------------------------------------------------
if "%BACKEND_DIR%"=="" (
    echo [ERROR] Backend directory not found!
    echo Please make sure MailTrace-Backend is cloned in this folder or side-by-side:
    echo   git clone https://github.com/rajatgarg112/MailTrace-Backend.git
    echo.
    pause
    exit /b 1
)

if "%FRONTEND_DIR%"=="" (
    echo [ERROR] Frontend directory not found!
    echo Please make sure MailTrace-Frontend is cloned in this folder or side-by-side:
    echo   git clone https://github.com/rajatgarg112/MailTrace-Frontend.git
    echo.
    pause
    exit /b 1
)

echo [OK] Backend located at:  %BACKEND_DIR%
echo [OK] Frontend located at: %FRONTEND_DIR%
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] 'python' was not found in your PATH!
    echo Please install Python 3.10+ from python.org and check "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] 'npm' was not found in your PATH!
    echo Please install Node.js LTS from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%\node_modules" (
    echo [INFO] First time run detected: node_modules missing in frontend.
    echo Installing frontend dependencies - running npm install...
    pushd "%FRONTEND_DIR%"
    call npm install
    popd
    echo.
)

:: ---------------------------------------------------------
:: 4. Start Services
:: ---------------------------------------------------------
echo [1/3] Starting FastAPI Backend on Port 8000...
start "MailTrace - Backend (Port 8000)" /D "%BACKEND_DIR%" cmd /k "python -m uvicorn app.main:app --reload --port 8000"

ping 127.0.0.1 -n 3 > nul

echo [2/3] Starting User Webmail Dashboard on Port 5173...
start "MailTrace - User Webmail (Port 5173)" /D "%FRONTEND_DIR%" cmd /k "npm run dev:user"

ping 127.0.0.1 -n 2 > nul

echo [3/3] Starting Security Gateway Dashboard on Port 5174...
start "MailTrace - Security Gateway (Port 5174)" /D "%FRONTEND_DIR%" cmd /k "npm run dev:security"

echo.
echo Waiting for servers to initialize...
ping 127.0.0.1 -n 4 > nul

echo Opening dashboards in your browser...
start "" "http://localhost:5173/fono"
start "" "http://localhost:5174/security"
start "" "http://localhost:8000/docs"

echo.
echo ========================================================
echo All services are running and opened in your browser!
echo.
echo   * User Webmail:        http://localhost:5173/fono
echo   * Security SOC Portal: http://localhost:5174/security
echo   * Backend API Docs:    http://localhost:8000/docs
echo.
echo Note: Keep the command windows open while working.
echo Run stop_all.bat to stop all servers at once.
echo ========================================================
echo.
pause

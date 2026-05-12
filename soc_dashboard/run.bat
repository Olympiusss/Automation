@echo off
setlocal EnableDelayedExpansion
title Sentrium SOC Dashboard

:: ── Banner ──────────────────────────────────────────────────────────────────
echo.
echo   ██████  ███████ ███    ██ ████████ ██████  ██ ██    ██ ███    ███
echo   ██      ██      ████   ██    ██    ██   ██ ██ ██    ██ ████  ████
echo   ███████ █████   ██ ██  ██    ██    ██████  ██ ██    ██ ██ ████ ██
echo        ██ ██      ██  ██ ██    ██    ██   ██ ██ ██    ██ ██  ██  ██
echo   ██████  ███████ ██   ████    ██    ██   ██ ██  ██████  ██      ██
echo.
echo   Security Operations Center — v1.0
echo   ════════════════════════════════════════════════════════
echo.

cd /d "%~dp0"

:: ── Parse args ───────────────────────────────────────────────────────────────
set PORT=8080
set HOST=0.0.0.0
set RELOAD=--reload
set LOG=info

:parse
if "%~1"=="--port"   ( set PORT=%~2  & shift & shift & goto parse )
if "%~1"=="--host"   ( set HOST=%~2  & shift & shift & goto parse )
if "%~1"=="--prod"   ( set RELOAD=   & set LOG=warning & shift & goto parse )
if "%~1"=="--debug"  ( set LOG=debug  & shift & goto parse )
if "%~1"=="--help"   ( goto help )

:: ── Load .env if present ─────────────────────────────────────────────────────
if exist ".env" (
    echo   [ENV] Loading .env file...
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "%%A=%%B"
    )
)

:: ── Check Python ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo   [ERROR] Python not found. Please install Python 3.10+
    pause & exit /b 1
)

:: ── Check/Install deps ───────────────────────────────────────────────────────
echo   [1/3] Checking dependencies...
pip install -r requirements.txt -q --disable-pip-version-check
if errorlevel 1 (
    echo   [ERROR] Failed to install dependencies
    pause & exit /b 1
)
echo         Done.

:: ── Validate critical env vars ───────────────────────────────────────────────
echo   [2/3] Validating configuration...
set WARNINGS=0

if "%S1_API_TOKEN%"=="" (
    echo         [WARN] S1_API_TOKEN not set — SentinelOne data will be unavailable
    set /a WARNINGS+=1
)
if "%AV_CLIENT_ID%"=="" (
    echo         [WARN] AV_CLIENT_ID not set — AlienVault data will be unavailable
    set /a WARNINGS+=1
)
if "%AV_CLIENT_SECRET%"=="" (
    echo         [WARN] AV_CLIENT_SECRET not set — AlienVault data will be unavailable
    set /a WARNINGS+=1
)

if !WARNINGS! == 0 (
    echo         All credentials configured.
) else (
    echo         !WARNINGS! warning(s) — some features may be limited.
)

:: ── Start server ─────────────────────────────────────────────────────────────
echo   [3/3] Starting dashboard...
echo.
echo   ┌────────────────────────────────────────────────────┐
echo   │                                                    │
echo   │   Dashboard : http://localhost:%PORT%              │
echo   │   Health    : http://localhost:%PORT%/api/health   │
echo   │   Mode      : %RELOAD%                             │
echo   │                                                    │
echo   │   Press Ctrl+C to stop                             │
echo   │                                                    │
echo   └────────────────────────────────────────────────────┘
echo.

uvicorn app:app --host %HOST% --port %PORT% %RELOAD% --log-level %LOG%
goto end

:help
echo.
echo   Usage: run.bat [options]
echo.
echo   Options:
echo     --port  PORT    Port to listen on (default: 8080)
echo     --host  HOST    Host to bind to   (default: 0.0.0.0)
echo     --prod          Production mode (no reload, reduced logging)
echo     --debug         Enable debug logging
echo     --help          Show this help
echo.
echo   Examples:
echo     run.bat
echo     run.bat --port 9090
echo     run.bat --prod
echo.

:end
endlocal

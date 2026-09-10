@echo off
setlocal enabledelayedexpansion
title AegisNet Docker Deployment Launcher

echo ======================================================
echo        [+] AegisNet Docker Production Launcher
echo ======================================================
echo.

:: 1. Check if Docker is running
echo [*] Checking Docker daemon status...
docker ps >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Docker daemon is not running.
    echo [*] Please open Docker Desktop on Windows, wait for it to start,
    echo     and then run this script again.
    echo.
    pause
    exit /b 1
)

:: 2. Ensure .env exists
if not exist .env (
    echo [*] Creating .env from .env.docker.example...
    copy .env.docker.example .env >nul
    echo [OK] Default .env created.
)

:: 3. Ensure data directories exist
if not exist data\uploads mkdir data\uploads
if not exist data\samples mkdir data\samples
if not exist data\models mkdir data\models
if not exist logs mkdir logs

:: 4. Build and run containers
echo.
echo [*] Building and launching AegisNet containers with Docker Compose...
echo [*] This will build PostgreSQL, FastAPI Backend, and React Nginx Frontend...
echo.
docker compose up -d --build

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ======================================================
    echo        [+] AegisNet Launched Successfully in Docker!
    echo ======================================================
    echo.
    echo   [-] Web Application Dashboard : http://localhost:80
    echo   [-] Backend API & Swagger Docs : http://localhost:8001/docs
    echo   [-] Backend Health Endpoint    : http://localhost:8001/health
    echo.
    echo   [-] To view live container logs : docker compose logs -f
    echo   [-] To stop all containers     : docker compose down
    echo ======================================================
) else (
    echo.
    echo [!] Docker compose build failed. Please review error messages above.
)

echo.
pause

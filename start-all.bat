@echo off
title AegisNet Platform Master Launcher
color 0b

echo =======================================================================
echo          AEGISNET: AI-Assisted Network Defense & Threat Platform
echo =======================================================================
echo.
echo [1/2] Launching AegisNet FastAPI Backend on Port 8001...
start "AegisNet Backend API (Port 8001)" cmd /c "cd /d "%~dp0" && .venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 --reload"

echo [2/2] Launching AegisNet Frontend on Port 5173...
start "AegisNet Frontend UI (Port 5173)" cmd /c "cd /d "%~dp0frontend" && npm.cmd run dev"

echo.
echo =======================================================================
echo  Services Starting!
echo.
echo  - Frontend Dashboard:  http://localhost:5173
echo  - Backend API:         http://localhost:8001
echo  - Interactive Docs:    http://localhost:8001/docs
echo =======================================================================
echo.
echo Press any key to open the dashboard in your browser...
pause >nul
start http://localhost:5173

@echo off
title AegisNet Backend API Server
echo ========================================================
echo         AegisNet Cyber Defense Platform - Backend
echo ========================================================
echo.
cd /d "%~dp0"
echo Starting AegisNet FastAPI Backend on http://localhost:8001 ...
call .venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8001 --reload
pause

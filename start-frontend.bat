@echo off
title AegisNet Frontend Dev Server
echo ========================================================
echo         AegisNet Cyber Defense Platform - Frontend
echo ========================================================
echo.
cd /d "%~dp0frontend"
echo Starting Vite Dev Server on http://localhost:5173 ...
call npm.cmd run dev
pause

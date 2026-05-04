@echo off
title NexPent Vulnerable Test Server
color 0C

echo.
echo  ========================================================
echo   NexPent Vulnerable Test Server
echo   WARNING: DELIBERATELY VULNERABLE - TESTING ONLY
echo  ========================================================
echo.

cd /d "%~dp0"

:: Check if node_modules exists
if not exist "node_modules" (
    echo  [*] Installing dependencies...
    npm install
    echo.
)

echo  [*] Starting server on http://localhost:3001
echo  [*] Press Ctrl+C to stop
echo.

node server.js

pause

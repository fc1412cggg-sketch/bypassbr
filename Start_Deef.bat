@echo off
title Start Deef Cleanly
cd /d "%~dp0"
echo [*] Terminating any existing or hanging instances...
taskkill /f /im deef.exe >nul 2>&1
taskkill /f /im FdrrAutoPatcher.exe >nul 2>&1
taskkill /f /im MadiumLoader.exe >nul 2>&1
timeout /t 1 /nobreak >nul
echo [*] Starting deef.exe cleanly...
start "" "%~dp0deef.exe"
echo [✓] Done!

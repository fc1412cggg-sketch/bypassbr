@echo off
title Login Key Patcher
cd /d "%~dp0"

if not exist "LoginKeyPatcher.exe" (
    echo [!] LoginKeyPatcher.exe not found — run Build_LoginKeyPatcher.bat first.
    echo [*] Fallback: trying Python version...
    where python >nul 2>&1
    if %ERRORLEVEL%==0 (
        python login_key_patch.py any
        pause
    ) else (
        echo [!] Python not found either.
        pause
    )
    exit /b
)

:menu
cls
echo ==================================================
echo           LOGIN KEY PATCHER - select mode
echo ==================================================
echo   [1] ANY KEY   - type anything to enter main screen
echo   [2] AUTO      - skip login, straight to main screen
echo   [3] CUSTOM    - only your key works
echo   [4] RESTORE   - restore original bytes
echo   [0] Exit
echo ==================================================
set /p C=Select (1-4, 0):
if "%C%"=="1" goto any
if "%C%"=="2" goto auto
if "%C%"=="3" goto custom
if "%C%"=="4" goto restore
if "%C%"=="0" exit /b
goto menu

:any
LoginKeyPatcher.exe any
pause
goto menu

:auto
LoginKeyPatcher.exe auto
pause
goto menu

:custom
set /p K=Enter key:
set /p U=Enter username [VIP User]:
if "%U%"=="" set U=VIP User
LoginKeyPatcher.exe custom "%K%" "%U%"
pause
goto menu

:restore
LoginKeyPatcher.exe --restore
pause
goto menu

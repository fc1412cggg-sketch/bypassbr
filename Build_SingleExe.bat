@echo off
title Build Single EXE (bundle)
cd /d "%~dp0"
set OUT=PlayDeef.exe

if not exist "LoginKeyPatcher.exe" (
    echo [!] LoginKeyPatcher.exe not found in this folder.
    pause
    exit /b 1
)
if not exist "deef.exe" (
    echo [!] deef.exe not found in this folder.
    pause
    exit /b 1
)

echo [*] Bundling LoginKeyPatcher.exe + deef.exe into %OUT% ...
echo [*] This takes a few seconds (copying ~100 MB)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllBytes('LoginKeyPatcher.exe'); $d=[IO.File]::ReadAllBytes('deef.exe'); $f=New-Object byte[] 16; [BitConverter]::GetBytes([int64]$d.Length).CopyTo($f,0); [Text.Encoding]::ASCII.GetBytes('LKPBNDL1').CopyTo($f,8); $o=[IO.File]::Create('%OUT%'); $o.Write($s,0,$s.Length); $o.Write($d,0,$d.Length); $o.Write($f,0,16); $o.Close(); echo ('[+] bundle done: {0:N0} bytes' -f (Get-Item '%OUT%').Length)"
if errorlevel 1 (
    echo [!] Bundle failed.
    pause
    exit /b 1
)

echo [*] Smoke test: run bundle --help from a temp folder...
mkdir "%TEMP%\btest" 2>nul
copy /y "%OUT%" "%TEMP%\btest\" >nul
"%TEMP%\btest\%OUT%" --help >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [OK] %OUT% runs fine.
) else (
    echo [!] WARNING: bundle exe failed to run.
)
del /q "%TEMP%\btest\%OUT%" 2>nul

echo.
echo [OK] Done! From now on just double-click %OUT% (single file).
echo [i] First run extracts deef.exe next to it, later runs reuse it.
echo [i] You can still use modes: %OUT% any / auto / custom KEY / --diag
pause

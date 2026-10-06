@echo off
title Build LoginKeyPatcher
cd /d "%~dp0"

echo [*] Building LoginKeyPatcher.exe (x64)...

set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if exist "%CSC%" (
    "%CSC%" /platform:x64 /optimize+ /out:LoginKeyPatcher.exe LoginKeyPatcher.cs
    if %ERRORLEVEL%==0 (
        echo [OK] Build success: LoginKeyPatcher.exe
    ) else (
        echo [!] Build failed with csc.exe
    )
    pause
    exit /b
)

where dotnet >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [*] csc.exe not found, trying dotnet...
    if not exist build_tmp mkdir build_tmp
    copy /y LoginKeyPatcher.cs build_tmp\Program.cs >nul
    echo ^<Project Sdk="Microsoft.NET.Sdk"^>^<PropertyGroup^>^<OutputType^>Exe^</OutputType^>^<TargetFramework^>net8.0^</TargetFramework^>^<PlatformTarget^>x64^</PlatformTarget^>^<AssemblyName^>LoginKeyPatcher^</AssemblyName^>^</PropertyGroup^>^</Project^> > build_tmp\build.csproj
    dotnet build build_tmp\build.csproj -c Release -o .
    if %ERRORLEVEL%==0 echo [OK] Build success: LoginKeyPatcher.exe
    pause
    exit /b
)

echo [!] Not found: csc.exe / dotnet — install .NET Framework or .NET SDK first.
pause

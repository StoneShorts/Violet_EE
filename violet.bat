@echo off
setlocal enabledelayedexpansion
title Violet

REM ===========================================================================
REM  violet.bat  -  fetch, build and inject Violet in one go.
REM
REM  Launch GTA V Enhanced into Story Mode first, wait until you are actually
REM  standing in the world, then run this.
REM
REM  It will:
REM    1. check the tools it needs are installed
REM    2. clone Dear ImGui if it is missing
REM    3. configure CMake the first time
REM    4. build Violet.dll and inject.exe
REM    5. make sure GTA is running and not already injected
REM    6. inject
REM ===========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

REM Build outside the repo on purpose. This project usually lives in a synced
REM folder (OneDrive/Dropbox), and those sync engines lock .obj and .pdb files
REM while MSBuild is writing them, producing random build failures that are
REM impossible to reproduce. Source syncs; intermediates do not.
set "BUILD=%LOCALAPPDATA%\Violet\build"

set "TARGET=GTA5_Enhanced.exe"
set "BUILDLOG=%TEMP%\violet_build.log"

echo.
echo   ===========================================
echo     V I O L E T
echo     single-player mod menu - GTA V Enhanced
echo   ===========================================
echo.

REM --- 1. tools --------------------------------------------------------------
where cmake >nul 2>&1
if errorlevel 1 (
    echo   [X] cmake is not on your PATH.
    echo       Install CMake and tick "Add to PATH", then run this again.
    goto :fail
)

where git >nul 2>&1
if errorlevel 1 (
    echo   [X] git is not on your PATH.
    goto :fail
)

REM --- 2. dependency ---------------------------------------------------------
if not exist "%ROOT%\third_party\imgui\imgui.cpp" (
    echo   [*] Dear ImGui missing - cloning it...
    git clone --depth 1 -q https://github.com/ocornut/imgui.git "%ROOT%\third_party\imgui"
    if errorlevel 1 (
        echo   [X] clone failed - check your internet connection.
        goto :fail
    )
    echo   [+] Dear ImGui ready
)

REM --- 3. configure ----------------------------------------------------------
if not exist "%BUILD%\CMakeCache.txt" (
    echo   [*] first run - configuring CMake...
    echo       build directory: %BUILD%
    cmake -S "%ROOT%" -B "%BUILD%" -G "Visual Studio 17 2022" -A x64 >"%BUILDLOG%" 2>&1
    if errorlevel 1 (
        echo   [!] Visual Studio 2022 generator failed, trying the default...
        cmake -S "%ROOT%" -B "%BUILD%" -A x64 >"%BUILDLOG%" 2>&1
        if errorlevel 1 (
            echo   [X] CMake configure failed. Last few lines:
            echo.
            powershell -NoProfile -Command "Get-Content '%BUILDLOG%' -Tail 15 | ForEach-Object { '       ' + $_ }"
            echo.
            echo       Most likely cause: Visual Studio is installed without the
            echo       "Desktop development with C++" workload.
            goto :fail
        )
    )
    echo   [+] configured
)

REM --- 4. build --------------------------------------------------------------
echo   [*] building...
cmake --build "%BUILD%" --config Release >"%BUILDLOG%" 2>&1
if errorlevel 1 (
    echo   [X] build failed:
    echo.
    powershell -NoProfile -Command "Select-String -Path '%BUILDLOG%' -Pattern 'error' | Select-Object -First 12 | ForEach-Object { '       ' + $_.Line.Trim() }"
    echo.
    echo       Full log: %BUILDLOG%
    goto :fail
)

if not exist "%ROOT%\bin\Violet.dll" (
    echo   [X] build reported success but bin\Violet.dll is missing.
    goto :fail
)
echo   [+] built

REM --- 5. is the game running? ----------------------------------------------
tasklist /fi "imagename eq %TARGET%" 2>nul | find /i "%TARGET%" >nul
if errorlevel 1 (
    echo.
    echo   [X] %TARGET% is not running.
    echo.
    echo       Launch GTA V Enhanced into STORY MODE, wait until you are
    echo       actually standing in the world, then run this again.
    echo.
    echo       Also set Screen Type to BORDERLESS in the graphics settings.
    echo       Exclusive fullscreen bypasses the desktop compositor, and
    echo       nothing can be drawn on top of it.
    goto :fail
)

REM Injecting a second time would give you two overlays fighting over the same
REM hotkeys. Note we look for "Violet_" rather than "Violet.dll": the injector
REM loads a uniquely-named staged copy so that building never trips over a
REM locked file.
tasklist /m /fi "imagename eq %TARGET%" 2>nul | find /i "Violet_" >nul
if not errorlevel 1 (
    echo.
    echo   [!] Violet is already running inside GTA.
    echo       Open the menu and press "Unload Violet" twice, then run this again.
    goto :fail
)

REM --- 6. inject -------------------------------------------------------------
echo   [*] injecting into %TARGET%...
echo.
"%ROOT%\bin\inject.exe" %TARGET% "%ROOT%\bin\Violet.dll"
if errorlevel 1 (
    echo.
    echo   [X] injection failed - see the message above.
    echo.
    echo       If it says ACCESS_DENIED, the Rockstar launcher started GTA
    echo       elevated. Right-click violet.bat and "Run as administrator".
    goto :fail
)

echo.
echo   ===========================================
echo     Violet is in.
echo.
echo     END  or  PAGE UP ............ toggle menu
echo     D-pad LEFT + right trigger .. toggle menu
echo     D-pad / stick, A, B ......... navigate
echo.
echo     Violet unloads itself when GTA closes.
echo   ===========================================
echo.
echo   Log: %LOCALAPPDATA%\Violet\Violet.log
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1

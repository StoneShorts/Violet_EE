@echo off
setlocal enabledelayedexpansion
title Violet

REM ===========================================================================
REM  violet.bat  -  everything, in one go.
REM
REM  Launch GTA V Enhanced into Story Mode first, wait until you are actually
REM  standing in the world, then run this.
REM
REM    1. check the tools it needs are installed
REM    2. clone Dear ImGui if it is missing
REM    3. configure CMake the first time
REM    4. build Violet.dll and inject.exe
REM    5. set up Script Hook V (the native layer) if it is not there yet
REM    6. make sure GTA is running and not already injected
REM    7. inject
REM
REM  On step 5: this never DOWNLOADS anything. It will open the official page
REM  for you, then find the zip you downloaded and install the right two files
REM  out of it. Fetching an executable from a hardcoded mirror URL and dropping
REM  it into your game folder is fine right up until that mirror changes hands,
REM  so that one click stays yours.
REM ===========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

REM Build outside the repo on purpose. This project usually lives in a synced
REM folder, and sync engines lock .obj and .pdb files while MSBuild is writing
REM them, producing build failures that cannot be reproduced on demand.
set "BUILD=%LOCALAPPDATA%\Violet\build"

set "TARGET=GTA5_Enhanced.exe"
set "BUILDLOG=%TEMP%\violet_build.log"

echo.
echo   ===========================================
echo     V I O L E T
echo     single-player mod menu - GTA V Enhanced
echo   ===========================================
echo.

REM --- are we elevated? Needed only to write into Program Files -------------
net session >nul 2>&1
if errorlevel 1 (set "ADMIN=0") else (set "ADMIN=1")

REM --- where is the game? ---------------------------------------------------
set "GAMEDIR="
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\WOW6432Node\Rockstar Games\GTAV Enhanced" /v InstallFolder 2^>nul ^| find "InstallFolder"') do set "GAMEDIR=%%B"

if not defined GAMEDIR (
    if exist "C:\Program Files\Rockstar Games\Grand Theft Auto V Enhanced\%TARGET%" (
        set "GAMEDIR=C:\Program Files\Rockstar Games\Grand Theft Auto V Enhanced"
    )
)

REM --- 1. tools -------------------------------------------------------------
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

REM --- 2. dependency --------------------------------------------------------
if not exist "%ROOT%\third_party\imgui\imgui.cpp" (
    echo   [*] Dear ImGui missing - cloning it...
    git clone --depth 1 -q https://github.com/ocornut/imgui.git "%ROOT%\third_party\imgui"
    if errorlevel 1 (
        echo   [X] clone failed - check your internet connection.
        goto :fail
    )
    echo   [+] Dear ImGui ready
)

REM --- 3. configure ---------------------------------------------------------
if not exist "%BUILD%\CMakeCache.txt" (
    echo   [*] first run - configuring CMake...
    cmake -S "%ROOT%" -B "%BUILD%" -G "Visual Studio 17 2022" -A x64 >"%BUILDLOG%" 2>&1
    if errorlevel 1 (
        echo   [-] Visual Studio 2022 generator failed, trying the default...
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

REM --- 4. build -------------------------------------------------------------
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

REM --- 5. the native layer --------------------------------------------------
REM
REM Violet's overlay, scanner, dumper and probe all work without this. Only the
REM Self / Weapons / World / Lobby tabs need it, because those call into the
REM game's own scripting functions.
if not defined GAMEDIR (
    echo   [-] could not find the GTA install folder - skipping the native layer.
    goto :shv_done
)

if exist "%GAMEDIR%\ScriptHookV.dll" if exist "%GAMEDIR%\dinput8.dll" (
    echo   [+] native layer present
    goto :shv_done
)

echo.
echo   [-] Script Hook V is not installed - the cheat tabs will be disabled.
echo.

REM Look for a zip the user has already downloaded.
set "SHVZIP="
for /f "delims=" %%F in ('dir /b /o-d "%USERPROFILE%\Downloads\ScriptHookV*.zip" 2^>nul') do (
    if not defined SHVZIP set "SHVZIP=%USERPROFILE%\Downloads\%%F"
)

if not defined SHVZIP (
    echo       Opening the official download page. Get the version matching
    echo       your game build, leave the .zip in your Downloads folder, then
    echo       run this again - it will install it for you.
    echo.
    start "" "https://www.dev-c.com/gtav/scripthookv/"
    echo       Waiting for: %USERPROFILE%\Downloads\ScriptHookV*.zip
    echo.
    echo       ^(Violet still works without it - just no cheats.^)
    goto :shv_done
)

echo       Found: !SHVZIP!

if "%ADMIN%"=="0" (
    echo.
    echo   [X] Installing into "%GAMEDIR%" needs Administrator.
    echo       Right-click violet.bat and choose "Run as administrator",
    echo       then run it again. Everything else is already built.
    goto :fail
)

echo   [*] installing the native layer...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$tmp = Join-Path $env:TEMP ('shv_' + [guid]::NewGuid().ToString('N'));" ^
  "New-Item -ItemType Directory -Path $tmp | Out-Null;" ^
  "Expand-Archive -LiteralPath '!SHVZIP!' -DestinationPath $tmp -Force;" ^
  "$want = @('ScriptHookV.dll','dinput8.dll');" ^
  "$found = 0;" ^
  "foreach ($n in $want) {" ^
  "  $f = Get-ChildItem -Path $tmp -Filter $n -Recurse -File | Select-Object -First 1;" ^
  "  if ($f) { Copy-Item $f.FullName -Destination '%GAMEDIR%' -Force; $found++;" ^
  "            Write-Host ('       installed ' + $n) }" ^
  "  else { Write-Host ('       MISSING in the zip: ' + $n) } };" ^
  "Remove-Item $tmp -Recurse -Force;" ^
  "if ($found -ne $want.Count) { exit 1 }"

if errorlevel 1 (
    echo   [X] install failed - the zip did not contain what was expected.
    goto :fail
)

REM Deliberately NOT installing NativeTrainer.asi, which ships in the same zip.
REM It is a second trainer bound to F4 and would sit on top of Violet.
echo   [+] native layer installed
echo       Restart GTA for it to load, then run this again.
goto :shv_done

:shv_done

REM --- 6. is the game running? ---------------------------------------------
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

REM Injecting twice would give you two overlays fighting over the same hotkeys.
REM We look for "Violet_" because the injector loads a uniquely-named staged
REM copy, so building never trips over a locked file.
tasklist /m /fi "imagename eq %TARGET%" 2>nul | find /i "Violet_" >nul
if not errorlevel 1 (
    echo.
    echo   [-] Violet is already running inside GTA.
    echo       Open the menu and press "Unload Violet" twice, then run this again.
    goto :fail
)

REM --- 7. inject ------------------------------------------------------------
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

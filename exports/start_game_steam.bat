@echo off
setlocal
pushd "%~dp0"

REM ----- Konfiguration -----
set "STEAM_EXE=C:\Program Files (x86)\Steam\steam.exe"
set "APPID=39520"
set "GAME_NAME=Europa1400Gold.exe"
set "GAME_DIR=C:\Program Files (x86)\Steam\steamapps\common\Europa 1400 The Guild - Gold Edition"
set "GAME_PATH=%GAME_DIR%\%GAME_NAME%"
set "SERVER_DIR=%GAME_DIR%\server"
set "HOOK1=%SERVER_DIR%\server.dll"
set "HOOK2=%SERVER_DIR%\hook_kernel32.dll"
set "HOOK3=%SERVER_DIR%\hook_ws2_32.dll"
set "HOOK4=%SERVER_DIR%\hook_server.dll"
set "INJECTOR=%~dp0injector.exe"

echo Starte Steam mit -applaunch %APPID%...
start "" "%STEAM_EXE%" -applaunch %APPID%

echo.
echo Warte auf den Game-Prozess %GAME_NAME%...
:WAIT_LOOP
    tasklist /FI "IMAGENAME eq %GAME_NAME%" 2>NUL | find /I "%GAME_NAME%" >NUL
    if errorlevel 1 (
        timeout /t 1 >nul
        goto WAIT_LOOP
    )
for /f "tokens=2 delims=," %%P in (
    'tasklist /FI "IMAGENAME eq %GAME_NAME%" /FO CSV /NH'
) do set "PID=%%~P"

echo Gefunden: PID %PID%
echo Injiziere Hooks...
echo   %INJECTOR% %PID% "%HOOK1%" "%HOOK2%" "%HOOK3%" "%HOOK4%" 
"%INJECTOR%" %PID% "%HOOK1%" "%HOOK2%" "%HOOK3%" "%HOOK4%" 

pause
popd
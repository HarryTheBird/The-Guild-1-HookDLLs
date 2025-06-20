@echo off
setlocal
pushd "%~dp0"

REM ----- Konfiguration -----
set "GAME_NAME=Europa1400Gold.exe"
set "GAME_PATH=%~dp0%GAME_NAME%"
set "SERVER_DIR=%~dp0server"
set "HOOK1=%SERVER_DIR%\server.dll"
set "HOOK2=%SERVER_DIR%\hook_kernel32.dll"
set "HOOK3=%SERVER_DIR%\hook_ws2_32.dll"
set "HOOK4=%SERVER_DIR%\hook_server.dll"
set "INJECTOR=%~dp0injector.exe"

if not exist "%GAME_PATH%" (
    echo ERROR: Spiel-Exe nicht gefunden: "%GAME_PATH%"
    pause
    popd & exit /b 1
)

echo Starte Spiel direkt...
start "" "%GAME_PATH%"

echo.
echo Warte auf den Prozess %GAME_NAME%...
:WAIT_GAME
    tasklist /FI "IMAGENAME eq %GAME_NAME%" 2>NUL | find /I "%GAME_NAME%" >NUL
    if errorlevel 1 (
        timeout /t 1 >nul
        goto WAIT_GAME
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
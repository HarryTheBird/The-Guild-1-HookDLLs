@echo off
setlocal

REM ——————————————————————————————————————————————
REM (Optional) UAC-Elevation
net session >nul 2>&1
if %errorLevel% NEQ 0 (
  PowerShell -NoProfile -Command "Start-Process '%~f0' -Verb runAs"
  exit /b
)
REM ——————————————————————————————————————————————

pushd "%~dp0"

REM Pfad zur echten Spiel-EXE (wie sie im Task-Manager heißt)
set "GAMEEXE=%~dp0Europa1400Gold.exe"

REM Pfade zu den Hook-DLLs
set "HOOK1=%~dp0server\hook_kernel32.dll"
set "HOOK2=%~dp0server\hook_ws2_32.dll"

REM Pfad zum Injector im selben Ordner
set "INJECTOR=%~dp0injector.exe"

REM Existenzprüfungen
if not exist "%GAMEEXE%" (
  echo ERROR: Spiel-EXE nicht gefunden: "%GAMEEXE%"
  pause
  popd & exit /b 1
)
if not exist "%HOOK1%" (
  echo ERROR: Hook DLL nicht gefunden: "%HOOK1%"
  pause
  popd & exit /b 1
)
if not exist "%HOOK2%" (
  echo ERROR: Hook DLL nicht gefunden: "%HOOK2%"
  pause
  popd & exit /b 1
)
if not exist "%INJECTOR%" (
  echo ERROR: Injector nicht gefunden: "%INJECTOR%"
  pause
  popd & exit /b 1
)

REM Steam-Launcher starten
echo Starte Steam Launcher...
start "" /B "C:\Program Files (x86)\Steam\steam.exe" -applaunch 39520

REM Warten, bis Spiel-.exe im Task-Manager auftaucht
echo Warte auf den Game-Prozess Europa1400Gold.exe...
:WAIT_LOOP
for /f "tokens=2 delims=," %%P in ('
    tasklist /FI "IMAGENAME eq Europa1400Gold.exe" /FO CSV /NH
') do set "GAMEPID=%%~P"
if not defined GAMEPID (
    timeout /t 1 >nul
    goto WAIT_LOOP
)
echo Gefunden: Europa1400Gold.exe hat PID %GAMEPID%.

REM Injection in den echten Game-Prozess
echo Injezieren in PID %GAMEPID%...
"%INJECTOR%" "%GAMEPID%" "%HOOK1%" "%HOOK2%"
if errorlevel 1 (
  echo Fehler beim Injizieren!
  pause
  popd & exit /b 1
)

echo Injector beendet und das Spiel (PID %GAMEPID%) ist mit Hooks geladen! - Schliesse dieses CMD-Fenster bitte!
pause
popd
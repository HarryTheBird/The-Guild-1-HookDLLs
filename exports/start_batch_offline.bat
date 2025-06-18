@echo off
setlocal

REM ——————————————————————————————————————————————
REM (Optional) UAC-Elevation – entferne, wenn nicht nötig
net session >nul 2>&1
if %errorLevel% NEQ 0 (
  PowerShell -NoProfile -Command "Start-Process '%~f0' -Verb runAs"
  exit /b
)
REM ——————————————————————————————————————————————

pushd "%~dp0"

REM Pfad zur Stand-Alone Game-EXE
set "GAMEEXE=%~dp0Europa1400Gold.exe"

REM Pfade zu den Hook-DLLs im Unterordner „server“
set "HOOK1=%~dp0server\hook_kernel32.dll"
set "HOOK2=%~dp0server\hook_ws2_32.dll"

REM Pfad zum Injector
set "INJECTOR=%~dp0injector.exe"

REM Existenzprüfungen
if not exist "%GAMEEXE%" (
  echo ERROR: Spiel-Exe nicht gefunden: "%GAMEEXE%"
  pause
  popd & exit /b 1
)
if not exist "%HOOK1%" (
  echo ERROR: Hook1 nicht gefunden: "%HOOK1%"
  pause
  popd & exit /b 1
)
if not exist "%HOOK2%" (
  echo ERROR: Hook2 nicht gefunden: "%HOOK2%"
  pause
  popd & exit /b 1
)
if not exist "%INJECTOR%" (
  echo ERROR: Injector nicht gefunden: "%INJECTOR%"
  pause
  popd & exit /b 1
)

echo Starte das Spiel direkt mit Injector...
echo   Game:   "%GAMEEXE%"
echo   Hook1:  "%HOOK1%"
echo   Hook2:  "%HOOK2%"
echo.

REM Injector legt das Spiel im Suspended State an, injiziert beide Hooks und resümiert dann
"%INJECTOR%" "%GAMEEXE%" "%HOOK1%" "%HOOK2%"
if errorlevel 1 (
  echo Fehler beim Injizieren!
  pause
  popd & exit /b 1
)

echo Fertig und das Spiel läuft nun mit Deinen Hooks.
popd
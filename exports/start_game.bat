@echo off
REM Wechsel in das Verzeichnis dieser Batch-Datei
pushd "%~dp0"

REM Name der Spiel-EXE
set "GAME=Europa1400Gold_TL.exe"

REM Verzeichnis für die Hooks
set "DLLDIR=%~dp0server"

REM Vollständige Pfade der umbenannten Hook-DLLs
set "HOOK1=%DLLDIR%\hook_kernel32.dll"
set "HOOK2=%DLLDIR%\hook_ws2_32.dll"

REM Existenz prüfen
if not exist "%GAME%" (
  echo ERROR: Spiel-EXE "%GAME%" nicht gefunden!
  pause
  popd
  exit /b 1
)
if not exist "%HOOK1%" (
  echo ERROR: Hook-DLL "%HOOK1%" nicht gefunden!
  pause
  popd
  exit /b 1
)
if not exist "%HOOK2%" (
  echo ERROR: Hook-DLL "%HOOK2%" nicht gefunden!
  pause
  popd
  exit /b 1
)

echo Starte Spiel mit Injector...
echo   Spiel:   "%~dp0%GAME%"
echo   Hook 1:  "%HOOK1%"
echo   Hook 2:  "%HOOK2%"
echo.

REM Injector aufrufen: startet Game im Suspended State und injiziert beide DLLs
injector.exe "%~dp0%GAME%" "%HOOK1%" "%HOOK2%"
if errorlevel 1 (
  echo Fehler beim Injizieren!
  pause
  popd
  exit /b 1
)

echo Injector fertig — das Spiel sollte nun laufen.
popd

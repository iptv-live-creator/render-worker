@echo off
rem ShaherWorker update. Only touches %LOCALAPPDATA%\ShaherWorker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0update.ps1"
if errorlevel 1 (
  echo.
  echo Update did not finish. Read the red message above.
) else (
  echo.
  echo Update finished.
)
pause

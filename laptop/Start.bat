@echo off
rem ShaherWorker - Start. Installs if missing, otherwise updates, then starts. After this the worker updates itself (signed releases only).
rem Only touches %LOCALAPPDATA%\ShaherWorker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
if errorlevel 1 (
  echo.
  echo Start did not finish. Read the red message above and send a screenshot of this window.
) else (
  echo.
  echo Start finished.
)
pause

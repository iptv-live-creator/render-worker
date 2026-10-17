@echo off
rem Shaher worker - one-click install. No admin. Everything goes in %LOCALAPPDATA%\ShaherWorker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if errorlevel 1 (
  echo.
  echo Install did not finish. Read the red message above, then send a screenshot of this window.
) else (
  echo.
  echo Install finished.
)
pause

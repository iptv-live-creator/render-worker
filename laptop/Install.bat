@echo off
rem Shaher worker - one-click install. No admin. Everything goes in %LOCALAPPDATA%\ShaherWorker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause

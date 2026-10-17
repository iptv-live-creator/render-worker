@echo off
schtasks /End /TN ShaherWorker >nul 2>&1
schtasks /Delete /TN ShaherWorker /F >nul 2>&1
cd /d %TEMP%
rmdir /s /q "%LOCALAPPDATA%\ShaherWorker"
echo Removed. Nothing else was installed.
pause

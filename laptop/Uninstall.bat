@echo off
echo stop> "%LOCALAPPDATA%\ShaherWorker\STOP" 2>nul
schtasks /End /TN ShaherWorker >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '*\ShaherWorker\py\python.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
schtasks /Delete /TN ShaherWorker /F >nul 2>&1
cd /d %TEMP%
rmdir /s /q "%LOCALAPPDATA%\ShaherWorker"
echo Removed. Nothing else was installed.
pause

@echo off
rem Stops the ShaherWorker (launcher + worker). Only touches %LOCALAPPDATA%\ShaherWorker
echo stop> "%LOCALAPPDATA%\ShaherWorker\STOP"
schtasks /End /TN ShaherWorker >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '*\ShaherWorker\py\python.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
echo Worker stopped. Run Start.bat to start it again.
pause

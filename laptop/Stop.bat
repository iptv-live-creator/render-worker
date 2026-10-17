@echo off
schtasks /End /TN ShaherWorker
echo stop> "%LOCALAPPDATA%\ShaherWorker\STOP"
echo Worker stopped. Delete STOP file or re-run Install to start again.
pause

# Installs the worker into ONE folder, no admin, no keys inside this file.
param([string]$BotUrl = 'https://tg-assistant-bot-hazel.vercel.app', [string]$RootDir = '', [string]$Code = '', [switch]$NoTask)
$ErrorActionPreference = 'Stop'
try {
  if (-not [Environment]::Is64BitOperatingSystem) { throw 'This installer needs 64-bit Windows. This PC is 32-bit, nothing was installed.' }
  $Root = if ($RootDir) { $RootDir } else { Join-Path $env:LOCALAPPDATA 'ShaherWorker' }
  $Bot  = $BotUrl
  $PyUrl  = 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip'
  $PySha  = '009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b'
  $Enroll = if ($Code) { $Code } else { Get-Content (Join-Path $PSScriptRoot 'enroll.txt') -Raw }   # one-time code from the bot, expires in 1 hour
  New-Item -ItemType Directory -Force -Path $Root | Out-Null
  Start-Transcript -Path (Join-Path $Root 'install.log') -Append | Out-Null
  $zip = Join-Path $Root 'py.zip'
  Invoke-WebRequest $PyUrl -OutFile $zip
  if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $PySha) { throw 'Python hash mismatch, stopping.' }
  Expand-Archive $zip -DestinationPath (Join-Path $Root 'py') -Force; Remove-Item $zip
  # allow site-packages in embeddable python
  $pth = Get-ChildItem (Join-Path $Root 'py') -Filter 'python*._pth' | Select-Object -First 1
  (Get-Content $pth.FullName) -replace '#import site','import site' | Set-Content $pth.FullName
  Remove-Item (Join-Path $Root 'STOP') -ErrorAction SilentlyContinue   # re-install after Stop.bat must start again
  Copy-Item (Join-Path $PSScriptRoot 'worker.py') (Join-Path $Root 'worker.py') -Force
  Copy-Item (Join-Path $PSScriptRoot 'Stop.bat') (Join-Path $Root 'Stop.bat') -Force
  Copy-Item (Join-Path $PSScriptRoot 'Uninstall.bat') (Join-Path $Root 'Uninstall.bat') -Force
  $py = Join-Path $Root 'py\python.exe'
  # worker.py itself installs pip + pinned deps on first run (see requirements in worker.py), then enrolls with the code
  & $py (Join-Path $Root 'worker.py') --enroll $Enroll --bot $Bot --root $Root
  if ($NoTask) { Write-Host 'NoTask: installed and enrolled, scheduled task skipped (CI).'; Stop-Transcript | Out-Null; exit 0 }
  # start at login, current user only (no admin)
  $act = New-ScheduledTaskAction -Execute $py -Argument ('"' + (Join-Path $Root 'worker.py') + '" --run --bot ' + $Bot + ' --root "' + $Root + '"')
  $trg = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  Register-ScheduledTask -TaskName 'ShaherWorker' -Action $act -Trigger $trg -Force | Out-Null
  Start-ScheduledTask -TaskName 'ShaherWorker'
  Write-Host 'Done. Worker is running. Log: ' (Join-Path $Root 'worker.log')
  Stop-Transcript | Out-Null

} catch {
  Write-Host ''
  Write-Host ('INSTALL FAILED: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host ('Details are in: ' + (Join-Path $Root 'install.log'))
  Write-Host 'Nothing was changed outside that folder. You can run Uninstall.bat to remove it.'
  exit 1
}
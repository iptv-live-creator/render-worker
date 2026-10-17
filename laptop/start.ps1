# Idempotent: install if missing (needs enroll.txt next to this file), otherwise update; then run under the launcher. Touches ONLY the ShaherWorker folder + its own scheduled task.
param([string]$BotUrl = 'https://tg-assistant-bot-hazel.vercel.app', [string]$RootDir = '', [string]$Code = '', [switch]$NoTask)
$ErrorActionPreference = 'Stop'
$Root = if ($RootDir) { $RootDir } else { Join-Path $env:LOCALAPPDATA 'ShaherWorker' }
try {
  New-Item -ItemType Directory -Force -Path $Root | Out-Null
  Start-Transcript -Path (Join-Path $Root 'start.log') -Append | Out-Null
  if (-not (Test-Path (Join-Path $Root 'token'))) {
    if (-not $Code -and -not (Test-Path (Join-Path $PSScriptRoot 'enroll.txt'))) { throw 'Not installed here and no enroll.txt next to Start.bat. Nothing was changed.' }
    Write-Host 'Not installed yet: installing first.'
    & (Join-Path $PSScriptRoot 'install.ps1') -BotUrl $BotUrl -Code $Code -RootDir $Root -NoTask
    if ($LASTEXITCODE -ne 0) { throw 'install step failed' }
  }
  if (-not $NoTask) { Stop-ScheduledTask -TaskName 'ShaherWorker' -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -like (Join-Path $Root 'py\python.exe') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  foreach ($f in 'worker.py','ed25519_verify.py','launcher.py','Stop.bat','Uninstall.bat') { Copy-Item (Join-Path $PSScriptRoot $f) (Join-Path $Root $f) -Force }
  $seqf = Join-Path $Root 'update_seq'
  $cur = 0; if (Test-Path $seqf) { try { $cur = [int](Get-Content $seqf -Raw) } catch { $cur = 0 } }
  if ($cur -lt 1) { Set-Content -Path $seqf -Value '1' -NoNewline }
  foreach ($f in 'pending.json','healthy.json') { Remove-Item (Join-Path $Root $f) -ErrorAction SilentlyContinue }
  $ffexe = Join-Path $Root 'ffmpeg\bin\ffmpeg.exe'
  if (-not (Test-Path $ffexe)) {
    $FfUrl = 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-essentials_build.zip'
    $FfSha = '60f467265b1e312373dbcd92200c2618a74850f98d3d078e94296bb3fa2047ba'
    Write-Host 'Downloading official ffmpeg build (about 110 MB), please wait...'
    $zip = Join-Path $Root 'ffmpeg.zip'
    Invoke-WebRequest $FfUrl -OutFile $zip
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $FfSha) { Remove-Item $zip -Force; throw 'ffmpeg download hash mismatch, stopped.' }
    $tmp = Join-Path $Root 'ffmpeg_tmp'; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip -DestinationPath $tmp -Force; Remove-Item $zip -Force
    $bin = Get-ChildItem $tmp -Recurse -Filter 'ffmpeg.exe' | Select-Object -First 1
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'ffmpeg\bin') | Out-Null
    Copy-Item $bin.FullName $ffexe -Force; Remove-Item $tmp -Recurse -Force
  }
  Remove-Item (Join-Path $Root 'STOP') -ErrorAction SilentlyContinue
  $py = Join-Path $Root 'py\python.exe'
  if ($NoTask) { Write-Host 'NoTask: files in place (CI).'; Stop-Transcript | Out-Null; exit 0 }
  $act = New-ScheduledTaskAction -Execute $py -Argument ('"' + (Join-Path $Root 'launcher.py') + '" --bot ' + $BotUrl + ' --root "' + $Root + '"')
  $trg = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  Register-ScheduledTask -TaskName 'ShaherWorker' -Action $act -Trigger $trg -Force | Out-Null
  Start-ScheduledTask -TaskName 'ShaherWorker'
  $ok = $false
  for ($i = 0; $i -lt 60; $i++) { Start-Sleep -Seconds 1; if (Test-Path (Join-Path $Root 'healthy.json')) { $ok = $true; break } }
  if (-not $ok) { throw 'Worker started but did not connect within 60 s. Check worker.log in the ShaherWorker folder.' }
  Write-Host 'Done. Worker v2 is running and connected. From now on it updates itself. Log: ' (Join-Path $Root 'worker.log')
  Stop-Transcript | Out-Null
} catch {
  Write-Host ''
  Write-Host ('START FAILED: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host 'Your enrollment was not removed.'
  exit 1
}

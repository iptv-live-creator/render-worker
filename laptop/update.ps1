# Updates ONLY the ShaherWorker folder: new worker.py + official ffmpeg (hash-checked). Keeps your enrollment. Does not touch anything else.
param([string]$RootDir = '', [switch]$NoTask)
$ErrorActionPreference = 'Stop'
$Root = if ($RootDir) { $RootDir } else { Join-Path $env:LOCALAPPDATA 'ShaherWorker' }
try {
  if (-not (Test-Path (Join-Path $Root 'token'))) { throw 'ShaherWorker is not installed here (no enrollment found). Nothing was changed.' }
  Start-Transcript -Path (Join-Path $Root 'update.log') -Append | Out-Null
  $FfUrl = 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-essentials_build.zip'
  $FfSha = '60f467265b1e312373dbcd92200c2618a74850f98d3d078e94296bb3fa2047ba'
  if (-not $NoTask) { Stop-ScheduledTask -TaskName 'ShaherWorker' -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
  Copy-Item (Join-Path $PSScriptRoot 'worker.py') (Join-Path $Root 'worker.py') -Force
  $ffexe = Join-Path $Root 'ffmpeg\bin\ffmpeg.exe'
  if (-not (Test-Path $ffexe)) {
    Write-Host 'Downloading official ffmpeg build (about 110 MB), please wait...'
    $zip = Join-Path $Root 'ffmpeg.zip'
    Invoke-WebRequest $FfUrl -OutFile $zip
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $FfSha) { Remove-Item $zip -Force; throw 'ffmpeg download hash mismatch, stopped. Nothing was installed.' }
    $tmp = Join-Path $Root 'ffmpeg_tmp'; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip -DestinationPath $tmp -Force; Remove-Item $zip -Force
    $bin = Get-ChildItem $tmp -Recurse -Filter 'ffmpeg.exe' | Select-Object -First 1
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'ffmpeg\bin') | Out-Null
    Copy-Item $bin.FullName $ffexe -Force
    Remove-Item $tmp -Recurse -Force
  }
  Remove-Item (Join-Path $Root 'STOP') -ErrorAction SilentlyContinue
  if (-not $NoTask) { Start-ScheduledTask -TaskName 'ShaherWorker' }
  Write-Host 'Update done. Worker v1 is running. Log: ' (Join-Path $Root 'worker.log')
  Stop-Transcript | Out-Null
} catch {
  Write-Host ''
  Write-Host ('UPDATE FAILED: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host 'Your old worker files were not removed. Send a screenshot of this window.'
  exit 1
}

$ErrorActionPreference = 'Stop'

$sdkRoot = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$downloadRoot = Join-Path $env:TEMP 'GatePass-Android-sdk-tools-15859902'
$archiveDir = Join-Path $downloadRoot 'archive'
$extractDir = Join-Path $downloadRoot 'extract'
$archivePath = Join-Path $archiveDir 'commandlinetools-win-15859902_latest.zip'
$downloadUrl = 'https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip'
$expectedSha256 = '90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a'

if (Test-Path $downloadRoot) {
  throw "Refusing to reuse existing download directory: $downloadRoot"
}
if (Test-Path $sdkRoot) {
  $existing = Get-ChildItem -Force $sdkRoot -ErrorAction SilentlyContinue
  if ($existing) { throw "Refusing to overwrite existing Android SDK directory: $sdkRoot" }
}

New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
if (-not (Test-Path $sdkRoot)) { New-Item -ItemType Directory -Path $sdkRoot -Force | Out-Null }

Write-Host "Downloading official Android command-line tools to $archivePath"
Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
$actualSha256 = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
  throw "SHA-256 mismatch for Android command-line tools. Expected $expectedSha256; got $actualSha256"
}
Write-Host 'Archive checksum verified.'

Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir
$source = Join-Path $extractDir 'cmdline-tools'
if (-not (Test-Path (Join-Path $source 'bin\sdkmanager.bat'))) {
  throw "Unexpected Android command-line tools archive layout: $source"
}
$cmdlineRoot = Join-Path $sdkRoot 'cmdline-tools'
$latestDir = Join-Path $cmdlineRoot 'latest'
New-Item -ItemType Directory -Path $latestDir -Force | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $latestDir -Recurse -Force

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$sdkManager = Join-Path $latestDir 'bin\sdkmanager.bat'
Write-Host 'Android SDK licenses will be presented for review in this terminal.'
& $sdkManager "--sdk_root=$sdkRoot" '--licenses'
if ($LASTEXITCODE -ne 0) { throw "sdkmanager --licenses failed with exit code $LASTEXITCODE" }

Write-Host 'Installing Android platform 36, build-tools 36.0.0, and platform-tools.'
& $sdkManager "--sdk_root=$sdkRoot" 'platforms;android-36' 'build-tools;36.0.0' 'platform-tools'
if ($LASTEXITCODE -ne 0) { throw "sdkmanager component installation failed with exit code $LASTEXITCODE" }

Write-Host "Android SDK installation complete: $sdkRoot"

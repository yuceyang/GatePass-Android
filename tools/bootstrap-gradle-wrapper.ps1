$ErrorActionPreference = 'Stop'

$downloadRoot = Join-Path $env:TEMP 'GatePass-Android-gradle-8.13'
$archiveDir = Join-Path $downloadRoot 'archive'
$extractDir = Join-Path $env:TEMP 'GatePass-Android-gradle-8.13-verified-extract'
$archivePath = Join-Path $archiveDir 'gradle-8.13-bin.zip'
$distributionUrl = 'https://downloads.gradle.org/distributions/gradle-8.13-bin.zip'
$expectedSha256 = '20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78'
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path $archivePath)) {
  if (Test-Path $downloadRoot) { throw "Refusing to reuse existing Gradle download directory: $downloadRoot" }
  New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
  Invoke-WebRequest -Uri $distributionUrl -OutFile $archivePath -UseBasicParsing
}
if (Test-Path $extractDir) { throw "Refusing to reuse existing extraction directory: $extractDir" }
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
$actualSha256 = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
  throw "SHA-256 mismatch for Gradle distribution. Expected $expectedSha256; got $actualSha256"
}
Write-Host 'Gradle distribution checksum verified against downloads.gradle.org.'
Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir
$gradle = Join-Path $extractDir 'gradle-8.13\bin\gradle.bat'
if (-not (Test-Path $gradle)) { throw "Gradle executable missing from verified archive: $gradle" }
Set-Location $projectRoot
& $gradle 'wrapper' '--gradle-version' '8.13' '--distribution-type' 'bin'
if ($LASTEXITCODE -ne 0) { throw "Gradle wrapper task failed with exit code $LASTEXITCODE" }
Write-Host "Gradle wrapper created in $projectRoot"

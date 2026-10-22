$ErrorActionPreference = 'Stop'

$downloadRoot = Join-Path $env:TEMP 'GatePass-Android-hev-tun2socks-2.19.1-gh'
$archiveDir = Join-Path $downloadRoot 'archive'
$archivePath = Join-Path $archiveDir 'hev-socks5-tunnel.aar'
$destination = Join-Path $PSScriptRoot '..\app\libs\hev-socks5-tunnel-2.19.1.aar'
$expectedSha256 = '107958f7a07051386248ba8dba778b63d8dcefdfb2c3665b0ee9a8c93de5f6ca'

if (Test-Path $downloadRoot) { throw "Refusing to reuse existing download directory: $downloadRoot" }
if (Test-Path $destination) { throw "Refusing to overwrite existing library: $destination" }
New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
& gh release download 2.19.1 --repo heiher/hev-socks5-tunnel --pattern hev-socks5-tunnel.aar --dir $archiveDir
if ($LASTEXITCODE -ne 0) { throw "GitHub release download failed with exit code $LASTEXITCODE" }
$actualSha256 = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
  throw "SHA-256 mismatch for HEV AAR. Expected $expectedSha256; got $actualSha256"
}
Copy-Item -LiteralPath $archivePath -Destination $destination
Write-Host "Verified and installed HEV SOCKS5 tunnel AAR at $destination"

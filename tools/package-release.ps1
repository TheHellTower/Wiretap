<#
.SYNOPSIS
    Assembles a Wiretap release archive from already signed build outputs.

.DESCRIPTION
    Expects tools\build-driver.ps1 to have produced target\driver-package (signed) and builds
    wiretap.exe in release mode. Optionally Authenticode-signs wiretap.exe, then writes
    target\release-package\wiretap-<version>-x64.zip plus SHA256SUMS.txt.

.PARAMETER CertThumbprint
    Code-signing certificate (Cert:\CurrentUser\My) used for wiretap.exe. Omit for lab builds.

.PARAMETER IncludeTestCertificate
    Adds target\WiretapTestSigning.cer (lab packages with a test-signed driver only).

.PARAMETER Label
    Appended to the archive name, e.g. -unsigned for CI drafts awaiting signing.
#>
param(
    [string]$CertThumbprint,
    [string]$TimestampUrl,
    [switch]$IncludeTestCertificate,
    [string]$Label = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches.Groups[1].Value
$driver = Join-Path $root 'target\driver-package'
foreach ($f in 'WiretapDriver.sys', 'WiretapDriver.inf', 'wiretapdriver.cat') {
    if (-not (Test-Path (Join-Path $driver $f))) { throw "missing ${f}: run tools\build-driver.ps1 first" }
}

Push-Location $root
try {
    $ErrorActionPreference = 'Continue'
    cargo build --release --locked -p wiretap-cli 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    $ErrorActionPreference = 'Stop'
} finally { Pop-Location }

$stage = Join-Path $root "target\release-package\wiretap-$version-x64$Label"
Remove-Item (Split-Path $stage) -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory (Join-Path $stage 'driver') | Out-Null
Copy-Item (Join-Path $root 'target\release\wiretap.exe') $stage
Copy-Item (Join-Path $driver 'WiretapDriver.sys'), (Join-Path $driver 'WiretapDriver.inf'), (Join-Path $driver 'wiretapdriver.cat') (Join-Path $stage 'driver')
Copy-Item (Join-Path $root 'README.md'), (Join-Path $root 'SETUP.md'), (Join-Path $root 'SECURITY.md') $stage
# wiretap.exe links Microsoft's WebView2 loader (BSD-3-Clause): ship its license and notice.
$sdk = (Get-Content (Join-Path $root 'tools\webview2-sdk.txt') | Select-Object -First 1).Trim()
$licenses = Join-Path $stage 'third-party'
New-Item -ItemType Directory $licenses | Out-Null
foreach ($n in 'LICENSE.txt', 'NOTICE.txt') {
    $src = Join-Path $root "target\webview2\$sdk\$n"
    if (-not (Test-Path $src)) { throw "missing ${src}: run tools\fetch-webview2.ps1 first" }
    Copy-Item $src (Join-Path $licenses "WebView2-$n")
}
# The Brotli dictionary and tables in wiretap-codec are RFC 7932 Code Components.
Copy-Item (Join-Path $root 'crates\wiretap-codec\RFC7932-NOTICE.txt') $licenses
if ($IncludeTestCertificate) { Copy-Item (Join-Path $root 'target\WiretapTestSigning.cer') $stage }

if ($CertThumbprint) {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $signtool = Get-ChildItem $kits -Recurse -Filter signtool.exe | Where-Object FullName -like '*\x64\*' | Select-Object -Last 1
    $sign = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $CertThumbprint)
    if ($TimestampUrl) { $sign += @('/tr', $TimestampUrl, '/td', 'SHA256') }
    & $signtool.FullName @sign (Join-Path $stage 'wiretap.exe')
    if ($LASTEXITCODE -ne 0) { throw 'signing wiretap.exe failed' }
}

$zip = "$stage.zip"
Compress-Archive -Path "$stage\*" -DestinationPath $zip
$sums = Get-ChildItem $stage -Recurse -File | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring($stage.Length + 1)
}
$sums += '{0}  {1}' -f (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower(), (Split-Path $zip -Leaf)
$sums | Set-Content -Encoding ascii (Join-Path (Split-Path $stage) 'SHA256SUMS.txt')
Write-Host "Release archive: $zip"

<#
.SYNOPSIS
    Builds, verifies and signs the WiretapDriver package (WiretapDriver.sys/.inf/.cat/.pdb).

.DESCRIPTION
    1. Checks the hand-written FFI layouts against the installed WDK headers (driver/layout_check.c).
    2. Builds the driver (release, locked dependencies).
    3. Stages the package, stamps the INF version and validates it with infverif /w.
    4. Signs the driver, generates the catalog with Inf2Cat and signs the catalog.

    Requires: Rust toolchain, Visual Studio 2022 C++ build tools, WDK 10.0.26100.

.PARAMETER CertThumbprint
    SHA-1 thumbprint of a code-signing certificate in Cert:\CurrentUser\My.

.PARAMETER NewTestCert
    Creates a self-signed *test* signing certificate (lab machines in test-signing mode only)
    and exports its public part as WiretapTestSigning.cer next to the package.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server (recommended for production signatures).

.EXAMPLE
    .\tools\build-driver.ps1 -NewTestCert
#>
[CmdletBinding()]
param(
    [string]$CertThumbprint,
    [switch]$NewTestCert,
    [string]$Version = '0.2.0.0',
    [string]$TimestampUrl
)
$ErrorActionPreference = 'Stop'

# Native tools report progress on stderr; judge them by exit code only (PowerShell 5.1 would
# otherwise turn every stderr line into a terminating error).
function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path $Exe -Leaf) failed with exit code $LASTEXITCODE" }
}

$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'target\driver-package'
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$kitVersion = Get-ChildItem (Join-Path $kits 'Include') -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'km\fwpsk.h') } |
    Sort-Object { [version]$_.Name } | Select-Object -Last 1 -ExpandProperty Name
if (-not $kitVersion) { throw 'Windows Driver Kit not found (install WDK 10.0.26100).' }
$bin = Join-Path $kits "bin\$kitVersion"
$include = Join-Path $kits "Include\$kitVersion"

Write-Host "== FFI layout check against WDK $kitVersion"
$vs = & (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe') -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$check = Join-Path $root 'driver\layout_check.c'
$ErrorActionPreference = 'Continue'
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /Zs /kernel /W4 /WX /D_AMD64_ /I`"$include\km`" /I`"$include\shared`" /I`"$include\km\crt`" `"$check`""
if ($LASTEXITCODE -ne 0) { throw 'FFI layout check failed: src/ffi.rs no longer matches the WDK headers.' }
$ErrorActionPreference = 'Stop'

Write-Host '== Building driver'
Push-Location (Join-Path $root 'driver')
try { Invoke-Checked cargo @('build', '--release', '--locked') } finally { Pop-Location }

Write-Host "== Staging package in $out"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $out | Out-Null
$built = Join-Path $root 'driver\target\release'
Copy-Item (Join-Path $built 'wiretap_driver.dll') (Join-Path $out 'WiretapDriver.sys')
Copy-Item (Join-Path $built 'wiretap_driver.pdb') (Join-Path $out 'WiretapDriver.pdb')
Copy-Item (Join-Path $root 'driver\WiretapDriver.inf') $out
$inf = Join-Path $out 'WiretapDriver.inf'
Invoke-Checked (Join-Path $bin 'x64\stampinf.exe') @('-f', $inf, '-d', '*', '-v', $Version, '-a', 'amd64')
Invoke-Checked (Join-Path $kits "Tools\$kitVersion\x64\infverif.exe") @('/w', $inf)

if ($NewTestCert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Wiretap Test Driver Signing (lab only)' `
        -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(1)
    $CertThumbprint = $cert.Thumbprint
    Export-Certificate -Cert $cert -FilePath (Join-Path $root 'target\WiretapTestSigning.cer') | Out-Null
    Write-Host "Created test certificate $CertThumbprint (public part: target\WiretapTestSigning.cer)"
}
if (-not $CertThumbprint) {
    Write-Warning 'No signing certificate given: the package is built but unsigned.'
    return
}

Write-Host '== Signing'
$signtool = Join-Path $bin 'x64\signtool.exe'
$sign = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $CertThumbprint)
if ($TimestampUrl) { $sign += @('/tr', $TimestampUrl, '/td', 'SHA256') }
Invoke-Checked $signtool ($sign + (Join-Path $out 'WiretapDriver.sys'))
Invoke-Checked (Join-Path $bin 'x86\Inf2Cat.exe') @("/driver:$out", '/os:10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64')
Invoke-Checked $signtool ($sign + (Join-Path $out 'WiretapDriver.cat'))

# A lab test certificate is not trusted on the build machine, so Windows reports the
# signature status as "UnknownError"/"NotTrusted": expected, not a failure. Only an unsigned
# file or a different signer is an error. The raw status is shown with -Verbose.
Get-ChildItem $out -Include *.sys, *.cat -Recurse | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName
    Write-Verbose ("{0}: {1} ({2})" -f $_.Name, $s.Status, $s.StatusMessage)
    if (-not $s.SignerCertificate -or $s.SignerCertificate.Thumbprint -ne $CertThumbprint) {
        throw "$($_.Name) is not signed with $CertThumbprint"
    }
    $how = if ($s.Status -eq 'Valid') { 'signed (trusted here)' } else { 'signed with the test certificate (trusted only on test machines)' }
    Write-Host ("{0,-20} {1}" -f $_.Name, $how)
}
Write-Host "Package ready: $out"

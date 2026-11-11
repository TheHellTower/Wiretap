<#
.SYNOPSIS
Fetches Microsoft's official WebView2 SDK (Microsoft.Web.WebView2 on nuget.org) and extracts the
static loader that wiretap.exe links, so no WebView2 DLL ships with Wiretap.

.DESCRIPTION
Version and SHA-512 are pinned in tools/webview2-sdk.txt (the build reads the same file). The
package is rejected unless its hash matches. Output: target/webview2/<version>/ with the x64
WebView2LoaderStatic.lib and the SDK's LICENSE.txt / NOTICE.txt (BSD-3-Clause, shipped with
releases).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version, $sha512 = Get-Content (Join-Path $PSScriptRoot 'webview2-sdk.txt') | Where-Object { $_.Trim() }
$dest = Join-Path $root "target\webview2\$version"
if (Test-Path (Join-Path $dest 'x64\WebView2LoaderStatic.lib')) { "WebView2 SDK $version ready: $dest"; return }

$tmp = Join-Path ([IO.Path]::GetTempPath()) "wiretap-webview2-$([guid]::NewGuid())"
New-Item -ItemType Directory $tmp | Out-Null
try {
    $nupkg = Join-Path $tmp 'sdk.nupkg'
    $url = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$version/microsoft.web.webview2.$version.nupkg"
    Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing
    $sha = [Security.Cryptography.SHA512]::Create()
    $stream = [IO.File]::OpenRead($nupkg)
    try { $actual = [Convert]::ToBase64String($sha.ComputeHash($stream)) } finally { $stream.Dispose() }
    if ($actual -ne $sha512) { throw "WebView2 SDK $version hash mismatch (got $actual)" }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    New-Item -ItemType Directory -Force (Join-Path $dest 'x64') | Out-Null
    $zip = [IO.Compression.ZipFile]::OpenRead($nupkg)
    try {
        $wanted = @{ 'build/native/x64/WebView2LoaderStatic.lib' = 'x64\WebView2LoaderStatic.lib'; 'LICENSE.txt' = 'LICENSE.txt'; 'NOTICE.txt' = 'NOTICE.txt' }
        foreach ($entry in $zip.Entries) {
            if ($wanted.ContainsKey($entry.FullName)) {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $dest $wanted[$entry.FullName]), $true)
            }
        }
    } finally { $zip.Dispose() }
    if (-not (Test-Path (Join-Path $dest 'x64\WebView2LoaderStatic.lib'))) { throw 'WebView2LoaderStatic.lib not found in the package' }
    "WebView2 SDK $version verified and extracted to $dest"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

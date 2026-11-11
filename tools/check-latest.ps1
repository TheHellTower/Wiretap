<#
.SYNOPSIS
Fails when any crate in a Cargo.lock is not the newest stable release on crates.io.

.DESCRIPTION
Queries the crates.io sparse index (no API token, no modules). An outdated crate is tolerated
only when cargo proves the upgrade impossible because a dependent (itself at its newest version)
requires the older release. Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
.\tools\check-latest.ps1 Cargo.lock fuzz\Cargo.lock driver\Cargo.lock
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$LockFile = @('Cargo.lock')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-IndexPath([string]$Name) {
    $n = $Name.ToLowerInvariant()
    if ($n.Length -le 2) { return "$($n.Length)/$n" }
    if ($n.Length -eq 3) { return "3/$($n[0])/$n" }
    "$($n.Substring(0, 2))/$($n.Substring(2, 2))/$n"
}

# Major.minor.patch as a comparable [version]; build metadata ignored.
function Get-VersionKey([string]$Version) {
    $parts = @([regex]::Matches(($Version -split '\+')[0], '\d+') | Select-Object -First 3 | ForEach-Object { [int]$_.Value })
    while ($parts.Count -lt 3) { $parts += 0 }
    [version]::new($parts[0], $parts[1], $parts[2])
}

function Get-Latest([string]$Name) {
    $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -UserAgent 'wiretap-dependency-check' `
        -Uri ('https://index.crates.io/' + (Get-IndexPath $Name))
    $text = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
    $stable = foreach ($line in $text -split "`n") {
        if (-not $line.Trim()) { continue }
        $entry = $line | ConvertFrom-Json
        if (-not $entry.yanked -and -not ($entry.vers -split '\+')[0].Contains('-')) { $entry.vers }
    }
    $stable | Sort-Object { Get-VersionKey $_ } | Select-Object -Last 1
}

# Asks cargo whether the lock file could move to $Newest (dry run, nothing is written).
function Test-Upgradable([string]$Lock, [string]$Name, [string]$Current, [string]$Newest) {
    $ErrorActionPreference = 'Continue'   # cargo writes progress to stderr
    $manifest = Join-Path (Split-Path -Parent (Resolve-Path $Lock)) 'Cargo.toml'
    $null = & cargo update --manifest-path $manifest --dry-run -p "$Name@$Current" --precise $Newest 2>&1
    $LASTEXITCODE -eq 0
}

$seen = @{}
$outdated = [Collections.Generic.List[string]]::new()
foreach ($lock in $LockFile) {
    $blocks = (Get-Content -Raw -LiteralPath $lock) -split '(?m)^\[\[package\]\]\s*$' | Select-Object -Skip 1
    foreach ($block in $blocks) {
        $field = { param($key) [regex]::Match($block, "(?m)^$key = `"([^`"]+)`"").Groups[1].Value }
        $name = & $field 'name'
        $version = & $field 'version'
        if (-not (& $field 'source').StartsWith('registry+') -or $seen.ContainsKey("$name@$version")) { continue }
        $seen["$name@$version"] = $true
        $newest = Get-Latest $name
        if ((Get-VersionKey $version) -ge (Get-VersionKey $newest)) { continue }
        $entry = "$name $version -> $newest ($lock)"
        if (Test-Upgradable $lock $name $version $newest) {
            $outdated.Add($entry)
        } else {
            Write-Output "CONSTRAINED $entry - required by a dependent; recheck when it updates"
        }
    }
}
foreach ($line in $outdated) { Write-Output "OUTDATED $line" }
Write-Output "checked $($seen.Count) crates, $($outdated.Count) outdated"
exit ([int]($outdated.Count -gt 0))

<#
.SYNOPSIS
    Headless end-to-end test of Wiretap and WiretapDriver in a Hyper-V lab VM.

.DESCRIPTION
    Runs entirely over PowerShell Direct (no console window):
      1. Restores the clean checkpoint and starts the VM.
      2. Copies the test-signed driver package, its test certificate and wiretap.exe.
      3. Enables test signing and Driver Verifier (standard checks) for WiretapDriver.sys,
         then reboots the VM.
      4. Trusts the test certificate, installs the package with pnputil.
      5. Runs `wiretap --headless capture --duration` while generating HTTP and HTTPS traffic.
      6. Verifies the driver is unloaded again, collects flows/events, checks for bugchecks.
      7. Copies results to target\vm-test\ on the host.
    Lab use only: test signing is never enabled on the host or on user machines.

.PARAMETER VMName
    Lab VM (Generation 2, Secure Boot off so test signing can be enabled).

.PARAMETER Credential
    Administrator account inside the VM.

.PARAMETER Checkpoint
    Checkpoint restored before the test (default: clean-before-wiretap).

.EXAMPLE
    .\tools\vm-test.ps1 -VMName 'Windows 11 dev environment' -Credential (Get-Credential)
#>
param(
    [Parameter(Mandatory)] [string]$VMName,
    [Parameter(Mandatory)] [pscredential]$Credential,
    [string]$Checkpoint = 'clean-before-wiretap',
    [int]$Duration = 30
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$results = Join-Path $root 'target\vm-test'
$package = Join-Path $root 'target\driver-package'
$files = @(
    (Join-Path $package 'WiretapDriver.sys'), (Join-Path $package 'WiretapDriver.inf'),
    (Join-Path $package 'wiretapdriver.cat'), (Join-Path $root 'target\WiretapTestSigning.cer'),
    (Join-Path $root 'target\release\wiretap.exe')
)
foreach ($f in $files) { if (-not (Test-Path $f)) { throw "missing $f (run tools\build-driver.ps1 -NewTestCert and cargo build --release)" } }
Remove-Item $results -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $results | Out-Null

function Wait-Session {
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        try { return New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop } catch { Start-Sleep -Seconds 5 }
    }
    throw "VM '$VMName' did not accept PowerShell Direct within 10 minutes"
}

Write-Host "== Restoring checkpoint '$Checkpoint'"
if ((Get-VM $VMName).State -ne 'Off') { Stop-VM $VMName -TurnOff -Force }
Restore-VMSnapshot -VMName $VMName -Name $Checkpoint -Confirm:$false
Start-VM $VMName
$s = Wait-Session

Write-Host '== Copying package and enabling test signing + Driver Verifier'
Invoke-Command -Session $s { New-Item -ItemType Directory C:\WiretapTest -Force | Out-Null }
foreach ($f in $files) { Copy-Item $f -Destination C:\WiretapTest -ToSession $s }
Invoke-Command -Session $s {
    bcdedit /set testsigning on | Out-File C:\WiretapTest\01-testsigning.txt
    verifier /standard /driver WiretapDriver.sys | Out-File C:\WiretapTest\02-verifier.txt
}
Remove-PSSession $s
Restart-VM $VMName -Type Reboot -Force -Wait -For Heartbeat
$s = Wait-Session

Write-Host "== Installing driver and capturing for $Duration s"
Invoke-Command -Session $s -ArgumentList $Duration {
    param($Duration)
    Set-Location C:\WiretapTest
    $log = { param($name) Join-Path C:\WiretapTest $name }
    certutil -addstore Root WiretapTestSigning.cer | Out-File (& $log '10-cert-root.txt')
    certutil -f -addstore TrustedPublisher WiretapTestSigning.cer | Out-File (& $log '11-cert-publisher.txt')
    pnputil /add-driver WiretapDriver.inf /install | Out-File (& $log '12-pnputil.txt')
    .\wiretap.exe --headless check *>&1 | Out-File (& $log '13-check.txt')
    $capture = Start-Process .\wiretap.exe -ArgumentList "--headless capture --duration $Duration --db C:\WiretapTest\test.db" `
        -RedirectStandardOutput (& $log '20-capture.txt') -RedirectStandardError (& $log '21-capture-err.txt') -PassThru -WindowStyle Hidden
    $null = $capture.Handle # keeps the handle so ExitCode is available later
    Start-Sleep -Seconds 5
    sc.exe query WiretapDriver | Out-File (& $log '22-driver-during.txt')
    $traffic = foreach ($url in 'http://example.com/', 'http://neverssl.com/', 'https://www.microsoft.com/', 'https://example.org/') {
        try { "$url -> $((Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 15).StatusCode)" } catch { "$url -> $($_.Exception.Message)" }
    }
    $traffic | Out-File (& $log '23-traffic.txt')
    $capture.WaitForExit(($Duration + 30) * 1000) | Out-Null
    "exit code: $($capture.ExitCode)" | Out-File (& $log '24-capture-exit.txt')
    sc.exe query WiretapDriver | Out-File (& $log '25-driver-after.txt')
    .\wiretap.exe --headless sessions --db C:\WiretapTest\test.db | Out-File (& $log '30-sessions.txt')
    $session = (Get-Content (& $log '30-sessions.txt') | Select-Object -First 1) -split '\s+' | Select-Object -First 1
    if ($session) {
        .\wiretap.exe --headless flows $session --db C:\WiretapTest\test.db | Out-File (& $log '31-flows.jsonl')
        .\wiretap.exe --headless events $session --db C:\WiretapTest\test.db | Out-File (& $log '32-events.jsonl')
    }
    $state = { ((sc.exe query WiretapDriver | Select-String STATE).Line -replace '\s+', ' ').Trim() }

    # Stress: many short connections plus bulk HTTP and HTTPS transfers (ring and flow budget).
    $stress = Start-Process .\wiretap.exe -ArgumentList '--headless capture --duration 60 --quiet --no-store' `
        -RedirectStandardOutput (& $log '50-stress.txt') -PassThru -WindowStyle Hidden
    $null = $stress.Handle
    Start-Sleep -Seconds 4
    & {
        curl.exe -s -o NUL --parallel --parallel-max 50 'http://example.com/?q=[1-300]'
        foreach ($u in 'http://ipv4.download.thinkbroadband.com/20MB.zip', 'https://speed.cloudflare.com/__down?bytes=50000000') {
            curl.exe -s -o NUL --max-time 40 -w "$u : %{size_download} bytes`n" $u
        }
    } | Out-File (& $log '51-stress-traffic.txt')
    $stress.WaitForExit(120000) | Out-Null
    "exit code: $($stress.ExitCode); driver: $(& $state)" | Out-File (& $log '52-stress-exit.txt')

    # Crash: kill the client mid-capture. Its dynamic WFP session (session, sublayer, 4 callouts,
    # 4 filters) must vanish with it; the next capture must reuse the still-loaded driver, which
    # then stays loaded (it may have redirected: docs/driver/README.md) and `driver stop` refuses.
    # Counted from the BFE state dump.
    $wfp = {
        netsh wfp show state file=C:\WiretapTest\wfpstate.xml | Out-Null
        ([regex]::Matches((Get-Content C:\WiretapTest\wfpstate.xml -Raw), 'Wiretap capture')).Count
    }
    $victim = Start-Process .\wiretap.exe -ArgumentList '--headless capture --no-store' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 5
    "before kill: driver $(& $state); Wiretap WFP objects: $(& $wfp)" | Out-File (& $log '60-crash.txt')
    Stop-Process -Id $victim.Id -Force
    Start-Sleep -Seconds 2
    "after kill: driver $(& $state); Wiretap WFP objects: $(& $wfp)" | Out-File (& $log '60-crash.txt') -Append
    .\wiretap.exe --headless capture --duration 8 --no-store --quiet *>&1 | Out-File (& $log '61-after-crash-capture.txt')
    "after next capture: driver $(& $state); Wiretap WFP objects: $(& $wfp)" | Out-File (& $log '60-crash.txt') -Append
    .\wiretap.exe --headless driver stop *>&1 | Out-File (& $log '60-crash.txt') -Append
    "after driver stop: $(& $state)" | Out-File (& $log '60-crash.txt') -Append

    verifier /query | Out-File (& $log '40-verifier-query.txt')
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting' } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Message | Format-List | Out-File (& $log '41-bugchecks.txt')
    Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue | Select-Object Name, Length | Out-File (& $log '42-minidumps.txt')
}

Write-Host "== Collecting results into $results"
$names = Invoke-Command -Session $s { Get-ChildItem C:\WiretapTest -Filter '*.txt' | ForEach-Object Name; Get-ChildItem C:\WiretapTest -Filter '*.jsonl' | ForEach-Object Name }
foreach ($n in $names) { Copy-Item "C:\WiretapTest\$n" -Destination $results -FromSession $s }
Remove-PSSession $s
Get-ChildItem $results | ForEach-Object { Write-Host "--- $($_.Name)"; Get-Content $_.FullName -TotalCount 40 }

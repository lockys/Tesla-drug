#requires -Version 5.1
<#
stop_api_intercept.ps1 - Disable api-prd interception to restore direct vehicle API access

  .\stop_api_intercept.ps1            # Apply the changes
  .\stop_api_intercept.ps1 -DryRun    # Preview which processes would be stopped

Actions:
  1) Restart ARP redirection with --no-api to keep the vehicle online without redirecting api-prd to this PC.
  2) Stop the mitmproxy reverse proxy on port 443.
  3) Remove the fsd-mitm-api443 firewall rule (prompts for elevation if needed).
  4) Confirm that port 443 is free and that redirection is running.

The vehicle still reaches the Internet through this PC via ARP redirection.
To stop redirection as well, run & C:\fsd-mitm\svc\stop_stack.ps1.
#>
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Continue'
$root  = $PSScriptRoot                     # This script is located in C:\fsd-mitm.
$pyw   = Join-Path $root 'venv\Scripts\pythonw.exe'
$entry = Join-Path $root 'tools\arp_mitm.py'
$log   = Join-Path $root 'logs\stop_api_intercept.log'

function Log($m) {
    $line = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    if (-not $DryRun) {
        $dir = Split-Path -Parent $log
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $log -Value $line -Encoding UTF8
    }
}

Log ('=== Disable api-prd interception ===' + $(if ($DryRun) { ' [DryRun]' } else { '' }))

# Match the interpreter or stub, excluding shells and DSH hosts that include those strings in their command lines.
$selfNames = @('powershell.exe','pwsh.exe','cmd.exe','DeepSeek Harness.exe')
function Get-Targets([string]$pattern, [string]$nameFilter) {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like $nameFilter -and
        $selfNames -notcontains $_.Name -and
        $_.CommandLine -and $_.CommandLine -match $pattern
    })
}

# 1) Restart redirection with --no-api to keep the vehicle online.
$arp = Get-Targets 'arp_mitm\.py' 'python*.exe'
foreach ($pr in $arp) {
    if ($DryRun) { Log ("[dry] Would stop arp_mitm pid={0}" -f $pr.ProcessId) }
    else { Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue; Log ("Stopped arp_mitm pid={0}" -f $pr.ProcessId) }
}
if (-not $DryRun) {
    Start-Sleep -Seconds 2
    $a = @($entry,'--target','192.168.199.95','--gateway','192.168.199.1',
           '--our-ip','192.168.199.148','--answer','192.168.199.148',
           '--iface','Wi-Fi','--duration','7200','--no-api')
    Start-Process -FilePath $pyw -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $n = @(Get-Targets 'arp_mitm\.py' 'python*.exe').Count
    if ($n -ge 1) { Log ("ARP redirection restarted ({0} processes). API traffic is no longer intercepted." -f $n) }
    else { Log 'ERROR: ARP redirection failed to restart. Run the start command now to restore vehicle connectivity.' }
}

# 2) Stop the intercept on port 443.
$mm = Get-Targets 'mitmdump' 'python*.exe'
foreach ($pr in $mm) {
    if ($pr.CommandLine -notmatch '@443') { continue }
    if ($DryRun) { Log ("[dry] Would stop mitm443 pid={0}" -f $pr.ProcessId) }
    else { Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue; Log ("Stopped mitm443 pid={0}" -f $pr.ProcessId) }
}
if (@($mm | Where-Object { $_.CommandLine -match '@443' }).Count -eq 0) { Log 'The intercept on port 443 is not running.' }

# 3) Remove the firewall rule.
$rule = Get-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue
if ($rule) {
    if ($DryRun) { Log '[dry] Would remove firewall rule fsd-mitm-api443' }
    elseif (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Remove-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue
        Log 'Removed firewall rule fsd-mitm-api443'
    } else {
        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',"Remove-NetFirewallRule -DisplayName 'fsd-mitm-api443' -ErrorAction SilentlyContinue"
        Log 'Elevation requested to remove the firewall rule. Approve the UAC prompt.'
    }
} else { Log 'The firewall rule is already absent.' }

if (-not $DryRun) {
    Start-Sleep -Seconds 4
    Log '--- Verification ---'
    Log ("Port 443 listeners = {0} (expected 0)" -f @(Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue).Count)
    Log ("arp_mitm processes = {0} (expected 2)" -f @(Get-Targets 'arp_mitm\.py' 'python*.exe').Count)
    Log '=== Done. The vehicle API should reconnect directly within about a minute. ==='
}
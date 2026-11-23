#requires -Version 5.1
<#
keep_hotspot.ps1 - Keep the FSD-PC Windows Mobile Hotspot running

  .\tools\keep_hotspot.ps1                  # Keep monitoring and restart the hotspot if it stops
  .\tools\keep_hotspot.ps1 -Minutes 120
  .\tools\keep_hotspot.ps1 -Once            # Check once

Windows Mobile Hotspot may turn off after several minutes with no clients (observed after five minutes).
Keep the hotspot available until the vehicle connects to FSD-PC.
Log: C:\fsd-mitm\logs\hotspot-keeper.log
#>
[CmdletBinding()]
param(
    [int]$Minutes = 240,
    [int]$IntervalSeconds = 90,
    [switch]$Once
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$hs   = Join-Path $root 'hotspot.ps1'
$log  = Join-Path $root 'logs\hotspot-keeper.log'

function Log($m) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Write-Host $line -ForegroundColor Gray
    Add-Content -LiteralPath $log -Value $line -Encoding UTF8
}

function ApUp {
    [bool](Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '192.168.137.1' })
}

if (-not (Test-Path (Split-Path -Parent $log))) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $log) | Out-Null }
Log ("keeper start  ap=" + $(if (ApUp) { 'On' } else { 'Off' }))
if ($Once) { return }

$deadline = (Get-Date).AddMinutes($Minutes)
$last = if (ApUp) { 'On' } else { 'Off' }
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $IntervalSeconds
    $up = ApUp
    $state = if ($up) { 'On' } else { 'Off' }
    if ($state -ne $last) { Log ("ap state {0} -> {1}" -f $last, $state) ; $last = $state }
    if (-not $up) {
        try {
            & $hs -Action start -Ssid 'FSD-PC' -Key 'fsd2026!!' 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            if (ApUp) { Log 'ap restored -> On (FSD-PC / 192.168.137.1)' ; $last = 'On' }
            else { Log 'ap restore FAILED (still Off)' }
        } catch { Log ("ap restore error: " + $_.Exception.Message) }
    }
}
Log 'keeper exit (deadline)'
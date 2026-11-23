#requires -Version 5.1
<#
route-b.ps1 - Connect the PC and vehicle over Wi-Fi using Windows Mobile Hotspot

  .\route-b.ps1                 # Start the hotspot and share the active Internet connection
  .\route-b.ps1 -Stop           # Stop the hotspot
  .\route-b.ps1 -Ssid FSD-PC -Key fsd2026!! -NoShare

Windows Mobile Hotspot shares the active Internet connection.
The -NoShare parameter is retained for compatibility. Windows manages connection sharing.
#>
[CmdletBinding()]
param(
    [string]$Ssid = 'FSD-PC',
    [string]$Key = 'fsd2026!!',
    [switch]$NoShare,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$hotspot = Join-Path $PSScriptRoot 'hotspot.ps1'
$action = if ($Stop) { 'stop' } else { 'start' }
& $shell -NoProfile -ExecutionPolicy Bypass -File $hotspot -Action $action -Ssid $Ssid -Key $Key
if ($LASTEXITCODE -ne 0) { throw "Mobile hotspot operation failed (exit $LASTEXITCODE)" }

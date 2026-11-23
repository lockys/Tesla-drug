#requires -Version 5.1
<#
stop_hotspot.ps1 - Stop the HTTPS intercept, DNS redirect, and dashboard on port 8900 in hotspot mode

  .\stop_hotspot.ps1                  # Stop the components and keep the hotspot running
  .\stop_hotspot.ps1 -StopHotspot     # Also stop the FSD-PC hotspot
  .\stop_hotspot.ps1 -DryRun          # Preview which processes would be stopped

Use stop_fsd_all.ps1 to stop the router-mode service stack and ARP redirection.
#>
[CmdletBinding()]
param([switch]$StopHotspot, [switch]$DryRun)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$patterns = @('fsd_mock\.py', 'dns_sink\.py', 'fsd_panel\.py', '@443')

$targets = @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object {
        $proc = $_
        if (-not $proc.CommandLine) { return $false }
        @($patterns | Where-Object { $proc.CommandLine -match $_ }).Count -gt 0
    })

if ($targets.Count -eq 0) {
    Write-Host 'No hotspot-mode components are running.' -ForegroundColor Green
} else {
    foreach ($p in $targets) {
        if ($DryRun) {
            Write-Host ("[dry] pid={0}  {1}" -f $p.ProcessId, $p.CommandLine) -ForegroundColor DarkGray
        } else {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host ("Stopped process {0}" -f $p.ProcessId) -ForegroundColor Yellow
        }
    }
}

if ($StopHotspot -and -not $DryRun) {
    Write-Host 'Stopping the hotspot...' -ForegroundColor Yellow
    & (Join-Path $root 'route-b.ps1') -Stop
}

if (-not $DryRun) {
    Write-Host 'Done. Reconnect the vehicle to its previous Wi-Fi network to restore connectivity.' -ForegroundColor Green
}

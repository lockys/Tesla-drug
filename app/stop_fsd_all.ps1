#requires -Version 3.0
<# stop_fsd_all.ps1 - Stop the FSD intercept environment and its watchdog to prevent automatic restart. #>
$root = $PSScriptRoot
Write-Host 'Stopping the watchdog...' -ForegroundColor Yellow
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'supervise_all\.py' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host 'Stopping ARP redirection, HTTPS interception, the dashboard, and the service stack...' -ForegroundColor Yellow
foreach ($pat in @('arp_mitm\.py','fsd_panel\.py','@443')) {
  Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match $pat } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
& (Join-Path $root 'svc\stop_stack.ps1') | Out-Null
Start-Sleep -Seconds 2
Write-Host 'Stopped. The vehicle should reconnect directly within about a minute.' -ForegroundColor Green
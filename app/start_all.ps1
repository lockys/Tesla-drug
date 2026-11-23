#requires -Version 5.1
<#
start_all.ps1 - Start the FSD intercept environment in router mode. Safe to rerun.

  .\start_all.ps1             # Start the environment
  .\start_all.ps1 -Status     # Show status only

Startup ensures the following are in place:
  1) Inbound firewall access on TCP 4567, 8080, 8899, and 443, and UDP 53. Missing rules prompt for elevation.
  2) The svc\stack.py service stack (DNS, forward proxy, reverse proxy, and web dashboard).
  3) ARP redirection via tools\arp_mitm.py (--rst-dst directs vehicle traffic to this PC).
  4) mitmdump on port 443 (reverse proxy for api-prd with responses from fsd_mock).
  5) The dashboard at http://127.0.0.1:8900.
  6) The tools\supervise_all.py watchdog, which restarts failed components.
  7) A per-user login startup entry for the watchdog in the registry.
#>
[CmdletBinding()]
param([switch]$Status, [switch]$Elevated)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$pyw  = Join-Path $root 'venv\Scripts\pythonw.exe'
$logs = Join-Path $root 'logs'
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }
$env:FSD_MOCK_LOG_DIR = $logs
$env:FSD_MOCK_JSON = Join-Path $root 'payload.json'
$env:FSD_MOCK_LOG_ALL = '1'
$env:FSD_MOCK_MODE_FILE = Join-Path $root 'mode.json'

function PortOpen([int]$p) {
    try { $c = New-Object System.Net.Sockets.TcpClient; $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(300); $c.Dispose(); return $ok } catch { return $false }
}

function ProcCount([string]$pattern) {
    @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern }).Count
}

function Show-Status {
    $rows = @(
        [pscustomobject]@{ Component='Service stack 4567'; Status=$(if (PortOpen 4567) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Proxy 8080'; Status=$(if (PortOpen 8080) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Dashboard 8899'; Status=$(if (PortOpen 8899) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='HTTPS intercept 443'; Status=$(if (PortOpen 443) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Dashboard 8900'; Status=$(if (PortOpen 8900) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='ARP redirection'; Status=$(if ((ProcCount 'arp_mitm\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Watchdog'; Status=$(if ((ProcCount 'supervise_all\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Firewall rules'; Status=("{0}/5" -f @('fsd-mitm-reverse-4567','fsd-mitm-proxy-8080','fsd-mitm-dns-53','fsd-mitm-web-8899','fsd-mitm-api443' | Where-Object { Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue }).Count) },
        [pscustomobject]@{ Component='Start at login'; Status=$(if ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'fsd-mitm-supervisor' -ErrorAction SilentlyContinue)) { 'OK' } else { 'Not configured' }) }
    )
    $rows | Format-Table -AutoSize | Out-String -Width 80
}

Write-Host "`n===== FSD Intercept Environment (Router Mode) =====" -ForegroundColor Cyan

if ($Status) { Show-Status; return }

# 1) Firewall
$rules = @(
    @{ Name='fsd-mitm-reverse-4567'; Proto='TCP'; Port=4567 },
    @{ Name='fsd-mitm-proxy-8080';   Proto='TCP'; Port=8080 },
    @{ Name='fsd-mitm-dns-53';       Proto='UDP'; Port=53 },
    @{ Name='fsd-mitm-web-8899';     Proto='TCP'; Port=8899 },
    @{ Name='fsd-mitm-api443';       Proto='TCP'; Port=443 }
)
$missing = @($rules | Where-Object { -not (Get-NetFirewallRule -DisplayName $_.Name -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) {
    if ($Elevated) {
        foreach ($r in $missing) {
            New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol $r.Proto -LocalPort $r.Port -Profile Any -Description 'FSD lab' -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host ("Firewall: Added {0} rules" -f $missing.Count) -ForegroundColor Green
    } else {
        Write-Host ("Firewall: {0} rules are missing. Approve the UAC prompt to add them." -f $missing.Count) -ForegroundColor Yellow
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated'
        Start-Sleep -Seconds 4
    }
} else { Write-Host 'Firewall: All 5 rules are present' -ForegroundColor Green }

# 2) Service stack
if (-not (PortOpen 4567)) {
    Write-Host 'Service stack: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList (Join-Path $root 'svc\stack.py') -WindowStyle Hidden
    Start-Sleep -Seconds 10
} else { Write-Host 'Service stack: Already running' -ForegroundColor Green }

# 3) ARP redirection
if ((ProcCount 'arp_mitm\.py') -eq 0) {
    Write-Host 'ARP redirection: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -WindowStyle Hidden -ArgumentList @(
        (Join-Path $root 'tools\arp_mitm.py'), '--target','192.168.199.95','--gateway','192.168.199.1',
        '--our-ip','192.168.199.148','--answer','192.168.199.148','--iface','Wi-Fi',
        '--duration','7200','--rst-dst','52.81.9.181')
    Start-Sleep -Seconds 6
} else { Write-Host 'ARP redirection: Already running' -ForegroundColor Green }

# 4) HTTPS interception
if (-not (PortOpen 443)) {
    Write-Host 'HTTPS intercept 443: Starting...' -ForegroundColor Yellow
    $a = @('-s',(Join-Path $root 'fsd_mock.py'),
           '--set',('confdir=' + (Join-Path $root 'certs2')),'--set','ssl_insecure=true',
           '--set','connection_strategy=lazy','--set','block_global=false','--emudhra',
           '--mode','reverse:https://api-prd.vn.cloud.tesla.cn@443')
    Start-Process -FilePath (Join-Path $root 'venv\Scripts\mitmdump.exe') -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 8
} else { Write-Host 'HTTPS intercept 443: Already running' -ForegroundColor Green }

# 5) Dashboard
if (-not (PortOpen 8900)) {
    Write-Host 'Dashboard 8900: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList @((Join-Path $root 'web\fsd_panel.py'),'--port','8900') -WindowStyle Hidden
    Start-Sleep -Seconds 4
} else { Write-Host 'Dashboard 8900: Already running' -ForegroundColor Green }

# 6) Watchdog
if ((ProcCount 'supervise_all\.py') -eq 0) {
    Write-Host 'Watchdog: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList (Join-Path $root 'tools\supervise_all.py') -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else { Write-Host 'Watchdog: Already running' -ForegroundColor Green }

# 7) Start at login
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$want = '"' + $pyw + '" "' + (Join-Path $root 'tools\supervise_all.py') + '"'
Set-ItemProperty -Path $runKey -Name 'fsd-mitm-supervisor' -Value $want -Type String
Write-Host 'Start at login: Configured' -ForegroundColor Green

Write-Host "`n===== Status =====" -ForegroundColor Cyan
Show-Status
Write-Host "Dashboard: http://127.0.0.1:8900    Configuration: http://127.0.0.1:8900/config`n" -ForegroundColor Green
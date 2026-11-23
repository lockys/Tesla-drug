#requires -Version 5.1
<#
start_hotspot.ps1 - Start the FSD intercept environment in hotspot mode (default)

  Share a phone connection over USB, start the FSD-PC hotspot, and connect the vehicle to FSD-PC.
  The PC at 192.168.137.1 acts as the vehicle's gateway and DNS server, so ARP poisoning is unnecessary.

  .\start_hotspot.ps1                  # Start the HTTPS intercept, DNS redirect, and dashboard on port 8900
  .\start_hotspot.ps1 -Status          # Show status only
  .\start_hotspot.ps1 -OurIp 192.168.137.1

For router mode, connect the vehicle and PC to the same router and run start_all.cmd.
#>
[CmdletBinding()]
param([switch]$Status, [switch]$Elevated, [switch]$NoFirewall, [string]$OurIp = '192.168.137.1')

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$logs = Join-Path $root 'logs'
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }

$mitm = Join-Path $root 'venv\Scripts\mitmdump.exe'
$py   = Join-Path $root 'venv\Scripts\python.exe'
$pyw  = Join-Path $root 'venv\Scripts\pythonw.exe'

function PortOpen([int]$p) {
    try { $c = New-Object System.Net.Sockets.TcpClient; $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(300); $c.Dispose(); return $ok } catch { return $false }
}

function ProcCount([string]$pattern) {
    @(Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and $_.CommandLine -match $pattern }).Count
}

function HotspotIpUp {
    [bool](Get-NetIPAddress -IPAddress $OurIp -ErrorAction SilentlyContinue)
}

function CarSeen {
    @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -like '192.168.137.*' -and $_.IPAddress -ne $OurIp -and $_.State -ne 'Unreachable' }).Count -gt 0
}

function Show-Status {
    $rows = @(
        [pscustomobject]@{ Component='HTTPS intercept 443'; Status=$(if (PortOpen 443) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='DNS 53'; Status=$(if ((ProcCount 'dns_sink\.py') -gt 0) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Dashboard 8900'; Status=$(if (PortOpen 8900) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component="Hotspot $OurIp"; Status=$(if (HotspotIpUp) { 'OK' } else { 'DOWN' }) },
        [pscustomobject]@{ Component='Vehicle online'; Status=$(if (CarSeen) { 'OK' } else { 'Not detected' }) }
    )
    $rows | Format-Table -AutoSize | Out-String -Width 80
}

Write-Host "`n===== FSD Intercept Environment (Hotspot Mode) =====" -ForegroundColor Cyan

if ($Status) { Show-Status; return }

# 1) Inbound firewall rules for TCP 443 and UDP 53
if ($NoFirewall) {
    Write-Host 'Firewall: Skipped (-NoFirewall)' -ForegroundColor DarkGray
} else {
$rules = @(
    @{ Name='fsd-mitm-api443'; Proto='TCP'; Port=443 },
    @{ Name='fsd-mitm-dns-53'; Proto='UDP'; Port=53 }
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
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated' | Out-Null
        Start-Sleep -Seconds 4
    }
} else { Write-Host 'Firewall: All required rules are present' -ForegroundColor Green }
}

# 2) Check the hotspot and prompt the user if it is down.
if (HotspotIpUp) {
    Write-Host "Hotspot: $OurIp is online" -ForegroundColor Green
} else {
    Write-Host "Hotspot: $OurIp is unavailable. Share a phone connection over USB and run the command below to enable the hotspot." -ForegroundColor Yellow
    Write-Host '      C:\fsd-mitm\route-b.ps1 -Ssid FSD-PC -Key fsd2026!!' -ForegroundColor Yellow
}

# 3) Reverse proxy on port 443
if (-not (PortOpen 443)) {
    Write-Host 'HTTPS intercept 443: Starting...' -ForegroundColor Yellow
    $env:FSD_MOCK_JSON      = Join-Path $root 'payload.json'
    $env:FSD_MOCK_LOG_DIR   = $logs
    $env:FSD_MOCK_LOG_ALL   = '1'
    $env:FSD_MOCK_MODE_FILE = Join-Path $root 'mode.json'
    $a = @('-s',(Join-Path $root 'fsd_mock.py'),
           '--set',('confdir=' + (Join-Path $root 'certs2')),'--set','ssl_insecure=true',
           '--set','connection_strategy=lazy','--set','block_global=false','--emudhra',
           '--mode','reverse:https://api-prd.vn.cloud.tesla.cn@443')
    Start-Process -FilePath $mitm -ArgumentList $a -WindowStyle Hidden
    Start-Sleep -Seconds 8
} else { Write-Host 'HTTPS intercept 443: Already running' -ForegroundColor Green }

# 4) DNS redirection on UDP 53. Check the process because there is no TCP listener.
if ((ProcCount 'dns_sink\.py') -eq 0) {
    Write-Host 'DNS 53: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $py -WindowStyle Hidden -ArgumentList @(
        (Join-Path $root 'dns_sink.py'), '--ip', $OurIp, '--redirect', 'api-prd.vn.cloud.tesla.cn')
    Start-Sleep -Seconds 3
    if ((ProcCount 'dns_sink\.py') -eq 0) {
        Write-Host 'DNS 53: Failed to start. Another process, such as the hotspot DNS proxy, may be using port 53. Check with netstat -ano | findstr ":53 "' -ForegroundColor Red
    }
} else { Write-Host 'DNS 53: Already running' -ForegroundColor Green }

# 5) Dashboard
if (-not (PortOpen 8900)) {
    Write-Host 'Dashboard 8900: Starting...' -ForegroundColor Yellow
    Start-Process -FilePath $pyw -ArgumentList @((Join-Path $root 'web\fsd_panel.py'),'--port','8900') -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else { Write-Host 'Dashboard 8900: Already running' -ForegroundColor Green }

Write-Host "`n===== Status =====" -ForegroundColor Cyan
Show-Status
Write-Host "Dashboard:     http://127.0.0.1:8900" -ForegroundColor Green
Write-Host "Configuration: http://127.0.0.1:8900/config" -ForegroundColor Green
Write-Host "Stop:          C:\fsd-mitm\stop_hotspot.cmd`n" -ForegroundColor DarkGray

#requires -Version 5.1
<#
Clear-FSD-Records.ps1 - Clear dashboard records from <project>\logs

  .\Clear-FSD-Records.ps1            # Preview the files and sizes without deleting them
  .\Clear-FSD-Records.ps1 -Force     # Delete the listed files

Deletes: hits.jsonl / dns.jsonl / arp_mitm.log / handshake.log / car_recent.jsonl /
      config_history.jsonl / requests\ / *.log / __pycache__
Preserves the logs directory, payload.json, payload.json.bak, certificates, and source files.

The read-only dashboard on port 8900 displays records from logs\.
Refresh the running dashboard after clearing the records, or stop it first with stop_fsd_all.ps1.
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [string]$Root = 'C:\fsd-mitm'
)

$ErrorActionPreference = 'Stop'
$logs = Join-Path $Root 'logs'

if (-not (Test-Path -LiteralPath $logs)) {
    Write-Host "Logs directory does not exist: $logs" -ForegroundColor Yellow
    Write-Host 'The dashboard has no records.' -ForegroundColor Green
    return
}

$targets = @(Get-ChildItem -LiteralPath $logs -Force -ErrorAction SilentlyContinue)
if ($targets.Count -eq 0) {
    Write-Host "Logs directory is already empty: $logs" -ForegroundColor Green
    Write-Host 'There are no dashboard records to clear.' -ForegroundColor Green
    return
}

$total = 0
Write-Host ''
Write-Host "Logs directory to clear: $logs" -ForegroundColor Cyan
foreach ($t in $targets) {
    $size = 0
    if ($t.PSIsContainer) {
        $size = (Get-ChildItem -LiteralPath $t.FullName -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object Length -Sum).Sum
    } else {
        $size = $t.Length
    }
    if (-not $size) { $size = 0 }
    $total += $size
    Write-Host ("  {0,-44} {1,10:N1} KB" -f $t.Name, ($size / 1KB))
}
Write-Host ("  Total: {0:N1} KB in {1} items" -f ($total / 1KB), $targets.Count) -ForegroundColor DarkGray

if (-not $Force) {
    Write-Host ''
    Write-Host 'Preview complete. To delete the files, run:' -ForegroundColor Yellow
    Write-Host '  .\Clear-FSD-Records.ps1 -Force' -ForegroundColor Yellow
    return
}

# Delete only entries inside logs, keeping the directory itself.
foreach ($t in $targets) {
    Remove-Item -LiteralPath $t.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

$left = @(Get-ChildItem -LiteralPath $logs -Force -ErrorAction SilentlyContinue)
Write-Host ''
Write-Host ("Finished clearing records. {0} items remain." -f $left.Count) -ForegroundColor Green
foreach ($l in $left) { Write-Host "  Remaining: $($l.Name)" -ForegroundColor Yellow }
Write-Host 'Refresh the dashboard on port 8900 to see the updated records.' -ForegroundColor Green

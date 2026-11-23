#requires -Version 5.1
<#
.SYNOPSIS
    Remove the FSD interception environment from C:\fsd-mitm.
.EXAMPLE
    .\uninstall.ps1
    Preview the removal without making changes.
.EXAMPLE
    .\uninstall.ps1 -Apply
    Run as administrator under the installing account. Removes the deployment,
    including logs, payloads, and the virtual environment.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param([switch]$Apply)

$ErrorActionPreference = 'Stop'
$target = 'C:\fsd-mitm'
$prefix = $target + '\'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runName = 'fsd-mitm-supervisor'
$firewallNames = @(
    'fsd-mitm-api443', 'fsd-mitm-dns-53', 'fsd-mitm-reverse-4567',
    'fsd-mitm-proxy-8080', 'fsd-mitm-web-8899'
)

function Assert-SafeDeploymentPath {
    if (-not (Test-Path -LiteralPath $target)) { return }
    $root = Get-Item -LiteralPath $target -Force
    if ($root.FullName -ne $target -or -not $root.PSIsContainer -or
        ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a real directory at $target."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $target 'fsd_mock.py') -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $target 'start_hotspot.ps1') -PathType Leaf)) {
        throw "Could not identify an FSD deployment at $target."
    }

    $directories = New-Object 'System.Collections.Generic.Stack[string]'
    $directories.Push($root.FullName)
    while ($directories.Count -gt 0) {
        foreach ($entry in Get-ChildItem -LiteralPath $directories.Pop() -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Remove or relocate this reparse point before uninstalling: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) { $directories.Push($entry.FullName) }
        }
    }
}

function Get-FsdProcess {
    $pythonCommands = [regex]::Escape($prefix) +
        '(?:venv\\Scripts\\(?:pythonw?|mitmdump)\.exe|(?:tools\\(?:supervise_all|arp_mitm)|svc\\stack|web\\(?:fsd_panel|server)|dns_sink|fsd_mock)\.py)'
    $powerShellCommands = [regex]::Escape($prefix) + '(?:start_all|start_hotspot|tools\\keep_hotspot)\.ps1'
    Get-CimInstance Win32_Process -Filter "Name LIKE 'python%' OR Name = 'mitmdump.exe' OR Name = 'powershell.exe' OR Name = 'pwsh.exe'" |
        Where-Object {
            $command = $_.CommandLine
            if ($_.Name -in @('powershell.exe', 'pwsh.exe')) {
                $command -match ('(?:^|[\s"])' + $powerShellCommands + '(?:$|[\s"])')
            } else {
                ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) -or
                ($command -match ('(?:^|[\s"])' + $pythonCommands + '(?:$|[\s"])'))
            }
        }
}

Write-Host "FSD uninstall target: $target"
Write-Host 'Removes deployment files (including logs, payloads, and venv), shortcuts, login startup, and FSD firewall rules.'
if (-not $Apply) {
    Write-Host 'Preview only. Use -Apply from an elevated PowerShell to remove them.'
    return
}
if (-not $PSCmdlet.ShouldProcess($target, 'Stop and remove the FSD deployment')) { return }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this command from an elevated PowerShell under the installing account.'
}

Assert-SafeDeploymentPath
$startup = Get-ItemProperty -LiteralPath $runKey -Name $runName -ErrorAction SilentlyContinue
$startupPattern = '(?:^|[\s"])' + [regex]::Escape($prefix) + 'start_(?:hotspot|all)\.ps1(?:$|[\s"])'
if ($startup -and $startup.$runName -match $startupPattern) {
    Remove-ItemProperty -LiteralPath $runKey -Name $runName
}

for ($attempt = 0; $attempt -lt 3; $attempt++) {
    # Stop the watchdog and launchers first so they cannot recreate the workers.
    $running = @(Get-FsdProcess | Sort-Object { $_.CommandLine -notmatch '(?:supervise_all\.py|start_(?:hotspot|all)\.ps1|keep_hotspot\.ps1)' })
    if ($running.Count -eq 0) { break }
    foreach ($process in $running) {
        $current = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $process.ProcessId)
        if ($current -and $current.CreationDate -eq $process.CreationDate) {
            Stop-Process -Id $process.ProcessId -Force
        }
    }
    Start-Sleep -Milliseconds 300
}
if (@(Get-FsdProcess).Count -gt 0) {
    throw 'FSD processes are still running. Deployment files were kept.'
}

Get-NetFirewallRule -PolicyStore PersistentStore |
    Where-Object { $_.DisplayName -in $firewallNames -and $_.Description -eq 'FSD lab' } |
    Remove-NetFirewallRule

$desktop = [Environment]::GetFolderPath('Desktop')
if ($desktop -and (Test-Path -LiteralPath $desktop -PathType Container)) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcutNames = @(
        'FSD Start.lnk', 'FSD Stop.lnk',
        [regex]::Unescape('FSD\u4e00\u952e\u542f\u52a8.lnk'),
        [regex]::Unescape('FSD\u4e00\u952e\u505c\u6b62.lnk')
    )
    foreach ($name in $shortcutNames) {
        $path = Join-Path $desktop $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $shortcut = $shell.CreateShortcut($path)
            if ($shortcut.TargetPath -eq (Join-Path $target 'start_hotspot.cmd') -or
                $shortcut.Arguments -match ('(?:^|[\s"])' + [regex]::Escape((Join-Path $target 'stop_hotspot.ps1')) + '(?:$|[\s"])')) {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }
}

Assert-SafeDeploymentPath
if (Test-Path -LiteralPath $target) {
    Remove-Item -LiteralPath $target -Recurse -Force
}
Write-Host 'FSD uninstall complete.'

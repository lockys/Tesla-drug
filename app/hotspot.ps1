#requires -Version 5.1
<#
hotspot.ps1 - Provide Wi-Fi for the vehicle using Windows Mobile Hotspot (no administrator access required)

  .\hotspot.ps1 -Action start
  .\hotspot.ps1 -Action start -Ssid FSD-SCORE -Key fsd2026!!
  .\hotspot.ps1 -Action status
  .\hotspot.ps1 -Action stop

Notes:
  * Windows 11 uses Wi-Fi Direct, which works without Hosted Network support.
  * To give the vehicle Internet access, select the upstream adapter under Settings > Network & internet > Mobile hotspot.
  * The default hotspot subnet is usually 192.168.137.0/24. Use the PC gateway address 192.168.137.1 for vehicle DNS or hosts configuration.
#>
[CmdletBinding()]
param(
    [ValidateSet('start', 'stop', 'status')] [string]$Action = 'status',
    [string]$Ssid = 'FSD-SCORE',
    [string]$Key = 'fsd2026!!'
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $task = $asTask.Invoke($null, @($WinRtTask))
    if (-not $task.Wait(20000)) { throw 'Timed out waiting for the mobile hotspot operation' }
    $task.Result
}

[Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime] | Out-Null

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if (-not $profile) { throw 'No Internet connection profile is available. Connect over Wi-Fi or Ethernet first.' }

$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)

switch ($Action) {
    'status' {
        Write-Host ("internet profile : {0}" -f $profile.ProfileName)
        Write-Host ("tethering state  : {0}" -f $mgr.TetheringOperationalState)
        Write-Host ("ssid             : {0}" -f $mgr.GetCurrentAccessPointConfiguration().Ssid)
        Write-Host ("max clients      : {0}" -f $mgr.MaxClientCount)
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Local Area Connection|\u672c\u5730\u8fde\u63a5|Wi-Fi Direct' } |
            Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String -Width 100
    }
    'start' {
        if ($mgr.TetheringOperationalState -eq 'On') {
            Write-Host 'The hotspot is already running' -ForegroundColor Yellow
        }
        else {
            $cfg = $mgr.GetCurrentAccessPointConfiguration()
            $cfg.Ssid = $Ssid
            $cfg.Passphrase = $Key
            $asActionTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
                $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.FullName -eq 'Windows.Foundation.IAsyncAction'
            }
            $task = $asActionTask.Invoke($null, @($mgr.ConfigureAccessPointAsync($cfg)))
            if (-not $task.Wait(20000)) { throw 'Timed out saving the mobile hotspot configuration' }

            $res = Await ($mgr.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
            if ($res.Status -ne 'Success') {
                throw ("Could not start the mobile hotspot: {0} {1}" -f $res.Status, $res.AdditionalErrorMessage)
            }
        }
        Start-Sleep -Seconds 2
        if ($mgr.TetheringOperationalState -ne 'On') { throw "Unexpected mobile hotspot state: $($mgr.TetheringOperationalState)" }
        $cfg = $mgr.GetCurrentAccessPointConfiguration()
        Write-Host ("state: {0}" -f $mgr.TetheringOperationalState)
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.137.*' } |
            Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String -Width 100
        Write-Host ("SSID={0}  KEY={1}" -f $cfg.Ssid, $cfg.Passphrase) -ForegroundColor Green
    }
    'stop' {
        $res = Await ($mgr.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
        if ($res.Status -ne 'Success') {
            throw ("Could not stop the mobile hotspot: {0} {1}" -f $res.Status, $res.AdditionalErrorMessage)
        }
        Write-Host ("state: {0}" -f $mgr.TetheringOperationalState)
    }
}

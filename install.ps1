#requires -Version 5.1
<#
install.ps1 - FSD intercept environment installer (hotspot mode)

  Run the one-click CMD launcher, or run this script from this directory:

    .\install.ps1                 # Check, copy, create venv, install dependencies, set up shortcuts and startup, then launch
    .\install.ps1 -Check          # Run checks without changing any files
    .\install.ps1 -SkipVenv       # Use an existing venv without rebuilding it
    .\install.ps1 -NoStart        # Install without launching
    .\install.ps1 -UseMirror      # Use the Tsinghua mirror for pip
    .\install.ps1 -AutoInstallPython # Install Python via WinGet if no compatible interpreter is found
    .\install.ps1 -Force          # Overwrite deployed source files, keep logs and venv, and back up payload.json

The installation directory is fixed at C:\fsd-mitm. About 24 paths are hard-coded, including in
svc\stack.py, tools\supervise_all.py, web\server.py, and stop_stack.ps1. Edit them before changing drives.
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Force,
    [switch]$SkipVenv,
    [switch]$NoStart,
    [switch]$NoShortcut,
    [switch]$NoAutostart,
    [switch]$UseMirror,
    [switch]$AutoInstallPython,
    [string]$PythonExe,
    [string]$Target = 'C:\fsd-mitm'
)

$ErrorActionPreference = 'Continue'
$src = Join-Path $PSScriptRoot 'app'
$script:okCount = 0
$script:warnCount = 0
$script:failCount = 0

function Step([string]$n, [string]$t) {
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $n, $t) -ForegroundColor Cyan
}
function Good([string]$m) { $script:okCount++;   Write-Host "     OK    $m" -ForegroundColor Green }
function Note([string]$m) { $script:warnCount++; Write-Host "     WARN  $m" -ForegroundColor Yellow }
function Fail([string]$m) { $script:failCount++; Write-Host "     FAIL  $m" -ForegroundColor Red }
function Info([string]$m) { Write-Host "           $m" -ForegroundColor DarkGray }

function Test-Port([int]$p) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $ok = $c.ConnectAsync('127.0.0.1', $p).Wait(250)
        $c.Dispose()
        return $ok
    } catch { return $false }
}

function Test-PythonExe([string]$Exe, [string[]]$PreArgs = @()) {
    if (-not $Exe) { return $null }
    if (-not (Test-Path -LiteralPath $Exe)) { return $null }
    # Skip Microsoft Store execution aliases and zero-byte placeholders.
    if ($Exe -match '\\WindowsApps\\') { return $null }
    try { $item = Get-Item -LiteralPath $Exe -Force -ErrorAction Stop } catch { return $null }
    if ($item.Length -eq 0) { return $null }
    try {
        $raw = & $Exe @PreArgs -I -c "import ensurepip, sys, venv; print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { return $null }
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    $v = "$(@($raw) | Select-Object -First 1)".Trim()
    if ($v -notmatch '^(\d+)\.(\d+)$') { return $null }
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]
    # mitmproxy 12.3.1 in requirements.txt requires Python 3.12 or later.
    if ($maj -ne 3 -or $min -lt 12) { return $null }
    return [pscustomobject]@{ Exe = $Exe; Pre = $PreArgs; Version = $v; Via = '' }
}

function Test-InstalledVenv([string]$VenvDir) {
    $python = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath (Join-Path $VenvDir 'Scripts\pythonw.exe') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $VenvDir 'Scripts\mitmdump.exe') -PathType Leaf) -or
        -not (Test-PythonExe $python)) {
        return $false
    }
    & $python -I -m pip check *> $null
    return ($LASTEXITCODE -eq 0)
}

function Find-Python {
    # 1) Explicit interpreter path
    if ($PythonExe) {
        $c = Test-PythonExe $PythonExe
        if ($c) { $c.Via = '-PythonExe'; return $c }
        Note "Specified Python is unavailable: $PythonExe"
    }
    # 2) PATH
    foreach ($n in @('python', 'python3')) {
        foreach ($cmd in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) {
            $c = Test-PythonExe $cmd.Source
            if ($c) { $c.Via = "PATH ($n)"; return $c }
        }
    }
    # 3) Python launcher
    foreach ($pyCmd in @(Get-Command 'py' -All -CommandType Application -ErrorAction SilentlyContinue)) {
        foreach ($v in @('3.12', '3.13', '3.14', '3')) {
            $c = Test-PythonExe $pyCmd.Source @("-$v")
            if ($c) { $c.Via = "py -$v"; return $c }
        }
    }
    # 4) Standard installation directories
    foreach ($pat in @(
            "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
            "C:\Python3*\python.exe",
            "$env:ProgramFiles\Python3*\python.exe",
            "${env:ProgramFiles(x86)}\Python3*\python.exe")) {
        foreach ($f in @(Get-ChildItem $pat -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $c = Test-PythonExe $f.FullName
            if ($c) { $c.Via = 'installation directory'; return $c }
        }
    }
    # 5) Registry
    foreach ($hive in @('HKLM:\SOFTWARE\Python\PythonCore',
                        'HKCU:\SOFTWARE\Python\PythonCore',
                        'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore')) {
        foreach ($k in @(Get-ChildItem $hive -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending)) {
            $ip = (Get-ItemProperty (Join-Path $k.PSPath 'InstallPath') -ErrorAction SilentlyContinue).'(default)'
            if ($ip) {
                $c = Test-PythonExe (Join-Path $ip 'python.exe')
                if ($c) { $c.Via = 'registry'; return $c }
            }
        }
    }
    # 6) Bundled or portable runtimes, such as the Python distributed with DSH
    foreach ($g in @("$env:USERPROFILE\.dsh\dsh-runtimes\*\dependencies\python\python.exe",
                     "$env:LOCALAPPDATA\dsh\dsh-runtimes\*\dependencies\python\python.exe")) {
        foreach ($f in @(Get-ChildItem $g -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $c = Test-PythonExe $f.FullName
            if ($c) { $c.Via = 'bundled runtime'; return $c }
        }
    }
    # 7) Base interpreter of the existing venv, from the home entry in pyvenv.cfg
    $cfg = Join-Path $Target 'venv\pyvenv.cfg'
    if (Test-Path $cfg) {
        $line = @(Get-Content $cfg | Where-Object { $_ -match '^\s*home\s*=' })
        if ($line.Count -gt 0) {
            $homePath = (($line[0] -split '=', 2)[1]).Trim()
            $c = Test-PythonExe (Join-Path $homePath 'python.exe')
            if ($c) { $c.Via = 'base interpreter of the existing venv'; return $c }
        }
    }
    return $null
}

# ---------------------------------------------------------------- Header
Write-Host ''
Write-Host '  ============================================' -ForegroundColor White
Write-Host '   FSD Intercept Environment' -ForegroundColor White
Write-Host '   ============================================' -ForegroundColor White
Write-Host ("   Package location: {0}" -f $PSScriptRoot) -ForegroundColor DarkGray
Write-Host ("   Install to: {0}" -f $Target) -ForegroundColor DarkGray
if ($Check) { Write-Host '   Mode: Check only (no files changed)' -ForegroundColor DarkGray }

$transcript = $null
if (-not $Check) {
    try {
        $logDir = Join-Path $Target 'logs'
        if (Test-Path $logDir) {
            $transcript = Join-Path $logDir ('install-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Start-Transcript -Path $transcript -Force | Out-Null
        }
    } catch { }
}

try {

# ---------------------------------------------------------------- 0 Environment
Step '0/7' 'Runtime environment'
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Fail ("PowerShell {0} is too old. Version 5.1 or later is required." -f $PSVersionTable.PSVersion)
    exit 1
}
Good ("PowerShell {0}" -f $PSVersionTable.PSVersion)
if (-not [Environment]::Is64BitOperatingSystem) {
    Fail '64-bit Windows is required'
} else {
    Good 'Windows x64'
}
if (-not (Test-Path (Join-Path $src 'start_all.ps1'))) {
    Fail "Installation source is incomplete. Missing file: $src\start_all.ps1"
    Fail 'Extract the entire archive before running the installer.'
    exit 1
}
Good ("Installation source is complete ({0} files in app\)" -f (Get-ChildItem $src -Recurse -File).Count)

# ---------------------------------------------------------------- 1 Destination
Step '1/7' 'Installation directory'
$canonical = 'C:\fsd-mitm'
if ($Target.TrimEnd('\') -ne $canonical) {
    Fail ("The installation directory must be {0}" -f $canonical)
    Info 'About 24 paths are hard-coded, including in svc\stack.py, tools\supervise_all.py, web\server.py, and stop_stack.ps1.'
    Info 'Edit those paths before changing the installation drive.'
    exit 2
}
$existing = Test-Path (Join-Path $Target 'start_all.ps1')
if ($existing) {
    Note "An existing installation was found at $Target"
    Info 'Installation replaces source files, keeps logs and venv, and backs up payload.json.'
    if ($Check) { Info 'Check mode leaves all files unchanged.' }
} else {
    Good 'Clean installation (destination is empty or does not exist)'
}

$busy = @()
foreach ($p in @(443, 4567, 8080, 8899, 8900)) {
    if (Test-Port $p) { $busy += $p }
}
if ($busy.Count -gt 0) {
    Note ("Ports already listening: {0}" -f (($busy | Sort-Object) -join ', '))
    Info 'An instance may already be running. Restart it to load the updated source files.'
    Info 'To stop it, run C:\fsd-mitm\stop_hotspot.ps1 (hotspot mode) or C:\fsd-mitm\stop_fsd_all.ps1 (router mode).'
} else {
    Good 'Required ports are available (443 / 4567 / 8080 / 8899 / 8900)'
}

if ($Check) {
    Write-Host ''
    Write-Host '  ===== Check results (no files changed) =====' -ForegroundColor Cyan
    $items = @(
        @{ N = 'pythonw.exe';       P = (Join-Path $Target 'venv\Scripts\pythonw.exe') },
        @{ N = 'mitmdump.exe';      P = (Join-Path $Target 'venv\Scripts\mitmdump.exe') },
        @{ N = 'CA (certs2)';       P = (Join-Path $Target 'certs2\mitmproxy-ca.pem') },
        @{ N = 'payload.json';      P = (Join-Path $Target 'payload.json') },
        @{ N = 'start_hotspot.ps1'; P = (Join-Path $Target 'start_hotspot.ps1') },
        @{ N = 'stop_hotspot.ps1';  P = (Join-Path $Target 'stop_hotspot.ps1') },
        @{ N = 'start_all.ps1';     P = (Join-Path $Target 'start_all.ps1') },
        @{ N = 'stop_fsd_all.ps1';  P = (Join-Path $Target 'stop_fsd_all.ps1') },
        @{ N = 'tools\arp_mitm.py'; P = (Join-Path $Target 'tools\arp_mitm.py') },
        @{ N = 'web\fsd_panel.py';  P = (Join-Path $Target 'web\fsd_panel.py') }
    )
    foreach ($i in $items) {
        if (Test-Path $i.P) { Good $i.N } else { Fail $i.N }
    }
    # A working venv can be used without finding another Python installation.
    if (Test-InstalledVenv (Join-Path $Target 'venv')) {
        Good 'Python: existing venv passed runtime and dependency checks'
    } else {
        Fail 'The venv is missing or unusable'
        $probe = Find-Python
        if ($probe) {
            Good ("Python {0} is available to rebuild the venv ({1})" -f $probe.Version, $probe.Via)
        } else {
            Fail 'Python 3.12 or later was not found. Rerun with -AutoInstallPython and without -Check.'
        }
    }
    $pl = Join-Path $Target 'payload.json'
    if (Test-Path $pl) {
        try {
            $txt = (Get-Content -LiteralPath $pl -Raw).Trim()
            $obj = $txt | ConvertFrom-Json
            $n = @($obj.PSObject.Properties).Count
            Good ("payload.json is valid ({0} bytes, {1} fields)" -f (Get-Item $pl).Length, $n)
        } catch { Fail 'payload.json is invalid JSON' }
    }
    Write-Host ''
    Write-Host ("  OK={0} WARN={1} FAIL={2}" -f $script:okCount, $script:warnCount, $script:failCount) -ForegroundColor $(if ($script:failCount) { 'Red' } else { 'Green' })
    if ($script:failCount -eq 0) {
        Write-Host '  All dependencies are available. Run C:\fsd-mitm\start_all.cmd to start.' -ForegroundColor Green
    } else {
        Write-Host '  Rerun the installer without -Check to install the missing items listed above.' -ForegroundColor Yellow
    }
    exit $(if ($script:failCount) { 1 } else { 0 })
}

# ---------------------------------------------------------------- 2 Copy files
Step '2/7' 'Copy application files'
New-Item -ItemType Directory -Path $Target -Force | Out-Null
$plTarget = Join-Path $Target 'payload.json'
if (Test-Path $plTarget) {
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    Copy-Item -LiteralPath $plTarget -Destination ("{0}.preinstall-{1}" -f $plTarget, $ts) -Force
    Info ("Backed up the existing payload to payload.json.preinstall-{0}" -f $ts)
}
$rc = robocopy $src $Target /E /NFL /NDL /NJH /NJS /NP /XD 'logs' 'venv' 'backup' '__pycache__' /XF '*.pyc'
if ($LASTEXITCODE -ge 8) {
    Fail ("Robocopy failed with exit code {0}" -f $LASTEXITCODE)
    exit 3
}
Good ("Copied {0} files (preserved logs and venv)" -f (Get-ChildItem $src -Recurse -File).Count)

# Windows PowerShell 5.1 uses the system ANSI code page for scripts without a BOM.
# Add a UTF-8 BOM to copied scripts so PowerShell reads their text correctly.
$bomFixed = 0
Get-ChildItem -LiteralPath $Target -Recurse -Filter '*.ps1' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "*\venv\*" } |
    ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        if (-not $hasBom) {
            $out = New-Object 'byte[]' ($bytes.Length + 3)
            $out[0] = 0xEF; $out[1] = 0xBB; $out[2] = 0xBF
            [Array]::Copy($bytes, 0, $out, 3, $bytes.Length)
            [System.IO.File]::WriteAllBytes($_.FullName, $out)
            $script:bomFixed++
        }
    }
if ($bomFixed -gt 0) { Good ("Added a UTF-8 BOM to {0} PowerShell scripts" -f $bomFixed) }
else { Good 'All PowerShell scripts have a UTF-8 BOM' }

# ---------------------------------------------------------------- 3 venv
Step '3/7' 'Python virtual environment'
$venvDir = Join-Path $Target 'venv'
$venvPy  = Join-Path $venvDir 'Scripts\python.exe'
$venvPyw = Join-Path $venvDir 'Scripts\pythonw.exe'
$venvMit = Join-Path $venvDir 'Scripts\mitmdump.exe'
$req     = Join-Path $Target 'requirements.txt'

if ($SkipVenv) {
    Note 'Skipped virtual environment setup (-SkipVenv)'
} elseif (Test-InstalledVenv $venvDir) {
    Good 'The existing venv passed runtime and dependency checks'
} else {
    $py = Find-Python
    if (-not $py -and $AutoInstallPython) {
        $winget = Get-Command 'winget' -CommandType Application -ErrorAction SilentlyContinue
        if ($winget) {
            Info 'Compatible Python was not found. Installing Python 3.12 via WinGet (requires internet access and may prompt for UAC)...'
            & $winget.Source install --id Python.Python.3.12 -e --source winget --silent `
                --accept-package-agreements --accept-source-agreements
            if ($LASTEXITCODE -ne 0) {
                Note ("WinGet returned exit code {0} while installing Python" -f $LASTEXITCODE)
            }
            $py = Find-Python
        } else {
            Note 'WinGet is unavailable for automatic Python installation'
        }
    }
    if (-not $py) {
        Fail 'No compatible Python 3.12 or later with venv and ensurepip was found'
        Info 'Checked -PythonExe, PATH, the Python launcher, standard installation directories, registry, bundled runtimes, and the existing venv base.'
        Info 'Skipped WindowsApps\python.exe because it is a Microsoft Store execution alias.'
        Info ''
        Info 'Available installation options:'
        Info '  1) Install automatically: .\install.ps1 -AutoInstallPython'
        Info '  2) Install manually:      winget install Python.Python.3.12'
        Info '     Or download from https://www.python.org/downloads/windows/ and select Add to PATH.'
        Info '  3) Specify an interpreter: .\install.ps1 -PythonExe "C:\Path\python.exe"'
        exit 4
    }
    if (Test-Path -LiteralPath $venvDir) {
        $bak = "$venvDir.broken-$(Get-Date -Format 'yyyyMMdd-HHmmssfff')"
        try {
            Move-Item -LiteralPath $venvDir -Destination $bak -ErrorAction Stop
        } catch {
            Fail ("Could not back up the existing venv: {0}" -f $_.Exception.Message)
            exit 4
        }
        Note ("Renamed the incomplete venv to {0}" -f (Split-Path $bak -Leaf))
    }
    Good ("Using Python {0} ({1})" -f $py.Version, $py.Via)
    Info ("Interpreter: {0} {1}" -f $py.Exe, ($py.Pre -join ' '))
    Info 'Creating the venv...'
    $pythonArgs = $py.Pre
    & $py.Exe @pythonArgs -I -m venv $venvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPy)) {
        Fail 'Could not create the venv'
        exit 4
    }
    Good 'Created the venv'

    $pipArgs = @('install', '--disable-pip-version-check', '--no-input', '-r', $req)
    if ($UseMirror) {
        $pipArgs += @('-i', 'https://pypi.tuna.tsinghua.edu.cn/simple',
                      '--trusted-host', 'pypi.tuna.tsinghua.edu.cn')
        Info 'pip is using the Tsinghua mirror'
    }
    Info 'Installing dependencies (mitmproxy 12.3.1, scapy, Flask, and cryptography). First-time setup usually takes 2 to 5 minutes.'
    & $venvPy -I -m pip @pipArgs
    if ($LASTEXITCODE -ne 0) {
        Fail ("pip install failed with exit code {0}" -f $LASTEXITCODE)
        Info 'For network issues, retry with .\install.ps1 -UseMirror'
        exit 4
    }
    if (-not (Test-InstalledVenv $venvDir)) {
        Fail 'The venv did not pass its checks after dependency installation'
        exit 4
    }
    Good 'Dependencies installed and mitmdump.exe is available'
}

# ---------------------------------------------------------------- 4 Verify files
Step '4/7' 'Verify required files'
$checks = @(
    @{ N = 'venv\Scripts\pythonw.exe';   P = $venvPyw },
    @{ N = 'venv\Scripts\mitmdump.exe';  P = $venvMit },
    @{ N = 'certs2\mitmproxy-ca.pem';    P = (Join-Path $Target 'certs2\mitmproxy-ca.pem') },
    @{ N = 'payload.json';               P = $plTarget },
    @{ N = 'fsd_mock.py';                P = (Join-Path $Target 'fsd_mock.py') },
    @{ N = 'start_hotspot.ps1';          P = (Join-Path $Target 'start_hotspot.ps1') },
    @{ N = 'stop_hotspot.ps1';           P = (Join-Path $Target 'stop_hotspot.ps1') },
    @{ N = 'dns_sink.py';                P = (Join-Path $Target 'dns_sink.py') },
    @{ N = 'start_all.ps1';              P = (Join-Path $Target 'start_all.ps1') },
    @{ N = 'stop_fsd_all.ps1';           P = (Join-Path $Target 'stop_fsd_all.ps1') },
    @{ N = 'tools\arp_mitm.py';          P = (Join-Path $Target 'tools\arp_mitm.py') },
    @{ N = 'tools\supervise_all.py';     P = (Join-Path $Target 'tools\supervise_all.py') },
    @{ N = 'web\fsd_panel.py';           P = (Join-Path $Target 'web\fsd_panel.py') }
)
foreach ($c in $checks) {
    if (Test-Path $c.P) { Good $c.N } else { Fail $c.N }
}
if (Test-Path $plTarget) {
    try {
        $txt = (Get-Content -LiteralPath $plTarget -Raw).Trim()
        $null = $txt | ConvertFrom-Json
        Good ("payload.json is valid ({0} bytes)" -f (Get-Item $plTarget).Length)
    } catch { Fail 'payload.json is invalid JSON' }
}

# ---------------------------------------------------------------- 5 Shortcuts
Step '5/7' 'Desktop shortcuts'
if ($NoShortcut) {
    Note 'Skipped desktop shortcuts (-NoShortcut)'
} else {
    try {
        $ws = New-Object -ComObject WScript.Shell
        $desktop = [Environment]::GetFolderPath('Desktop')

        $l1 = $ws.CreateShortcut((Join-Path $desktop 'FSD Start.lnk'))
        $l1.TargetPath = Join-Path $Target 'start_hotspot.cmd'
        $l1.WorkingDirectory = $Target
        $l1.IconLocation = 'C:\Windows\System32\shell32.dll,137'
        $l1.Description = 'Start the FSD intercept environment in hotspot mode'
        $l1.Save()

        $l2 = $ws.CreateShortcut((Join-Path $desktop 'FSD Stop.lnk'))
        $l2.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $l2.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Target 'stop_hotspot.ps1') + '" -NoExit'
        $l2.WorkingDirectory = $Target
        $l2.IconLocation = 'C:\Windows\System32\shell32.dll,131'
        $l2.Description = 'Stop the FSD intercept environment in hotspot mode'
        $l2.Save()

        Good 'Created FSD Start and FSD Stop desktop shortcuts'
    } catch {
        Fail ("Could not create a desktop shortcut: {0}" -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- 6 Startup
Step '6/7' 'Start at login (watchdog)'
if ($NoAutostart) {
    Note 'Skipped startup registration (-NoAutostart)'
} else {
    try {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
        $val = '"' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') + '" ' +
               '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
               (Join-Path $Target 'start_hotspot.ps1') + '" -NoFirewall'
        Set-ItemProperty -Path $runKey -Name 'fsd-mitm-supervisor' -Value $val -Type String
        Good 'Registered HKCU\Run\fsd-mitm-supervisor for hotspot mode'
    } catch {
        Fail ("Could not register startup at login: {0}" -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- 7 Launch
Step '7/7' 'Launch'
if ($NoStart) {
    Note 'Skipped launch (-NoStart)'
} else {
    if ($script:failCount -gt 0) {
        Note 'Launch skipped because checks failed. Fix the reported issues, then run C:\fsd-mitm\start_hotspot.cmd.'
    } else {
        Info 'Launching. Select Yes if Windows asks to add firewall rules on first launch.'
        & (Join-Path $Target 'start_hotspot.ps1')
    }
}

# ---------------------------------------------------------------- Summary
Write-Host ''
Write-Host '  ============================================' -ForegroundColor White
Write-Host ("   Result: OK={0} WARN={1} FAIL={2}" -f $script:okCount, $script:warnCount, $script:failCount) -ForegroundColor $(if ($script:failCount) { 'Red' } else { 'Green' })
Write-Host '  ============================================' -ForegroundColor White
Write-Host '   Dashboard       : http://127.0.0.1:8900' -ForegroundColor White
Write-Host '   Payload editor  : http://127.0.0.1:8900/payload' -ForegroundColor White
Write-Host ("   Start           : {0}\start_hotspot.cmd (hotspot mode)" -f $Target) -ForegroundColor DarkGray
Write-Host ("   Status          : powershell -File {0}\start_hotspot.ps1 -Status" -f $Target) -ForegroundColor DarkGray
Write-Host ("   Stop            : powershell -File {0}\stop_hotspot.ps1" -f $Target) -ForegroundColor DarkGray
Write-Host ("   Router mode     : {0}\start_all.cmd (vehicle and computer on the same router)" -f $Target) -ForegroundColor DarkGray
Write-Host ("   Stop intercept  : powershell -File {0}\stop_api_intercept.ps1" -f $Target) -ForegroundColor DarkGray
Write-Host ''

} finally {
    if ($transcript) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

exit $(if ($script:failCount) { 1 } else { 0 })

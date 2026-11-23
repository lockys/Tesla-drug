@echo off
setlocal

if not exist "%~dp0uninstall.ps1" (
    >&2 echo Missing uninstall.ps1. Keep it next to uninstall.cmd.
    if "%~1"=="" pause
    exit /b 1
)

if "%~1"=="" goto confirm

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
exit /b %ERRORLEVEL%

:confirm
echo This will remove C:\fsd-mitm, including logs, payloads, and the virtual environment.
echo Run as administrator under the account that installed FSD.
choice /c YN /n /m "Remove FSD? [Y/N] "
if not "%ERRORLEVEL%"=="1" (
    echo Uninstall cancelled.
    pause
    exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" -Apply
set "UNINSTALL_EXIT=%ERRORLEVEL%"
if not "%UNINSTALL_EXIT%"=="0" echo Uninstall failed. See the message above.
pause
exit /b %UNINSTALL_EXIT%

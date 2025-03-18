@echo off

:: Capture the directory of the script
set "scriptDir=%~dp0"

:: Check if Windows Terminal (wt.exe) is available.
where wt >nul 2>nul
if %errorlevel%==0 (
    :: Run PowerShell script in Windows Terminal.
    :: Script will prompt for elevation if required.
    wt new-tab -p "PowerShell" powershell -NoProfile -ExecutionPolicy Bypass -File "%scriptDir%Tweaks.ps1"
) else (
    :: Run PowerShell script normally with elevated privileges.
    PowerShell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%scriptDir%Tweaks.ps1""' -Verb RunAs}"
)
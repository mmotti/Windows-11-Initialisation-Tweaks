@echo off
:: Check if Windows Terminal (wt.exe) is available.
where wt >nul 2>nul
if %errorlevel%==0 (
    :: Run PowerShell script in Windows Terminal.
    :: Script will prompt for elevation if required.
    wt new-tab -p "PowerShell" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Tweaks.ps1"
) else (
    :: Run PowerShell script normally with elevated privileges.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0Tweaks.ps1\"' -Verb RunAs }"
)
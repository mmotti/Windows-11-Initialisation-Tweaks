$script:BackedUpRegistryPaths = @()
$script:DisableBackups = $false
$script:RegistryTweaksDisabled = $false
$script:ScriptRunBackupDir = $null
$script:OKChar = [char]0x2714
$script:FailChar = [char]0x2716
$script:WarningChar = [char]0x26A0

function Test-IsAdminElevated {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Import-RegKeys {
    param (
        [ValidateNotNullOrEmpty()]
        [string]$keyPath
    )

    if (!(Test-Path -Path $keyPath -PathType Container)) {
        return
    }

    $regKeys = Get-ChildItem -Path $keyPath -Filter "*.reg" -ErrorAction SilentlyContinue

    foreach ($key in $regKeys) {

        if ($script:DisableBackups -eq $false) {
            if (!(Export-RegKeys -KeyPath $key.FullName)) {
                Write-Host "`t$script:FailChar " -NoNewline -ForegroundColor Red
                Write-Host "`t$($key.Name): Failed to create registry backup."
                continue
            }
        }

        $result = reg import $key.FullName 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Host "`t$script:FailChar $($key.Name): $($result -replace '^ERROR:\s*', '')" -ForegroundColor Red
        } else {
            Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
            Write-Host $key.Name
        }
    }
}

function Export-RegKeys {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyPath
    )

    if ($script:DisableBackups -eq $false -and !(Test-Path -Path $script:ScriptRunBackupDir)) {
        return $false
    }

    $regFileContents = Get-Content -Path $KeyPath -ErrorAction SilentlyContinue

    if ($regFileContents) {

        $pattern = '\[(HKEY_[^\]]+)\]'
        $patternMatches = [regex]::Matches($regFileContents, $pattern)
    
        $patternMatches | ForEach-Object {
    
            $keyRegPath = $_.Groups[1].Value
    
            if($keyRegPath -notin $script:BackedUpRegistryPaths) {
    
                $friendlyFileName = $keyRegPath -replace '^([A-Z]{3,4}):\\|\\', '$1-'
    
                $fileNameParts = $friendlyFileName -split '-'
    
                if ($fileNameParts.Count -ge 4) {
                    $friendlyFileName = "$($fileNameParts[0..1] -join '-')...$($fileNameParts[-2..-1] -join '-').reg"
                } else {
                    $friendlyFileName = "${friendlyFileName}.reg"
                }
    
                $result = reg export $keyRegPath "$script:ScriptRunBackupDir\$friendlyFileName" /y 2>&1
    
                if ($LASTEXITCODE -eq 0) {
                    $script:BackedUpRegistryPaths += $_.Groups[1].Value
                    return $true
                } else {
                    return $false
                }
            } else {
                return $true
            }
        }
    }

    return $false
}

if (!(Test-IsAdminElevated)) {

    Write-Warning "Attempting to relaunch the script with elevated privileges..."

    $scriptPath =  $MyInvocation.MyCommand.Path

    if (Get-Command wt -ErrorAction SilentlyContinue) {
        $cmd = "wt"
        $arguments = "new-tab -p `"PowerShell`" powershell -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    } else {
        $cmd = "powershell"
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    }
    
    Start-Process $cmd -ArgumentList $arguments -Verb RunAs
    exit
}

Clear-Host

# ==================== PREREQUISITES CHECK ====================

# Check for Windows 11.

if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
    throw "Windows 11 is required for this script to run."
}

# Check for whether to enable backups or not.
# Disable if running in Windows Sandbox as read-only access and... it's a sandbox.

if ([Environment]::UserName -eq 'WDAGUtilityAccount') {
    $script:DisableBackups = $true
}

# ==================== SYSTEM UTILITIES ====================

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(uint action, uint param, IntPtr vparam, uint init);
}

public class RefreshDesktop
{
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public const uint WM_KEYDOWN = 0x0100;
    public const uint WM_KEYUP = 0x0101;
    public const int VK_F5 = 0x74; // Virtual-key code for the F5 key

    public static void Refresh()
    {
        IntPtr hWnd = FindWindow("Progman", "Program Manager");
        if (hWnd == IntPtr.Zero)
        {
            throw new Exception("Could not find the desktop window.");
        }

        PostMessage(hWnd, WM_KEYDOWN, (IntPtr)VK_F5, IntPtr.Zero);
        PostMessage(hWnd, WM_KEYUP, (IntPtr)VK_F5, IntPtr.Zero);
    }
}
"@

# ==================== BACKUP INITIALISATION ====================

if ($script:DisableBackups -eq $false) {

    Write-Host "[i] Initialising backup area..." -ForegroundColor Blue

    # Initialise the backup folders.

    $backupDir = "$PSScriptRoot\backups"
    $scriptRunID = Get-date -Format 'dd-MM-yy_HH-mm-ss'
    $script:ScriptRunBackupDir = "$backupDir\$scriptRunID"

    # Create the backup dir.

    $backupDirs = @(
        $backupDir,
        $script:ScriptRunBackupDir
    )

    foreach ($dir in $backupDirs) {
        if (!(Test-Path $dir))  {
            try {
                New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "`t$script:FailChar Unable to create path: `"$dir`"." -ForegroundColor Red
                Write-Host "`t$script:WarningChar Registry tweaks will be skipped." -ForegroundColor Yellow
                $script:RegistryTweaksDisabled = $true
                break
            }

            Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
            Write-Host "Registry backup directory initialised:"
            Write-Host "`t`t`"$script:ScriptRunBackupDir`""
        }
    }
}

# ==================== REGISTRY TWEAKS ====================

if ($script:RegistryTweaksDisabled -eq $false) {
    Write-Host "[i] Starting registry tweaks..." -ForegroundColor Blue
    Import-RegKeys -keyPath "$PSScriptRoot\assets\reg"
}

# ==================== SET APPROPRIATE POWER PLAN ====================

# Balanced for X3D, High Performance otherwise.
# Disable sleep whilst AC powered if target plan is balanced.

Write-Host '[i] Setting appropriate power plan...' -ForegroundColor Blue

$powerSchemes = & powercfg /list

if ($powerSchemes) {

    $processorString = $null
    $x3dCPU = $false

    try {
        $processorString = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString").ProcessorNameString
    }
    catch {
        Write-Host "`t$script:WarningChar It was not possible to obtain the processor string." -ForegroundColor Yellow
    }

    $x3dCPU = if ($processorString -and $processorString -match "^AMD.*X3D") { $true } else { $false }
    $targetPowerPlan = if ($x3dCPU) { "Balanced" } else { "High performance" }

    $activeSchemeGUID = [regex]::Match($powerSchemes, 'Power Scheme GUID: ([a-f0-9-]+)\s+\([^\)]+\)\s*\*').Groups[1].Value
    $desiredSchemeGUID = [regex]::Match($powerSchemes, "Power Scheme GUID: ([a-f0-9-]+)\s+\($targetPowerPlan\)").Groups[1].Value

    # If the desired GUID was matched and the active power scheme is not our desired scheme.
    if ($desiredSchemeGUID) {

        if ($activeSchemeGUID -eq $desiredSchemeGUID) {
            Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
            Write-Host "Successfully applied $targetPowerPlan power plan."
        } else {
            # Set the desired scheme.
            Write-Host "[i] Setting active power plan to: $targetPowerPlan" -ForegroundColor Blue
            & powercfg /setactive $desiredSchemeGUID

            if ($LASTEXITCODE -ne 0) {
                Write-Host "`t$script:FailChar Failed to set $targetPowerPlan power plan."-ForegroundColor Red
            } else {
                Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
                Write-Host "Successfully applied $targetPowerPlan power plan."
            }
        }
    }
}

# ==================== ENABLE FEATURES ====================

Write-Host "[i] Processing Windows features..." -ForegroundColor Blue


# Apply Windows Firewall rules only outside of Windows Sandbox.
if ([Environment]::UserName -ne 'WDAGUtilityAccount') {
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Write-Host "`t$script:OKChar " -ForegroundColor Green -NoNewline
        Write-Host "Allowed RDP in Windows Firewall."
    }
    catch {
        Write-Host "`t$script:FailChar: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# ==================== REMOVE SHORTCUTS ====================

$publicShortcuts = @(
    'Microsoft Edge.lnk'
)

if (@($publicShortcuts).Count -gt 0) {

    Write-Host "[i] Processing Public Desktop shortcuts..." -ForegroundColor Blue

    $publicShortcuts |
    ForEach-Object { Join-Path "$env:SYSTEMDRIVE\Users\Public\Desktop" $_ } |
    Where-Object { (Test-Path $_) -and $_ -match "\.lnk$" } |
    ForEach-Object {
        try {
            $_ | Remove-Item -Force
            Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
            Write-Host "Removed `"$_`""
        }
        catch {
            Write-Host "`t$script:FailChar Failed to remove `"$_`"" -ForegroundColor Red
        }
    }
}

# ==================== REMOVE ONEDRIVE ====================

# Standard OneDrive entries.

Write-Host "[i] Checking for OneDrive..." -ForegroundColor Blue

@(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
) | Sort-Object -Unique | Where-Object {Test-Path $_} | ForEach-Object {
    $uninstallString = Get-ItemPropertyValue -Path $_ -Name "UninstallString" -ErrorAction SilentlyContinue
    if ($uninstallString){
        Write-Host "[i] Executing: $uninstallString" -ForegroundColor Blue
        Start-Process cmd -ArgumentList "/c $uninstallString" -Wait
    }
}

# Default user registry hive.

try {
    
    $oneDriveKeyValue = "OneDriveSetup"
    $defaultUserRunPath = "HKU:\TempDefault\Software\Microsoft\Windows\CurrentVersion\Run"

    Write-Host "[i] Checking the default user's registry hive for $oneDriveKeyValue..." -ForegroundColor Blue
    
    $hkuDrive = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop
    
    $null = reg load HKU\TempDefault C:\users\Default\NTUSER.DAT 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to load the default user's registry hive."
    }

    $hiveLoaded = $true

    $oneDriveDefaultUserSetup = Get-ItemProperty -Path $defaultUserRunPath -Name $oneDriveKeyValue -ErrorAction SilentlyContinue

    if ($oneDriveDefaultUserSetup) {
        try {
            Write-Host "[i] Removing $oneDriveKeyValue from $($defaultUserRunPath -replace "HKU:", "HKEY_USERS")" -ForegroundColor Blue
            $oneDriveDefaultUserSetup | Remove-ItemProperty -Name $oneDriveKeyValue -Force
            Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
            Write-Host "Registry key removed."
        }
        catch {
            throw "Failed to remove $oneDriveKeyValue"
        }
    } else {
        Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
        Write-Host "No $oneDriveKeyValue detected in the default user's registry hive."
    }
    
}
catch {
    Write-Host "`t$script:FailChar  $_" -ForegroundColor Red
}
finally {
    if ($hkuDrive) {
        Remove-PSDrive -Name HKU
    }
    if ($hiveLoaded) {
        $null = reg unload HKU\TempDefault 2>&1
    }
}

# ==================== RESURRECT EXPLORER ====================

Write-Host '[i] Restarting explorer...' -ForegroundColor Blue

Stop-Process -Name explorer -Force

while (!(Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 500
}

Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
Write-Host "Explorer restarted."

# ==================== APPLY WALLPAPER CHANGES ====================

Write-Host "[i] Applying wallpaper..." -ForegroundColor Blue

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

$result = [User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, [IntPtr]::Zero, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)

if ($result) {
    Write-Host "`t$script:OKChar " -NoNewline -ForegroundColor Green
    Write-Host "Wallpaper applied."
} else {
    Write-Host "`t$script:FailChar " -NoNewline -ForegroundColor Red
    Write-Host "Failed to apply wallpaper."
}

# ==================== REFRESH DESKTOP ====================

while ([RefreshDesktop]::FindWindow("Progman", "Program Manager") -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 500
    continue
}

Write-Host "[i] Refreshing desktop..." -ForegroundColor Blue

[RefreshDesktop]::Refresh()

Write-Host "[i] Done."
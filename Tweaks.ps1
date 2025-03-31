$script:BackedUpRegistryPaths = @()
$script:DisableBackups = $false
$script:RegistryTweaksDisabled = $false
$script:ScriptRunBackupDir = $null

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

    $regKeys = Get-ChildItem -Path $keyPath -Include *.reg -Recurse -ErrorAction SilentlyContinue |
               Where-Object {$_.DirectoryName -notlike "*\Manual\*"}

    foreach ($key in $regKeys) {

        if ($script:DisableBackups -eq $false) {
            if (!(Export-RegKeys -KeyPath $key.FullName)) {
                Write-Status -Status FAIL -Message "$($key.Name): Failed to create registry backup." -Indent 1
                continue
            }
        }

        $result = reg import $key.FullName 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Status -Status FAIL -Message "$($key.Name): $($result -replace '^ERROR:\s*', '')" -Indent 1
        } else {
            Write-Status -Status OK -Message $key.Name -Indent 1
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

function Write-Status {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet("INFO", "ACTION", "OK", "FAIL", "WARN", IgnoreCase=$true)]
        [string] $Status,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [int] $Indent = 0
    )

    process {

        $OKChar = [char]0x2714
        $FailChar = [char]0x2716
        $WarningChar = [char]0x26A0
        $ActionChar = [char]0x2699

        switch ($Status.ToUpperInvariant()) {
            "ACTION" {$char=$ActionChar;$colour="Blue"}
            "OK" {$char=$OKChar;$colour="Green"}
            "FAIL" {$char=$FailChar;$colour="Red"}
            "WARN" {$char=$WarningChar;$colour="Yellow"}
            default {$char=$null; $colour="White"}
        }

        if ($Indent -gt 0) {
            Write-Host ("`t" * $Indent) -NoNewline
        }

        if ($char) {
            Write-Host $char -ForegroundColor $colour -NoNewline
            $Message = " $Message"
        }

        Write-Host $Message
    }
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

    Write-Status -Status ACTION -Message "Initialising backup area..."

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
                Write-Status -Status FAIL -Message "Unable to create path: `"$dir`"." -Indent 1
                Write-Status -Status WARN -Message "Registry tweaks will be skipped." -Indent 1
                $script:RegistryTweaksDisabled = $true
                break
            }

            Write-Status -Status OK -Message "Registry backup directory initialised:" -Indent 1
            Write-Host "`t`t`"$script:ScriptRunBackupDir`""
        }
    }
}

# ==================== STOP EXPLORER ====================
$getExplorerProcess = {Get-Process -Name "explorer" -ErrorAction SilentlyContinue}
$explorerStopSuccess = $false

if (& $getExplorerProcess) {

    Write-Status -Status ACTION -Message "Stopping explorer..."

    $result = taskkill.exe /im explorer.exe /f 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Status -Status OK -Message "Explorer stopped." -Indent 1
        $explorerStopSuccess = $true
    } else {
        Write-Status -Status FAIL -Message "Failed to stop explorer." -Indent 1
    }
} else {
    $explorerStopSuccess = $true
}

# ==================== REGISTRY TWEAKS ====================

if ($script:RegistryTweaksDisabled -eq $false) {
    Write-Status -Status ACTION -Message "Starting registry tweaks..."
    Import-RegKeys -keyPath "$PSScriptRoot\assets\reg"
}

# ==================== SET APPROPRIATE POWER PLAN ====================

# Balanced for X3D, High Performance otherwise.
# Disable sleep whilst AC powered if target plan is balanced.

Write-Status -Status ACTION -Message "Setting appropriate power plan..."

$powerSchemes = & powercfg /list

if ($powerSchemes) {

    $processorString = $null
    $x3dCPU = $false

    try {
        $processorString = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString").ProcessorNameString
    }
    catch {
        Write-Status -Status WARN -Message "It was not possible to obtain the processor string." -Indent 1
    }

    $x3dCPU = if ($processorString -and $processorString -match "^AMD.*X3D") { $true } else { $false }
    $targetPowerPlan = if ($x3dCPU) { "Balanced" } else { "High performance" }

    $activeSchemeGUID = [regex]::Match($powerSchemes, 'Power Scheme GUID: ([a-f0-9-]+)\s+\([^\)]+\)\s*\*').Groups[1].Value
    $desiredSchemeGUID = [regex]::Match($powerSchemes, "Power Scheme GUID: ([a-f0-9-]+)\s+\($targetPowerPlan\)").Groups[1].Value

    # If the desired GUID was matched and the active power scheme is not our desired scheme.
    if ($desiredSchemeGUID) {

        if ($activeSchemeGUID -eq $desiredSchemeGUID) {
            Write-Status -Status OK -Message "Successfully applied $targetPowerPlan power plan." -Indent 1
        } else {
            # Set the desired scheme.
            Write-Status -Status ACTION -Message "Setting active power plan to: $targetPowerPlan" -Indent 1
            & powercfg /setactive $desiredSchemeGUID

            if ($LASTEXITCODE -ne 0) {
                Write-Status -Status FAIL -Message "Failed to set $targetPowerPlan power plan." -Indent 1
            } else {
                Write-Status -Status OK -Message "Successfully applied $targetPowerPlan power plan." -Indent 1
            }
        }
    }
}

# ==================== ENABLE FEATURES ====================

Write-Status -Status ACTION -Message "Processing Windows features..."


# Apply Windows Firewall rules only outside of Windows Sandbox.
if ([Environment]::UserName -ne 'WDAGUtilityAccount') {
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Write-Status -Status OK -Message "Allowed RDP in Windows Firewall. " -Indent 1
    }
    catch {
        Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
    }
}


# ==================== REMOVE SHORTCUTS ====================

$publicShortcuts = @(
    'Microsoft Edge.lnk'
)

if (@($publicShortcuts).Count -gt 0) {

    Write-Status -Status ACTION -Message "Processing Public Desktop shortcuts..."

    $publicShortcuts |
    ForEach-Object { Join-Path "$env:SYSTEMDRIVE\Users\Public\Desktop" $_ } |
    Where-Object { (Test-Path $_) -and $_ -match "\.lnk$" } |
    ForEach-Object {
        try {
            $_ | Remove-Item -Force
            Write-Status -Status OK -Message "Removed $_" -Indent 1
        }
        catch {
            Write-Status -Status FAIL -Message "Failed to remove $_" -Indent 1
        }
    }
}

# ==================== NOTEPAD SETTINGS (CURRENT USER) ====================

$notepadHiveLoaded = $false

try {

    Write-Status -Status ACTION -Message "Checking for Notepad..."

    $packageName = "Microsoft.WindowsNotepad"
    $appxPackage = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue

    if (!$appxPackage) {
        Write-Status -Status WARN -Message "Notepad is not installed." -Indent 1
        throw
    }
    Write-Status -Status OK -Message "Notepad is installed." -Indent 1

    $notepadHive = Join-Path $env:LOCALAPPDATA "Packages\$($appxPackage.PackageFamilyName)\Settings\settings.dat"
    $notepadConfig = Join-Path $PSScriptRoot "assets\reg\Manual\WindowsNotepad\LocalState.reg"

    $notepadHive, $notepadConfig | ForEach-Object {
        if (!(Test-Path -Path $_ -PathType Leaf)) {
            Write-Status -Status FAIL -Message "Path not found: $_" -Indent 1
            throw
        }
    }

    Write-Status -Status OK -Message "Notepad user hive and configuration file detected." -Indent 1

    $notepadProcess = {Get-Process -Name Notepad -ErrorAction SilentlyContinue}

    if (& $notepadProcess) {

        Write-Status -Status ACTION -Message "Killing Notepad processes..." -Indent 1
        (& $notepadProcess) | ForEach-Object {$_ | Stop-Process -Force}

        while (& $notepadProcess) {
            Start-Sleep -Milliseconds 500
        }
    }

    Write-Status -Status OK -Message "Notepad process killed." -Indent 1

    Write-Status -Status ACTION -Message "Loading Notepad registry hive: `"$notepadHive`"" -Indent 1
    $result = reg load HKU\TempUser $notepadHive 2>&1

    if ($LASTEXITCODE -eq 0) {
        $notepadHiveLoaded = $true
        Write-Status -Status OK -Message "Hive loaded." -Indent 1
    } else {
        Write-Status -Status FAIL -Message "Failed to load hive."
        throw
    }

    Write-Status -Status ACTION -Message "Importing $notepadConfig" -Indent 1
    $result = reg import $notepadConfig 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Status -Status OK -Message "Settings successfully imported." -Indent 1
    } else {
        Write-Status -Status FAIL -Message "Error code $LASTEXITCODE received during the import process." -Indent 1
    }
}
catch {
    if ($_.Exception.Message -ne "ScriptHalted") {
        Write-Host $_.Exception.Message
    }
}

finally {
    if ($notepadHiveLoaded) {
        Write-Status -Status ACTION -Message "Unloading Notepad registry hive..." -Indent 1
        $result = reg unload HKU\TempUser 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status -Status OK -Message "Hive unloaded." -Indent 1
        } else {
            Write-Status -Status FAIL -Message "Error code $LASTEXITCODE received when unloading hive." -indent 1
        }
    }
}

# ==================== REMOVE ONEDRIVE ====================

# Standard OneDrive entries.

Write-Status -Status ACTION -Message "Checking for OneDrive installations..."

$oneDriveInstallations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
) | Sort-Object -Unique | Where-Object {Test-Path $_}

if ($oneDriveInstallations) {
    $oneDriveInstallations | ForEach-Object {
        $uninstallString = Get-ItemPropertyValue -Path $_ -Name "UninstallString" -ErrorAction SilentlyContinue
        if ($uninstallString){
            Write-Status -Status ACTION -Message "Executing: $uninstallString" -Indent 1
            Start-Process cmd -ArgumentList "/c $uninstallString" -Wait
        }
    }
} else {
     Write-Status -Status OK -Message "No OneDrive installations detected." -Indent 1
}

# Default user registry hive.

try {

    $oneDriveKeyValue = "OneDriveSetup"
    $defaultUserRunPath = "HKU:\TempDefault\Software\Microsoft\Windows\CurrentVersion\Run"

    Write-Status -Status ACTION -Message "Checking the default user's registry hive for $oneDriveKeyValue..." -Indent 1

    $hkuDrive = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop

    $null = reg load HKU\TempDefault C:\users\Default\NTUSER.DAT 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to load the default user's registry hive."
    }

    $hiveLoaded = $true

    $oneDriveDefaultUserSetup = Get-ItemProperty -Path $defaultUserRunPath -Name $oneDriveKeyValue -ErrorAction SilentlyContinue

    if ($oneDriveDefaultUserSetup) {
        try {
            Write-Status -Status ACTION -Message "Removing $oneDriveKeyValue from $($defaultUserRunPath -replace "HKU:", "HKEY_USERS")" -Indent 1
            $oneDriveDefaultUserSetup | Remove-ItemProperty -Name $oneDriveKeyValue -Force
            Write-Status -Status OK -Message "Registry key removed." -Indent 1
        }
        catch {
            throw "Failed to remove $oneDriveKeyValue"
        }
    } else {
        Write-Status -Status OK -Message "No `"$oneDriveKeyValue`" detected in the default user's registry hive." -Indent 1
    }

}
catch {
    Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
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

# A little bit of error handling as there's currently a bug or "feature" within Windows Sandbox (insider build)
# where taskkill permissions are denied. If we can't keep explorer killed whilst registry tweaks are applied, some
# settings won't stick (such as small icons).

Write-Status -Status ACTION -Message "Restarting explorer..."

if ($explorerStopSuccess) {
    try {
        Start-Process "explorer.exe"
    }
    catch {
        Write-Status -Status FAIL -Message "Failed to restart explorer " -Indent 1
    }
} else {
    Stop-Process -Name explorer -Force
}

if (!(& $getExplorerProcess)) {
    
    Write-Status -Status ACTION "Waiting for explorer process..." -Indent 1

    while (!(& $getExplorerProcess)) {
        Start-Sleep -Milliseconds 500
    }
}

Write-Status -Status OK -Message "Explorer restarted." -Indent 1

# ==================== APPLY WALLPAPER CHANGES ====================

Write-Status -Status ACTION -Message "Applying wallpaper..."

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

$result = [User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, [IntPtr]::Zero, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)

if ($result) {
    Write-Status -Status OK -Message "Wallpaper applied." -Indent 1
} else {
    Write-Status -Status FAIL -Message "Failed to apply wallpaper." -Indent 1
}

# ==================== REFRESH DESKTOP ====================

while ([RefreshDesktop]::FindWindow("Progman", "Program Manager") -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 500
    continue
}

Write-Status -Status ACTION -Message "Refreshing desktop..."

[RefreshDesktop]::Refresh()

Write-Host
Write-Status -Status OK -Message "Script execution complete."
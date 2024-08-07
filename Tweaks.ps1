. "$PSScriptRoot\assets\classes.ps1"

Function Test-IsAdminElevated {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            return $true
        }
        else {
            return $false
        }
}

Function Test-IsAdminRequired {
    param (
        [Parameter(Mandatory=$true)]
        $keyName
    )

    if ($keyName -notmatch '^HKCU' -and !(Test-IsAdminElevated)) {
        Write-Host "Admin access required: ${keyName}" -ForegroundColor Yellow
        return $true
    }

    return $false
}

# Check for Windows 11.

if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
    throw "Windows 11 is required for this script to run."
}


# Check for Administrator and exit if necessary.

$userIsAdminElevated = Test-IsAdminElevated

# Check for whether to enable backups or not.
# Disable if running in Windows Sandbox as read-only access and... it's a sandbox.

$backupsEnabled = $true

if ([Environment]::UserName -eq 'WDAGUtilityAccount') {
    $backupsEnabled = $false
}

if ($backupsEnabled) {

    # Initialise the backup folders.

    $backupDir = "$PSScriptRoot\backups"
    $scriptRunID = Get-date -Format 'dd-MM-yy_HH-mm-ss'
    $scriptRunBackupDir = "$backupDir\$scriptRunID"

    # Create the backup dir.

    $backupDirs = @(
        $backupDir,
        $scriptRunBackupDir
    )

    foreach ($dir in $backupDirs) {
        if (!(Test-Path $dir))  {
            try {
                New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
            }
            catch {
                throw "Unable to create backup directory: $dir"
            }
        }
    }
}

# Load JSON file with the registry tweaks.

$registryJSON = Get-Content "$PSScriptRoot\assets\reg.json" -ErrorAction Stop | ConvertFrom-Json

if ($registryJSON) {

    Write-Host 'Killing Windows Explorer...'
    taskkill /f /im explorer.exe 2>&1> $null

    foreach ($category in $registryJSON.PSObject.Properties.Name) {

        $tweaks = $registryJSON.$category | Where-Object {$_.IsEnabled.ToUpper() -eq 'TRUE'}
        $tweakCount = @($tweaks).Count
        $successfulTweaks = 0

        if ($tweakCount -eq 0) {
            continue
        }

        Write-Host ("Applying registry tweaks for ${category}:")

        foreach ($tweak in $tweaks) {

            # Check at least an action is set.

            if ([string]::IsNullOrEmpty($tweak.Action)) {
                continue
            }

            $tweakAction = $tweak.Action.ToUpper()

            if ($tweakAction -eq 'ADD') {

                $requiredProperties = @('RegPath', 'Name', 'Type', 'Value')

                if ($requiredProperties | Where-Object {[string]::IsNullOrEmpty($tweak.$_)}) {
                    continue
                }

                $regKeyObject = [RegistryKey]::new($tweak.RegPath, $tweak.Name, $tweak.Type.ToUpper(), $tweak.Value, $null)


            }
            elseif ($tweakAction -eq 'DEL') {

                $requiredProperties = @('RegPath')

                if ($requiredProperties | Where-Object {[string]::IsNullOrEmpty($tweak.$_)}) {
                    continue
                }

                $tweakType = if (!([string]::IsNullOrEmpty($tweak.Type))) { $tweak.Type.ToUpper() } else { $null }

                $regKeyObject = [RegistryKey]::new($tweak.RegPath, $tweak.Name, $tweakType, $null, $null)
            }

            if ($backupsEnabled) {
                $regKeyObject.backupDirectory = $scriptRunBackupDir
            }

            $setResult = switch ($tweakAction) {
                'ADD' {$regKeyObject.addToReg()}
                'DEL' {$regKeyObject.deleteFromReg()}
            }

            if ($setResult) {
                $successfulTweaks++
            }
        }

        $resultOutput = switch ($successfulTweaks) {
            0 {'All tweaks were skipped or failed to apply.', 'Red'}
            {$successfulTweaks -gt 0 -and $successfulTweaks -lt $tweakCount} {"Some tweaks were skipped or failed to apply.", 'Yellow'}
            {$successfulTweaks -eq $tweakCount} {'Tweaks successfully applied.', 'Green'}
        }

        Write-Host $resultOutput[0] -ForegroundColor $resultOutput[1]
    }
}

# Refresh after the changes have been made.

Write-Host 'Starting Windows Explorer process...'
Start-Process explorer.exe

# Chat-GPT generated code to "refresh" the current wallpaper
# and send a virtual F5 to the desktop. 


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

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

[User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, [IntPtr]::Zero, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)

[RefreshDesktop]::Refresh()

# Set the High Performance power plan.

Write-Host 'Tweaking power plan...'

$powerSchemes = powercfg /list

if ($powerSchemes) {
    $activeSchemeGUID = $powerSchemes -match '\*$' `
                                    -replace "Power Scheme GUID: ([a-z0-9\-]+).*",'$1'
    $desiredSchemeGUID = $powerSchemes -match 'High performance' `
                                    -replace "Power Scheme GUID: ([a-z0-9\-]+).*",'$1'

    if ($activeSchemeGUID -ne $desiredSchemeGUID) {
        powercfg /setactive $desiredSchemeGUID
    }

    if ($LASTEXITCODE -eq 0)
    {
        Write-Host "High performance profile active" -ForegroundColor Green
    }
    else {
        write-Host "Failed to set High Performance power plan" -ForegroundColor Red
    }
}

# Admin related tasks.

if ($userIsAdminElevated) {

    # Enable RDP Firewall rules.

    Write-Host 'Enabling RDP firewall rules...'

    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Write-Host "Firewall rules enabled" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to activate firewall rules" -ForegroundColor Red
    }

    # Remove Public Desktop shortcuts.

    Write-Host 'Removing specified Public Desktop shortcuts...'

    $publicDesktopShortcuts = @(
        'C:\Users\Public\Desktop\Microsoft Edge.lnk'
    )

    $publicDesktopShortcutsFound = $false

    foreach ($shortcut in $publicDesktopShortcuts) {

        if (Test-Path $shortcut) {
            $publicDesktopShortcutsFound = $true
            try {
                Remove-item $shortcut
                Write-Host "$shortcut`nRemoved" -ForegroundColor Green
            }
            catch {
                Write-Host "$shortcut`nFailed to remove" -ForegroundColor Red
            }
        }
    }

    if(!$publicDesktopShortcutsFound) {
        Write-Host 'No shortcuts require removal' -ForegroundColor Green
    }
}


# Uninstall OneDrive.

Write-Host 'Checking for OneDrive...'

$oneDriveProcessName = 'OneDrive.exe'
$oneDriveUserPath = "${env:LOCALAPPDATA}\Microsoft\OneDrive\*\OneDriveSetup.exe"
$oneDriveProgramFilesPath = "${env:PROGRAMFILES(X86)}\Microsoft OneDrive\*\OneDriveSetup.exe"
$oneDriveSystemPaths = @(
    "${env:systemroot}\System32\OneDriveSetup.exe",
    "${env:systemroot}\SysWOW64\OneDriveSetup.exe"
)

$oneDriveProcessObject = Get-Process $oneDriveProcessName -ErrorAction SilentlyContinue

if ($oneDriveProcessObject) {
    Write-Host "OneDrive process was found" -ForegroundColor Yellow
    taskkill /f /im OneDrive.exe 2>&1 > $null
}

if ($userIsAdminElevated) {

    foreach ($uninstallPath in $oneDriveSystemPaths) {
        if (Test-Path $uninstallPath) {
            Write-Host "OneDrive Found: $uninstallPath" -ForegroundColor Yellow
            Start-Process $uninstallPath -ArgumentList '/uninstall /allusers' -PassThru | Wait-Process
        }
    }

    $oneDriveProgramFiles = Get-ChildItem -Path $oneDriveProgramFilesPath `
                                -Filter OneDriveSetup.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($oneDriveProgramFiles) {
        Write-Host "OneDrive Found: $($oneDriveProgramFiles.FullName)" -ForegroundColor Yellow
        Start-Process $oneDriveProgramFiles.FullName -ArgumentList '/uninstall /allusers' -PassThru | Wait-Process
    }
}

# %localappdata% installer.
# I've come across it installed here too previously.

if (Test-Path $oneDriveUserPath) {
    $oneDriveUserPath = Get-ChildItem -Path $oneDriveUserPath `
                                -Filter OneDriveSetup.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($oneDriveUserPath) {
        Write-Host "OneDrive Found: $($oneDriveUserPath.FullName)" -ForegroundColor Yellow
        Start-Process $oneDriveUserPath.FullName -ArgumentList '/uninstall' -PassThru | Wait-Process
    }
}

 # Remove backup directory if no changes were made.
 
 if ($backupsEnabled) {
    if (!(Get-ChildItem -Path $scriptRunBackupDir -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $scriptRunBackupDir
    }
 }
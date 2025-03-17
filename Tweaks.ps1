$script:BackedUpRegistryPaths = @()

$classFilePath = "$PSScriptRoot\assets\classes.ps1"

if (!(Test-Path $classFilePath)) {
    throw "The file path `"$classFilePath`" does not exist."
}

. $classFilePath

$GENERIC_SUCCESS_MESSAGE = "Tweaks successfully applied."
$GENERIC_FAIL_MESSAGE = "Failed to apply tweaks."

Function Test-IsAdminElevated {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
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

Clear-Host

# ==================== PREREQUISITES CHECK ====================

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

# ==================== SYSTEM UTILITIES ====================

# Workaround for "refreshing" the desktop.

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

# ==================== REGISTRY TWEAKS ====================

# Load JSON file with the registry tweaks.

$registryJSON = Get-Content "$PSScriptRoot\assets\reg.json" -ErrorAction Stop | ConvertFrom-Json

if ($registryJSON) {

    foreach ($category in $registryJSON.PSObject.Properties.Name) {

        $tweaks = $registryJSON.$category | Where-Object {$_.IsEnabled.ToUpper() -eq 'TRUE'}
        $tweakCount = @($tweaks).Count
        $successfulTweaks = 0

        if ($tweakCount -eq 0) {
            continue
        }

        Write-Host "[i] Processing `"$category`" registry tweaks..."

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
            {$successfulTweaks -eq $tweakCount} {"Tweaks successfully applied.", 'Green'}
        }

        Write-Host $resultOutput[0] -ForegroundColor $resultOutput[1]
    }
}

# ==================== SET APPROPRIATE POWER PLAN ====================

# Balanced for X3D, High Performance otherwise.
# Disable sleep whilst AC powered if target plan is balanced.

Write-Host '[i] Checking power plan...'

$powerSchemes = & powercfg /list

if ($powerSchemes) {

    $processorString = $null
    $x3dCPU = $false

    try {
        $processorString = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString").ProcessorNameString
    }
    catch {
        Write-Error "It was not possible to capture the ProcessorNameString"
    }

    $x3dCPU = if ($processorString -and $processorString -match "^AMD.*X3D") { $true } else { $false }
    $targetPowerPlan = if ($x3dCPU) { "Balanced" } else { "High performance" }

    $activeSchemeGUID = [regex]::Match($powerSchemes, 'Power Scheme GUID: ([a-f0-9-]+)\s+\([^\)]+\)\s*\*').Groups[1].Value
    $desiredSchemeGUID = [regex]::Match($powerSchemes, "Power Scheme GUID: ([a-f0-9-]+)\s+\($targetPowerPlan\)").Groups[1].Value

    # If the desired GUID was matched and the active power scheme is not our desired scheme.
    if ($desiredSchemeGUID) {

        if ($activeSchemeGUID -eq $desiredSchemeGUID) {

            Write-Host "Successfully applied $targetPowerPlan power plan." -ForegroundColor Green

        } else {

            # Set the desired scheme.
            Write-Host "Setting active power plan to: $targetPowerPlan" -ForegroundColor Blue
            & powercfg /setactive $desiredSchemeGUID

            if ($LASTEXITCODE -ne 0) {
                Write-Host "Failed to set $targetPowerPlan power plan." -ForegroundColor Red
            }

            Write-Host "Successfully applied $targetPowerPlan." -ForegroundColor Green
        }
    }
}

# ==================== ENABLE FEATURES ====================

if ($userIsAdminElevated) {
    # Apply Windows Firewall rules only outside of Windows Sandbox.
    if ([Environment]::UserName -ne 'WDAGUtilityAccount') {
        try {
            Write-Host "[i] Enabling firewall rules (allow RDP)..."
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
            Write-Host $GENERIC_SUCCESS_MESSAGE -ForegroundColor Green
        }
        catch {
            Write-Host $GENERIC_FAIL_MESSAGE -ForegroundColor Red
        }
    }
}

# ==================== REMOVE SHORTCUTS ====================

if ($userIsAdminElevated) {

    $publicShortcuts = @(
        'Microsoft Edge.lnk'
    )

    if (@($publicShortcuts).Count -gt 0) {

        $publicShortcuts |
        ForEach-Object { Join-Path "$env:SYSTEMDRIVE\Users\Public\Desktop" $_ } |
        Where-Object { (Test-Path $_) -and $_ -match "\.lnk$" } |
        ForEach-Object {
            try {
                $_ | Remove-Item -Force
                Write-Host "[-] $_" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to remove `"$_`"" -ForegroundColor Red
            }
        }
    }
}

# ==================== REMOVE ONEDRIVE ====================

Write-Host "[i] Processing OneDrive..."

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
    $oneDriveProcessObject | ForEach-Object {
        $_ | Stop-Process -ErrorAction SilentlyContinue
    }
}

if ($userIsAdminElevated) {

    foreach ($uninstallPath in $oneDriveSystemPaths) {
        if (Test-Path $uninstallPath) {
            Write-Host "Executing: $uninstallPath /uninstall /allusers" -ForegroundColor Blue
            Start-Process $uninstallPath -ArgumentList '/uninstall /allusers' -PassThru | Wait-Process
        }
    }

    $oneDriveProgramFiles = Get-ChildItem -Path $oneDriveProgramFilesPath `
                                -Filter OneDriveSetup.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($oneDriveProgramFiles) {
        Write-Host "Executing: $($oneDriveProgramFiles.FullName) /uninstall /allusers" -ForegroundColor Blue
        Start-Process $oneDriveProgramFiles.FullName -ArgumentList '/uninstall /allusers' -PassThru | Wait-Process
    }
}

# %localappdata% installer.
# I've come across it installed here too previously.

if (Test-Path $oneDriveUserPath) {
    $oneDriveUserPath = Get-ChildItem -Path $oneDriveUserPath `
                                -Filter OneDriveSetup.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($oneDriveUserPath) {
        Write-Host "Executing: $($oneDriveUserPath.FullName) /uninstall" -ForegroundColor Blue
        Start-Process $oneDriveUserPath.FullName -ArgumentList '/uninstall' -PassThru | Wait-Process
    }
}

# ==================== BACKUP CLEANUP ====================

 # Remove backup directory if no changes were made.

 if ($backupsEnabled) {
    if (!(Get-ChildItem -Path $scriptRunBackupDir -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $scriptRunBackupDir
    }
 }

# ==================== RESURRECT EXPLORER ====================

Write-Host '[i] Restarting explorer...'

Stop-Process -Name explorer -Force

while (!(Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 500
}

# ==================== APPLY WALLPAPER CHANGES ====================

Write-Host "[i] Applying wallpaper..."

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

[User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, [IntPtr]::Zero, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE) | Out-Null

# ==================== REFRESH DESKTOP ====================

while ([RefreshDesktop]::FindWindow("Progman", "Program Manager") -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 500
    continue
}

Write-Host "[i] Refreshing desktop..."
[RefreshDesktop]::Refresh()

Write-Host "[i] Done."
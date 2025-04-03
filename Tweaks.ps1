<#
.SYNOPSIS
    Configures and tweaks Windows 11 settings.

.DESCRIPTION
    This script applies various registry tweaks, sets power plans, manages firewall rules,
    removes specified shortcuts, configures Notepad, removes OneDrive, and applies a custom wallpaper.
    It includes options for enabling/disabling registry tweaks and backups, and a switch
    to indicate intent to modify the Default user profile (implementation specifics may vary).

.PARAMETER EnableBackups
    Enable or disable the creation of backups before applying changes. Defaults to $true.
    Backups are automatically disabled if running in Windows Sandbox.

.PARAMETER DefaultUser
    A switch parameter. If present, the script will attempt to apply relevant settings
    (like specific registry tweaks) to the Default User profile instead of the current user.
    NOTE: Full implementation for default user requires modifying functions to target the
    Default User registry hive (NTUSER.DAT) and profile folders.

.EXAMPLE
    .\Tweaks.ps1
    Runs the script with default settings (Registry Tweaks enabled, Backups enabled, targets current user).

.EXAMPLE
    .\Tweaks.ps1 -DefaultUser
    Runs the script attempting to target the Default User profile where applicable

    .EXAMPLE
    .\Tweaks.ps1 -AllUsers
    Runs the script attempting to target all existing user profiles (excluding Default).
.NOTES
    Author: mmotti (https://github.com/mmotti)
    Requires Windows 11 (Build 22000+).
    Ensure the 'assets' folder structure exists relative to the script.
#>

[CmdletBinding(DefaultParameterSetName='CurrentUser')] # Define the default behavior set
param(
    # --- Parameter Set: All Users ---
    [Parameter(ParameterSetName='AllUsers',
               Mandatory=$false,
               HelpMessage="Apply settings to all existing user accounts (excluding Default).")]
    [switch]$AllUsers,

    # --- Parameter Set: Default User ---
    [Parameter(ParameterSetName='DefaultUser',
               Mandatory=$false,
               HelpMessage="Apply settings to the Default User profile template for future new users.")]
    [switch]$DefaultUser,

    # --- Common Parameter (Available in ALL sets, including the default 'CurrentUser' set) ---
    [Parameter(Mandatory=$false, HelpMessage="Enable or disable backups.")]
    [bool]$EnableBackups = $true
)

$global:scriptPath = $MyInvocation.MyCommand.Path
$global:scriptParentDir = Split-Path $global:scriptPath -Parent

$global:DefaultUserOnly = $DefaultUser.IsPresent
$global:AllUsers = $AllUsers.IsPresent
$global:RegistryTweaksEnabled = $true
$global:BackupsEnabled = $EnableBackups
$global:BackupDirectory = (Join-Path $global:scriptParentDir "backups\$(Get-date -Format 'dd-MM-yy_HH-mm-ss')")


$ps1Path = Join-Path $global:scriptParentDir "assets\ps1"
$ps1Functions = Join-Path $ps1Path "Functions.ps1"

$ps1Path, $ps1Functions | ForEach-Object {
    if (!(Test-Path -Path $_)) {
        throw "Path not found: $_"
    }
}

# ==================== IMPORTS ====================

# Fail here if we can't import the functions otherwise the rest 
# of the script will fail.

try {
    . $ps1Functions
} catch {
    throw "Unable to import file: $ps1Functions"
}

# ==================== OBTAIN ELEVATION ====================

Get-ElevatedTerminal

Clear-Host

# ==================== PREREQUISITES CHECK ====================

# Check for Windows 11.

if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
    Write-Status -Status FAIL -Message "Windows 11 is required for this script to run."
    throw
}

# Check for whether to enable backups or not.
# Disable if running in Windows Sandbox as read-only access and... it's a sandbox.

if ([Environment]::UserName -eq 'WDAGUtilityAccount') {
    $global:BackupsEnabled = $false
}


# ==================== BACKUP INITIALISATION ====================

if ($global:BackupsEnabled -eq $true) {
    # Initialise the backup folders.
    New-BackupDirectory -BackupPath $global:BackupDirectory
}

# ==================== STOP EXPLORER ====================

$explorerStopSuccess = Stop-Explorer

# ==================== REGISTRY TWEAKS ====================

if ($global:RegistryTweaksEnabled -eq $true) {
    
    Write-Status -Status ACTION -Message "Starting registry tweaks..."

    $keyArray = Get-ChildItem -Path (Join-Path $global:scriptParentDir "assets\reg") -Include *.reg -Recurse -ErrorAction SilentlyContinue

    if ($DefaultUser.IsPresent) {
        Import-RegKeys -KeyArray $keyArray -DefaultUser
    } elseif ($AllUsers.IsPresent) {
        Import-RegKeys -KeyArray $keyArray -AllUsers
    } else {
        Import-RegKeys -KeyArray $keyArray
    }
}

# ==================== SET APPROPRIATE POWER PLAN ====================

# Balanced for X3D, High Performance otherwise.
# Disable sleep whilst AC powered if target plan is balanced.

Write-Status -Status ACTION -Message "Setting appropriate power plan..."

if (!(Set-PowerPlan)) {
    Write-Status -Status FAIL -Message "Power plan change failed."
}

# ==================== ENABLE FEATURES ====================

Write-Status -Status ACTION -Message "Processing Windows Firewall rules..."

if ([Environment]::UserName -ne 'WDAGUtilityAccount') {
    Add-FirewallRules
}

# ==================== REMOVE SHORTCUTS ====================

$publicDesktopShortcuts = @(
    'Microsoft Edge.lnk'
)

Remove-PublicDesktopShortcuts -ShortcutArray $publicDesktopShortcuts

# ==================== NOTEPAD SETTINGS (CURRENT USER) ====================

Write-Status -Status ACTION -Message "Processing Notepad settings..." -Indent 1
try {

    $notepadTweakPath = (Join-Path $global:scriptParentDir "assets\dat\WindowsNotepad\Settings.dat")
    $notepadResult = $false

    if ($AllUsers.IsPresent) {
        $notepadResult = Import-NotepadTweaks -TweakPath $notepadTweakPath -AllUsers
    } elseif ($DefaultUser.IsPresent) {
        $notepadResult = Import-NotepadTweaks -TweakPath $notepadTweakPath -DefaultUser
    } else {
        $notepadResult = Import-NotepadTweaks -TweakPath $notepadTweakPath
    }

    if (-not $notepadResult) {
        Write-Status -Status WARN -Message "Notepad tweak processing completed with one or more errors." -Indent 1
    }
}
catch {
    Write-Status -Status FAIL -Message "Failed to apply Notepad tweaks. Error: $($_.Exception.Message)" -Indent 1
}

# ==================== REMOVE ONEDRIVE ====================

Remove-OneDrive

# ==================== RESURRECT EXPLORER ====================

# A little bit of error handling as there's currently a bug or "feature" within Windows Sandbox (insider build)
# where taskkill permissions are denied. If we can't keep explorer killed whilst registry tweaks are applied, some
# settings won't stick (such as small icons).

Start-Explorer -ExplorerStoppedSuccessfully $explorerStopSuccess

# ==================== APPLY WALLPAPER CHANGES ====================

if (Update-Wallpaper) {
    Write-Status -Status OK -Message "Wallpaper applied." -Indent 1
} else {
    Write-Status -Status FAIL -Message "Failed to apply wallpaper." -Indent 1
}

# ==================== REFRESH DESKTOP ====================
Write-Status -Status ACTION -Message "Updating the desktop..."
Update-Desktop

# ==================== CLEAN-UP ====================
Write-Status -Status ACTION -Message "Cleaning up..."
Remove-Variable -Name scriptPath, scriptParentDir, RegistryTweaksEnabled, BackupsEnabled, ScriptRunBackupDir, DefaultUserOnly, AllUsers -Scope Global -ErrorAction SilentlyContinue
Write-Status -Status OK -Message "Clean-up complete." -Indent 1

# ==================== DONE ====================

Write-Host
Write-Status -Status OK -Message "Script execution complete. Press any key to exit..."
$null = $host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
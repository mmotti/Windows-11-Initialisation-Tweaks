<#
.SYNOPSIS
    A comprehensive script for customizing Windows 11 settings, applying privacy enhancements etc.

.DESCRIPTION
    This script provides several functional and privacy related tweaks to Windows 11.
    For further information on the script actions, please see: https://github.com/mmotti/Windows-11-Initialisation-Tweaks?tab=readme-ov-file#actions

.PARAMETER EnableBackups
    Enable or disable the creation of backups before applying changes.
    Default: $true.
    Default (Windows Sandbox): $false

.PARAMETER DefaultUser
    A switch parameter. If present, the script will attempt to apply relevant settings
    (like specific registry tweaks) to the Default User profile instead of the current user.

.PARAMETER AllUsers
    A switch parameter. If present, the script will attempt to apply relevant settings
    (like specific registry tweaks) to the each user profile (including the current user).

.PARAMETER Debloat
    A switch parameter. If present, the script will attempt to debloat Windows by removing packages specified
    within the configuration file.

.PARAMETER NoWait
    A switch parameter. If present, the script will not pause at the end of execution.

.EXAMPLE
    .\Tweaks.ps1
    See basic and advanced usage instructions here: https://github.com/mmotti/Windows-11-Initialisation-Tweaks?tab=readme-ov-file#usage

.LINK
    https://github.com/mmotti/Windows-11-Initialisation-Tweaks

.NOTES
    Author: mmotti (https://github.com/mmotti)
    Requires Windows 11 (Build 22000+).
    Requires PowerShell 5.1 or higher.
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
    [Parameter(ParameterSetName='DefaultUser',
               Mandatory=$false,
               HelpMessage="Specify a custom path for a default user hive.")]
    [ValidateNotNullOrEmpty()] # Prevent the user from being able to provide an empty or null string as an argument.
    [string]$DefaultUserCustomHive = $null,

    # --- Common Parameter (Available in ALL sets, including the default 'CurrentUser' set) ---
    [Parameter(Mandatory=$false, HelpMessage="Enable or disable backups.")]
    [bool]$EnableBackups = $true,
    [Parameter(Mandatory=$false, HelpMessage="Debloat apps listed within the configuration file.")]
    [switch]$Debloat,
    [Parameter(Mandatory=$false, HelpMessage="Disable waiting on exit.")]
    [switch]$NoWait
)

Clear-Host

# Try block we can make us of finally
try {

    $global:g_scriptPath = $MyInvocation.MyCommand.Path
    $global:g_scriptParentDir = Split-Path $global:g_scriptPath -Parent

    $global:g_DefaultUserOnly = $PSCmdlet.ParameterSetName -eq "DefaultUser"
    $global:g_AllUsers = $PSCmdlet.ParameterSetName -eq "AllUsers"

    $global:g_DefaultUserCustomHive = $null
    if (![string]::IsNullOrWhiteSpace($DefaultUserCustomHive)) {
        if (!((Test-Path -Path $DefaultUserCustomHive -PathType Leaf) -and $DefaultUserCustomHive -match "\.dat$" )) {
            throw "Invalid path specified for -DefaultUserCustomHive."
        }
        $global:g_DefaultUserCustomHive = $DefaultUserCustomHive
    }

    $global:g_RegistryTweaksEnabled = $true
    $global:g_BackupsEnabled = $EnableBackups
    $global:g_BackupDirectory = (Join-Path $global:g_scriptParentDir "backups\$(Get-date -Format 'dd-MM-yy_HH-mm-ss')")

    $ps1Path = Join-Path $global:g_scriptParentDir "assets\ps1"
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

    Get-ElevatedTerminal -OriginalParameters $PSBoundParameters

    # ==================== PREREQUISITES CHECK ====================

    write-Status -Status ACTION -Message "Running prerequisite checks..."

    # Check for Windows 11.

    if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
        throw "Windows 11 is required for this script to run."
    }

    # Check for whether to enable backups or not.
    # Disable if running in Windows Sandbox as read-only access and... it's a sandbox.

    if ([Environment]::UserName -eq 'WDAGUtilityAccount') {
        Write-Status -Status WARN -Message "Backups disabled (Windows Sandbox detected)." -Indent 1
        $global:g_BackupsEnabled = $false
    }

    # Check for >1 user logged in when -AllUsers is used.

    if ($global:g_AllUsers) {
        if ((Get-ActiveUserSessionCount) -gt 1) {
            throw "Please ensure you are the only logged on user with the -AllUsers switch."
        }
    }

    # ==================== BACKUP INITIALISATION ====================

    if ($global:g_BackupsEnabled -eq $true) {
        # Initialise the backup folders.
        New-BackupDirectory -BackupPath $global:g_BackupDirectory
    }

    # ==================== STOP EXPLORER ====================

    $explorerStopSuccess = Stop-Explorer

    # ==================== REGISTRY TWEAKS ====================

    if ($global:g_RegistryTweaksEnabled -eq $true) {

        Write-Status -Status ACTION -Message "Starting registry tweaks..."

        $keyArray = Get-ChildItem -Path (Join-Path $global:g_scriptParentDir "assets\reg") -Include *.reg -Recurse -ErrorAction SilentlyContinue

        $argParams = @{
            KeyArray = $keyArray
        }

        if ($global:g_DefaultUserOnly) {
            $argParams.DefaultUser = $true
        } elseif ($global:g_AllUsers) {
            $argParams.AllUsers = $true
        }

        Import-RegKeys @argParams
    }

    # ==================== Start Menu ====================

    if ($global:g_DefaultUserOnly) {

        $start2Path = Join-Path -Path $global:g_scriptParentDir -ChildPath "assets\bin\StartMenu\start2.bin"

        if (Test-Path -Path $start2Path -PathType Leaf) {
            Copy-DefaultStartMenu -Start2Path $start2Path
        }
    }

    # ==================== DEBLOAT ====================

    if ($Debloat) {

        $debloatPath = Join-Path -Path $global:g_scriptParentDir -ChildPath "assets\txt\debloat.txt"

        if (Test-Path -Path $debloatPath -PathType Leaf) {

            $argParams = @{}

            if ($global:g_DefaultUserOnly) {
                $argParams.DefaultUser = $true
            } elseif ($global:g_AllUsers) {
                $argParams.AllUsers = $true
            }

            Start-Debloat -DebloatConfig $debloatPath @argParams
        }
    }

    # ==================== SET APPROPRIATE POWER PLAN ====================

    # Balanced for X3D, High Performance otherwise.
    # Disable sleep whilst AC powered if target plan is balanced.

    Write-Status -Status ACTION -Message "Setting appropriate power plan..."

    if (!(Set-PowerPlan)) {
        Write-Status -Status FAIL -Message "Power plan change failed." -Indent 1
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

        $notepadTweakPath = (Join-Path $global:g_scriptParentDir "assets\dat\WindowsNotepad\Settings.dat")
        $notepadResult = $false

        $argParams = @{
            TweakPath = $notepadTweakPath
        }

        if ($global:g_DefaultUserOnly) {
            $argParams.DefaultUser = $true
        } elseif ($global:g_AllUsers) {
            $argParams.AllUsers = $true
        }

        $notepadResult = Import-NotepadTweaks @argParams

        if (-not $notepadResult) {
            Write-Status -Status WARN -Message "Notepad tweak processing completed with one or more errors." -Indent 1
        }
    }
    catch {
        Write-Status -Status FAIL -Message "Failed to apply Notepad tweaks. Error: $($_.Exception.Message)" -Indent 1
    }

    # ==================== REMOVE ONEDRIVE ====================

    # Modes:
    # CurrentUser: Only run HKCU uninstallers.
    # AllUsers: Run uninstallers found in HKCU and HKLM, and notify of other user installations (if applicable).
    # DefaultUser: Remove from registry Default registry hive.

    $argParams = @{}

    if ($global:g_DefaultUserOnly) {
        $argParams.DefaultUser = $true
    } elseif ($global:g_AllUsers) {
        $argParams.AllUsers = $true
    }

    Remove-OneDrive @argParams

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
} catch {
    Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
    exit 1
} finally {
     # ==================== CLEAN-UP ====================
     Write-Status -Status ACTION -Message "Cleaning up..."
     Get-Variable -Scope Global -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "g_*"} | ForEach-Object {$_ | Remove-Variable -ErrorAction SilentlyContinue}
 
     Write-Status -Status OK -Message "Clean-up complete." -Indent 1
 
     # ==================== DONE ====================
 
     Write-Host
     Write-Status -Status OK -Message "Script execution complete."
 
     if (!$NoWait) {
         Write-Host
         Write-Status -Status INFO -Message "Press any key to continue..."
         $null = $host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
     }
}



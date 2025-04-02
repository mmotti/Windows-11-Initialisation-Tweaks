$global:scriptPath = $MyInvocation.MyCommand.Path
$global:scriptParentDir = Split-Path $global:scriptPath -Parent
$global:RegistryTweaksEnabled = $true
$global:BackupsEnabled = $true
$global:ScriptRunBackupDir = (Join-Path $global:scriptParentDir "backups\$(Get-date -Format 'dd-MM-yy_HH-mm-ss')")

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
    New-BackupDirectory -BackupPath $global:ScriptRunBackupDir
}

# ==================== STOP EXPLORER ====================

$explorerStopSuccess = Stop-Explorer

# ==================== REGISTRY TWEAKS ====================

if ($global:RegistryTweaksEnabled -eq $true) {
    Write-Status -Status ACTION -Message "Starting registry tweaks..."

    $keyArray = Get-ChildItem -Path (Join-Path $global:scriptParentDir "assets\reg") -Include *.reg -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.DirectoryName -notlike "*\Manual\*"}

    Import-RegKeys -KeyArray $keyArray
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

if ($global:RegistryTweaksEnabled -eq $true) {
    if (!(Import-NotepadTweaks -TweakPath (Join-Path $global:scriptParentDir "assets\reg\MISC\Manual\WindowsNotepad"))) {
        Write-Status -Status FAIL -Message "Failed to apply Notepad tweaks." -Indent 1
    }
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

Update-Desktop

# ==================== CLEAN-UP ====================

Remove-Variable -Name scriptPath, scriptParentDir, RegistryTweaksEnabled, BackupsEnabled, ScriptRunBackupDir -Scope Global -ErrorAction SilentlyContinue

# ==================== DONE ====================

Write-Host
Write-Status -Status OK -Message "Script execution complete. Press any key to exit..."
$null = $host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
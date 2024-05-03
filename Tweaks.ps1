Function Export-RegBackup {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $backupKeyName, $backupFilename, $backupPath    
    )

    $backupFileNameArray = $backupFileName -split '-'

    if ($backupFileNameArray.Count -ge 4) {
        $backupFileName = "$($backupFileNameArray[0])-$($backupFileNameArray[1])...$($backupFileNameArray[-2])-$($backupFileNameArray[-1]).reg"
    }

    reg export $backupKeyName "$backupPath\$backupFileName" /y 2> $null

    if ($LASTEXITCODE -ne 0) {
        throw "Fatal error: unable to backup registry key(s)"
    }
    else {
        return $true
    }
}

Function Set-RegValueData {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $regKeyName, $regValueName, $regType, $regValueData,

        [Parameter(Mandatory=$false)]
        [bool]
        $regBackup,

        [Parameter(Mandatory=$false)]
        [ValidateScript({
            if ($regBackup -and ($_ -eq $null)) {
                throw "$_ must have a value when regBackup is enabled"
            }
            return $true
        })]
        [string]
        $regBackupPath
    )
        $preSwitchedRegKeyName = $regKeyName

        # Powershell requires altering the reg key prefix
         $regKeyName = switch -Regex ($regKeyName) {
            '^HKEY_CLASSES_ROOT' {$_ -replace 'HKEY_CLASSES_ROOT', 'HKCR:'}
            '^HKEY_CURRENT_USER' {$_ -replace 'HKEY_CURRENT_USER', 'HKCU:'}
            '^HKEY_LOCAL_MACHINE' {$_ -replace 'HKEY_LOCAL_MACHINE', 'HKLM:'}
            '^HKEY_USERS' {$_ -replace 'HKEY_USERS', 'HKU:'}
            '^HKEY_CURRENT_CONFIG' {$_ -replace 'HKEY_CURRENT_CONFIG', 'HKCC:'}
        }

        if ($regBackup) {
            # Create an array to store reg keys that we've already backed up
            $backedUpKeys = @()
            $backupFriendlyRegKeyName = $regKeyName -replace '^([A-Z]{3,4}):\\|\\', '$1-'
        }

        # Handle special cases where the data needs to be formatted from the
        # input Json string
        $regValueData = switch ($regType) {
            'BINARY' {$regValueData -split ',' -as [byte[]]}
            Default {$regValueData}
        }

        # If the path to the key exists
        if (Test-Path $regKeyName) {

            $itemPropertyObject = Get-ItemProperty $regKeyName $regValueName -ErrorAction SilentlyContinue

            # If the key already exists
            # Compare the passed parameter data against the existing values
            if ($null -ne $itemPropertyObject) {

                # First check whether the key is the correct type
                $valueDiff = $false
                $existingRegValueType = $itemPropertyObject.$regValueName.GetType().Name

                $strExistingRegType = switch ($existingRegValueType) {
                    'String' {'STRING'}
                    'Int32' {'DWORD'}
                    'Int64' {'QWORD'}
                    'Byte[]' {'BINARY'}
                    'String[]' {'MULTISTRING'}
                    Default {'UNKNOWN'}
                }

                # Reg value exists but key types are different
                if ($strExistingRegType -ne $regType) {
                    $valueDiff = $true
                }
                # Reg value exists and key types are the same
                else {
                    # Compare passed reg value gainst existing
                    if ($itemPropertyObject.$regValueName -is [array]) {

                        for ($i=0; $i -lt $itemPropertyObject.$regValueName.Count; $i++) {
                            if ($itemPropertyObject.$regValueName[$i] -ne $regValueData[$i]) {
                                $valueDiff = $true
                                break
                            }
                        }
                    }
                    else {
                        if ($itemPropertyObject.$regValueName -ne $regValueData) {
                            $valueDiff = $true
                        }
                    }
                }

                # Differences were found
                # Backups will currently made if we're changing existing reg key values OR
                # if we're creating new values in a path that pre-exists
                if ($valueDiff) {

                    if ($regBackup -and $regKeyName -notin $backedUpKeys) {
                        Export-RegBackup -backupKeyName $preSwitchedRegKeyName -backupFilename $backupFriendlyRegKeyName -backupPath $regBackupPath
                        $backedUpKeys += $regKeyName
                    }

                    try {
                        Set-ItemProperty -Path $regKeyName -Name $regValueName -Type $regType -Value $regValueData -ErrorAction SilentlyContinue
                        return $true
                    }
                    catch{
                        Write-Host "$regKeyName`n$regValueName`Failed to set reg value" -ForegroundColor Red
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
            # Path exists but key doesn't
            else {
                    # Check whether we need to backup the registry key
                    # and do so if necessary
                    if ($regBackup -and $regKeyName -notin $backedUpKeys) {
                        Export-RegBackup -backupKeyName $preSwitchedRegKeyName -backupFilename $backupFriendlyRegKeyName -backupPath $regBackupPath
                        $backedUpKeys += $regKeyName
                    }

                    try {
                        New-ItemProperty -Path $regKeyName -Name $regValueName -Type $regType -Value $regValueData -ErrorAction SilentlyContinue | Out-Null
                        return $true
                    }
                    catch {
                        Write-Host "$regKeyName`n$regValueName`Failed to create reg value" -ForegroundColor Red
                        return $false
                    }
            }
        }
        # Path to key does not exist
        # Create the path and then try to create a new item property
        else {
            try {
                New-Item -Path $regKeyName -ErrorAction SilentlyContinue | Out-Null
                return $true
            }
            catch {
                Write-Host "$regKeyName`nFailed to create reg key" -ForegroundColor Red
                return $false
            }

            try {
                New-ItemProperty -Path $regKeyName -Name $regValueName -Type $regType -Value $regValueData -ErrorAction SilentlyContinue | Out-Null
                return $true
            }
            catch {
                Write-Host "$regKeyName`n$RegValueName`nFailed to create reg value" -ForegroundColor Red
                return $false
            }
        }
}

# Check for Windows 11
if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
    throw "Windows 11 is required for this script to run."
}

# Check for Administrator
# and exit if necessary
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
        GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host 'Administrator privileges are required to change the state of IPv6.' -ForegroundColor Red
    Write-Host 'Please re-run the script as Administrator' -ForegroundColor Red
    Start-Sleep -Seconds 5
    Exit 1
}

# Check for whether to enable backups or not
# Disable if running in Windows Sandbox as read-only access and... it's a sandbox
$backupsEnabled = $true

if ([Environment]::UserName -eq 'WDAGUtilityAccount') {
    $backupsEnabled = $false
}

if ($backupsEnabled) {
    # Initialise the backup folders
    $backupDir = "$PSScriptRoot\backups"
    $scriptRunID = Get-date -Format 'dd-MM-yy_HH-mm-ss'
    $scriptRunBackupDir = "$backupDir\$scriptRunID"

    # Create the backup dir
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

# Load JSON file with the registry tweaks
$registryJSON = Get-Content "$PSScriptRoot\assets\reg.json" -ErrorAction Stop | ConvertFrom-Json

foreach ($category in $registryJSON.PSObject.Properties.Name) {

    Write-Host ("Applying registry tweaks for $category")
    $tweaks = $registryJSON.$category | Where-Object {$_.Active -eq 'true'}
    $tweakCount = $tweaks.Count
    $successfulTweaks = 0

    foreach ($tweak in $tweaks) {

        $requiredProperties = @('Active', 'Action', 'RegPath', 'Name', 'Type', 'Value')

        if ($requiredProperties | Where-Object {$null -eq $tweak.$_}) {
            continue
        }
            
        if ($tweak.Active.ToUpper() -eq 'TRUE') {

            if ($tweak.Action.ToUpper() -eq 'ADD') {

                $regParams = @{
                    regKeyName = $tweak.RegPath
                    regValueName = $tweak.Name
                    regType = $tweak.Type.ToUpper()
                    regValueData = $tweak.Value
                }

                if ($backupsEnabled) {
                    $regParams['regBackup'] = $true
                    $regParams['regBackupPath'] = $scriptRunBackupDir
                }

                $setOrUpdateReg = Set-RegValueData @regParams

                if ($setOrUpdateReg) {
                    $successfulTweaks++
                }
            }
        }
    }

    $foregroundColour = switch ($successfulTweaks) {
        {$successfulTweaks -eq 0} {'Red'}
        {$successfulTweaks -gt 0 -and $successfulTweaks -lt $tweakCount} {'Yellow'}
        {$successfulTweaks -eq $tweakCount} {'Green'}
        default {'White'}
    }

    Write-Host "$successfulTweaks/$tweakCount successful tweaks successful" -ForegroundColor $foregroundColour
}

# Set the High Performance power plan

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

    if ($(powercfg /getactivescheme) -match 'High performance')
    {
        Write-Host "High performance profile active" -ForegroundColor Green
    }
}

# Enable RDP

Write-Host 'Enabling RDP firewall rules...'

try {
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Firewall rules enabled" -ForegroundColor Green
}
catch {
    Write-Host "Failed to activate firewall rules" -ForegroundColor Red
}

# Remove Public Desktop shortcuts

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

# Uninstall OneDrive

Write-Host 'Uninstalling OneDrive (if installed)...'

taskkill /f /im OneDrive.exe 2> $null

# %localappdata installer
if (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive\*\OneDriveSetup.exe") {
    $pathLocalOD = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\OneDrive\" `
                                 -Filter OneDriveSetup.exe -Recurse | Select-Object -First 1
    if ($pathLocalOD) {
        & $pathLocalOD.FullName /uninstall
    }
}

# 32-bit uninstaller
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall /allusers
}

#64-bit uninstaller
if(Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall /allusers
}

#"Refresh" the desktop etc. with direct call to RUNDLL32
 Start-Process "RUNDLL32.EXE" -ArgumentList "USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" -PassThru | Wait-Process
 Stop-Process -Name explorer -PassThru | Wait-Process

 # Remove backup directory if no changes were made
 if ($backupsEnabled) {
    if (!(Get-ChildItem -Path $scriptRunBackupDir)) {
        Remove-Item -Path $scriptRunBackupDir
    }
 }
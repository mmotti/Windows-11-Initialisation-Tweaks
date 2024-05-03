Class RegistryKey {
    [string] $keyName
    [string] $valueName
    [string] $type
    [string] $valueData
    [string] $backupDirectory
    
    RegistryKey ([string]$keyName, [string]$valueName, [string]$type, [string]$valueData, [string]$backupDirectory) {
        $this.keyName = $keyName
        $this.valueName = $valueName
        $this.type = $type
        $this.valueData = $valueData
        $this.backupDirectory = $backupDirectory
    }

    [bool] addToReg() {

        $arrBackedUpKeys = @()
        $preSwitchedRegKeyName = $this.keyName

        # Powershell requires altering the reg key prefix
         $psFriendlyKeyName = switch -Regex ($this.keyName) {
            #'^HKEY_CLASSES_ROOT' {$_ -replace 'HKEY_CLASSES_ROOT', 'HKCR:'}
            '^HKEY_CURRENT_USER' {$_ -replace 'HKEY_CURRENT_USER', 'HKCU:'}
            '^HKEY_LOCAL_MACHINE' {$_ -replace 'HKEY_LOCAL_MACHINE', 'HKLM:'}
            #'^HKEY_USERS' {$_ -replace 'HKEY_USERS', 'HKU:'}
            #'^HKEY_CURRENT_CONFIG' {$_ -replace 'HKEY_CURRENT_CONFIG', 'HKCC:'}
        }

        if ($psFriendlyKeyName -notmatch '^HKCU' -and !(Test-IsAdmin)) {
            Write-Host "$($psFriendlyKeyName)`nAdmin access required." -ForegroundColor Yellow
            return $false
        }
     
        # Handle special cases where the data needs to be formatted from the
        # input Json string
        $this.valueData = switch ($this.type) {
            'BINARY' {$this.valueData -split ',' -as [byte[]]}
            Default {$this.valueData}
        }

        # If the path to the key exists
        if (Test-Path $psFriendlyKeyName) {

            $itemPropertyObject = Get-ItemProperty $psFriendlyKeyName $this.valueName -ErrorAction SilentlyContinue

            # If the key already exists
            # Compare the passed parameter data against the existing values
            if ($null -ne $itemPropertyObject) {

                # First check whether the key is the correct type
                $valueDiff = $false
                $existingRegValueType = $itemPropertyObject.$($this.valueName).GetType().Name

                $strExistingRegType = switch ($existingRegValueType) {
                    'String' {'STRING'}
                    'Int32' {'DWORD'}
                    'Int64' {'QWORD'}
                    'Byte[]' {'BINARY'}
                    'String[]' {'MULTISTRING'}
                    Default {'UNKNOWN'}
                }

                # Reg value exists but key types are different
                if ($strExistingRegType -ne $this.type) {
                    $valueDiff = $true
                }
                # Reg value exists and key types are the same
                else {
                    # Compare passed reg value against existing
                    if ($itemPropertyObject.$($this.valueName) -is [array]) {

                        for ($i=0; $i -lt $itemPropertyObject.$($this.valueName).Count; $i++) {
                            if ($itemPropertyObject.$($this.valueName)[$i] -ne $this.valueData[$i]) {
                                $valueDiff = $true
                                break
                            }
                        }
                    }
                    else {
                        if ($itemPropertyObject.$($this.valueName) -ne $this.valueData) {
                            $valueDiff = $true
                        }
                    }
                }

                # Differences were found
                # Backups will currently made if we're changing existing reg key values OR
                # if we're creating new values in a path that pre-exists
                if ($valueDiff) {
                
                    if ($this.backupDirectory -and $psFriendlyKeyName -notin $arrBackedUpKeys) {

                        $exportKeys = $this.backupRegKey()

                        if (!$exportKeys) {
                            return $false
                        }

                        $arrBackedUpKeys += $psFriendlyKeyName
                    }

                    try {
                        Set-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop
                        return $true
                    }
                    catch{
                        Write-Host "$($psFriendlyKeyName)`n$($this.valueName)`Failed to set reg value"
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
                    if ($this.backupDirectory -and $psFriendlyKeyName -notin $arrBackedUpKeys) {

                        $exportKeys = $this.backupRegKey()

                        if (!$exportKeys) {
                            return $false
                        }

                        $arrBackedUpKeys += $psFriendlyKeyName
                    }

                    try {
                        New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
                        return $true
                    }
                    catch {
                        Write-Host "$($psFriendlyKeyName)`n$($this.valueName)`Failed to create reg value" -ForegroundColor Red
                        return $false
                    }
            }
        }
        # Path to key does not exist
        # Create the path and then try to create a new item property
        else {
            try {
                # Be careful worth New-Item -Force
                # Always verify the directory does not exist beforehand
                New-Item -Path $psFriendlyKeyName -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "$($psFriendlyKeyName)`nFailed to create reg key" -ForegroundColor Red
                return $false
            }

            try {
                New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "$($psFriendlyKeyName)`n$($this.valueName)`nFailed to create reg value" -ForegroundColor Red
                return $false
            }

            return $true
        }
    }

    [bool] backupRegKey() {
        
        if ($null -eq $this.backupDirectory) {
            Write-Error "You did not specify a backup directory."
            return $false
        }

        if (!(Test-Path $this.backupDirectory)) {
            Write-Error "The specified backup directory does not exist."
            return  $false
        }

        $backupFriendlyFileName = $this.keyName -replace '^([A-Z]{3,4}):\\|\\', '$1-'
        
        $arrFileName = $backupFriendlyFileName -split '-'
        

        if ($arrFileName.Count -ge 4) {
            $backupFriendlyFileName = "$($arrFileName[0])-$($arrFileName[1])...$($arrFileName[-2])-$($arrFileName[-1]).reg"
        }

        reg export $this.keyName "$($this.backupDirectory)\$backupFriendlyFileName" /y 2>&1 > $null

        if ($LASTEXITCODE -ne 0) {
            Write-Error "$($this.keyName)`n$($this.backupDirectory)\$backupFriendlyFileName`nFatal error: unable to backup registry key(s)"
            return $false
        }
        else {
            return $true
        }
    }
}

Function Test-IsAdmin {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            return $true
        }
        else {
            return $false
        }
}


# Check for Windows 11
if ([System.Environment]::OSVersion.Version.Build -lt 22000) {
    throw "Windows 11 is required for this script to run."
}


# Check for Administrator
# and exit if necessary
$userIsAdmin = Test-IsAdmin

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

if ($registryJSON) {

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
    
                    $regKeyObject = [RegistryKey]::new($tweak.RegPath, $tweak.Name, $tweak.Type.ToUpper(), $tweak.Value, $null)
    
                    if ($backupsEnabled) {
                        $regKeyObject.backupDirectory = $scriptRunBackupDir
                    }
    
                    $setResult = $regKeyObject.addToReg()
    
                    if ($setResult) {
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

    if ($LASTEXITCODE -eq 0)
    {
        Write-Host "High performance profile active" -ForegroundColor Green
    }
}

# Admin related tasks

if ($userIsAdmin) {

    # Enable RDP Firewall rules

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
}


# Uninstall OneDrive

Write-Host 'Checking for OneDrive...'

$oneDriveProcessName = 'OneDrive.exe'
$oneDriveUserPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\*\OneDriveSetup.exe"
$oneDriveSystemPaths = @(
    "$env:systemroot\System32\OneDriveSetup.exe",
    "$env:systemroot\SysWOW64\OneDriveSetup.exe"
)

$oneDriveProcessObject = Get-Process $oneDriveProcessName -ErrorAction SilentlyContinue

if ($oneDriveProcessObject) {
    Write-Host "OneDrive process was found" -ForegroundColor Yellow
    taskkill /f /im OneDrive.exe 2>&1 > $null
}

if ($userIsAdmin) {

    foreach ($uninstallPath in $oneDriveSystemPaths) {
        if (Test-Path $uninstallPath) {
            Write-Host 'Uninstalling OneDrive:`n$uninstallPath'
            & $uninstallPath /uninstall /allusers
        }
    }
}
# This will still require elevation
else {

    # %localappdata installer
    if (Test-Path $oneDriveUserPath) {
        $oneDriveUserPath = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\OneDrive\" `
                                    -Filter OneDriveSetup.exe -Recurse | Select-Object -First 1
        if ($oneDriveUserPath) {
            & $oneDriveUserPath.FullName /uninstall
        }
    }
}

#>

#"Refresh" the desktop etc. with direct call to RUNDLL32
 Start-Process "RUNDLL32.EXE" -ArgumentList "USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" -PassThru | Wait-Process
 Stop-Process -Name explorer -PassThru | Wait-Process

 # Remove backup directory if no changes were made
 if ($backupsEnabled) {
    if (!(Get-ChildItem -Path $scriptRunBackupDir)) {
        Remove-Item -Path $scriptRunBackupDir
    }
 }
if (!(Get-Variable -Name BackedUpRegistryPaths -Scope Script -ErrorAction SilentlyContinue) -or
    $null -eq $script:BackedUpRegistryPaths -or
    $script:BackedUpRegistryPaths -isnot [array]) {
    $script:BackedUpRegistryPaths = @()
 }

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

    static [bool] isAdminElevated() {
        return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
        GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }

    static [bool] isAdminRequired([string]$keyName) {

        if ($keyName -notmatch '^HKCU' -and !([RegistryKey]::isAdminElevated())) {
            Write-Host "Admin access required: ${keyName}" -ForegroundColor Yellow
            return $true
        }

        return $false
    }

    static [string] getPSFriendlyKeyName([string]$keyName) {
        
        $result = switch -Regex ($keyName) {
            '^(HKEY_CURRENT_USER)' { $_ -replace $Matches[1], 'HKCU:'; break}
            '^(HKEY_LOCAL_MACHINE)' {$_ -replace $Matches[1], 'HKLM:'; break }
            Default { $keyName }
        }

        return $result
    }

    static [string] convertRegTypes([string]$itemType) {

        $result = switch ($itemType) {
            'String' {'STRING'}
            'Int32' {'DWORD'}
            'Int64' {'QWORD'}
            'Byte[]' {'BINARY'}
            'String[]' {'MULTISTRING'}
            Default {'UNKNOWN'}
        }

        return $result

    }

    [bool] addToReg() {

        # Powershell requires altering the reg key prefix
         $psFriendlyKeyName = [RegistryKey]::getPSFriendlyKeyName($this.keyName)
        
         if (([RegistryKey]::isAdminRequired($psFriendlyKeyName)) -and (!([RegistryKey]::isAdminElevated()))) {
            return $false
         }

        # Handle special cases where the data needs to be formatted
        $this.valueData = switch ($this.type) {
            'BINARY' {$this.valueData -split ',' -as [byte[]]}
            Default {$this.valueData}
        }

        $pathExists = Test-Path $psFriendlyKeyName
        $keyExists = $false
        $valueDiff = $false

        # If the path to the key exists
        if ($pathExists) {

            $itemPropertyObject = Get-ItemProperty $psFriendlyKeyName $this.valueName -ErrorAction SilentlyContinue

            if ($null -ne $itemPropertyObject) {
                
                $keyExists = $true

                # Convert types
                $existingRegValueType = $itemPropertyObject.$($this.valueName).GetType().Name
                $existingRegValueType = [RegistryKey]::convertRegTypes($existingRegValueType)

                if ($existingRegValueType -ne $this.type) {
                    $valueDiff = $true
                }
                else {
                    # Compare existing arrays or single values
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
            }
            # Path exists but key doesn't
            else {
                $valueDiff = $true
            }
        }
        
        # Only backup if we're making changes
        $needsChanges = (!$pathExists) -or (!$keyExists) -or $valueDiff

        if (!$needsChanges) {
            return $true
        }
        
        if ($pathExists -and $this.backupDirectory -and $psFriendlyKeyName -notin $script:BackedUpRegistryPaths) {
            
            $exportKeys = $this.backupRegKey()

            if (!$exportKeys) {
                return $false
            }

            $script:BackedUpRegistryPaths += $psFriendlyKeyName
        }
        
        # Apply changes based on what's required
        try {
            # Create the path if it doesn't exist
            if (!$pathExists) {
                New-Item -Path $psFriendlyKeyName -Force -ErrorAction Stop | Out-Null
                New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
                return $true
            }
            # Create the key if it doesn't exist
            elseif (!$keyExists) {
                New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
                return $true
            }
            # Update the existing key
            else {
                Set-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop
                return $true
            }
            
        }
        catch {
            Write-Host "${psFriendlyKeyName}`n$($this.valueName)`nFailed to modify registry" -ForegroundColor Red
            return $false
        }
    }

    [bool] deleteFromReg() {

         # Powershell requires altering the reg key prefix
         $psFriendlyKeyName = [RegistryKey]::getPSFriendlyKeyName($this.keyName)


         if ([RegistryKey]::isAdminRequired($psFriendlyKeyName) -and (!([RegistryKey]::isAdminElevated))) {
            Write-Host "${psFriendlyKeyName}`nSkipped processing as admin elevation is required for deletion." -ForegroundColor Yellow
            return $false
        }

        if (Test-Path $psFriendlyKeyName) {

            # Deleting a key value
            if (!([string]::IsNullOrEmpty($this.valueName))) {

                $itemPropertyObject = Get-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -ErrorAction SilentlyContinue

                # Key value exists
                if ($null -ne $itemPropertyObject) {

                    if (!([string]::IsNullOrEmpty($this.type))) {

                        # Double check the key matches our target type
                        $existingRegValueType = $itemPropertyObject.$($this.valueName).GetType().Name
                        $existingRegValueType = [RegistryKey]::convertRegTypes($existingRegValueType)
                        # Reg value exists but key types are different
                        if ($existingRegValueType -ne $this.type) {
                            Write-Host "${psFriendlyKeyName}`nSkipped processing as the specified value type did not match the existing registry key." -ForegroundColor Yellow
                            return $false
                        }
                    }

                    if ($this.backupDirectory -and $psFriendlyKeyName -notin $script:BackedUpRegistryPaths) {

                        $exportKeys = $this.backupRegKey()

                        if (!$exportKeys) {
                            return $false
                        }

                        $script:BackedUpRegistryPaths += $psFriendlyKeyName
                    }

                    # Key value exists and matches our target type
                    try {
                        Remove-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName
                        return $true
                    }
                    catch {
                        Write-Host "${psFriendlyKeyName}`nFailed to delete key value" -ForegroundColor Red
                        return $false
                    }
                }
                # Key value does not exist
                else {
                    return $true
                }
            }
            # Nothing was specified for a valuename so targeting
            # key path
            else {

                if ($this.backupDirectory -and $psFriendlyKeyName -notin $script:BackedUpRegistryPaths) {

                    $exportKeys = $this.backupRegKey()

                    if (!$exportKeys) {
                        return $false
                    }

                    $script:BackedUpRegistryPaths += $psFriendlyKeyName
                }

                try {
                    Remove-Item -Path $psFriendlyKeyName
                    return $true
                }
                catch {
                    Write-Host "${psFriendlyKeyName}`nFailed to delete key" -ForegroundColor Red
                    return $false
                }
            }
        }
        else {
            return $true
        }
    }

    [bool] backupRegKey() {

        if ([string]::IsNullOrEmpty($this.backupDirectory)) {
            Write-Error "You did not specify a backup directory."
            return $false
        }

        if (!(Test-Path $this.backupDirectory)) {
            Write-Error "The specified backup directory does not exist."
            return  $false
        }

        $psFriendlyKeyName = [RegistryKey]::getPSFriendlyKeyName($this.keyName)

        if ($psFriendlyKeyName -in $script:BackedUpRegistryPaths) {
            return $true
        }

        # It may have been sensible to include a Test-Path for the
        # reg key here however we have already checked this in the
        # other method and reg export will fail anyway if invalid

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
            $script:BackedUpRegistryPaths += $psFriendlyKeyName
            return $true
        }
    }
}
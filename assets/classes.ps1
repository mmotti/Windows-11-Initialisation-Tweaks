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

    $arrBackedUpKeys = @()

    [bool] addToReg() {

        # Powershell requires altering the reg key prefix
         $psFriendlyKeyName = switch -Regex ($this.keyName) {
            '^(HKEY_CURRENT_USER)' {$_ -replace $Matches[1], 'HKCU:'}
            '^(HKEY_LOCAL_MACHINE)' {$_ -replace $Matches[1], 'HKLM:'}
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

                $existingRegValueType = switch ($existingRegValueType) {
                    'String' {'STRING'}
                    'Int32' {'DWORD'}
                    'Int64' {'QWORD'}
                    'Byte[]' {'BINARY'}
                    'String[]' {'MULTISTRING'}
                    Default {'UNKNOWN'}
                }

                # Reg value exists but key types are different
                if ($existingRegValueType -ne $this.type) {
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

                    if (Test-IsAdminRequired -keyName $psFriendlyKeyName) {
                        return $false
                    }

                    if ($this.backupDirectory -and $psFriendlyKeyName -notin $this.arrBackedUpKeys) {

                        $exportKeys = $this.backupRegKey()

                        if (!$exportKeys) {
                            return $false
                        }

                        $this.arrBackedUpKeys += $psFriendlyKeyName
                    }

                    try {
                        Set-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop
                        return $true
                    }
                    catch{
                        Write-Host "${psFriendlyKeyName}`n$($this.valueName)`nFailed to set reg value"
                        return $false
                    }
                }
                else {
                    return $true
                }
            }
            # Path exists but key doesn't
            else {

                if (Test-IsAdminRequired -keyName $psFriendlyKeyName) {
                    return $false
                }

                if ($this.backupDirectory -and $psFriendlyKeyName -notin $this.arrBackedUpKeys) {

                    $exportKeys = $this.backupRegKey()

                    if (!$exportKeys) {
                        return $false
                    }

                    $this.arrBackedUpKeys += $psFriendlyKeyName
                }

                try {
                    New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
                    return $true
                }
                catch {
                    Write-Host "${psFriendlyKeyName}`n$($this.valueName)`Failed to create reg value" -ForegroundColor Red
                    return $false
                }
            }
        }
        # Path to key does not exist
        # Create the path and then try to create a new item property
        else {

            if (Test-IsAdminRequired -keyName $psFriendlyKeyName) {
                return $false
            }

            try {
                # Be careful worth New-Item -Force
                # Always verify the directory does not exist beforehand
                # -Force will re-create the destination key and remove all existing subkeys from it
                New-Item -Path $psFriendlyKeyName -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "${psFriendlyKeyName}`nFailed to create reg key" -ForegroundColor Red
                return $false
            }

            try {
                New-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -Type $this.type -Value $this.valueData -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "${psFriendlyKeyName}`n$($this.valueName)`nFailed to create reg value" -ForegroundColor Red
                return $false
            }

            return $true
        }
    }

    [bool] deleteFromReg() {

         # Powershell requires altering the reg key prefix
         $psFriendlyKeyName = switch -Regex ($this.keyName) {
            '^(HKEY_CURRENT_USER)' {$_ -replace $Matches[1], 'HKCU:'}
            '^(HKEY_LOCAL_MACHINE)' {$_ -replace $Matches[1], 'HKLM:'}
        }

        if (Test-Path $psFriendlyKeyName) {

            # Deleting a key value
            if (!([string]::IsNullOrEmpty($this.valueName))) {

                $itemPropertyObject = Get-ItemProperty -Path $psFriendlyKeyName -Name $this.valueName -ErrorAction SilentlyContinue

                # Key value exists
                if ($null -ne $itemPropertyObject) {

                    # Double check the key matches our target type
                    $existingRegValueType = $itemPropertyObject.$($this.valueName).GetType().Name
                    $existingRegValueType = switch ($existingRegValueType) {
                        'String' {'STRING'}
                        'Int32' {'DWORD'}
                        'Int64' {'QWORD'}
                        'Byte[]' {'BINARY'}
                        'String[]' {'MULTISTRING'}
                        Default {'UNKNOWN'}
                    }

                    if (!([string]::IsNullOrEmpty($this.type))) {
                        # Reg value exists but key types are different
                        if ($existingRegValueType -ne $this.type) {
                            Write-Host "${psFriendlyKeyName}`nSkipped processing as the specified value type did not match the existing registry key." -ForegroundColor Yellow
                            return $false
                        }
                    }

                    if (Test-IsAdminRequired -keyName $psFriendlyKeyName) {
                        return $false
                    }

                    if ($this.backupDirectory -and $psFriendlyKeyName -notin $this.arrBackedUpKeys) {

                        $exportKeys = $this.backupRegKey()

                        if (!$exportKeys) {
                            return $false
                        }

                        $this.arrBackedUpKeys += $psFriendlyKeyName
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

                if (Test-IsAdminRequired -keyName $psFriendlyKeyName) {
                    return $false
                }

                if ($this.backupDirectory -and $psFriendlyKeyName -notin $this.arrBackedUpKeys) {

                    $exportKeys = $this.backupRegKey()

                    if (!$exportKeys) {
                        return $false
                    }

                    $this.arrBackedUpKeys += $psFriendlyKeyName
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
            return $true
        }
    }
}
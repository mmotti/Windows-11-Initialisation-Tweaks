$script:BackedUpRegistryPaths = @()

function Test-IsAdminElevated {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Get-ElevatedTerminal {

    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$OriginalParameters
    )

    if (Test-IsAdminElevated) {
        return
    }

    $baseArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$global:g_scriptPath`""
    )
    
    Write-Status -Status WARN -Message "Attempting to relaunch the script with elevated privileges..."

    $additionalArgs = @()

    if ($OriginalParameters.Count -gt 0) {
        foreach ($param in $OriginalParameters.GetEnumerator()){
            $key = $param.Key
            $value = $param.Value

            if ($value -is [switch]) {
                if ($value.IsPresent) {
                    $additionalArgs += "-$key"
                }
            } elseif ($null -eq $value) {
                $additionalArgs += "- $key"
            } else {
                $formattedValue = "`"$value`""
                $additionalArgs += "-$key", $formattedValue
            }
        }
    }

    $cmdToRun = ""
    $finalArgumentList = @()

    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {
        $cmdToRun = "wt.exe"
        $finalArgumentList = @(
            "new-tab",
            "-p",
            "--",
            "powershell.exe"
        ) + $baseArguments + $additionalArgs
    } else {
        $cmdToRun = "powershell.exe"
        $finalArgumentList = $baseArguments + $additionalArgs
    }

    try {
        Start-Process $cmdToRun -ArgumentList @($finalArgumentList -split " ") -Verb RunAs -ErrorAction Stop
        exit 0
    }
    catch {
        Write-Error "Failed to start elevated process: $($_.Exception.Message)"
        exit 1
    }
}

function Get-HKUDrive {

    [CmdletBinding(DefaultParameterSetName='Load')] # Default set is Load
    param (
        # --- Parameter Set: Load ---
        [Parameter(Mandatory=$true,
                   ParameterSetName='Load',
                   HelpMessage="Loads the specified registry hive.")]
        [switch]$Load,

        # --- Parameter Set: Unload ---
        [Parameter(Mandatory=$true,
                   ParameterSetName='Unload',
                   HelpMessage="Unloads the specified registry hive.")]
        [switch]$Unload
    )
    
    switch ($PSCmdlet.ParameterSetName) {
        "Load" {
            try {
                if (!(Get-PSdrive -Name HKU -ErrorAction SilentlyContinue)) {
                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop
                }
            }
            catch {
                throw "Unable to load PSDrive: $($_.Exception.Message)"
            }
        }
        "Unload" {
            try {
                if (Get-PSdrive -Name HKU -ErrorAction SilentlyContinue) {
                    $null = Remove-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop
                }
            }
            catch {
                throw "Unable to unload PSDrive: $($_.Exception.Message)"
            }
        }
        default {
            throw "Unexpected ParameterSet. Unable to continue."
        }
    }
}

function Import-RegKeys {
    [CmdletBinding(DefaultParameterSetName='CurrentUser')]
    param (
        [Parameter(Mandatory=$true)]
        [System.IO.FileInfo[]]$KeyArray,

        [Parameter(ParameterSetName='AllUsers',
        Mandatory=$false,
        HelpMessage="Apply settings to all existing user accounts (excluding Default).")]
        [switch]$AllUsers,

        [Parameter(ParameterSetName='DefaultUser',
            Mandatory=$false,
            HelpMessage="Apply settings to the Default User profile template for future new users.")]
        [switch]$DefaultUser
    )

    # Sanity check that the required variables etc are definitely in the desired state.

    if ($global:g_RegistryTweaksEnabled -eq $false) {
        Write-Status -Status WARN -Message "Registry import command was called when registry tweaks are disabled. Skipping." -Indent 1
        return
    }

    if ($global:g_BackupsEnabled -eq $true -and !(Test-Path $global:g_BackupDirectory)) {
        Write-Status -Status FAIL -Message "Backup path does not exist: $global:g_BackupDirectory" -Indent 1
        $global:g_RegistryTweaksEnabled = $false
    }

    $validKeys = $KeyArray | Where-Object {$_.Name -match "\.reg$"}

    if (!($validKeys)) {
        Write-Status -Status WARN "There we no valid .reg files provided to import." -Indent 1
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        "AllUsers" {
            Write-Status -Status ACTION -Message "Starting registry import process (Mode: AllUsers)."

            $userSids = Get-AllUserSids

            if ($null -eq $userSids -or $userSids.Count -eq 0) {
                Write-Status -Status FAIL -Message "AllUsers mode failed: No sids were returned during the lookup."
                return
            }

            foreach ($sid in $userSids) {
                Write-Status -Status ACTION -Message "Processing user: $sid" -Indent 1

                foreach ($key in $validKeys) {
                    $originalFilePath = $key.FullName
                    $tempFilePath = $null
                    $importFile = $originalFilePath

                    try {

                        $originalContent = Get-Content -Path $originalFilePath -Raw -Encoding Unicode -ErrorAction Stop
                        $modifiedContent = $originalContent -replace "(?im)^\[HKEY_CURRENT_USER", "[HKEY_USERS\$sid"

                        if ($originalContent -ne $modifiedContent) {
                            $tempFilePath = Join-Path $env:TEMP "$([guid]::NewGuid()).reg"
                            Set-Content -Path $tempFilePath -Value $modifiedContent -Encoding Unicode -ErrorAction Stop
                            $importFile = $tempFilePath
                        }

                        if ($global:g_BackupsEnabled -eq $true) {
                            if (!(Export-RegKeys -KeyPath $importFile)) {
                                Write-Status -Status FAIL -Message "$($key.Name): Failed to create registry backup." -Indent 1
                                continue
                            }
                        }

                        $result = reg import "$importFile" 2>&1

                        if ($LASTEXITCODE -ne 0) {
                            Write-Status -Status FAIL -Message "$($key.Name): $($result -replace '^ERROR:\s*', '')" -Indent 1
                        } else {
                            Write-Status -Status OK -Message "$($key.Name)" -Indent 1
                        }
                    }
                    catch {
                    Write-Status -Status FAIL -Message "$($key.Name): An error occurred during the import process for user: $sid. Error: $($_.Exception.Message) "
                    }
                    finally {
                        if ($null -ne $tempFilePath -and (Test-Path -Path $tempFilePath)) {
                            Remove-Item -Path $tempFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }

        {$_ -eq "CurrentUser" -or $_ -eq "DefaultUser"} {

            Write-Status -Status ACTION -Message "Starting registry import process (Mode: $_)."

            $defaultHiveWasLoadedSuccessfully = $false 

            try {

                if ($_ -eq "DefaultUser") {
                    Write-Status -Status ACTION -Message "Attempting to load Default User hive..." -Indent 1
                    $defaultHivePath = if ([string]::IsNullOrEmpty($global:g_DefaultUserCustomHive)) {Join-Path $env:SystemDrive "Users\Default\NTUSER.dat"} else {$global:g_DefaultUserCustomHive}
                    $defaultHiveWasLoadedSuccessfully = Get-UserRegistryHive -Load -HiveName HKU\TempDefault -HivePath $defaultHivePath
                    if (-not $defaultHiveWasLoadedSuccessfully) {
                        # Get-UserRegistryHive should write the specific error. We just need to stop.
                        Write-Status -Status FAIL -Message "Failed to load Default User hive. Cannot proceed with registry imports for DefaultUser mode." -Indent 1
                        return # Exit function if hive load fails
                    }
                    Write-Status -Status OK -Message "Hive loaded successfully." -Indent 1
                }

                foreach ($key in $validKeys) {
                    $originalFilePath = $key.FullName
                    $tempFilePath = $null
                    $importFile = $originalFilePath

                    try {

                        if ($_ -eq "DefaultUser") {
                            $originalContent = Get-Content -Path $originalFilePath -Raw -Encoding Unicode -ErrorAction Stop
                            if ($originalContent -match "(?im)^\[HKEY_CURRENT_USER") {
                                $modifiedContent = $originalContent -replace "(?im)^\[HKEY_CURRENT_USER", "[HKEY_USERS\TempDefault"
                                $tempFilePath = Join-Path $env:TEMP "$([guid]::NewGuid()).reg"
                                Set-Content -Path $tempFilePath -Value $modifiedContent -Encoding Unicode -ErrorAction Stop
                                $importFile = $tempFilePath
                            }
                        }

                        if ($global:g_BackupsEnabled -eq $true) {
                            if (!(Export-RegKeys -KeyPath $importFile)) {
                                Write-Status -Status FAIL -Message "$($key.Name): Failed to create registry backup." -Indent 1
                                continue
                            }
                        }

                        $result = reg import "$importFile" 2>&1

                        if ($LASTEXITCODE -ne 0) {
                            Write-Status -Status FAIL -Message "$($key.Name): $($result -replace '^ERROR:\s*', '')" -Indent 1
                        } else {
                            Write-Status -Status OK -Message "$($key.Name)" -Indent 1
                        }

                    }
                    catch {
                        Write-Status -Status FAIL -Message "$($key.Name): An error occurred during the import process: $($_.Exception.Message) "
                    }
                    finally {
                        if ($null -ne $tempFilePath -and (Test-Path -Path $tempFilePath)) {
                            Remove-Item -Path $tempFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            } finally {
                if ($_ -eq "DefaultUser" -and $defaultHiveWasLoadedSuccessfully) {
                    $null = Get-UserRegistryHive -Unload -HiveName HKU\TempDefault
                }
            }

        }

        default {
            Write-Status -Status FAIL -Message "Unexpected ParameterSet. Unable to continue." -Indent 1
            return
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

    # Sanity checks.

    if ($global:g_BackupsEnabled -eq $false) {
        return $true
    }

    if (!(Test-Path -Path $global:g_BackupDirectory)) {
        return $false
    }

    $regFileContents = Get-Content -Path $KeyPath -Raw -Encoding Unicode -ErrorAction SilentlyContinue

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

                $null = reg export $keyRegPath "$global:g_BackupDirectory\$friendlyFileName" /y 2>&1

                if ($LASTEXITCODE -eq 0) {
                    $script:BackedUpRegistryPaths += $_.Groups[1].Value
                } else {
                    return $false
                }
            }
        }
    }

    return $true
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

        $okPrefix = "[OK]"
        $failPrefix = "[FAIL]"
        $warningPrefix = "[WARN]"
        $actionPrefix = "[>>]"
        $infoPrefix = "[i]"

        switch ($Status.ToUpperInvariant()) {
            "ACTION" {$prefix=$actionPrefix;$colour="Blue"}
            "OK" {$prefix=$okPrefix;$colour="Green"}
            "FAIL" {$prefix=$failPrefix;$colour="Red"}
            "WARN" {$prefix=$warningPrefix;$colour="Yellow"}
            "INFO" {$prefix=$infoPrefix; $colour="White"}
            default {$prefix=$null; $colour="White"}
        }

        if ($Indent -gt 0) {
            Write-Host ("`t" * $Indent) -NoNewline
        }

        if ($prefix) {
            Write-Host $prefix -ForegroundColor $colour -NoNewline
            $Message = " $Message"
        }

        Write-Host $Message
}

function New-BackupDirectory {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath
    )

    Write-Status -Status ACTION -Message "Initialising backup area..."

    # Create the backup dir.

    if (!(Test-Path -Path $BackupPath)) {

        try {
            New-Item -Path $BackupPath -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Status -Status OK -Message "Registry backup directory initialised:" -Indent 1
            Write-Status -Status INFO -Message $BackupPath -Indent 1
        }
        catch {
            Write-Status -Status FAIL -Message "Unable to create path: `"$BackupPath`"." -Indent 1
            Write-Status -Status WARN -Message "Registry tweaks will be skipped." -Indent 1
            $global:g_RegistryTweaksEnabled = $false
        }
    }
}

function Set-PowerPlan {

    try {

        $powerSchemes = powercfg /list

        if ($LASTEXITCODE -ne 0) {
            return $false
        }

        if ($null -ne $powerSchemes) {

            $targetPlanActive = $false
            $processorString = $null
            $isX3D = $false

            try {
                $processorString = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString").ProcessorNameString
            }
            catch {
                Write-Status -Status WARN -Message "It was not possible to obtain the processor string." -Indent 1
            }

            $isX3D = if ($processorString -and $processorString -match "^AMD.*X3D") { $true } else { $false }
            $targetPlan = if ($isX3D) { "Balanced" } else { "High performance" }

            # Use regex matching against the power plan list in case M$ ever decides to change them.

            $activeSchemeGUID = [regex]::Match($powerSchemes, 'Power Scheme GUID: ([a-f0-9-]+)\s+\([^\)]+\)\s*\*').Groups[1].Value
            $desiredSchemeGUID = [regex]::Match($powerSchemes, "Power Scheme GUID: ([a-f0-9-]+)\s+\($targetPlan\)").Groups[1].Value

            # If the desired GUID was matched in the powercfg output.
            if ($desiredSchemeGUID) {
                # The current scheme is the desired scheme.
                if ($activeSchemeGUID -eq $desiredSchemeGUID) {
                    $targetPlanActive = $true
                    Write-Status -Status OK -Message "`"$targetPlan`" already active." -Indent 1
                # The current scheme is not the desired scheme.
                } else {
                    Write-Status -Status ACTION -Message "Setting active power plan to: $targetPlan" -Indent 1
                    powercfg /setactive $desiredSchemeGUID

                    if ($LASTEXITCODE -ne 0) {
                        Write-Status -Status FAIL -Message "An error occurred: $($_.Exception.Message)"
                        return $false
                    } else {
                        $targetPlanActive = $true
                        Write-Status -Status OK -Message "Successfully applied `"$targetPlan`" power plan." -Indent 1
                    }
                }

                if ($targetPlanActive) {

                    # Disable sleep if the system does not have a battery (hopefully only targeting desktops).
                    try {

                        $hasBattery = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop

                        if ($null -eq $hasBattery) {

                            powercfg /change standby-timeout-ac 0

                            if ($LASTEXITCODE -eq 0) {
                                Write-Status -Status OK -Message "Sleep mode disabled." -Indent 1
                            } else {
                                Write-Status -Status FAIL -Message "Unable to disable sleep mode." -Indent 1
                            }
                        }
                    }
                    catch {
                        Write-Status -Status FAIL -Message "CimInstance query for battery detection failed." -Indent 1
                        return $false
                    }
                }
            } else {
                $targetPlanActive = $false
                Write-Status -Status WARN -Message "The desired power plan was not found on this system." -Indent 1
                return $false
            }

            return $true
        }
    }
    catch {
        Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
    }
}

function Import-NotepadTweaks {

    [CmdletBinding(DefaultParameterSetName='CurrentUser')]
    param (

        [Parameter(ParameterSetName='AllUsers',
        Mandatory=$false,
        HelpMessage="Apply settings to all existing user accounts (excluding Default).")]
        [switch]$AllUsers,

        [Parameter(ParameterSetName='DefaultUser',
            Mandatory=$false,
            HelpMessage="Apply settings to the Default User profile template for future new users.")]
        [switch]$DefaultUser,

        [Parameter(Mandatory=$true,
                    HelpMessage="Location of your tweaked settings file.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $fileName = Split-Path -Path $_ -Leaf
            if ($fileName -eq 'settings.dat') {
                $true
            } else {
                throw "The file specified by TweakPath must be named 'settings.dat'. Found: '$fileName'"
            }
        })]
        [string]$TweakPath
        )

    if (!(Test-Path -Path $TweakPath -PathType Leaf)) {
        Write-Status -Status FAIL -Message "Path not found: $TweakPath"
        return $false
    }

    Write-Status -Status ACTION -Message "Checking for Notepad..."

    $appxPackage = Get-AppxPackage -Name "Microsoft.WindowsNotepad" -ErrorAction SilentlyContinue

    if (!$appxPackage) {
        Write-Status -Status WARN -Message "Notepad is not installed." -Indent 1
        return $false
    }

    $notepadRelativePath = "Packages\$($appxPackage.PackageFamilyName)\Settings\settings.dat"

    $targetBasePaths = @()

    switch ($PSCmdlet.ParameterSetName) {
        'AllUsers' {
            $targetBasePaths = Get-AllUserProfilePaths | ForEach-Object { Join-Path $_ "AppData\Local" }
            if ($targetBasePaths.Count -eq 0) {
                 Write-Status -Status WARN -Message "No user profile paths found for AllUsers mode." -Indent 1
                 return $false
            }
             Write-Status -Status INFO -Message "Targeting $($targetBasePaths.Count) user profiles." -Indent 1
        }
        'DefaultUser' {
            $targetBasePaths += Join-Path "$env:SystemDrive\Users\Default" "AppData\Local"
            Write-Status -Status INFO -Message "Targeting Default User profile." -Indent 1
        }
        'CurrentUser' { # Default case
            $targetBasePaths += $env:LOCALAPPDATA
            Write-Status -Status INFO -Message "Targeting Current User profile." -Indent 1
        }
    }

    $getNotepadProcess = {Get-Process -Name Notepad -ErrorAction SilentlyContinue}

    if (& $getNotepadProcess) {

        Write-Status -Status WARN "Please close Notepad to continue (ALT+TAB to the window)." -Indent 1
        Write-Status -Status WARN "If another user has Notepad open, use CTRL + SHIFT + ESC and force close all Notepad tasks." -Indent 1

        while (& $getNotepadProcess) {
            Start-Sleep -Milliseconds 500
        }

        Write-Status -Status OK -Message "Notepad process closed." -Indent 1
    } else {
        Write-Status -Status OK -Message "No Notepad process detected." -Indent 1
    }

    $errorCount = 0
    foreach ($basePath in $targetBasePaths) {

        $destinationPath = Join-Path $basePath $notepadRelativePath
        $destinationDir = Split-Path $destinationPath -Parent
        
        try {

            if (!(Test-Path -Path $destinationDir)) {
                New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            Write-Status -Status ACTION -Message "Copying file to: $destinationPath " -Indent 1
            Copy-Item $TweakPath $destinationPath -Force -ErrorAction Stop
            Write-Status -Status OK -Message "File copied successfully." -Indent 1
        }
        catch {
            $errorCount++
            Write-Status -Status FAIL -Message "File copy failed." -Indent 1
        }
    }

    if ($errorCount -eq 0) {
        Write-Status -Status OK -Message "Notepad settings file copy process completed successfully." -Indent 1
        return $true
    } else {
        Write-Status -Status WARN -Message "Notepad settings file copy process failed for one or more users." -Indent 1
        return $false
    }
}

function Remove-OneDrive {
    [CmdletBinding(DefaultParameterSetName='CurrentUser')]
    param (

        [Parameter(ParameterSetName='AllUsers',
        Mandatory=$true,
        HelpMessage="Search the HKCU hives for OneDrive installations.")]
        [switch]$AllUsers,

        [Parameter(ParameterSetName='DefaultUser',
            Mandatory=$true,
            HelpMessage="Search the Default user's registry hive.")]
        [switch]$DefaultUser
    )

        # Sanity check
        $mode = $PSCmdlet.ParameterSetName
        if ([string]::IsNullOrEmpty($mode)) {
            Write-Status -Status FAIL -Message "Unexpected parameter conditions." -Indent 1
            return
        }

        Write-Status -Status ACTION -Message "Looking for OneDrive (Mode: $mode)"

        $oneDriveInstallations = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
        ) | Sort-Object -Unique

        $hiveLoaded = $false

        try {

            switch ($PSCmdlet.ParameterSetName) {
                {$_ -eq "CurrentUser" -or $_ -eq "AllUsers"} {

                    $mode = $_

                    $uninstallActionBlock = {
                        
                        $currentRegistryPath = $_

                        if ([string]::IsNullOrWhiteSpace($currentRegistryPath)) {
                            return
                        }

                        $uninstallString = $null

                        try {
                            $uninstallString = Get-ItemPropertyValue -Path $currentRegistryPath -Name "UninstallString" -ErrorAction SilentlyContinue

                            if ($uninstallString) {
                                Write-Status -Status ACTION -Message "Executing: $uninstallString" -Indent 1
                                $argList = "/c `"$uninstallString`""
                                Start-Process cmd -ArgumentList $argList -Wait -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
                        }
                    }

                    $currentUserOneDriveInstallations = $oneDriveInstallations | Where-Object {$_ -match "^HKCU:" -and (Test-Path -Path $_)}

                    if ($currentUserOneDriveInstallations) {
                        Write-Status -Status INFO -Message "OneDrive installation detected within HKCU (Mode: $mode)" -Indent 1
                        $currentUserOneDriveInstallations | ForEach-Object -Process $uninstallActionBlock
                    } else {
                        Write-Status -Status OK -Message "No OneDrive installations detected within HKCU." -Indent 1
                    }

                    if ($mode -eq "AllUsers") {
                        
                        # First check for HKLM, run the uninstallers.
                        # Then check other user profiles for OneDrive entries and notify if found.

                        $localMachineOneDriveInstallations = $oneDriveInstallations | Where-Object {$_ -match "^HKLM:" -and (Test-Path -Path $_)}

                        if ($localMachineOneDriveInstallations) {
                            Write-Status -Status INFO -Message "OneDrive installation detected within HKLM (Mode: $mode)" -Indent 1
                            $localMachineOneDriveInstallations | ForEach-Object -Process $uninstallActionBlock
                        } else {
                            Write-Status -Status OK -Message "No OneDrive installations detected within HKLM." -Indent 1
                        }

                        $oneDriveHKCUPathsToCheck = $oneDriveInstallations | Where-Object {$_ -match "^HKCU:"}

                        if ($oneDriveHKCUPathsToCheck) {

                            Write-Status -Status ACTION -Message "Checking whether OneDrive is installed for other users..." -Indent 1

                            $foundOneDriveForOthers = $false

                            try {

                                Get-HKUDrive -Load

                                $userSids = Get-AllUserSids

                                if ($null -eq $userSids -or $userSids.Count -eq 0) {
                                    write-Status -Status WARN -Message "Unable to query user sids." -Indent 1
                                    return
                                }

                                $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                                $otherUserSids = $userSids | Where-Object {$_ -ne $currentSid}

                                foreach ($path in $oneDriveHKCUPathsToCheck) {
                                        foreach ($sid in $otherUserSids) {
                                            $targetHKUPath = $path -replace "^HKCU:", "HKU:\$sid"
                                            if (Test-Path -Path $targetHKUPath) {
                                                
                                                $userIdentifier = $sid
                                                try {
                                                    $sidObject = [System.Security.Principal.SecurityIdentifier]::new($sid)
                                                    $ntAccount = $sidObject.Translate([System.Security.Principal.NTAccount])
                                                    $userIdentifier = $ntAccount.Value
                                                } catch [System.Security.Principal.IdentityNotMappedException]{
                                                    # Unable to map sid to NT account. Just catch but don't do anything.
                                                } catch {
                                                    Write-Status -Status WARN -Message "Unexpected error translating SID ($sid): $($_.Exception.Message)" -Indent 1
                                                }
                                                
                                                $foundOneDriveForOthers = $true
                                                Write-Status -Status WARN -Message "OneDrive detected for user: $userIdentifier" -Indent 1
                                            }
                                        }
                                }

                                if ($foundOneDriveForOthers) {
                                    Write-Status -Status WARN -Message "You will need to run this script in the other user contexts to remove OneDrive fully." -Indent 1
                                } else {
                                    Write-Status -Status OK -Message "OneDrive has not been detected in any other user profiles." -Indent 1
                                }
                            }
                            catch {
                                Write-Status -Status FAIL -Message "An error occurred during the OneDrive check: $($_.Exception.Message)"
                            }
                        }
                    }
                }
                "DefaultUser" {
                    try {
    
                        $oneDriveKeyValue = "OneDriveSetup"
                        $defaultUserRunPath = "HKU:\TempDefault\Software\Microsoft\Windows\CurrentVersion\Run"            
                        $defaultHivePath = if ([string]::IsNullOrEmpty($global:g_DefaultUserCustomHive)) {Join-Path $env:SystemDrive "Users\Default\NTUSER.dat"} else {$global:g_DefaultUserCustomHive}

                        Write-Status -Status ACTION -Message "Loading the Default user's registry hive..." -Indent 1
            
                        if (Get-UserRegistryHive -Load -HiveName HKU\TempDefault -HivePath $defaultHivePath) {
                            Write-Status -Status OK -Message "Hive loaded successfully." -Indent 1
                            Get-HKUDrive -Load
                        } else {
                            Write-Status -Status FAIL -Message "Unable to continue searching for OneDrive without hive loaded."
                            return
                        }
            
                        $hiveLoaded = $true

                        $oneDriveDefaultUserSetup =  Get-ItemProperty -Path $defaultUserRunPath -Name $oneDriveKeyValue -ErrorAction SilentlyContinue

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
                }
                default {
                    Write-Status -Status FAIL -Message "Unexpected parameter conditions." -Indent 1
                    return
                }
            }
        }
        finally {
            Get-HKUDrive -Unload
            if ($hiveLoaded) {
                $null = Get-UserRegistryHive -Unload -HiveName HKU\TempDefault
            }
        }
}

function Get-UserRegistryHive {

    [CmdletBinding(DefaultParameterSetName='Load')] # Default set is Load
    param (
        # --- Parameter Set: Load ---
        [Parameter(Mandatory=$true,
                   ParameterSetName='Load',
                   HelpMessage="Loads the specified registry hive.")]
        [switch]$Load,

        [Parameter(Mandatory=$true,
                   ParameterSetName='Load',
                   HelpMessage="The temporary name to assign the loaded hive under HKU (e.g., TempDefault).")]
        [ValidateNotNullOrEmpty()]
        [string]$HivePath,

        # --- Parameter Set: Unload ---
        [Parameter(Mandatory=$true,
                   ParameterSetName='Unload',
                   HelpMessage="Unloads the specified registry hive.")]
        [switch]$Unload,

        # --- Common Parameter (Available in BOTH sets) ---

        [Parameter(Mandatory=$true,
                   HelpMessage="The temporary name to assign the loaded hive under HKU (e.g., TempDefault).")]
        [ValidateNotNullOrEmpty()]
        [string]$HiveName
    )
    
    if ($HiveName -notmatch "^HKU\\") {
        Write-Status -Status FAIL -Message "Hive name must match HKU\" -Indent 1
        return $false
    }

    # Sanity check
    $mode = $PSCmdlet.ParameterSetName
    if ([string]::IsNullOrWhiteSpace($mode)) {
        Write-Status -Status FAIL -Message "Unexpected parameter conditions." -Indent 1
        return
    }

    if ($mode -eq "Load") {
        if (!(Test-Path -Path $HivePath -PathType Leaf)) {
            Write-Status -Status FAIL -Message "Path not found: $HivePath" -Indent 1
            return $false
        }
    }

    # We need to check whether the HKU:\TempDefault hive is already loaded or we will encounter errors.

    try {
        Get-HKUDrive -Load
        if (Test-Path -Path "HKU:\$HiveName") {
            return $true
        }
    }
    catch {
        Write-Status -Status FAIL -Message "Unable to create PSDrive: $($_.Exception.Message)" -Indent 1
        return $false
    }
    finally {
        Get-HKUDrive -Unload
    }

    switch ($mode) {
        "Load" {
            try {
                $null = reg load $HiveName "$HivePath" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "Unable to load the Default user's registry hive."
                }
                return $true
            }
            catch {
                Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
                return $false
            }
        }
        "Unload" {
            try {
                Wait-RegeditExit
                $null = reg unload $HiveName 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "Unable to unload the Default user's registry hive."
                }
                return $true
            }
            catch {
                Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
                return $false
            }
        }
        Default {return $false}
    }
}

function Stop-Explorer {

    $getExplorerProcess = {Get-Process -Name "explorer" -ErrorAction SilentlyContinue}

    if (& $getExplorerProcess) {

        Write-Status -Status ACTION -Message "Stopping explorer..."

        $null = taskkill.exe /im explorer.exe /f 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Status -Status OK -Message "Explorer stopped." -Indent 1
            return $true
        } else {
            Write-Status -Status FAIL -Message "Failed to stop explorer." -Indent 1
            return $false
        }
    }

    return $true
}

function Wait-RegeditExit {
    
    $getRegeditProcess = {Get-Process -Name regedit -ErrorAction SilentlyContinue}

    if (& $getRegeditProcess) {
        Write-Status -Status WARN -Message "Please close regedit (ALT+TAB) to the window." -Indent 1
    }

    while (& $getRegeditProcess) {
        Start-Sleep -Milliseconds 500
    }
}

function Start-Explorer {
    [CmdletBinding()]
    param (
        [bool]$ExplorerStoppedSuccessfully
    )

    $getExplorerProcess = {Get-Process -Name "explorer" -ErrorAction SilentlyContinue}

    Write-Status -Status ACTION -Message "Restarting explorer..."

    if ($ExplorerStoppedSuccessfully) {
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
}

function Get-ProfileList {

    try {
        $profileList = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction Stop
        if ($null -eq $profileList) {
           return @()
        }
   }
   catch {
       Write-Status -Status FAIL -Message "Unable to query user sids." -Indent 1
       return @()
   }

   $filteredProfiles = $profileList | Where-Object {
        $profilePath = $null
        try {$profilePath = $_.GetValue("ProfileImagePath", $null)} catch {}
        $_.PSChildName -notmatch "^(S-1-5-(18|19|20)|S-1-5-93-2-(1|2)|\.DEFAULT)$" -and 
        $null -ne $profilePath -and
        (Test-Path -Path $profilePath -PathType Container)
   }

   if ($null -eq $filteredProfiles -or $filteredProfiles.Count -eq 0) {
       Write-Status -Status FAIL -Message "No sids were returned."
       return @()
   }

   return $filteredProfiles

}

function Get-AllUserSids {
    return Get-ProfileList | Select-Object -ExpandProperty PSChildName 
}

function Get-AllUserProfilePaths {
   return Get-ProfileList | ForEach-Object {$_.GetValue("ProfileImagePath")}
}

function Remove-PublicDesktopShortcuts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$ShortcutArray
    )

    if (@($ShortcutArray).Count -gt 0) {

        Write-Status -Status ACTION -Message "Processing Public Desktop shortcuts..."

        $ShortcutArray |
        ForEach-Object { Join-Path "$env:SystemDrive\Users\Public\Desktop" $_ } |
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
    } else {
        Write-Status -Status OK -Message "There are no shortcuts to remove." -Indent 1
    }
}

function Update-Wallpaper {

    Write-Status -Status ACTION -Message "Applying wallpaper..."

    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE = 0x01
    $SPIF_SENDCHANGE = 0x02

    return [User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, [IntPtr]::Zero, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
}

function Update-Desktop {

    Write-Status -Status ACTION "Waiting for Windows Desktop shell..." -Indent 1
    while ([RefreshDesktop]::FindWindow("Progman", "Program Manager") -eq [IntPtr]::Zero) {
        Start-Sleep -Milliseconds 500
        continue
    }

    Write-Status -Status OK -Message "Desktop shell located." -Indent 1

    Write-Status -Status ACTION -Message "Refreshing desktop..." -Indent 1

    [RefreshDesktop]::Refresh()
}

function Add-FirewallRules {
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Write-Status -Status OK -Message "Allowed RDP in Windows Firewall. " -Indent 1
    }
    catch {
        Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
    }
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
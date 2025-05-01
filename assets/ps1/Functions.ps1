$script:BackedUpRegistryPaths = @()

function Test-IsAdminElevated {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::
            GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Get-ElevatedTerminal {

    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$OriginalParameters,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptPath
    )

    if (Test-IsAdminElevated) {
        return
    }

    # Sanity check script path
    if (!((Test-Path -Path $ScriptPath -PathType Leaf) -and $ScriptPath -match "\.ps1$" )) {
        throw "Path not found or invalid PS1 file: $ScriptPath"
    }

    $baseArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$ScriptPath`""
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
                $additionalArgs += "-$key"
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
            "powershell",
            "powershell.exe"
        ) + $baseArguments + $additionalArgs
    } else {
        $cmdToRun = "powershell.exe"
        $finalArgumentList = $baseArguments + $additionalArgs
    }

    try {
        Start-Process $cmdToRun -ArgumentList $finalArgumentList -Verb RunAs -ErrorAction Stop
        exit 0
    }
    catch {
        Write-Error "Failed to start elevated process: $($_.Exception.Message)"
        exit 1
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

            $profileList = Get-ProfileList

            if ($null -eq $profileList -or $profileList.Count -eq 0) {
                Write-Status -Status FAIL -Message "AllUsers mode failed: No sids were returned during the lookup." -Indent 1
                return
            }

            foreach ($profile in $profileList) {
                # Try block primarily so we can have a "finally" to unload registry hives if necessary.
                try {
                    $sid = $profile.SID
                    $profilePath = $profile.ProfileImagePath

                    $userHiveLoaded = $false

                    Write-Status -Status ACTION -Message "Processing user: $sid" -Indent 1

                    # Mount the registry hive if the user is not logged in
                    if (!(Test-Path -Path "Registry::HKU\$sid")) {

                        $userRegHivePath = Join-Path $profilePath "NTUSER.dat"

                        if (!(Test-Path -Path $userRegHivePath -PathType Leaf)) {
                            throw "Path not found: $userRegHivePath"
                        }

                        if (Get-UserRegistryHive -Load -HiveName HKU\$sid -HivePath $userRegHivePath) {
                            $userHiveLoaded = $true
                        } else {
                            throw "Unable to load registry hive for SID ($sid). Error: $($_.Exception.Message)"
                        }
                    }

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
                                    throw "$($key.Name): Failed to create registry backup."
                                }
                            }

                            $result = reg import "$importFile" 2>&1

                            if ($LASTEXITCODE -ne 0) {
                                throw "$($key.Name): $($result -replace '^ERROR:\s*', '')"
                            } else {
                                Write-Status -Status OK -Message "$($key.Name)" -Indent 1
                            }
                        }
                        catch {
                            Write-Status -Status FAIL -Message "$($key.Name): An error occurred during the import process for user: $sid. Error: $($_.Exception.Message) " -Indent 1
                            continue
                        }
                        finally {
                            if ($null -ne $tempFilePath -and (Test-Path -Path $tempFilePath)) {
                                Remove-Item -Path $tempFilePath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                catch {
                    Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
                    continue
                }
                finally {
                    if ($userHiveLoaded) {
                        $null = Get-UserRegistryHive -Unload -HiveName HKU\$sid
                    }
                }
            }
        }

        {$_ -eq "CurrentUser" -or $_ -eq "DefaultUser"} {

            Write-Status -Status ACTION -Message "Starting registry import process (Mode: $_)."

            try {

                if ($_ -eq "DefaultUser") {

                    Write-Status -Status ACTION -Message "Attempting to load Default User hive..." -Indent 1

                    $defaultHivePath = if ([string]::IsNullOrEmpty($global:g_DefaultUserCustomHive)) {Join-Path $env:SystemDrive "Users\Default\NTUSER.dat"} else {$global:g_DefaultUserCustomHive}
                    $defaultHiveLoaded = $false

                    if (!(Test-Path -Path "Registry::HKU\TempDefault")) {
                        if (Get-UserRegistryHive -Load -HiveName HKU\TempDefault -HivePath $defaultHivePath) {
                            $defaultHiveLoaded = $true
                        } else {
                             # Get-UserRegistryHive should write the specific error. We just need to stop.
                             Write-Status -Status FAIL -Message "Failed to load Default User hive. Cannot proceed with registry imports for DefaultUser mode." -Indent 1
                             return
                        }
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
                        Write-Status -Status FAIL -Message "$($key.Name): An error occurred during the import process: $($_.Exception.Message) " -Indent 1
                    }
                    finally {
                        if ($null -ne $tempFilePath -and (Test-Path -Path $tempFilePath)) {
                            Remove-Item -Path $tempFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            } finally {
                if ($_ -eq "DefaultUser" -and $defaultHiveLoaded) {
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

function Copy-DefaultStartMenu {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Start2Path
    )

    $fileName = "start2.bin"

    # Sanity check path.
    if (!((Test-Path -Path $Start2Path -PathType Leaf) -and (Split-Path -Path $Start2Path -Leaf) -eq $fileName)) {
        return
    }

    # Sanity check script mode.
    if (!$global:g_DefaultUserOnly) {
        return
    }

    Write-Status -Status ACTION -Message "Processing Default user's start menu..."

    $destinationDir = Join-Path -Path "$env:SystemDrive\Users\Default" -ChildPath "AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
    $destinationPath = Join-Path -Path $destinationDir -ChildPath $fileName

    if (!(Test-Path -Path $destinationDir)) {
        New-Item -Path $destinationDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    try {
        Write-Status -Status ACTION -Message "Copying $fileName to the Default User profile." -Indent 1
        Copy-Item -Path $Start2Path -Destination $destinationPath
        Write-Status -Status OK -Message "File copied successfully." -Indent 1
    }
    catch {
        Write-Status -Status FAIL -Message "File copy failed. Error: $($_.Exception.Message)" -Indent 1
    }
}

function Start-Debloat {
    [CmdletBinding(DefaultParameterSetName='CurrentUser')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DebloatConfig,

        [Parameter(ParameterSetName='AllUsers',
        Mandatory=$false,
        HelpMessage="Apply settings to all existing user accounts (excluding Default).")]
        [switch]$AllUsers,

        [Parameter(ParameterSetName='DefaultUser',
            Mandatory=$false,
            HelpMessage="Apply settings to the Default User profile template for future new users.")]
        [switch]$DefaultUser
    )

    # Sanity check for path

    if (!((Test-Path -Path $DebloatConfig -PathType Leaf) -and $DebloatConfig -match "\.txt$")) {
        Write-Status -Status WARN -Message "Debloat config file was not found: $DebloatConfig"
        return
    }

    $debloatConfigContent = Get-Content -Path $DebloatConfig -ErrorAction SilentlyContinue |
                            Sort-Object -Unique |
                            ForEach-Object {$_.Trim(" *")} |
                            Where-Object {![string]::IsNullOrEmpty($_)}

    if (!$debloatConfigContent) {
        Write-Status -Status WARN -Message "No content was found within: $DebloatConfig"
        return
    }

    $appxPackageArgs  = @{}
    if ($PSCmdlet.ParameterSetName -eq "AllUsers") {
        $appxPackageArgs.AllUsers = $true
    }

    $mode = switch ($PSCmdlet.ParameterSetName) {
        "CurrentUser" {"Current User"}
        "AllUsers" {"All Users"}
        "DefaultUser" {"Default User"}
        Default {$null}
    }

    Write-Status -Status ACTION -Message "Starting debloat process (Mode: $mode)..."

    $debloatConfigContent | ForEach-Object {

        # Add the wildcards to our trimmed strings.
        $appName = "*$_*"

        Write-Status -Status ACTION -Message "Processing: $appName" -Indent 1

        # Only remove installed packages when running in CurrentUser or AllUsers mode.

        if ($PSCmdlet.ParameterSetName -in ("CurrentUser", "AllUsers")) {

            $installedPackages = Get-AppxPackage -Name $appName @appxPackageArgs -ErrorAction SilentlyContinue

            if ($installedPackages) {
                foreach ($package in $installedPackages) {
                    try {
                        Write-Status -Status ACTION -Message "Uninstalling..." -Indent 1
                        Remove-AppxPackage -Package $package.PackageFullName @appxPackageArgs -ErrorAction Stop | Out-Null
                        Write-Status -Status OK -Message "Removed." -Indent 1
                    }
                    catch {
                        Write-Status -Status FAIL -Message "Failed to remove. Error: $($_.Exception.Message)" -Indent 1
                    }
                }
            } else {
                Write-Status -Status OK -Message "Not installed." -Indent 1
            }
        }

        # Only remove provisioned packages when running in AllUsers or DefaultUser mode.

        if ($PSCmdlet.ParameterSetName -in ("AllUsers", "DefaultUser")) {

            $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like $appName}

            if ($provisionedPackages) {
                foreach ($package in $provisionedPackages) {
                    try {
                        Write-Status -Status ACTION -Message "Removing from provisioned packages..." -Indent 1
                        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
                        Write-Status -Status OK -Message "Removed." -Indent 1
                    }
                    catch {
                        Write-Status -Status FAIL -Message "Failed to remove provisioned package. Error: $($_.Exception.Message)" -Indent 1
                    }
                }
            } else {
                Write-Status -Status OK -Message "Not provisioned." -Indent 1
            }
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
            throw "Unable to query available power schemes."
        }

        if ([string]::IsNullOrWhiteSpace($powerSchemes)) {
            throw "No power schemes were returned by the query."
        }

        $processorString = $null
        $hasBattery = $false
        $isX3D = $false

        try {
            $processorString = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString").ProcessorNameString
        }
        catch {
            Write-Status -Status WARN -Message "It was not possible to obtain the processor string." -Indent 1
        }

        try {
            if (Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) {
                $hasBattery = $true
            }
        }
        catch {
            Write-Status -Status WARN -Message "It was not possible to determine whether a battery is present." -Indent 1
        }

        $isX3D = if ($processorString -and $processorString -match "^AMD.*X3D") { $true } else { $false }
        $targetPlan = if ($isX3D -or $hasBattery) { "Balanced" } else { "High performance" }

        # Use regex matching against the power plan list in case M$ ever decides to change them.
        $activeSchemeGUID = [regex]::Match($powerSchemes, 'Power Scheme GUID: ([a-f0-9-]+)\s+\([^\)]+\)\s*\*').Groups[1].Value
        $desiredSchemeGUID = [regex]::Match($powerSchemes, "Power Scheme GUID: ([a-f0-9-]+)\s+\($targetPlan\)").Groups[1].Value

        # The target plan for whatever reason is not available on this system.
        if (!$desiredSchemeGUID) {
            Write-Status -Status WARN -Message "The desired power plan ($targetPlan) was not found on this system." -Indent 1
            return $false
        }

        # The current scheme is the desired scheme.
        if ($activeSchemeGUID -eq $desiredSchemeGUID) {
            Write-Status -Status OK -Message "`"$targetPlan`" already active." -Indent 1
        # The current scheme is not the desired scheme.
        } else {
            Write-Status -Status ACTION -Message "Setting active power plan to: $targetPlan" -Indent 1
            powercfg /setactive $desiredSchemeGUID
            if ($LASTEXITCODE -ne 0) {
                throw "An error occurred: $($_.Exception.Message)"
            } else {
                Write-Status -Status OK -Message "Successfully applied `"$targetPlan`" power plan." -Indent 1
            }
        }

        # Disable sleep mode for machines that don't have a battery installed.
        if ($hasBattery -eq $false) {
            powercfg /change standby-timeout-ac 0
            if ($LASTEXITCODE -eq 0) {
                Write-Status -Status OK -Message "Sleep mode disabled." -Indent 1
            } else {
                throw "Unable to disable sleep mode."
            }
        }

        return $true
    }
    catch {
        Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
        return $false
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
        Write-Status -Status FAIL -Message "Path not found: $TweakPath" -Indent 1
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

                            $profileList = Get-ProfileList

                            if ($null -eq $profileList -or $profileList.Count -eq 0) {
                                Write-Status -Status FAIL -Message "AllUsers mode failed: No sids were returned during the lookup." -Indent 1
                                return
                            }

                            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                            $otherUserProfiles = $profileList | Where-Object {$_.SID -ne $currentSid}

                            foreach ($profile in $otherUserProfiles) {

                                $sid = $profile.SID
                                $profilePath = $profile.ProfileImagePath
                                $userHiveLoaded = $false

                                try {
                                    # Mount the registry hive if the user is not logged in
                                    if (!(Test-Path -Path "Registry::HKU\$sid")) {

                                        $userRegHivePath = Join-Path $profilePath "NTUSER.dat"

                                        if (!(Test-Path -Path $userRegHivePath -PathType Leaf)) {
                                            throw "Path not found: $userRegHivePath"
                                        }

                                        if (Get-UserRegistryHive -Load -HiveName HKU\$sid -HivePath $userRegHivePath) {
                                            $userHiveLoaded = $true
                                        } else {
                                            throw "Unable to load registry hive for SID ($sid). Error: $($_.Exception.Message)"
                                        }
                                    }

                                    foreach ($path in $oneDriveHKCUPathsToCheck) {

                                        $targetHKUPath = $path -replace "^HKCU:", "Registry::HKU\$sid"

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
                                catch {
                                    Write-Status -Status FAIL -Message $_.Exception.Message -Indent 1
                                    continue
                                }
                                finally {
                                    if ($userHiveLoaded) {
                                        $null = Get-UserRegistryHive -Unload -HiveName HKU\$sid
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
                            Write-Status -Status FAIL -Message "An error occurred during the OneDrive check: $($_.Exception.Message)" -Indent 1
                        }
                    }
                }
            }
            "DefaultUser" {
                try {

                    $oneDriveKeyValue = "OneDriveSetup"
                    $defaultUserRunPath = "Registry::HKU\TempDefault\Software\Microsoft\Windows\CurrentVersion\Run"
                    $defaultHivePath = if ([string]::IsNullOrEmpty($global:g_DefaultUserCustomHive)) {Join-Path $env:SystemDrive "Users\Default\NTUSER.dat"} else {$global:g_DefaultUserCustomHive}
                    $defaultHiveLoaded = $false

                    Write-Status -Status ACTION -Message "Loading the Default user's registry hive..." -Indent 1

                    if (!(Test-Path -Path "Registry::HKU\TempDefault")) {
                        if (Get-UserRegistryHive -Load -HiveName HKU\TempDefault -HivePath $defaultHivePath) {
                            $defaultHiveLoaded = $true
                            Write-Status -Status OK -Message "Hive loaded successfully." -Indent 1
                        } else {
                            Write-Status -Status FAIL -Message "Unable to continue searching for OneDrive without hive loaded." -Indent 1
                            return
                        }
                    }

                    $oneDriveDefaultUserSetup =  Get-ItemProperty -Path $defaultUserRunPath -Name $oneDriveKeyValue -ErrorAction SilentlyContinue

                    if ($oneDriveDefaultUserSetup) {
                        try {
                            Write-Status -Status ACTION -Message "Removing $oneDriveKeyValue from $($defaultUserRunPath -replace "Registry::HKU", "HKEY_USERS")" -Indent 1
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
        if ($defaultHiveLoaded) {
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

    $registryHivePath = "Registry::$HiveName"

    switch ($mode) {
        "Load" {
            # Check if already loaded.
            if (Test-Path -Path $registryHivePath) {
                return $true
            }

            # Check if source hive file exists.
            if (!(Test-Path -Path $HivePath -PathType Leaf)) {
                Write-Status -Status FAIL -Message "Path not found: $HivePath" -Indent 1
                return $false
            }

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

                if (!(Test-Path -Path $registryHivePath)) {
                    return $true
                }

                Wait-RegeditExit

                [System.GC]::Collect()
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

    $excludedProfiles = @(
        "WSIAccount"
    )

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

   $filteredProfiles = foreach ($profile in $profileList) {

        $sid = $profile.PSChildName
        $profilePath = $null

        try {
            $profilePath = $profile.GetValue("ProfileImagePath", $null)
            if ($null -eq $profilePath) {continue}
        } catch {
            Write-Status -Status WARN -Message "Could not read ProfileImagePath for SID $sid. Error: $($_.Exception.Message)" -Indent 1
            continue
        }

        if ($sid -match "^(S-1-5-(18|19|20)|S-1-5-93-2-(1|2)|\.DEFAULT)$") {
            continue
        }


        if (!(Test-Path -Path $profilePath -PathType Container)) {
            continue
        }


        if ((Split-Path -Path $profilePath -Leaf) -in $excludedProfiles) {
            continue
        }

        [PSCustomObject]@{
            SID              = $sid
            ProfileImagePath = $profilePath
        }
   }

   if ($null -eq $filteredProfiles -or $filteredProfiles.Count -eq 0) {
       Write-Status -Status FAIL -Message "No sids were returned." -Indent 1
       return @()
   }

   return $filteredProfiles
}

function Get-AllUserSids {
    return Get-ProfileList | Select-Object -ExpandProperty SID
}

function Get-AllUserProfilePaths {
   return Get-ProfileList | Select-Object -ExpandProperty ProfileImagePath
}

function Get-ActiveUserSessionCount {

    # Sanity check to ignore calls if not using the correct switch.
    if (!$global:g_AllUsers) {
        return 0
    }

    try {
        $null = Get-Command -Name quser -ErrorAction Stop
        $quserOutputLines = quser /server:$env:COMPUTERNAME 2>&1
        if (!$?) { throw }
        # Skip the header row and return count of active sessions.
        return @($quserOutputLines | Select-Object -Skip 1).Count
    }
    catch {
        Write-Status -Status FAIL -Message "Unable to determine the number of active user sessions." -Indent 1
        Write-Status -Status WARN -Message "The -AllUsers parameter requires that you be the sole logged-in user." -Indent 1
        while ($true) {
            $result = Read-Host "[>>] Confirm that you are the only logged-in user (Y/N)"
            switch ($result) {
                {$_ -match "Y(es)?"} {return 1 }
                {$_ -match "N(o)?"} {return 100}
                Default {continue}
            }
        }
    }
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
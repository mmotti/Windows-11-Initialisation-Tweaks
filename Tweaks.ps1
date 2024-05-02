Function Set-RegValueData {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $regPath,

        [Parameter(Mandatory=$true)]
        [object]
        $regValueData,

        [Parameter(Mandatory=$false)]
        [switch]
        $Create
    )

        $strRegPath = Split-Path $regPath
        $regValue = Split-Path $regPath -Leaf

        # If the path to the key exists
        if (Test-Path $strRegPath) {

            $itemPropertyObject = Get-ItemProperty $strRegPath $regValue -ErrorAction SilentlyContinue
            
            # If the key already exists
            # Compare the passed parameter data against the existing key value data
            if ($null -ne $itemPropertyObject) {

                if ($itemPropertyObject.$regValue -is [array]) {
                
                    $valueDiff = $false
                    
                    for ($i=0; $i -lt $itemPropertyObject.$regValue.Count; $i++) {
                        if ($itemPropertyObject.$regValue[$i] -ne $regValueData[$i]) {       
                            $valueDiff = $true
                            break
                        }
                    }
                }
                else {
                    if ($itemPropertyObject.$regValue -ne $regValueData) {
                        $valueDiff = $true
                    }
                }

                # Differences were found so we need to update the key in the registry
                if ($valueDiff) {
                    try {
                        Set-ItemProperty -Path $strRegPath -Name $regValue -Value $regValueData -ErrorAction Stop
                    }
                    catch{
                        throw $_.Exception.Message
                    }
                }
            }
            # Path exists but key doesn't
            else {
                    try {
                        New-ItemProperty -Path $strRegPath -Name $regValue -Value $regValueData -ErrorAction Stop | Out-Null
                    }
                    catch {
                        throw $_.Exception.Message
                    }
            }  
        }
        # Path to key does not exist
        # Create the path and then try to create a new item property
        else { 
            if ($Create) {
                try {
                    New-Item -Path $strRegPath | Out-Null
                }
                catch {
                    throw $_.Exception.Message
                }
                        
                try {
                    New-ItemProperty -Path $strRegPath -Name $regValue -Value $regValueData -ErrorAction Stop | Out-Null
                }
                catch {
                    throw $_.Exception.Message
                }
            }
            else {
                    Write-Host $strRegPath -ForegroundColor Red
                    Write-Host "${regValue}: $regValueData" -ForegroundColor Red
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

<#

Set the dark theme

#>

Write-Host 'Applying dark theme...'

$regPathCurrentTheme = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\CurrentTheme'
$currentTheme = (Get-ItemProperty (Split-Path $regPathCurrentTheme) `
                                  (Split-Path $regPathCurrentTheme -Leaf) -ErrorAction Stop).CurrentTheme
$newTheme = 'C:\Windows\resources\Themes\dark.theme'
$newThemeWallpaper = 'C:\Windows\web\wallpaper\Windows\img19.jpg'

if($newTheme -ne $currentTheme) {

    $regDictTheme = @{
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\CurrentTheme' = [string] 'C:\Windows\resources\Themes\dark.theme'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\HighContrast\Pre-High Contrast Scheme' = [string] $newTheme
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme' = [int] 0
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme' = [int] 0
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\ThemeMRU' = [string] "$newTheme;$currentTheme;"
    }

    if (Test-Path $newThemeWallpaper) {
        $regDictTheme['HKCU:\Control Panel\Desktop\WallPaper'] = [string] $newThemeWallpaper
    }

    foreach ($key in $regDictTheme.GetEnumerator()) { 
        Set-RegValueData $key.Name $key.Value
    }
}

<#

Show 'This PC' and custom icon settings
Small icons, sort by item type.

#>

Write-Host 'Setting icon layout...'

$iconLayoutsByteArray = 
@(
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,1,0,1,0,1,0,2,0,0,0,0,0,0,0,44,0,0,0,0,0,0,0,58,0,58,0,123,0,50,0
    48,0,68,0,48,0,52,0,70,0,69,0,48,0,45,0,51,0,65,0,69,0,65,0,45,0,49,0,48,0,54,0,57,0,45,0,65,0,50,0,68
    0,56,0,45,0,48,0,56,0,48,0,48,0,50,0,66,0,51,0,48,0,51,0,48,0,57,0,68,0,125,0,62,0,32,0,32,0,0,0,44,0
    0,0,0,0,0,0,58,0,58,0,123,0,54,0,52,0,53,0,70,0,70,0,48,0,52,0,48,0,45,0,53,0,48,0,56,0,49,0,45,0,49
    0,48,0,49,0,66,0,45,0,57,0,70,0,48,0,56,0,45,0,48,0,48,0,65,0,65,0,48,0,48,0,50,0,70,0,57,0,53,0,52,0
    69,0,125,0,62,0,32,0,32,0,0,0,1,0,0,0,0,0,0,0,2,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,0,1,0,0,0,0,0
    0,0,0,0,34,0,0,0,16,0,0,0,1,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,63,1,0
)

 $regDictIcons = @{
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu\{20D04FE0-3AEA-1069-A2D8-08002B30309D}' = [int] 0
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{20D04FE0-3AEA-1069-A2D8-08002B30309D}' = [int] 0
    'HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop\IconLayouts' = [array] $iconLayoutsByteArray
 }

 foreach ($key in $regDictIcons.GetEnumerator()) {
    Set-RegValueData $key.Name $key.Value
 }


<# 

Taskbar: Align to left, hide Copilot button, Widgets button and search

#>

Write-Host 'Tweaking Taskbar...'

$regDictTaskbar = @{
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\SearchboxTaskbarMode' = [int] 0
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowCopilotButton' = [int] 0
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl' = [int] 0
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa' = [int] 0
}


foreach ($key in $regDictTaskbar.GetEnumerator()) { 
    Set-RegValueData $key.Name $key.Value
}

<#

Disable online search from start menu

#>

Write-Host 'Setting Windows Explorer policies...'

Set-RegValueData -regPath 'HKCU:\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions' -regValueData 1 -Create

<#

Set File Explorer to:
Launch to This PC
Show hidden files and known folder extensions

#>

Write-Host 'Tweaking File Explorer...'

$regDictFileExplorer = @{
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden' = [int] 1
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt' = [int] 0
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\LaunchTo' = [int] 1
}

foreach ($key in $regDictFileExplorer.GetEnumerator()) { 
    Set-RegValueData $key.Name $key.Value
}

<#

Set the High Performance power plan

#>


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
}

<#

Enable RDP

#>

Write-Host 'Tweaking RDP...'

$regDictRDPEnable = @{
    'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\fDenyTSConnections' = [int] 0
    'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\updateRDStatus' = [int] 1
}


foreach ($key in $regDictRDPEnable.GetEnumerator()) { 
    Set-RegValueData $key.Name $key.Value
}

Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

<#

Refresh user system parameters and then restart Explorer

#>

Write-Host 'Refreshing...'

Start-Process "RUNDLL32.EXE" -ArgumentList "USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" -PassThru | Wait-Process
Stop-Process -Name explorer -PassThru | Wait-Process

<#

Remove public desktop shortcuts

#>

Write-Host 'Removing specified Public Desktop shortcuts...'

$publicDesktopShortcuts = @(
    'C:\Users\Public\Desktop\Microsoft Edge.lnk'
    )

foreach ($shortcut in $publicDesktopShortcuts) {
    Remove-item $shortcut
}


<#

Uninstall OneDrive

#>

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

<#

"Refresh" the desktop etc. with direct call to RUNDLL32

#>

 # Refresh the desktop
 Start-Process "RUNDLL32.EXE" -ArgumentList "USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" -PassThru | Wait-Process
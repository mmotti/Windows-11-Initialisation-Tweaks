# Windows 11 initialisation Tweaks
This script is an "initialisation" for fresh Windows installs (after OOBE). **It needs to be run as Administrator**.

## Usage
```
powershell.exe -ExecutionPolicy Bypass -File ".\Tweaks.ps1"
```

### Script actions

1. **Apply the Windows(dark) theme.**

    Windows is a little particular with the wallpaper; sometimes it needs a reboot or multiple script runs.

1. **Taskbar:**
    * Align to the left.
    * Hide the Copilot button.
    * Hide Widgets button.
    * Hide Search button.
  
1. **Disables start menu internet search suggestions.**

1. **File Explorer:**
    * Show hidden files.
    * Show extensions for known file types.
    * Open "This PC" by default.
  
1. **Set the power plan to High Performance.**

1. **Enable RDP:**
    * Change registry settings to enable RDP.
    * Enable firewall rules for the associated "Remote Desktop" display group.

1. **Remove the Microsoft Edge shortcut from the Public Desktop.**

1. **Run OneDrive Uninstallers:**
    * Run the uninstallers in the %localappdata% and Windows folders.

      Note: Windows will likely install these again.
   
1. **Desktop icons:**
    * Show "This PC" on the desktop.
    * Set the icon layout that I like (small icons & sort by item type).

### Windows Sandbox usage
You can use this file to initialise the Windows Sandbox too!

#### Sample  configuration

```wsb
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Data\Scripts</HostFolder>
      <SandboxFolder>C:\Scripts</SandboxFolder>
      <ReadOnly>True</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\Windows-Tweaks\Tweaks.ps1</Command>
  </LogonCommand>
</Configuration>
```
Save this with your relevant `<HostFolder>` and `SandboxFolder` preferences to a `.wsb` file (e.g. `Sandbox.wsb`) and then double-click the wsb file to launch the Sandbox.

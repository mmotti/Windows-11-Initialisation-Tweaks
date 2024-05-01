# Windows 11 initialisation Tweaks
This script is an "initialisation" for fresh Windows installs (after OOBE). **It needs to be run as Administrator**.

### What does it do?
1. Applies the Windows(dark) theme. 
    
    Windows is a little particular with the wallpaper; sometimes it needs a reboot or multiple script runs.

2. Taskbar:
    1. Aligns to the left.
    2. Hides the Copilot button.
    3. Hides Widgets button.
    4. Hides Search button.
3. Disables start menu internet search suggestions.
4. File Explorer
    1. Show hidden files
    2. Don't hide extensions for known file types
    3. Open "This PC" by default.
5. Set the power plan to High Performance.
6. Enable RDP
    1. Change registry settings to enable RDP.
    2. Enable firewall rules for the associated "Remote Desktop" display group.
7. Remove the Microsoft Edge shortcut from the Public Desktop.
8. Run OneDrive Uninstallers
    1. Run the uninstallers in the %localappdata% and Windows folders
    
    Note: Windows will likely install these again.
9. Desktop icons
    1. Show "This PC" on the desktop
    2. Set the icon layout that I like (small icons & sort by item type).

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

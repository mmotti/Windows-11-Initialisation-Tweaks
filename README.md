# Windows 11 initialisation Tweaks
This script is an "initialisation" for fresh Windows installs (after OOBE). **It needs to be run as Administrator**.

### What does it do?
**Applies the Windows(dark) theme.**

Windows is a little particular with the wallpaper; sometimes it needs a reboot or multiple script runs.

1. **Taskbar**:
    * Aligns to the left
    * Hides the Copilot button
    * Hides Widgets button
    * Hides Search button
  
2. **Disables start menu internet search suggestions**

3. **File Explorer**:
    * Show hidden files
    * Don't hide extensions for known file types
    * Open "This PC" by default.
  
4. **Set the power plan to High Performance**

5. **Enable RDP**:
    * Change registry settings to enable RDP.
    * Enable firewall rules for the associated "Remote Desktop" display group.

6. **Remove the Microsoft Edge shortcut from the Public Desktop**

7. **Run OneDrive Uninstallers**:
    * Run the uninstallers in the %localappdata% and Windows folders

      Note: Windows will likely install these again.
   
8. **Desktop icons**:
    * Show "This PC" on the desktop
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

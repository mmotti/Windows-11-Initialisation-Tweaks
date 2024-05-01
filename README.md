# Windows 11 initialisation Tweaks
This script is an "initialisation" for fresh Windows installs (after OOBE). **It needs to be run as Administrator**.

### What does it do?
1. Applies the Windows(dark) theme. Windows is a little particular with the wallpaper; sometimes it needs a reboot or multiple script runs.
2. Taskbar: Aligns to the left, hides the Copilot, Widgets and Search buttons.
3. Disables internet search suggestions with the start menu search.
4. File Explorer: show hidden files, don't hide extensions for known file types and open "This PC" by default.
5. Set the power plan to high performance.
6. Allows RDP.
7. Remove Microsoft Edge shortcut from the Public Desktop.
8. Run OneDrive Uninstallers. Windows will likely re-install though.
9. Show "This PC" on the desktop and set the icon layout that I like (small icons & sort by item type).

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
Save this with your relevant `<HostFolder>` and `SandboxFolder` preferences to a `.wsb` file and then double-click the wsb file to launch the Sandbox.

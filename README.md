# Windows 11 initialisation Tweaks
This script is a user "initialisation" for fresh Windows installs (after OOBE). It's here to make my life easier with VMs and such.

**This script requires administrative privileges**.

![Demonstration of script running.](assets/img/demo.gif)

## Usage
Execute using Run.bat

Or manually:
```
powershell.exe -ExecutionPolicy Bypass -File ".\Tweaks.ps1"
```

## Script actions

1. **Defaults**
    * Set Windows Terminal as the default console application.
    
1. **Apply the Windows(dark) theme.**

1. **Taskbar:**
    * Align to the left.
    * Hide the Copilot button.
    * Disable Widgets.
    * Hide Search button.
    * Select the far right corner of the taskbar to show the desktop.

1. **Desktop icons:**
    * Show "This PC" on the desktop.
    * Set desktop icons to small

1. **File Explorer:**
    * Hide recent files from Quick Access.
    * Hide frequently used folders from Quick Access.
    * Show hidden files.
    * Show extensions for known file types.
    * Open "This PC" by default.
    * Disable "Show sync provider notifications"

1. **Disable fast startup**

1. **Privacy / Annoyances:**
    * Disable Copilot+ Recall.
    * Disable "Store my activity history on this device".
    * Disable online search suggestions.
    * Disable app permission to use advertising ID.
    * Disable lock screen "fun facts, tips and tricks" on the lock screen.
    * Disable "Get tips and suggestions when using Windows" notifications.
    * Disable "Show me suggested content in the Settings app".
    * Disable the "Windows welcome experience" after updates.
    * Disable "Suggest ways to get the most out of Windows.
    * Disable "Tailored experiences".
    * Disable "Show recommendations for tips, shortcuts, new apps and more" in the start menu.
    * Disable "Let websites show me locally relevant content by accessing my language list".
    * Disable "Let Windows improve Start and Search by tracking app launches".
    * Disable "Improve ink and typing".
    * Disable "Sending optional diagnostic data". 
    * Disable Windows toast suggestions (notifications).

1. **Set the Power plan**:
    * Balanced: X3D processors.
    * High Performance: Everything else.

1. **Enable RDP** 
    * Change registry settings to enable RDP.
    * Enable firewall rules for the associated "Remote Desktop" display group.

1. **Remove the Microsoft Edge shortcut from the Public Desktop** 

1. **Remove OneDrive:**
    * Scan registry for UninstallStrings and run the uninstallers.
    * Remove "OneDriveSetup" from the default user's registry hive (HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run).

1. **Windows Update**
    * Disable "Delivery Optimisation" (Don't allow downloads from other devices).

## Usage with Windows Sandbox
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
Save this with your relevant `<HostFolder>`, `<SandboxFolder>` and `<Command>` preferences to a `.wsb` file (e.g. `Sandbox.wsb`) and then double-click the wsb file to launch the Sandbox.

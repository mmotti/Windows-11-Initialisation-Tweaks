# Windows 11 Initialisation Tweaks
This script is a user "initialisation" for a fresh Windows install. The majority of these tweaks will run in the current user's context by default.

**This script requires administrative privileges**.

![Demonstration of script running.](assets/img/demo030425.gif)

## Instructions

### 1. Open PowerShell and change directory:
    
    powershell
    cd 'PATH\TO\THE\SCRIPT\DIRECTORY\'

### 2. Run the script in the current user's context:

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1"

#### -- OR --

### Run the script for all existing users (excluding Default):

    "powershell -ExecutionPolicy Bypass -File ".\Tweaks" -AllUsers

#### -- OR --

### Run the script in the Default user's context (settings to apply to new users):

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser


## Actions

1. **Defaults:**
    * Set Windows Terminal as the default console application.

1. **Apply the Windows(dark) theme.**

1. **Lock screen:**
    * Disable Windows Spotlight.
    * Disable "fun facts, tips and tricks" on the lock screen.
    * Disable lock screen status.

1. **Taskbar:**
    * Align to the left.
    * Hide the Copilot button.
    * Hide Search button.
    * Select the far right corner of the taskbar to show the desktop.

1. **Desktop icons:**
    * Show "This PC" on the desktop.
    * Set desktop icons to small.

1. **File Explorer:**
    * Hide recent files from Quick Access.
    * Hide frequently used folders from Quick Access.
    * Show hidden files.
    * Show extensions for known file types.
    * Open "This PC" by default.
    * Disable "Show sync provider notifications".

1. **Disable fast startup.**

1. **Privacy / Annoyances:**
    * Disable Copilot+ Recall.
    * Disable Widgets.
    * Disable "Store my activity history on this device".
    * Disable online search suggestions.
    * Disable app permission to use advertising ID.
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

1. **Set the Power plan:**
    * Balanced: X3D processors.
    * High Performance: Everything else.
    * Disable sleep mode if no battery is detected.

1. **Enable RDP:**
    * Change registry settings to enable RDP.
    * Enable firewall rules for the associated "Remote Desktop" display group.

1. **Remove the Microsoft Edge shortcut from the Public Desktop.**

1. **Notepad settings:**
    * Open files in a new tab.
    * Start a new session / discard unsaved changes when Notepad starts.
    * WordWrap enabled.
    * Recent files enabled.
    * AutoCorrect enabled.
    * Disable CoPilot (Notepad integration).

    Note: Spellcheck option (enabled by default) is not altered as it could exclude file formats in future should they add further support.

1. **Remove OneDrive (current user only):**
    * Scan registry for UninstallStrings and run the uninstallers.
    * Remove "OneDriveSetup" from the default user's registry hive (HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run).
    * Scan for OneDrive in other user profiles and notify if detected.

1. **Windows Update:**
    * Disable "Delivery Optimisation" (Don't allow downloads from other devices).

## Usage with Windows Sandbox
You can use this file to initialise the Windows Sandbox too!

#### Sample configuration

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

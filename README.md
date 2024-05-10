# Windows 11 initialisation Tweaks
This script is a user "initialisation" for fresh Windows installs (after OOBE). It's here to make my life easier with VMs and such.

Items marked <code style="color : red">*</code> require the script to be elevated as Administrator

## Usage
```
powershell.exe -ExecutionPolicy Bypass -File ".\Tweaks.ps1"
```

## Script actions

1. **Apply the Windows(dark) theme.**

    Windows is a little particular with the wallpaper; sometimes it needs a reboot or multiple script runs.

1. **Taskbar:**
    * Align to the left.
    * Hide the Copilot button.
    * Hide Widgets button.
    * Hide Search button.

1. **Desktop icons:**
    * Show "This PC" on the desktop.
    * Set desktop icons to small
    * ~~Set the icon layout that I like (small icons & sort by item type).~~

1. **File Explorer:**
    * Show hidden files.
    * Show extensions for known file types.
    * Open "This PC" by default.
    * Disable 'Show sync provider notifications'

1. **Disable fast startup**<code style="color : red">*</code>

1. **Privacy / Annoyances:**<code style="color : red">*</code>
    * Disable online search suggestions.
    * Disable app permission to user advertising ID.
    * Disable lock screen "fun facts, tips and tricks" on the lock screen.
    * Disable "Get tips and suggestions when using Windows" notifications.
    * Disable "Show me suggested content in the Settings app".
    * Disable the "Windows welcome experience" after updates.
    * Disabled "Suggest ways to get the most out of Windows.
    * Disabled "Tailored experiences".
    * Disabled "Show recommendations for tips, shortcuts, new apps and more" in the start menu.
    * Disabled "Let websites show me locally relevant content by accessing my language list".
    * Disabled "Let Windows improve Start and Search by tracking app launches".
    * Disabled "Improve ink and typing".
    * Disabled "Sending optional diagnostic data". <code style="color : red">*</code>
    * Disabled Windows toast suggestions (notifications).

    Note: It is not possible to disable optional diagnostic data without admin elevation programmatically even though you can disable it in control panel without. If you can't run this script as admin and want to disable it, you need to do it manually.

1. **Set the power plan to High Performance.**

1. **Enable RDP** <code style="color : red">*</code>
    * Change registry settings to enable RDP.<code style="color : red">*</code>
    * Enable firewall rules for the associated "Remote Desktop" display group.<code style="color : red">*</code>

1. **Remove the Microsoft Edge shortcut from the Public Desktop** <code style="color : red">*</code>

1. **Run OneDrive Uninstallers:**<code style="color : red">*</code>
    * Run the uninstaller within the %localappdata% folder.
    * Run the uninstaller within the Windows folders with `/uninstall /allusers` <code style="color : red">*</code>

      Note: Windows will likely install these again.

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

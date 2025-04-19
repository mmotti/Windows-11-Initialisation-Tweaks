# Windows 11 Initialisation Tweaks
This script is a user "initialisation" for a fresh Windows install.

**Admin elevation required**.

![Demonstration of script running.](assets/img/demo030425.gif)

## Instructions

**1. Open PowerShell and change directory:**
    
    powershell
    cd 'PATH\TO\THE\SCRIPT\DIRECTORY\'

**2. Run the script in the current user's context:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1"

<hr />

<details closed>
<summary>Additional commandline options</summary>


### Debloating
Include debloat of [specified packages](assets/txt/debloat.txt).

**Debloat packages for current user**:

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -Debloat


**Debloat packages for all current and future users:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -AllUsers -Debloat
   
**Debloat packages for all future users:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser -Debloat
    
<hr />

### Script modes

**AllUsers mode (excluding Default profile):**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks" -AllUsers


**DefaultUser mode (convert HKCU registry entries to Default to apply to new users):**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser


**DefaultUser mode with a custom hive location:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUserCustomHive "PATH\TO\YOUR\FILE.dat"

### Misc options

**Don't exit on completion:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -Wait
<hr />

**Disable registry backups:**

    powershell -ExecutionPolicy Bypass -File ".\Tweaks" -EnableBackups $false
<hr />
</details>

## Modes
The modes currently available to this script are:
<ul>
<li>CurrentUser (default)</li>
<li>DefaultUser (Default user profile)</li>
<li>AllUsers</li>
</ul>

<details>
<summary>How each mode affects each action</summary>
<br />

**General Registry Tweaks:**

**Note:** Whilst you are able to specify one of the scopes below for the general registry tweaks, **tweaks that are out of scope (e.g. HKLM policies) will still apply**. The scope setting in this instance only determines how HKCU keys are imported (and converted where necessary).

<ul>
<li>
CurrentUser (Default Selection)

HKEY_CURRENT_USER keys remain unchanged and HKEY_LOCAL_MACHINE keys etc are imported as normal.
</li>
<li>
AllUsers

HKEY_CURRENT_USER keys are individually converted to HKEY_USERS\sid and applied to every user with a user profile. HKEY_LOCAL_MACHINE keys etc are imported as normal.
</li>

<li>
DefaultUser

HKEY_CURRENT_USER keys are individually converted to HKEY_USERS\TempDefault (for importing to the Default user's registry hive). HKEY_LOCAL_MACHINE keys etc are imported as normal.
</li>
</ul>

**Debloat:**

<ul>
<li>
CurrentUser (Default Selection)

Uninstall the specified packages for the current user.
</li>
<li>
AllUsers

Uninstall the specified packages for all users and also remove them as provisioned packages. 
</li>

<li>
DefaultUser

Remove the specified packages as provisioned packages.
</li>
</ul>

**Notepad:**

<ul>
<li>
CurrentUser (Default Selection)

Copy settings.dat file to: %LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\Settings
</li>
<li>
AllUsers

Copy settings.dat file to the above folder for all users.
</li>

<li>
DefaultUser

Copy the above file to the Default user's folder, relative to the above.
</li>
</ul>

**OneDrive**:
<ul>
<li>
CurrentUser (Default Selection)

Run uninstallers within HKCU.
</li>
<li>
AllUsers

Run uninstallers within HKCU, HKLM and notify you of OneDrive installations in other user profiles.</li>
<li>
DefaultUser

Remove OneDriveSetup from the Default user's registry hive.</li>
</ul>

</details>

## Actions

<details closed>
<summary>Script actions</summary>
<br />

1. **Debloat (if -Debloat switch present):**
    * Remove the packages specified in [debloat.txt](assets/txt/debloat.txt).
    * Conditionally remove provisioning of the specified apps for new users (depending on [mode](#modes)).

1. **Start Menu (if -DefaultUser switch present):**
    * Copy a "clean" start menu to the Default user's profile (for new users).

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
    * Open files in a new window.
    * Start a new session / discard unsaved changes when Notepad starts.
    * WordWrap enabled.
    * Recent files enabled.
    * AutoCorrect enabled.
    * Disable CoPilot (Notepad integration).

    Note: Spellcheck is left as default as M$ could introduce spellcheck support for further file types in future  which this could interfere with. Default setting is currently enabled for all file types.

1. **Remove OneDrive:**
    * Run the OneDrive uninstallers depending on the script mode.
    

1. **Windows Update:**
    * Disable "Delivery Optimisation" (Don't allow downloads from other devices).
</details>

## Usage with Windows Sandbox
You can use this file to initialise the Windows Sandbox too!

**Sample configuration**

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

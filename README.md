# Windows 11 Initialization Tweaks

![Demonstration](assets/img/demo030425.gif)

This PowerShell script helps streamline the setup of a fresh Windows 11 installation by applying various customization tweaks, privacy enhancements, and debloating options.

**⚠️ Important:**
- This script modifies system settings.
- **Administrator elevation is required.**
- Use at your own risk.
- Backups are enabled by default (except in Windows Sandbox).

## Features

This script performs a range of actions, including:

*   **UI Customization:**
    *   Applies the Windows dark theme.
    *   Align taskbar: left.
    *   Hides Taskbar Search and Copilot buttons.
    *   Enables "Show Desktop" on the far right corner of the taskbar.
    *   Enables "Show Clock in Notification Centre".
    *   Adds "This PC" icon to the desktop and sets icons to small.
    *   Configures File Explorer (show hidden files/extensions, hide recent/frequent items, open to This PC).
*   **Privacy & Annoyances:**
    *   Disables automatic installation of recommended Windows Store apps.
    *   Disables various tracking and advertising features (activity history, advertising ID, tailored experiences, diagnostic data, etc.).
    *   Disables transmission of typing data.
    *   Disables tips, suggestions, welcome experience, and Start Menu recommendations.
    *   Disables suggestions in "timeline".
    *   Disables Windows Spotlight and "fun facts" on the lock screen.
    *   Disables Widgets.
    *   Disables Windows Copilot features (exposed to Group Policy):
        - Paint: Co-Creator, Generative Fill, Image Creator.
    *   Disables Copilot+ Recall (and other "WindowsAI" features exposed to Group Policy):
        - Recall Enablement, Recall Export, AI Data Analysis, ClickToDo, SettingsAgent.
    *   Disables "Search with AI" in the task bar search box.
    *   Disables Start Menu suggestions from Windows Store (for apps not currently installed).
    *   Disables clipboard history.
*   **System Configuration:**
    *   Sets Windows Terminal as the default console.
    *   Set Balanced as the active power plan.
    *   Disables sleep mode on AC power if no battery is detected.
    *   Disables Fast Startup.
    *   Enables RDP (registry settings and firewall rules).
    *   Disables Windows Update Delivery Optimization (P2P downloads).
*   **Debloating & Cleanup (Optional):**
    *   Removes specified AppX packages (see [assets/txt/debloat.txt](assets/txt/debloat.txt)) using the [`-Debloat`](#debloating) switch.
    *   Removes the Microsoft Edge shortcut from the Public Desktop.
    *   Uninstalls OneDrive (scope depends on execution mode).
*   **Application Settings:**
    *   Applies custom settings for Notepad:
        - Misc: Open files in a new window.
        - Enable: Word wrap, Formatting, Recent Files, Spell Check, Autocorrect.
        - Disable: Copilot.
    *   Copies a clean Start Menu layout for new users (when using [`-DefaultUser`](#script-modes) mode).

## Prerequisites

*   Windows 11 (Build 22000 or higher)
*   PowerShell 5.1 or higher
*   Administrator privileges

## Installation

1.  Download the script files (ensure you have `Tweaks.ps1` and the [assets](assets) folder in the same directory). You can clone the repository or download a ZIP archive.
2.  Open PowerShell **as Administrator**.
3.  Navigate to the script's directory using `cd`:
    ```powershell
    cd 'C:\path\to\your\script\directory'
    ```

## Usage

### Basic Execution (Applies to Current User)

This is the simplest way to run the script. It applies tweaks to the currently logged-in user profile.

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1"
```

### Recommended Basic Execution (Applies to Current User, then the Default User)
```powershell
powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1"
powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser
```
---

### Advanced Usage & Command-Line Options

You can modify the script's behavior using different modes and switches:

#### Script Modes

These options change the *scope* of where the tweaks are applied:

*   **`-AllUsers`**: Attempts to apply relevant settings (Registry HKCU tweaks, Debloating, Notepad settings, OneDrive removal) to **all existing user profiles** found on the system (excluding the Default profile). HKLM settings are applied normally.
*   **`-DefaultUser`**: Attempts to apply relevant settings (Registry HKCU tweaks converted for Default, Debloating provisioned packages, Notepad settings, OneDrive setup removal) to the **Default User profile**. This affects **future users** created on the system. HKLM settings are applied normally.
    *   **`-DefaultUserCustomHive "PATH\TO\NTUSER.DAT"`**: (Use with `-DefaultUser`) Specify a path to a custom `NTUSER.dat` file for the Default User profile, instead of the system's default one.
    * **Note:** Some changes made to the Default User profile will be overwritten by Windows when a new profile is created. For more details, check out [Important Notes](#important-notes).

    

*(If no mode switch is specified, the script defaults to applying settings only to the **Current User**.)*

#### Debloating

*   **`-Debloat`**: Performs the debloating actions (removing apps listed in [assets/txt/debloat.txt](assets/txt/debloat.txt)). Combine this with modes (`-AllUsers`, `-DefaultUser`) to control the debloating scope.

    *   **Debloat for current user:**
        ```powershell
        powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -Debloat
        ```
    *   **Debloat for all current users AND future users:**
        ```powershell
        powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -AllUsers -Debloat
        ```
    *   **Debloat for future users only (provisioned apps):**
        ```powershell
        powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser -Debloat
        ```

#### Misc Options

*   **`-EnableBackups $false`**: Disables the automatic registry backup creation. **Use with caution.** (Backups are automatically disabled in Windows Sandbox).
    ```powershell
    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -EnableBackups $false
    ```
*   **`-NoWait`**: Do not prompt to continue on script completion..
    ```powershell
    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -NoWait
    ```

---

### Examples Combining Options

*   **Apply tweaks and debloat for ALL current users and remove provisioned apps for future users:**
    ```powershell
    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -AllUsers -Debloat
    ```

*   **Apply tweaks to the Default User profile (for future users) and remove provisioned apps:**
    ```powershell
    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser -Debloat
    ```

*   **Apply tweaks to a custom Default User hive:**
    ```powershell
    powershell -ExecutionPolicy Bypass -File ".\Tweaks.ps1" -DefaultUser -DefaultUserCustomHive "C:\Data\NTUSER.DAT"
    ```

---

## How Modes Affect Actions

The `-AllUsers` and `-DefaultUser` modes change how certain actions are performed compared to the default (Current User) mode:

| Action                | Default (Current User)                                                              | `-AllUsers`                                                                                                   | `-DefaultUser`                                                                                                     |
| :-------------------- | :---------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------- |
| **Registry Tweaks**   | Applies HKCU keys to current user. Applies HKLM keys system-wide.                   | Converts HKCU keys and applies them to *each existing user's* profile. Applies HKLM keys system-wide.       | Converts HKCU keys and applies them to the *Default User's* registry hive (for new users). Applies HKLM keys system-wide. |
| **Debloat** (`-Debloat`) | Uninstalls specified packages for the *current user*.                               | Uninstalls for *all users* AND removes *provisioned packages* (for new users).                                | Removes *provisioned packages* only (for new users).                                                               |
| **Notepad Settings**  | Copies [settings.dat](assets/dat//WindowsNotepad/settings.dat) to the *current user's* Notepad settings folder.              | Copies [settings.dat](assets/dat//WindowsNotepad/settings.dat) to *each existing user's* Notepad settings folder.                                      | Copies [settings.dat](assets/dat//WindowsNotepad/settings.dat) to the *Default User's* relative Notepad settings folder (for new users).                    |
| **OneDrive Removal**  | Runs uninstallers found in *current user's* registry (HKCU).                        | Runs HKCU & HKLM uninstallers. *Notifies* if OneDrive is detected in other user profiles (manual removal needed). | Removes OneDrive setup entry from the *Default User's* registry hive (for new users).                              |
| **Start Menu Layout** | No action.                                                                          | No action.                                                                                                    | Copies [start2.bin](assets/bin/StartMenu/start2.bin) to the *Default User* profile (for new users).                                                 |

**Note:** System-wide settings (like HKLM registry keys, firewall rules, power plans) are generally applied regardless of the chosen mode. The mode primarily dictates how user-specific settings (HKCU registry, user-installed apps, profile files) are handled.

---

## Usage with Windows Sandbox

You can easily use this script to initialize a Windows Sandbox environment on launch.

**Sample `.wsb` Configuration:**

```xml
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <!-- Adjust HostFolder to where you downloaded the script -->
      <HostFolder>C:\Path\To\Your\Script\Directory</HostFolder>
      <!-- This is where it will appear inside the Sandbox -->
      <SandboxFolder>C:\Tweaks</SandboxFolder>
      <ReadOnly>true</ReadOnly> <!-- Optional: Mount as read-only -->
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <!-- Command to run the script inside the Sandbox -->
    <!-- Example: Run default tweaks and don't wait -->
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Tweaks\Tweaks.ps1 -NoWait</Command>
  </LogonCommand>
</Configuration>
```

Save this configuration as a `.wsb` file (e.g., `SandboxTweak.wsb`) and double-click it to launch a pre-configured Sandbox instance. Registry backups are automatically disabled when running inside the Sandbox.

---

## Important Notes

*   **Backups:** The script automatically backs up registry keys it intends to modify to a `backups` subfolder unless `-EnableBackups $false` is used or when run in Windows Sandbox.
*   **Explorer Restart:** The script temporarily stops `explorer.exe` to ensure certain settings (like taskbar alignment and icon sizes) apply correctly. It will restart Explorer automatically before finishing.
*   **Compatibility:** While designed for Windows 11, some tweaks might work on Windows 10, but this is not tested or guaranteed.

* **Default User Customizations:** When a new user logs in for the first time, Windows runs its own setup process which can overwrite certain settings (like Taskbar Search or Windows Spotlight) previously applied to the Default User template (`NTUSER.DAT`).

    <u>Recommendation</u>: For the most reliable results with these types of settings:
    1.  Allow new users to log in **once** to complete the initial Windows profile creation.
    2.  **After** that first login, apply your custom settings by either:
        *   Running this script while logged in as the new user (targets current profile).
        *   Logging back in as an administrator and using the `-AllUsers` parameter (targets all existing profiles, including the newly initialized one).
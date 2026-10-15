# dsh-smart-guard

Smart guard plugin for DeepSeek Harness (DSH).

## Philosophy

Do not restrict the agent's work -- protect the system from destructive
actions. The agent may create, read, download, install, run, compile and copy
anything, anywhere. Deleting, formatting and killing processes is only
allowed inside project folders.

## Categories

### ALLOWED EVERYWHERE (no restrictions)

- Creating new files and folders
- Reading any files
- Downloading (Invoke-WebRequest, curl, wget)
- Installing software (winget, choco, npm, pip, scoop)
- Launching browsers, Playwright, Chrome, Firefox
- Running Python, Node.js, npm, git
- Installing ADB, Android SDK, Platform Tools
- Compiling, building, rendering
- Copying and moving files into and out of projects

### REQUIRES CONFIRMATION (asked in chat)

- Deleting files outside project folders
- Deleting temporary files in AppData\Local\Temp
- Stopping processes unrelated to a project
- Changing environment variables

### BLOCKED FOREVER (deny-list)

- Any del / Remove-Item / rmdir / rd / format / diskpart inside:
  - C:\Windows\
  - C:\Program Files\
  - C:\Program Files (x86)\
  - C:\ProgramData\
  - C:\Users\79881\AppData\
  - C:\Users\79881\Documents\
  - C:\Users\79881\Downloads\
- Any folder containing in its name: MetaTrader, MT4, MT5, terminal.exe,
  terminal64.exe, Chrome\User Data, Mozilla\Firefox, Edge\User Data, Opera,
  Brave, Yandex
- Registry changes: reg delete, reg add
- Services: sc delete, sc stop, net stop
- taskkill for: terminal.exe, terminal64.exe, chrome.exe, firefox.exe,
  explorer.exe, winlogon.exe, services.exe, lsass.exe
- Formatting: format, diskpart, format-volume
- Disabling Windows Defender or the firewall
- Deleting accounts, resetting passwords

## How interception works

The plugin registers a listener on the DSH tool registry's
`tools/pre-execute` waterfall. Every `pwsh` (and `bash`) tool call passes
through the listener before the command body runs. The listener:

1. Reads the command.
2. Splits it into segments (&&, ||, ;, |, newlines).
3. For each segment, checks whether it is destructive (delete, format, kill,
   registry, service, environment, system protection).
4. Non-destructive segments are allowed.
5. Destructive segments are checked against the configured project folders,
   deny-list and deny-patterns:
   - path in deny-list -> blocked, the agent receives
     `BLOCKED: path X is in a protected zone. Reason: Y`
   - path in a project folder -> allowed
   - path outside both -> the user is asked through the approval channel
6. Every denial and confirmation request is logged to
   `C:\Users\79881\.dsh\profiles\desktop\dsh-smart-guard.log`

## Configuration

`dsh-smart-guard.yml` (next to `index.js`) holds the lists:

```yaml
projects:            # free destructive zone
deny_delete:         # permanently protected absolute zones
deny_delete_patterns:# protected substrings anywhere on disk
deny_processes_kill: # processes that must never be killed
require_confirmation:# which ambiguous operations ask the user
```

## Install

From the plugin folder:

```
dsh plugin --profile desktop add C:\Users\79881\Desktop\dsh-smart-guard
```

or via the DSH GUI: Settings -> Plugins -> Add plugin.

The bundle patch (`cordis.patch.yml`) inserts the plugin row automatically
when the package is installed through the plugin manager.

## Test

```
Remove-Item C:\Windows\System32\test.txt        -> BLOCKED (Windows zone)
Remove-Item C:\Users\79881\Desktop\MyClaudeProjects\test.txt -> ALLOWED (project)
winget install Python.3.12                       -> ALLOWED (creative)
taskkill /IM terminal.exe /F                     -> BLOCKED (protected process)
```

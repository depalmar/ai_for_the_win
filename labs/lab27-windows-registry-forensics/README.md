# Lab 27: Windows Registry Forensics [Deep Dive]

**Difficulty:** Intermediate | **Time:** 75 min | **Prerequisites:** Lab 25 (DFIR Fundamentals)

Master Windows Registry analysis for persistence hunting and forensic investigation.

## Learning Objectives

By the end of this lab, you will:
- Understand the Windows Registry structure and hive files
- Hunt for persistence mechanisms in registry
- Extract forensic artifacts (UserAssist, ShimCache, MRU)
- Detect malware indicators in registry keys
- Use AI to analyze and explain suspicious registry entries

## Prerequisites

- Completed Lab 25 (DFIR Fundamentals)
- Basic Windows administration knowledge

---

## Registry Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                  WINDOWS REGISTRY HIVES                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  SYSTEM HIVES (C:\Windows\System32\config\)             │  │
│  ├─────────────────────────────────────────────────────────┤  │
│  │                                                         │  │
│  │  SYSTEM    → Services, drivers, boot config             │  │
│  │  SOFTWARE  → Installed programs, Run keys               │  │
│  │  SAM       → User accounts (encrypted)                  │  │
│  │  SECURITY  → Security policies, cached creds            │  │
│  │  DEFAULT   → Default user profile                       │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  USER HIVES (C:\Users\<username>\)                      │  │
│  ├─────────────────────────────────────────────────────────┤  │
│  │                                                         │  │
│  │  NTUSER.DAT   → User preferences, Run keys, history     │  │
│  │  UsrClass.dat → User file associations, shell settings  │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  VOLATILE (RAM only, not persisted)                     │  │
│  ├─────────────────────────────────────────────────────────┤  │
│  │                                                         │  │
│  │  HKLM\HARDWARE → Current hardware config                │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

---

## Persistence Locations (Priority Order)

### CRITICAL - Check First

```
🔴 AUTO-START PERSISTENCE (most common malware locations)

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

### HIGH - Login/Startup Hooks

```
🟠 WINLOGON HOOKS (T1547.004)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  └── Shell       (default: explorer.exe) - HIJACKED for persistence
  └── Userinit    (default: userinit.exe) - HIJACKED for persistence
  └── Notify      (legacy DLLs, pre-Vista)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList
  └── Hidden accounts (value = 0 hides from login screen)
```

### HIGH - Service Persistence

```
🟠 SERVICES (T1543.003)

HKLM\SYSTEM\CurrentControlSet\Services\<servicename>
  └── ImagePath   → Binary location (check for suspicious paths)
  └── Start       → 2=Automatic, 3=Manual, 4=Disabled
  └── Type        → 16=Own process, 32=Share process
  └── Description → Often blank for malware

Red Flags:
  - ImagePath in user-writable location
  - No Description
  - Strange service name (random characters)
  - ServiceDll pointing to unusual DLL
```

### HIGH - Scheduled Tasks in Registry

```
🟠 TASK SCHEDULER (T1053.005)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}
  └── Path   → Task name
  └── Hash   → Task file hash

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
  └── Folder structure of scheduled tasks
```

### MEDIUM - Execution Hijacking

```
🟡 IMAGE FILE EXECUTION OPTIONS (T1546.012)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>
  └── Debugger → Redirects execution to another binary

Example attack:
  HKLM\...\Image File Execution Options\sethc.exe
    Debugger = cmd.exe   ← Sticky Keys backdoor!
```

```
🟡 APP PATHS HIJACKING

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<app.exe>
  └── (Default) → Path to execute when app.exe is run

Can redirect legitimate application names to malware.
```

```
🟡 SHELL EXTENSION HANDLERS

HKCR\*\shellex\ContextMenuHandlers\
HKCR\Directory\shellex\ContextMenuHandlers\
HKCR\Folder\shellex\ContextMenuHandlers\

Malicious DLLs loaded when right-clicking files/folders.
```

### MEDIUM - COM Object Hijacking

```
🟡 COM HIJACKING (T1546.015)

HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
  └── (Default) → DLL path

HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
  └── (Default) → DLL path

Attackers create HKCU key to override HKLM, loading malicious DLL.
```

---

## Forensic Artifacts

### UserAssist (Program Execution History)

```
Location:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

Key GUIDs:
{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} - Executable file execution
{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} - Shortcut file execution

Values are ROT13 encoded!

Example:
  P:\Hfref\nqzva\Qbjaybnqf\zvzvxngm.rkr  (encoded)
  C:\Users\admin\Downloads\mimikatz.exe    (decoded)
```

### ShimCache (Application Compatibility Cache)

```
Location:
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

Contains:
- Full path to executed binary
- Last modification time of file
- Execution flag (varied by OS version)

Note: Presence ≠ Execution (may just be file system access)
But insertion order can indicate timeline.
```

### AmCache (Detailed Execution History)

```
Location:
C:\Windows\appcompat\Programs\Amcache.hve

Contains:
- First execution time
- File path
- SHA1 hash
- PE header metadata
- Publisher information
```

### MRU (Most Recently Used)

```
Recent Documents:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

Recent Commands (Run dialog):
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

Typed Paths:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

ComDlg32 (Open/Save dialogs):
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```

### USB Device History

```
Location:
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

Contains:
- Device manufacturer
- Product name
- Serial number
- First/last connection times

Also check:
HKLM\SYSTEM\MountedDevices
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

---

## Your Tasks

### Task 1: Registry Persistence Scanner (30 min)

Build a scanner that checks all persistence locations.

```python
def scan_persistence_locations(hive_path: str = None) -> dict:
    """
    Scan registry for persistence mechanisms.

    If hive_path is provided, parse offline hive file.
    Otherwise, query live registry.

    Returns dict with:
    - location: registry path
    - entries: list of name/value pairs
    - risk_level: critical/high/medium/low
    - technique: MITRE ATT&CK ID
    """
    # TODO: Implement
    pass
```

### Task 2: UserAssist Decoder (15 min)

Decode and analyze UserAssist entries.

```python
def decode_userassist(hive_path: str) -> list:
    """
    Parse UserAssist registry key and decode ROT13 values.

    Returns list of:
    - decoded_path: actual file path
    - run_count: number of executions
    - last_run: timestamp of last execution
    - focus_time: total focus time in seconds
    """
    # TODO: Implement
    pass
```

### Task 3: Service Analyzer (15 min)

Analyze services for suspicious indicators.

```python
def analyze_services(hive_path: str) -> list:
    """
    Analyze SYSTEM hive services for suspicious entries.

    Red flags to detect:
    - ImagePath in user-writable locations
    - No Description
    - ServiceDll in unusual location
    - Random/suspicious service names
    - Recently created (if timestamps available)

    Returns list of suspicious services with risk scores.
    """
    # TODO: Implement
    pass
```

### Task 4: Timeline Builder (15 min)

Build a timeline from registry artifacts.

```python
def build_registry_timeline(hive_paths: dict) -> list:
    """
    Build timeline from multiple registry artifacts:
    - UserAssist (execution times)
    - ShimCache (file modification times)
    - MRU entries (access times)
    - Service creation (if timestamps in hive)

    Returns chronologically sorted list of events.
    """
    # TODO: Implement
    pass
```

---

## Sample Data

Use sample registry hives in `data/registry_samples/`:
- `SYSTEM_infected` - System hive with malicious service
- `SOFTWARE_backdoor` - Software hive with Run key persistence
- `NTUSER_malware` - User hive with execution artifacts

---

## Hints

<details>
<summary>Hint 1: ROT13 Decoding</summary>

```python
import codecs

def rot13_decode(encoded_string):
    """Decode ROT13 encoded UserAssist values."""
    return codecs.decode(encoded_string, 'rot_13')

# Example
encoded = "P:\\Hfref\\nqzva\\Qbjaybnqf\\zvzvxngm.rkr"
decoded = rot13_decode(encoded)
print(decoded)  # C:\Users\admin\Downloads\mimikatz.exe
```

</details>

<details>
<summary>Hint 2: Parsing Offline Hives</summary>

```python
from Registry import Registry

def parse_run_keys(software_hive_path):
    """Parse Run keys from offline SOFTWARE hive."""
    reg = Registry.Registry(software_hive_path)

    run_keys = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    results = []
    for key_path in run_keys:
        try:
            key = reg.open(key_path)
            for value in key.values():
                results.append({
                    'path': key_path,
                    'name': value.name(),
                    'value': value.value(),
                    'type': value.value_type_str()
                })
        except Registry.RegistryKeyNotFoundException:
            continue

    return results
```

</details>

<details>
<summary>Hint 3: Suspicious Path Detection</summary>

```python
SUSPICIOUS_PATHS = [
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\programdata\\",
    "\\downloads\\",
]

SYSTEM_PATHS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
]

def is_suspicious_path(path):
    """Check if path is in suspicious location."""
    path_lower = path.lower()

    # System binaries should be in system paths
    system_binaries = ['svchost', 'csrss', 'lsass', 'services']
    for binary in system_binaries:
        if binary in path_lower:
            if not any(sp in path_lower for sp in SYSTEM_PATHS):
                return True  # Masquerading!

    # Check for user-writable locations
    return any(sp in path_lower for sp in SUSPICIOUS_PATHS)
```

</details>

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           WINDOWS REGISTRY FORENSICS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Hive Analyzed: SYSTEM, SOFTWARE, NTUSER.DAT
Analysis Date: 2026-01-07

━━━━━ PERSISTENCE MECHANISMS ━━━━━

🔴 CRITICAL: Malicious Run Key Entry
   Location: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   Name: WindowsUpdateCheck
   Value: C:\Users\Public\update.exe -silent
   Risk: Binary in user-writable location
   Technique: T1547.001 (Registry Run Keys)

🔴 CRITICAL: Sticky Keys Backdoor
   Location: HKLM\...\Image File Execution Options\sethc.exe
   Debugger: cmd.exe
   Risk: Accessibility feature hijacked
   Technique: T1546.008 (Accessibility Features)

🟠 HIGH: Suspicious Service
   Name: WinSvcUpdate
   ImagePath: C:\ProgramData\Microsoft\svc.exe
   Start: Automatic
   Description: (empty)
   Risk: No description, unusual path
   Technique: T1543.003 (Windows Service)

🟠 HIGH: COM Object Hijack
   CLSID: {BCDE0395-E52F-467C-8E3D-C4579291692E}
   InprocServer32: C:\Users\admin\AppData\Local\shell32.dll
   Risk: HKCU overriding system DLL
   Technique: T1546.015 (COM Hijacking)

━━━━━ EXECUTION ARTIFACTS ━━━━━

UserAssist (Decoded):
  C:\Users\admin\Downloads\mimikatz.exe
    Run Count: 3
    Last Run: 2026-01-05 14:23:45
    Focus Time: 127 seconds

  C:\Windows\System32\cmd.exe
    Run Count: 47
    Last Run: 2026-01-07 09:15:00

  C:\Tools\procdump64.exe
    Run Count: 2
    Last Run: 2026-01-05 14:25:12

ShimCache (Recent Entries):
  1. C:\Users\Public\update.exe (2026-01-04 22:15:00)
  2. C:\ProgramData\Microsoft\svc.exe (2026-01-04 22:14:30)
  3. C:\Windows\Temp\payload.exe (2026-01-04 22:10:00)

━━━━━ ATTACK TIMELINE ━━━━━

2026-01-04 22:10:00 - payload.exe created in Temp
2026-01-04 22:14:30 - svc.exe installed as service
2026-01-04 22:15:00 - update.exe Run key added
2026-01-05 14:23:45 - Mimikatz executed (3 times)
2026-01-05 14:25:12 - Procdump executed (LSASS dump?)
2026-01-07 09:15:00 - Attacker using cmd.exe

━━━━━ RECOMMENDATIONS ━━━━━

1. IMMEDIATE: Delete Run key "WindowsUpdateCheck"
2. IMMEDIATE: Remove IFEO debugger for sethc.exe
3. IMMEDIATE: Disable and remove WinSvcUpdate service
4. HIGH: Delete malicious binaries:
   - C:\Users\Public\update.exe
   - C:\ProgramData\Microsoft\svc.exe
5. HIGH: Investigate credential theft (Mimikatz + Procdump)
6. MEDIUM: Check for additional COM hijacking
```

---

## PowerShell Quick Reference

```powershell
# Check Run keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check services for suspicious paths
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -like "*Users*" -or
    $_.PathName -like "*Temp*" -or
    $_.PathName -like "*ProgramData*"
} | Select-Object Name, PathName, State

# Check Image File Execution Options
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    ForEach-Object {
        $debugger = (Get-ItemProperty $_.PSPath).Debugger
        if ($debugger) {
            [PSCustomObject]@{
                Target = $_.PSChildName
                Debugger = $debugger
            }
        }
    }

# Export registry hive for offline analysis
reg save HKLM\SYSTEM C:\forensics\SYSTEM.hiv
reg save HKLM\SOFTWARE C:\forensics\SOFTWARE.hiv
```

---

## Resources

- [Windows Registry Reference](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [SANS Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)
- [Registry Persistence Mechanisms](https://attack.mitre.org/techniques/T1547/)
- [python-registry](https://github.com/williballenthin/python-registry) - Python library for parsing registry hives

---

*Next: Lab 28 - Live Response Techniques*

# Lab 25: DFIR Fundamentals [Bridge Lab]

**Difficulty:** 🟡 Intermediate | **Time:** 60-90 min | **Prerequisites:** Labs 00-01

> **Bridge Lab:** This lab introduces incident response concepts and artifacts before the advanced DFIR labs (26-35).

Essential incident response concepts before diving into advanced DFIR labs.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab25_dfir_fundamentals.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand the incident response lifecycle
- Identify common attack artifacts (processes, files, network, registry)
- Map findings to MITRE ATT&CK techniques
- Build an artifact analysis toolkit
- Be prepared for Labs 26-35 (DFIR deep dives)

## Prerequisites

- Completed Labs 00-01 (Environment + Python Fundamentals)
- Basic understanding of operating systems (Windows/Linux)

## Time Required

⏱️ **60-90 minutes**

---

## Windows Event Log Quick Reference

### Critical Security Events

| Event ID | Log | Description | Technique |
|----------|-----|-------------|-----------|
| **4624** | Security | Successful logon | - |
| **4625** | Security | Failed logon | T1110 (Brute Force) |
| **4648** | Security | Explicit credential logon | T1078 (Valid Accounts) |
| **4672** | Security | Admin privileges assigned | Priv Escalation indicator |
| **4688** | Security | Process created | All execution |
| **4689** | Security | Process terminated | - |
| **4697** | Security | Service installed | T1543.003 (Service) |
| **4698** | Security | Scheduled task created | T1053 (Scheduled Task) |
| **4720** | Security | User account created | T1136 (Create Account) |
| **4732** | Security | User added to local group | - |
| **7045** | System | Service installed | T1543.003 |
| **1102** | Security | Audit log cleared | T1070.001 (Clear Logs) |

### PowerShell Logging

| Event ID | Log | Description |
|----------|-----|-------------|
| **4103** | PowerShell | Module logging |
| **4104** | PowerShell | Script block logging (shows actual code!) |
| **4105** | PowerShell | Script block start |
| **4106** | PowerShell | Script block stop |

### Event Log Parsing with PowerShell

```powershell
# Get failed logins in last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=(Get-Date).AddDays(-1)
}

# Get process creation events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} | Select-Object TimeCreated, @{N='Process';E={$_.Properties[5].Value}}

# Get PowerShell script blocks (requires script block logging enabled)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} | Select-Object TimeCreated, Message

# Export events to CSV
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} |
    Export-Csv -Path "auth_events.csv" -NoTypeInformation
```

---

## Why DFIR Matters

Digital Forensics and Incident Response (DFIR) is critical when:
- 🚨 An active breach is detected
- 🔍 You need to understand what happened
- 📋 Legal/compliance requires evidence preservation
- 🛡️ You want to prevent future attacks

---

## The Incident Response Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│              INCIDENT RESPONSE LIFECYCLE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   1. PREPARATION        2. IDENTIFICATION                   │
│   ──────────────        ───────────────                     │
│   • Playbooks           • Alert triage                      │
│   • Tools ready         • Scope assessment                  │
│   • Team trained        • Initial IOC collection            │
│                                                             │
│         │                       │                           │
│         ▼                       ▼                           │
│                                                             │
│   6. LESSONS LEARNED    3. CONTAINMENT                      │
│   ──────────────────    ─────────────                       │
│   • Post-mortem         • Isolate systems                   │
│   • Update playbooks    • Block C2/exfil                    │
│   • Improve detection   • Preserve evidence                 │
│                                                             │
│         ▲                       │                           │
│         │                       ▼                           │
│                                                             │
│   5. RECOVERY           4. ERADICATION                      │
│   ──────────            ─────────────                       │
│   • Restore systems     • Remove malware                    │
│   • Monitor closely     • Patch vulnerabilities             │
│   • Validate clean      • Reset credentials                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Attack Artifacts: What to Look For

### 1. Process Artifacts

Suspicious process indicators:

| Indicator | Why It's Suspicious | Example |
|-----------|---------------------|---------|
| **Unusual parent** | Office spawning cmd/powershell | WINWORD.EXE → powershell.exe |
| **Wrong path** | System binary from user folder | C:\Users\Public\svchost.exe |
| **Encoded commands** | Obfuscation attempt | powershell -enc JABjAG... |
| **No arguments** | Possible injected process | rundll32.exe (no DLL specified) |
| **High thread count** | Possible injection target | notepad.exe with 50+ threads |

### 2. File System Artifacts

| Artifact | Location | Indicates |
|----------|----------|-----------|
| **Prefetch** | C:\Windows\Prefetch\ | Program execution history |
| **Recent files** | %APPDATA%\Microsoft\Windows\Recent | User activity |
| **Temp files** | %TEMP%, C:\Windows\Temp | Malware staging |
| **Alternate Data Streams** | file.txt:hidden | Hidden data |

### 3. Network Artifacts

| Indicator | Pattern | Technique |
|-----------|---------|-----------|
| **Beaconing** | Regular interval connections | C2 communication |
| **DNS tunneling** | Long subdomains, high volume | Data exfiltration |
| **Unusual ports** | 443 to non-HTTPS server | Encrypted C2 |
| **Large uploads** | Spikes in outbound data | Exfiltration |

### 4. Registry Artifacts (Windows)

| Location | Purpose | Attack Use |
|----------|---------|------------|
| `HKLM\...\Run` | Startup programs | Persistence (T1547.001) |
| `HKCU\...\Run` | User startup | Persistence (T1547.001) |
| `HKLM\...\Services` | Windows services | Backdoor services (T1543.003) |
| `HKLM\...\Winlogon` | Login process | Credential theft (T1547.004) |

#### Deep Dive: Registry Persistence Locations

```
🔴 HIGH PRIORITY (check first):
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
├── HKLM\SYSTEM\CurrentControlSet\Services  ← Malicious services
├── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
│   └── Shell, Userinit, Notify  ← Login hooks
│
🟡 MEDIUM PRIORITY:
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
├── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
│   └── Debugger hijacking (T1546.012)
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
│   └── BHO malware
│
🔵 EVIDENCE (user activity):
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
├── NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
│   └── Program execution history (ROT13 encoded)
```

#### Registry Analysis Commands

```powershell
# PowerShell: Check Run keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check services for suspicious entries
Get-WmiObject Win32_Service | Where-Object {$_.PathName -like "*Temp*" -or $_.PathName -like "*Users\Public*"}

# Check Image File Execution Options (debugger hijacking)
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    Where-Object {(Get-ItemProperty $_.PSPath).Debugger}
```

---

## MITRE ATT&CK Mapping

Every finding should map to ATT&CK:

```
FINDING: PowerShell spawned by Word document
         │
         ▼
┌────────────────────────────────────────┐
│         MITRE ATT&CK MAPPING           │
├────────────────────────────────────────┤
│                                        │
│  Tactic: Execution                     │
│  Technique: T1059.001                  │
│  Name: PowerShell                      │
│                                        │
│  Tactic: Initial Access                │
│  Technique: T1566.001                  │
│  Name: Spearphishing Attachment        │
│                                        │
└────────────────────────────────────────┘
```

### Common Techniques by Phase

| Phase | Technique | ID | Example |
|-------|-----------|-----|---------|
| **Initial Access** | Phishing | T1566 | Malicious email attachment |
| **Execution** | PowerShell | T1059.001 | Encoded command execution |
| **Persistence** | Registry Run Keys | T1547.001 | HKCU\...\Run entry |
| **Privilege Escalation** | Valid Accounts | T1078 | Stolen credentials |
| **Defense Evasion** | Process Injection | T1055 | Code injection into explorer.exe |
| **Credential Access** | LSASS Dump | T1003.001 | Mimikatz usage |
| **Lateral Movement** | Remote Services | T1021 | PsExec, WMI, WinRM |
| **Collection** | Data Staged | T1074 | Files copied to temp folder |
| **Exfiltration** | Exfil Over C2 | T1041 | Data sent to C2 server |
| **Impact** | Data Encrypted | T1486 | Ransomware encryption |

---

## Your Task

Build an artifact analysis toolkit that:
1. Parses process data and identifies anomalies
2. Analyzes file system artifacts
3. Detects suspicious network connections
4. Maps findings to MITRE ATT&CK

### TODOs

1. **TODO 1**: Implement process anomaly detection
2. **TODO 2**: Build file artifact analyzer
3. **TODO 3**: Create network connection analyzer
4. **TODO 4**: Implement ATT&CK mapping
5. **TODO 5**: Generate incident summary report

---

## Hints

<details>
<summary>💡 Hint 1: Process Anomalies</summary>

Check for these patterns:
```python
SUSPICIOUS_PARENTS = {
    "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "rundll32.exe": ["powershell.exe", "cmd.exe"],
}

def is_suspicious_parent(process_name, parent_name):
    if process_name.lower() in SUSPICIOUS_PARENTS:
        return parent_name.lower() in SUSPICIOUS_PARENTS[process_name.lower()]
    return False
```

</details>

<details>
<summary>💡 Hint 2: Path Analysis</summary>

System binaries should be in system folders:
```python
SYSTEM_PATHS = ["c:\\windows\\system32", "c:\\windows\\syswow64"]

def is_masquerading(process_name, path):
    system_binaries = ["svchost.exe", "csrss.exe", "lsass.exe"]
    if process_name.lower() in system_binaries:
        return not any(sp in path.lower() for sp in SYSTEM_PATHS)
    return False
```

</details>

<details>
<summary>💡 Hint 3: ATT&CK Mapping</summary>

```python
TECHNIQUE_PATTERNS = {
    "T1059.001": ["powershell", "-enc", "-encoded"],
    "T1055": ["injection", "hollowing", "writeprocessmemory"],
    "T1003.001": ["mimikatz", "sekurlsa", "lsass"],
    "T1486": ["encrypt", "ransom", ".locked", "readme.txt"],
}

def map_to_attack(finding_text):
    for technique, patterns in TECHNIQUE_PATTERNS.items():
        if any(p in finding_text.lower() for p in patterns):
            return technique
    return None
```

</details>

---

## Expected Output

```
🔍 DFIR Artifact Analysis Toolkit
==================================

INCIDENT: Suspected Ransomware Attack
Timeline: 2024-01-15 09:00 - 11:30

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROCESS ANALYSIS:
  🔴 CRITICAL: Office spawning shell
     WINWORD.EXE (PID 4100) → powershell.exe (PID 4200)
     Technique: T1566.001 (Phishing), T1059.001 (PowerShell)

  🔴 CRITICAL: Masquerading detected
     svchost.exe running from C:\Users\Public\
     Technique: T1036.005 (Masquerading)

  🟡 WARNING: Encoded PowerShell
     Command: powershell.exe -enc JABjAGwAaQBlAG4...
     Technique: T1059.001 (PowerShell)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FILE ANALYSIS:
  🔴 CRITICAL: Shadow copy deletion attempted
     vssadmin delete shadows /all
     Technique: T1490 (Inhibit System Recovery)

  🟡 WARNING: Suspicious temp file
     C:\Windows\Temp\locker.exe
     Technique: T1204.002 (Malicious File)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NETWORK ANALYSIS:
  🔴 CRITICAL: C2 communication detected
     Connection to 185.143.223.47:443
     Technique: T1071.001 (Web Protocols)

  🔴 CRITICAL: Data exfiltration suspected
     Large upload to mega.nz (12.5 GB)
     Technique: T1567.002 (Exfil to Cloud Storage)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MITRE ATT&CK COVERAGE:
  Initial Access:    T1566.001 (Phishing Attachment)
  Execution:         T1059.001 (PowerShell)
  Defense Evasion:   T1036.005 (Masquerading)
  Exfiltration:      T1567.002 (Cloud Storage)
  Impact:            T1490 (Inhibit Recovery)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDED ACTIONS:
  1. Isolate affected hosts immediately
  2. Block C2 IP 185.143.223.47 at firewall
  3. Preserve memory dumps before remediation
  4. Reset credentials for compromised accounts
  5. Scan all endpoints for locker.exe hash
```

---

---

## Timeline Generation

Building a timeline is critical for understanding attack progression.

### Super Timeline with Plaso (log2timeline)

```bash
# Create timeline from disk image
log2timeline.py --storage-file timeline.plaso disk_image.E01

# Parse specific artifacts only (faster)
log2timeline.py --parsers "winevtx,prefetch,mft" timeline.plaso disk_image.E01

# Convert to CSV for analysis
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Filter to specific time window
psort.py -o l2tcsv -w timeline.csv timeline.plaso "date > '2024-01-15 08:00:00' AND date < '2024-01-15 18:00:00'"
```

### Key Artifacts for Timeline

| Artifact | Parser | What It Shows |
|----------|--------|---------------|
| Windows Event Logs | `winevtx` | Security events, logins, process creation |
| Prefetch | `prefetch` | Program execution with timestamps |
| $MFT | `mft` | File creation/modification/access |
| Registry | `winreg` | Configuration changes |
| ShimCache | `appcompatcache` | Program execution evidence |
| AmCache | `amcache` | First execution times |
| Browser History | `chrome_history`, `firefox_history` | Web activity |

### Timeline Analysis Tips

1. **Start from known-bad** - Anchor on confirmed malicious activity
2. **Work backwards** - How did attacker get initial access?
3. **Work forwards** - What did they do after compromise?
4. **Look for gaps** - Missing logs = potential anti-forensics
5. **Correlate sources** - Cross-reference events with network data

---

## Key Concepts

### Severity Levels

| Level | Meaning | Response Time |
|-------|---------|---------------|
| 🔴 CRITICAL | Active threat, immediate action | < 15 minutes |
| 🟠 HIGH | Likely malicious, investigate now | < 1 hour |
| 🟡 MEDIUM | Suspicious, needs analysis | < 4 hours |
| 🟢 LOW | Informational, review when possible | < 24 hours |

### Evidence Preservation

**Order of Volatility** (collect in this order):
1. Memory (most volatile)
2. Running processes
3. Network connections
4. Disk contents
5. Logs (least volatile)

### Chain of Custody

Always document:
- Who collected the evidence
- When it was collected
- How it was preserved
- Where it's stored

---

## Key Takeaways

1. **Follow the lifecycle** - Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
2. **Know your artifacts** - Processes, files, network, registry all tell a story
3. **Map to ATT&CK** - Gives common language and helps identify gaps
4. **Preserve evidence** - Order of volatility matters
5. **Document everything** - Chain of custody is critical

---

---

## Cloud DFIR (Brief Overview)

Modern IR often involves cloud environments. Key artifacts:

| Cloud | Log Source | What It Contains |
|-------|------------|------------------|
| **AWS** | CloudTrail | API calls, console logins |
| **AWS** | GuardDuty | Threat detection findings |
| **AWS** | VPC Flow Logs | Network traffic metadata |
| **Azure** | Activity Log | Control plane operations |
| **Azure** | Sign-in Logs | Authentication events |
| **Azure** | Monitor Logs | Application and security events |
| **GCP** | Cloud Audit Logs | Admin activity, data access |
| **GCP** | VPC Flow Logs | Network traffic |

> 💡 **Tip**: For cloud IR, focus on IAM (who), API calls (what), and timestamps (when).
> Most cloud providers have 90-day log retention by default - plan accordingly!

---

## SANS DFIR Resources

SANS is the gold standard for DFIR training. These free resources will level up your skills:

### Essential SANS Posters (Free Downloads)

| Poster | What It Covers | Why You Need It |
|--------|----------------|-----------------|
| **[Hunt Evil](https://www.sans.org/posters/hunt-evil/)** | Normal vs. malicious Windows process behaviors | Know what suspicious looks like |
| **[Windows Forensic Analysis](https://www.sans.org/posters/windows-forensic-analysis/)** | Registry, event logs, artifacts by location | Quick reference during investigations |
| **[DFIR Memory Forensics](https://www.sans.org/posters/memory-forensics-cheat-sheet/)** | Volatility commands, memory analysis | Lab 13 companion |
| **[Network Forensics](https://www.sans.org/posters/network-forensics-poster/)** | Protocol analysis, packet investigation | Lab 14 companion |
| **[Intrusion Discovery Cheat Sheet](https://www.sans.org/posters/intrusion-discovery-cheat-sheet-for-linux/)** | Linux artifact locations | Linux IR |

> 💡 **Pro Tip**: Print the "Hunt Evil" poster and keep it visible. It shows what normal Windows processes look like vs. what attackers try to mimic. Invaluable during triage.

### SANS DFIR Reading Room Papers

Search these topics at [sans.org/white-papers](https://www.sans.org/white-papers/):
- "Incident Response" - IR methodology and case studies
- "Memory Forensics" - RAM analysis techniques
- "Timeline Analysis" - Building attack timelines
- "Windows Forensics" - Artifact deep dives
- "Cloud Forensics" - AWS/Azure/GCP IR

### SANS Webcasts (Free)

[sans.org/webcasts](https://www.sans.org/webcasts/) offers free 1-hour technical sessions. Search for:
- "DFIR Summit" presentations
- "Blue Team" defensive techniques
- "Threat Hunting" methodologies

### SANS DFIR Courses (Paid, but excellent)

If you want to go deep, these are industry-standard certifications:

| Course | Focus | Certification |
|--------|-------|---------------|
| **FOR500** | Windows Forensics | GCFE |
| **FOR508** | Advanced Incident Response | GCFA |
| **FOR572** | Network Forensics | GNFA |
| **FOR610** | Malware Analysis | GREM |
| **FOR578** | Threat Intelligence | GCTI |

> Most employers recognize GIAC certifications. FOR508 (GCFA) is particularly valued for IR roles.

---

## What's Next?

You're now ready for advanced DFIR labs:

- **Lab 31**: Ransomware Detection (behavioral + static analysis)
- **Lab 12**: Purple Team (adversary emulation)
- **Lab 13**: Memory Forensics (Volatility3 + AI)
- **Lab 14**: C2 Traffic Analysis (network forensics)
- **Lab 15**: Lateral Movement Detection

Go catch some threats! 🎯

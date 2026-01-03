# Lab 10b: DFIR Fundamentals

**Difficulty:** 🟡 Intermediate | **Time:** 60-90 min | **Prerequisites:** Labs 01-10

Essential incident response concepts before diving into advanced DFIR labs.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab10b_dfir_fundamentals.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand the incident response lifecycle
- Identify common attack artifacts (processes, files, network, registry)
- Map findings to MITRE ATT&CK techniques
- Build an artifact analysis toolkit
- Be prepared for Labs 11-16 (DFIR deep dives)

## Prerequisites

- Completed Labs 01-10 (ML + LLM foundations)
- Basic understanding of operating systems (Windows/Linux)

## Time Required

⏱️ **60-90 minutes**

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
| `HKLM\...\Run` | Startup programs | Persistence |
| `HKCU\...\Run` | User startup | Persistence |
| `HKLM\...\Services` | Windows services | Backdoor services |
| `HKLM\...\Winlogon` | Login process | Credential theft |

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

## What's Next?

You're now ready for advanced DFIR labs:

- **Lab 11**: Ransomware Detection (behavioral + static analysis)
- **Lab 12**: Purple Team (adversary emulation)
- **Lab 13**: Memory Forensics (Volatility3 + AI)
- **Lab 14**: C2 Traffic Analysis (network forensics)
- **Lab 15**: Lateral Movement Detection

Go catch some threats! 🎯

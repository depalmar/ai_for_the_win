# Lab 10b: DFIR Fundamentals Walkthrough

Step-by-step guide to incident response and forensic analysis.

## Overview

This walkthrough guides you through:
1. The incident response lifecycle
2. Identifying attack artifacts
3. Analyzing processes, files, and network
4. Mapping findings to MITRE ATT&CK

**Difficulty:** Intermediate
**Time:** 60-90 minutes
**Prerequisites:** Labs 01-10 (ML + LLM foundations)

---

## The IR Lifecycle

Every incident follows this pattern:

```
PREPARATION → IDENTIFICATION → CONTAINMENT
     ↑                              ↓
LESSONS ← RECOVERY ← ERADICATION
```

This lab focuses on **Identification** - finding the artifacts that tell the story.

---

## Exercise 1: Process Analysis (TODO 1)

### What to Look For

| Indicator | Normal | Suspicious |
|-----------|--------|------------|
| Parent process | Expected | Office → PowerShell |
| Path | System folders | C:\Users\Public\ |
| Arguments | Standard | Encoded/obfuscated |
| Thread count | Low | Very high (injection) |

### Implementation

```python
SUSPICIOUS_PARENT_CHILD = {
    "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe", "wscript.exe"],
    "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe", "wscript.exe"],
    "rundll32.exe": ["powershell.exe", "cmd.exe"],
}

SYSTEM_BINARIES = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe"]
SYSTEM_PATHS = ["c:\\windows\\system32", "c:\\windows\\syswow64"]

def analyze_process(process: dict) -> dict:
    """Analyze a process for suspicious indicators."""
    findings = []
    severity = "LOW"

    name = process["name"].lower()
    parent = process["parent"].lower()
    path = process["path"].lower()

    # Check suspicious parent-child relationship
    if name in SUSPICIOUS_PARENT_CHILD:
        if parent in SUSPICIOUS_PARENT_CHILD[name]:
            findings.append({
                "type": "Suspicious Parent",
                "detail": f"{parent} spawned {name}",
                "technique": "T1566.001 (Phishing) + T1059 (Scripting)"
            })
            severity = "HIGH"

    # Check masquerading (system binary in wrong location)
    if name in SYSTEM_BINARIES:
        if not any(sp in path for sp in SYSTEM_PATHS):
            findings.append({
                "type": "Masquerading",
                "detail": f"{name} running from {path}",
                "technique": "T1036.005 (Masquerading)"
            })
            severity = "CRITICAL"

    # Check for encoded commands
    if "powershell" in name and process.get("command_line"):
        cmd = process["command_line"]
        if "-enc" in cmd.lower() or "-encoded" in cmd.lower():
            findings.append({
                "type": "Encoded Command",
                "detail": "PowerShell with encoded command",
                "technique": "T1059.001 (PowerShell)"
            })
            severity = max(severity, "HIGH")

    return {
        "process": process["name"],
        "pid": process["pid"],
        "findings": findings,
        "severity": severity
    }
```

### Testing

```python
processes = [
    {"name": "WINWORD.EXE", "pid": 4100, "parent": "explorer.exe",
     "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"},
    {"name": "powershell.exe", "pid": 4200, "parent": "WINWORD.EXE",
     "path": "C:\\Windows\\System32\\powershell.exe"},
    {"name": "svchost.exe", "pid": 5600, "parent": "rundll32.exe",
     "path": "C:\\Users\\Public\\svchost.exe"},
]

for proc in processes:
    result = analyze_process(proc)
    if result["findings"]:
        print(f"⚠️ {result['process']} (PID {result['pid']}): {result['severity']}")
        for f in result["findings"]:
            print(f"   └─ {f['type']}: {f['detail']}")
            print(f"      ATT&CK: {f['technique']}")
```

---

## Exercise 2: File Analysis (TODO 2)

### Key File Artifacts

| Artifact | Location | Reveals |
|----------|----------|---------|
| Prefetch | C:\Windows\Prefetch | Execution history |
| Recent files | %APPDATA%\Microsoft\Windows\Recent | User activity |
| Temp files | %TEMP%, C:\Windows\Temp | Malware staging |
| Startup | Shell:Startup | Persistence |

### Implementation

```python
import os
from datetime import datetime

SUSPICIOUS_LOCATIONS = [
    r"C:\Users\Public",
    r"C:\Windows\Temp",
    r"C:\ProgramData",
]

SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta"]

def analyze_file(file_info: dict) -> dict:
    """Analyze a file for suspicious indicators."""
    findings = []
    path = file_info["path"]

    # Check location
    for suspicious_loc in SUSPICIOUS_LOCATIONS:
        if suspicious_loc.lower() in path.lower():
            findings.append({
                "type": "Suspicious Location",
                "detail": f"File in {suspicious_loc}",
                "technique": "T1204.002 (Malicious File)"
            })

    # Check extension
    ext = os.path.splitext(path)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        findings.append({
            "type": "Executable in Temp",
            "detail": f"Executable ({ext}) in staging area",
            "technique": "T1105 (Ingress Tool Transfer)"
        })

    # Check for double extension
    if ".txt.exe" in path.lower() or ".pdf.exe" in path.lower():
        findings.append({
            "type": "Double Extension",
            "detail": "File using double extension to deceive",
            "technique": "T1036.007 (Double Extension)"
        })

    # Check file content hints
    if file_info.get("content_hint"):
        content = file_info["content_hint"].lower()
        if "vssadmin delete" in content or "bcdedit" in content:
            findings.append({
                "type": "Recovery Inhibition",
                "detail": "Commands to delete backups/recovery",
                "technique": "T1490 (Inhibit System Recovery)"
            })

    return {
        "file": path,
        "findings": findings,
        "severity": "HIGH" if findings else "LOW"
    }
```

---

## Exercise 3: Network Analysis (TODO 3)

### Network Indicators

| Pattern | Indicator | Technique |
|---------|-----------|-----------|
| Regular intervals | Beaconing | C2 |
| Long DNS subdomains | DNS tunneling | Exfil |
| Large uploads | Data exfil | T1041 |
| Known bad IPs | C2 infrastructure | T1071 |

### Implementation

```python
from collections import defaultdict

KNOWN_BAD_IPS = ["185.143.223.47", "45.33.32.156"]  # Example C2 IPs
KNOWN_BAD_PORTS = [4444, 5555, 6666, 8888]  # Common RAT ports

def analyze_network(connections: list) -> dict:
    """Analyze network connections for suspicious patterns."""
    findings = []

    # Track connection frequency per destination
    dest_counts = defaultdict(list)
    for conn in connections:
        dest_counts[conn["remote_ip"]].append(conn["timestamp"])

    for conn in connections:
        remote_ip = conn["remote_ip"]
        remote_port = conn["remote_port"]

        # Known bad IP
        if remote_ip in KNOWN_BAD_IPS:
            findings.append({
                "type": "Known C2 IP",
                "detail": f"Connection to {remote_ip}:{remote_port}",
                "technique": "T1071.001 (Web Protocols)",
                "severity": "CRITICAL"
            })

        # Suspicious port
        if remote_port in KNOWN_BAD_PORTS:
            findings.append({
                "type": "Suspicious Port",
                "detail": f"Connection on port {remote_port}",
                "technique": "T1571 (Non-Standard Port)",
                "severity": "HIGH"
            })

        # Check for beaconing (regular intervals)
        timestamps = dest_counts[remote_ip]
        if len(timestamps) >= 3:
            intervals = [timestamps[i+1] - timestamps[i]
                        for i in range(len(timestamps)-1)]
            if all(abs(i - intervals[0]) < 5 for i in intervals):  # Within 5 sec
                findings.append({
                    "type": "Beaconing",
                    "detail": f"Regular {intervals[0]}s intervals to {remote_ip}",
                    "technique": "T1071 (Application Layer Protocol)",
                    "severity": "HIGH"
                })

    return {
        "total_connections": len(connections),
        "unique_destinations": len(dest_counts),
        "findings": findings
    }
```

---

## Exercise 4: ATT&CK Mapping (TODO 4)

### Comprehensive Mapping

```python
TECHNIQUE_DATABASE = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "indicators": ["office spawning script", "macro", "attachment"]
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "indicators": ["powershell", "-enc", "iex", "downloadstring"]
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "indicators": ["injection", "hollowing", "writeprocessmemory"]
    },
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name",
        "tactic": "Defense Evasion",
        "indicators": ["svchost", "wrong path", "masquerade"]
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "indicators": ["mimikatz", "sekurlsa", "lsass", "credential dump"]
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "indicators": ["vssadmin", "bcdedit", "shadow", "recovery"]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "indicators": ["ransom", "encrypt", "locked", "bitcoin"]
    },
}

def map_findings_to_attack(findings: list) -> dict:
    """Map all findings to ATT&CK matrix."""
    technique_map = defaultdict(list)

    for finding in findings:
        if "technique" in finding:
            tech_id = finding["technique"].split()[0]  # Extract T1234
            if tech_id in TECHNIQUE_DATABASE:
                technique_map[TECHNIQUE_DATABASE[tech_id]["tactic"]].append({
                    "id": tech_id,
                    "name": TECHNIQUE_DATABASE[tech_id]["name"],
                    "evidence": finding["detail"]
                })

    return dict(technique_map)

def print_attack_matrix(technique_map: dict):
    """Print findings in ATT&CK matrix format."""
    print("\n📊 MITRE ATT&CK MAPPING")
    print("=" * 60)

    # Order tactics by kill chain
    tactic_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact"
    ]

    for tactic in tactic_order:
        if tactic in technique_map:
            print(f"\n{tactic}:")
            for tech in technique_map[tactic]:
                print(f"  • {tech['id']}: {tech['name']}")
                print(f"    Evidence: {tech['evidence']}")
```

---

## Exercise 5: Incident Summary (TODO 5)

### Complete Report Generator

```python
def generate_incident_report(incident_data: dict) -> str:
    """Generate complete incident report."""
    report = []

    # Header
    report.append("=" * 60)
    report.append("INCIDENT RESPONSE REPORT")
    report.append("=" * 60)
    report.append(f"Incident ID: {incident_data.get('id', 'TBD')}")
    report.append(f"Date: {datetime.now().isoformat()}")
    report.append(f"Status: {incident_data.get('status', 'Active')}")

    # Process findings
    report.append("\n" + "─" * 60)
    report.append("PROCESS ANALYSIS")
    report.append("─" * 60)

    critical_findings = []
    for proc in incident_data.get("processes", []):
        result = analyze_process(proc)
        if result["findings"]:
            for f in result["findings"]:
                if result["severity"] == "CRITICAL":
                    report.append(f"🔴 CRITICAL: {f['type']}")
                elif result["severity"] == "HIGH":
                    report.append(f"🟠 HIGH: {f['type']}")
                else:
                    report.append(f"🟡 {f['type']}")
                report.append(f"   {f['detail']}")
                report.append(f"   Technique: {f['technique']}")
                critical_findings.append(f)

    # Network findings
    report.append("\n" + "─" * 60)
    report.append("NETWORK ANALYSIS")
    report.append("─" * 60)

    net_result = analyze_network(incident_data.get("network", []))
    for f in net_result["findings"]:
        icon = "🔴" if f["severity"] == "CRITICAL" else "🟠"
        report.append(f"{icon} {f['type']}: {f['detail']}")

    # ATT&CK mapping
    all_findings = critical_findings + net_result["findings"]
    attack_map = map_findings_to_attack(all_findings)

    report.append("\n" + "─" * 60)
    report.append("MITRE ATT&CK COVERAGE")
    report.append("─" * 60)

    for tactic, techniques in attack_map.items():
        report.append(f"\n{tactic}:")
        for t in techniques:
            report.append(f"  • {t['id']}: {t['name']}")

    # Recommendations
    report.append("\n" + "─" * 60)
    report.append("RECOMMENDED ACTIONS")
    report.append("─" * 60)
    report.append("1. Isolate affected hosts immediately")
    report.append("2. Block identified C2 IPs at firewall")
    report.append("3. Preserve memory dumps before remediation")
    report.append("4. Reset credentials for compromised accounts")
    report.append("5. Search for IOCs across all endpoints")

    return "\n".join(report)
```

---

## Common Errors

### 1. Case Sensitivity

```python
# WRONG: Case mismatch
if "powershell.exe" in process["name"]:  # Fails for "PowerShell.exe"

# CORRECT: Normalize case
if "powershell.exe" in process["name"].lower():
```

### 2. Missing Context

```python
# WRONG: Flag every PowerShell as suspicious
if "powershell" in name:
    findings.append("Suspicious!")

# CORRECT: Check context
if "powershell" in name and suspicious_parent:
    findings.append("PowerShell spawned by Office!")
```

### 3. Not Correlating Events

```python
# WRONG: Analyze each event in isolation
for event in events:
    analyze(event)

# CORRECT: Look for patterns across events
timeline = build_timeline(events)
find_attack_chains(timeline)
```

---

## Key Takeaways

1. **Follow the lifecycle** - Preparation → Identification → Containment → Eradication → Recovery → Lessons
2. **Know your artifacts** - Processes, files, network, registry
3. **Context matters** - A process alone isn't suspicious; its parent and path are
4. **Map to ATT&CK** - Common language for findings
5. **Document everything** - Evidence preservation is critical

---

## Next Steps

You're ready for advanced DFIR:

- **Lab 11**: Ransomware detection and response
- **Lab 12**: Purple team adversary emulation
- **Lab 13**: Memory forensics with AI
- **Lab 14**: C2 traffic analysis

# Lab 28: Live Response Techniques [Deep Dive]

**Difficulty:** Intermediate-Advanced | **Time:** 90 min | **Prerequisites:** Labs 10a-10c

Master live response techniques for active incident investigation without taking systems offline.

## Learning Objectives

By the end of this lab, you will:
- Execute live response collection from compromised systems
- Capture volatile data in correct order of volatility
- Use remote collection tools safely
- Build automated live response scripts
- Triage findings in real-time during an incident

## Prerequisites

- Completed Labs 10a-10c (DFIR series)
- PowerShell experience (intermediate)
- Understanding of Windows internals

---

## Live Response Principles

```
┌────────────────────────────────────────────────────────────────┐
│              LIVE RESPONSE GOLDEN RULES                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. PRESERVE BEFORE INVESTIGATE                                │
│     • Memory first, disk later                                 │
│     • Don't install tools to compromised drive                 │
│     • Use external/network storage for output                  │
│                                                                │
│  2. MINIMIZE FOOTPRINT                                         │
│     • Every action modifies evidence                           │
│     • Use trusted, static binaries                             │
│     • Document everything you do                               │
│                                                                │
│  3. ORDER OF VOLATILITY                                        │
│     • Collect most volatile data first                         │
│     • Memory → Network → Processes → Files → Registry          │
│                                                                │
│  4. WORK FROM EXTERNAL MEDIA                                   │
│     • USB drive with tools                                     │
│     • Network share for output                                 │
│     • Never write to local C: drive                            │
│                                                                │
│  5. ASSUME THE ATTACKER IS WATCHING                            │
│     • Use encrypted channels                                   │
│     • Avoid alerting through unusual activity                  │
│     • Coordinate with network team for isolation               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Order of Volatility

Collect in this order (most volatile first):

```
┌─────────────────────────────────────────────────────────┐
│  VOLATILITY PRIORITY                                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. 🔴 CPU Registers, Cache           (milliseconds)    │
│     └── Usually not collectible                         │
│                                                         │
│  2. 🔴 Memory (RAM)                   (power dependent) │
│     └── DumpIt, WinPMEM, Belkasoft RAM Capturer         │
│                                                         │
│  3. 🟠 Network State                  (seconds-minutes) │
│     └── netstat, dns cache, arp cache                   │
│                                                         │
│  4. 🟠 Running Processes              (seconds-minutes) │
│     └── tasklist, wmic process, handles                 │
│                                                         │
│  5. 🟡 Disk (non-volatile)            (days-years)      │
│     └── Can wait, but may be modified                   │
│                                                         │
│  6. 🟢 Logs, Registry                 (days-months)     │
│     └── May be cleared by attacker                      │
│                                                         │
│  7. 🔵 Physical Configuration         (years)           │
│     └── Network topology, asset info                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Live Response Toolkit

### Essential Tools (Run from USB)

| Tool | Purpose | Command |
|------|---------|---------|
| **WinPMEM** | Memory acquisition | `winpmem_mini_x64.exe memdump.raw` |
| **netstat** | Network connections | `netstat -anob` |
| **tasklist** | Running processes | `tasklist /v` |
| **handle** | Open handles | `handle.exe -a` |
| **listdlls** | Loaded DLLs | `listdlls.exe -v` |
| **autorunsc** | Persistence locations | `autorunsc.exe -a * -c -h` |
| **sigcheck** | Binary verification | `sigcheck.exe -e -h -v -vt` |

### PowerShell Collection Commands

```powershell
# ═══════════════════════════════════════════════════════════════
# NETWORK STATE (collect first after memory)
# ═══════════════════════════════════════════════════════════════

# Active connections with process info
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort,
    RemoteAddress, RemotePort, State, OwningProcess,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Export-Csv -Path E:\Collection\netstat.csv -NoTypeInformation

# DNS client cache (recently resolved domains)
Get-DnsClientCache | Export-Csv -Path E:\Collection\dns_cache.csv -NoTypeInformation

# ARP cache (MAC addresses seen)
Get-NetNeighbor | Export-Csv -Path E:\Collection\arp_cache.csv -NoTypeInformation

# Routing table
Get-NetRoute | Export-Csv -Path E:\Collection\routes.csv -NoTypeInformation

# ═══════════════════════════════════════════════════════════════
# PROCESS INFORMATION
# ═══════════════════════════════════════════════════════════════

# All processes with details
Get-Process | Select-Object Id, ProcessName, Path, StartTime,
    @{N='ParentId';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}},
    @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} |
    Export-Csv -Path E:\Collection\processes.csv -NoTypeInformation

# Services
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv -Path E:\Collection\services.csv -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{N='Actions';E={$_.Actions.Execute}} |
    Export-Csv -Path E:\Collection\scheduled_tasks.csv -NoTypeInformation

# ═══════════════════════════════════════════════════════════════
# USER AND SESSION INFORMATION
# ═══════════════════════════════════════════════════════════════

# Logged on users
quser 2>$null | Out-File -FilePath E:\Collection\logged_users.txt

# Local users
Get-LocalUser | Export-Csv -Path E:\Collection\local_users.csv -NoTypeInformation

# Local group membership
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $group 2>$null | ForEach-Object {
        [PSCustomObject]@{
            Group = $group
            Member = $_.Name
            Type = $_.ObjectClass
        }
    }
} | Export-Csv -Path E:\Collection\group_members.csv -NoTypeInformation

# ═══════════════════════════════════════════════════════════════
# PERSISTENCE LOCATIONS
# ═══════════════════════════════════════════════════════════════

# Run keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$runKeys | ForEach-Object {
    $path = $_
    if (Test-Path $path) {
        Get-ItemProperty $path | Get-Member -MemberType NoteProperty |
            Where-Object {$_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider')} |
            ForEach-Object {
                [PSCustomObject]@{
                    Path = $path
                    Name = $_.Name
                    Value = (Get-ItemProperty $path).$($_.Name)
                }
            }
    }
} | Export-Csv -Path E:\Collection\run_keys.csv -NoTypeInformation

# ═══════════════════════════════════════════════════════════════
# RECENT ACTIVITY
# ═══════════════════════════════════════════════════════════════

# Prefetch files (program execution history)
Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue |
    Select-Object Name, CreationTime, LastAccessTime, LastWriteTime |
    Export-Csv -Path E:\Collection\prefetch.csv -NoTypeInformation

# Recent files
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
    Select-Object Name, CreationTime, LastAccessTime |
    Export-Csv -Path E:\Collection\recent_files.csv -NoTypeInformation

# Temp folders
@("$env:TEMP", "C:\Windows\Temp", "C:\Users\Public") | ForEach-Object {
    Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.Extension -in '.exe','.dll','.ps1','.bat','.cmd','.vbs'} |
        Select-Object FullName, CreationTime, LastWriteTime, Length,
            @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}}
} | Export-Csv -Path E:\Collection\temp_executables.csv -NoTypeInformation
```

---

## Remote Live Response

### PowerShell Remoting

```powershell
# Enable PSRemoting on target (if not already enabled)
Enable-PSRemoting -Force

# Create session to remote host
$session = New-PSSession -ComputerName TARGET-PC -Credential (Get-Credential)

# Execute collection script remotely
Invoke-Command -Session $session -ScriptBlock {
    # Collection commands here
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort,
        RemoteAddress, RemotePort, State, OwningProcess
}

# Copy files back
Copy-Item -Path "C:\Windows\Temp\collection.zip" -Destination "E:\Evidence\" -FromSession $session

# Clean up
Remove-PSSession $session
```

### Remote Memory Acquisition

```powershell
# Using WinRM to trigger memory dump
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock {
    # Assuming WinPMEM is on network share
    & \\DFIR-SRV\Tools\winpmem_mini_x64.exe \\DFIR-SRV\Evidence\TARGET-PC.raw
}
```

---

## Your Tasks

### Task 1: Build Live Response Script (30 min)

Create a comprehensive PowerShell live response script.

```python
def generate_live_response_script(output_path: str, include_memory: bool = True) -> str:
    """
    Generate a PowerShell live response script that:
    1. Creates timestamped output folder
    2. Collects data in order of volatility
    3. Hashes collected files
    4. Creates summary report

    Args:
        output_path: Base path for evidence collection
        include_memory: Whether to include memory dump command

    Returns:
        Path to generated PowerShell script
    """
    # TODO: Implement
    pass
```

### Task 2: Remote Collection Tool (25 min)

Build a tool for remote evidence collection.

```python
def remote_collection(
    target_hosts: list,
    credential: dict,
    output_share: str,
    collection_type: str = "full"
) -> dict:
    """
    Execute remote live response collection.

    Args:
        target_hosts: List of hostnames/IPs
        credential: Dict with username and password
        output_share: UNC path for evidence storage
        collection_type: "quick" (network+processes) or "full"

    Returns:
        Dict with collection status per host
    """
    # TODO: Implement
    pass
```

### Task 3: Triage Analyzer (20 min)

Analyze collected data and identify IOCs.

```python
def triage_analysis(collection_path: str) -> dict:
    """
    Analyze live response collection for indicators.

    Checks:
    - Suspicious network connections (known bad IPs, unusual ports)
    - Unusual processes (wrong path, encoded commands)
    - Persistence mechanisms (Run keys, services, tasks)
    - Recent suspicious files (temp executables)

    Returns:
        Dict with findings by category and severity
    """
    # TODO: Implement
    pass
```

### Task 4: Timeline Correlator (15 min)

Correlate findings into attack timeline.

```python
def build_attack_timeline(triage_results: dict) -> list:
    """
    Build attack timeline from triage findings.

    Correlates:
    - Process start times
    - Network connection times
    - File creation times
    - Persistence creation times

    Returns:
        Chronologically sorted list of events with context
    """
    # TODO: Implement
    pass
```

---

## Quick Triage Checklist

Use this during active incidents:

```
┌────────────────────────────────────────────────────────────────┐
│              LIVE RESPONSE QUICK TRIAGE                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  □ NETWORK (1-2 min)                                           │
│    □ Connections to known bad IPs?                             │
│    □ Unusual outbound ports (4444, 8080, non-standard)?        │
│    □ Beaconing pattern (regular intervals)?                    │
│    □ Large data transfers?                                     │
│                                                                │
│  □ PROCESSES (2-3 min)                                         │
│    □ Unsigned binaries running?                                │
│    □ System binaries from wrong path?                          │
│    □ Encoded PowerShell commands?                              │
│    □ Unusual parent-child relationships?                       │
│    □ Process with network connection to suspicious IP?         │
│                                                                │
│  □ PERSISTENCE (2-3 min)                                       │
│    □ Unknown Run key entries?                                  │
│    □ New services in user-writable paths?                      │
│    □ Scheduled tasks with suspicious actions?                  │
│    □ Modified accessibility features (sethc, utilman)?         │
│                                                                │
│  □ FILES (2-3 min)                                             │
│    □ Executables in temp/public folders?                       │
│    □ Recently created files in Windows/System32?               │
│    □ Scripts in startup folders?                               │
│    □ Alternate data streams?                                   │
│                                                                │
│  □ USERS (1 min)                                               │
│    □ Unknown local accounts?                                   │
│    □ Unexpected group memberships?                             │
│    □ Disabled accounts re-enabled?                             │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
              LIVE RESPONSE TRIAGE REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Host: WKS-042.corp.local
Collection Time: 2026-01-07 14:32:15 UTC
Analyst: jsmith

━━━━━ IMMEDIATE THREATS ━━━━━

🔴 ACTIVE C2 CONNECTION
   Process: svchost.exe (PID 4872)
   Path: C:\Users\Public\svchost.exe  ← MASQUERADING!
   Connection: 185.143.223.47:443
   Duration: 4 hours 23 minutes
   Action: ISOLATE IMMEDIATELY

🔴 CREDENTIAL THEFT INDICATORS
   Process: powershell.exe (PID 6120)
   Command: -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAt...
   Decoded: Invoke-Mimikatz -DumpCreds
   Parent: cmd.exe ← wmiprvse.exe (WMI execution)
   Action: Assume credentials compromised

━━━━━ PERSISTENCE DETECTED ━━━━━

🟠 Malicious Service
   Name: WindowsUpdateSvc
   Path: C:\ProgramData\update.exe
   Status: Running
   Start: Automatic

🟠 Run Key Entry
   Key: HKCU\...\Run\SyncHelper
   Value: powershell.exe -w hidden -ep bypass -f C:\Users\Public\sync.ps1

🟠 Scheduled Task
   Name: \Microsoft\Windows\Maintenance\WMI
   Action: C:\Windows\Temp\wmi.exe
   Trigger: Daily at 03:00

━━━━━ NETWORK INDICATORS ━━━━━

Suspicious Connections:
  185.143.223.47:443 ← svchost.exe (fake)
  10.0.0.50:445      ← Lateral movement to FILESRV01
  10.0.0.10:88       ← Kerberos to DC (normal, but check timing)

DNS Cache (Suspicious):
  update.malware-c2.com → 185.143.223.47
  download.legit-update.net → 192.168.1.200 (internal?)

━━━━━ SUSPICIOUS FILES ━━━━━

Temp Executables:
  C:\Users\Public\svchost.exe
    Created: 2026-01-07 10:15:23
    SHA256: abc123...
    Signed: NO
    VT Score: 45/70

  C:\Windows\Temp\wmi.exe
    Created: 2026-01-07 10:16:45
    SHA256: def456...
    Signed: NO
    VT Score: 52/70

━━━━━ ATTACK TIMELINE ━━━━━

10:14:32 - WMI process started (lateral movement from SRV-DC01)
10:15:02 - PowerShell spawned by wmiprvse.exe
10:15:23 - svchost.exe dropped to C:\Users\Public\
10:15:45 - C2 connection established to 185.143.223.47
10:16:45 - wmi.exe dropped to C:\Windows\Temp\
10:17:02 - Scheduled task created for persistence
10:18:30 - Run key persistence added
10:20:00 - Credential dumping detected
10:25:00 - Lateral movement to FILESRV01 (10.0.0.50)

━━━━━ IMMEDIATE ACTIONS ━━━━━

1. ⚠️  ISOLATE HOST from network immediately
2. ⚠️  Block 185.143.223.47 at firewall
3. ⚠️  Check FILESRV01 for compromise
4. ⚠️  Rotate all credentials used on this host
5.    Preserve memory dump for analysis
6.    Collect disk image before remediation

━━━━━ EVIDENCE COLLECTED ━━━━━

Memory Dump: E:\Evidence\WKS-042\memory.raw (8.2 GB)
Network State: E:\Evidence\WKS-042\netstat.csv
Processes: E:\Evidence\WKS-042\processes.csv
Registry: E:\Evidence\WKS-042\registry\
Event Logs: E:\Evidence\WKS-042\evtx\
Prefetch: E:\Evidence\WKS-042\prefetch\

Total Collection Size: 12.4 GB
Collection Duration: 8 minutes 45 seconds
```

---

## Hints

<details>
<summary>Hint 1: Order of Collection</summary>

Always collect in this order:
```powershell
# 1. Memory (if tools available)
# 2. Network state (changes rapidly)
# 3. Running processes
# 4. Open handles/DLLs
# 5. User sessions
# 6. Persistence locations
# 7. Recent files
# 8. Event logs
# 9. Registry hives
```

</details>

<details>
<summary>Hint 2: Suspicious Process Detection</summary>

```python
def is_suspicious_process(process):
    """Check if process has suspicious characteristics."""
    red_flags = 0

    # System binary from wrong location
    system_binaries = ['svchost.exe', 'csrss.exe', 'lsass.exe']
    if process['name'].lower() in system_binaries:
        if 'system32' not in process['path'].lower():
            red_flags += 3  # Critical

    # Encoded PowerShell
    if 'powershell' in process['name'].lower():
        if '-enc' in process['commandline'].lower():
            red_flags += 2

    # Unusual parent
    if process['parent'] == 'wmiprvse.exe':
        if 'powershell' in process['name'].lower():
            red_flags += 2  # WMI spawning PowerShell

    # Running from temp/public
    suspicious_paths = ['\\temp\\', '\\public\\', '\\appdata\\']
    if any(p in process['path'].lower() for p in suspicious_paths):
        red_flags += 1

    return red_flags >= 2  # Threshold
```

</details>

<details>
<summary>Hint 3: Network Anomaly Detection</summary>

```python
KNOWN_BAD_PORTS = [4444, 5555, 6666, 8888, 31337]
EXPECTED_SERVICES = {
    'svchost.exe': [80, 443, 53],
    'chrome.exe': [80, 443],
    'outlook.exe': [443, 993, 587]
}

def analyze_connections(connections, processes):
    suspicious = []
    for conn in connections:
        proc = processes.get(conn['pid'])
        if not proc:
            continue

        # Check known bad ports
        if conn['remote_port'] in KNOWN_BAD_PORTS:
            suspicious.append({
                'type': 'known_bad_port',
                'severity': 'high',
                'connection': conn,
                'process': proc
            })

        # Check if process should have network access
        expected = EXPECTED_SERVICES.get(proc['name'], [])
        if expected and conn['remote_port'] not in expected:
            suspicious.append({
                'type': 'unexpected_port',
                'severity': 'medium',
                'connection': conn,
                'process': proc
            })

    return suspicious
```

</details>

---

## Resources

- [SANS Digital Forensics Cheat Sheets](https://www.sans.org/posters/)
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/) - Essential Windows tools
- [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) - Automated collection tool
- [Velociraptor](https://docs.velociraptor.app/) - Open source endpoint monitoring and collection

---

*Series Complete! See Labs 11-16 for advanced DFIR topics.*

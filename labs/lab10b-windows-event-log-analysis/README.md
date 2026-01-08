# Lab 10b: Windows Event Log Analysis [Deep Dive]

**Difficulty:** Intermediate | **Time:** 90 min | **Prerequisites:** Lab 10a (DFIR Fundamentals)

Deep dive into Windows Event Log analysis for threat hunting and incident response.

## Learning Objectives

By the end of this lab, you will:
- Parse and analyze Windows Security, System, and PowerShell logs
- Detect lateral movement, privilege escalation, and persistence
- Correlate events to build attack timelines
- Use AI to identify suspicious event patterns

## Prerequisites

- Completed Lab 10a (DFIR Fundamentals)
- Basic PowerShell knowledge
- Understanding of Windows authentication

---

## Windows Event Log Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    WINDOWS EVENT LOGS                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │   SECURITY      │  │    SYSTEM       │  │  APPLICATION    ││
│  │   %Security%    │  │   %System%      │  │  %Application%  ││
│  │                 │  │                 │  │                 ││
│  │ • Logons        │  │ • Services      │  │ • App errors    ││
│  │ • Process start │  │ • Drivers       │  │ • Installer     ││
│  │ • Object access │  │ • Reboots       │  │ • Custom apps   ││
│  └─────────────────┘  └─────────────────┘  └─────────────────┘│
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│  │  POWERSHELL     │  │   SYSMON        │  │  DEFENDER       ││
│  │  Operational    │  │  (if installed) │  │  Operational    ││
│  │                 │  │                 │  │                 ││
│  │ • Script blocks │  │ • Process tree  │  │ • Detections    ││
│  │ • Module load   │  │ • Network conn  │  │ • Quarantine    ││
│  │ • Pipeline      │  │ • File creates  │  │ • Scans         ││
│  └─────────────────┘  └─────────────────┘  └─────────────────┘│
│                                                                │
│  Default Location: C:\Windows\System32\winevt\Logs\           │
│  Format: .evtx (binary, XML-based internally)                 │
└────────────────────────────────────────────────────────────────┘
```

---

## Critical Event IDs Reference

### Authentication Events (Security Log)

| Event ID | Name | MITRE Technique | What to Look For |
|----------|------|-----------------|------------------|
| **4624** | Successful Logon | - | Logon Type 3 (network) from unexpected IPs |
| **4625** | Failed Logon | T1110 | Brute force patterns (many failures, then success) |
| **4648** | Explicit Credential Logon | T1078 | Pass-the-hash, runas attacks |
| **4672** | Special Privileges Assigned | - | Admin privileges to unexpected accounts |
| **4768** | Kerberos TGT Requested | T1558 | Kerberoasting, Golden Ticket |
| **4769** | Kerberos Service Ticket | T1558.003 | Kerberoasting (RC4 encryption) |
| **4771** | Kerberos Pre-Auth Failed | T1110 | Password spray attempts |

### Logon Types (Event 4624)

| Type | Name | Normal For | Suspicious When |
|------|------|------------|-----------------|
| **2** | Interactive | Console logins | RDP to servers |
| **3** | Network | File shares, SMB | Combined with PsExec artifacts |
| **4** | Batch | Scheduled tasks | Unknown task names |
| **5** | Service | Service accounts | Service running as user account |
| **7** | Unlock | Workstation unlock | After hours |
| **10** | RemoteInteractive | RDP connections | Unexpected source IPs |

### Process Events (Security Log - Requires Audit Policy)

| Event ID | Name | MITRE Technique | Detection Use |
|----------|------|-----------------|---------------|
| **4688** | Process Created | T1059 | Command line logging (if enabled) |
| **4689** | Process Terminated | - | Short-lived suspicious processes |
| **4697** | Service Installed | T1543.003 | Malicious service persistence |
| **4698** | Scheduled Task Created | T1053.005 | Persistence via schtasks |
| **4699** | Scheduled Task Deleted | T1070 | Covering tracks |

### Privilege and Account Events

| Event ID | Name | MITRE Technique | Alert On |
|----------|------|-----------------|----------|
| **4720** | User Account Created | T1136.001 | Any unexpected new account |
| **4722** | User Account Enabled | T1098 | Previously disabled accounts |
| **4724** | Password Reset Attempt | T1098 | Admin resetting sensitive accounts |
| **4728** | Member Added to Security-Enabled Global Group | T1098 | Adding to Domain Admins |
| **4732** | Member Added to Security-Enabled Local Group | T1098 | Adding to Administrators |
| **4756** | Member Added to Security-Enabled Universal Group | T1098 | Enterprise Admin additions |

### Defense Evasion Events

| Event ID | Log | What It Means | MITRE |
|----------|-----|---------------|-------|
| **1102** | Security | Audit log cleared | T1070.001 |
| **104** | System | Log was cleared | T1070.001 |
| **7045** | System | New service installed | T1543.003 |
| **7040** | System | Service start type changed | T1562 |

### PowerShell Events (PowerShell/Operational Log)

| Event ID | Name | What It Captures |
|----------|------|------------------|
| **4103** | Module Logging | Module/cmdlet execution |
| **4104** | Script Block Logging | **Full script content** (CRITICAL for hunting) |
| **4105** | Script Block Start | Script execution beginning |
| **4106** | Script Block End | Script execution end |
| **403** | Engine Lifecycle | Engine stopped (can indicate -nop usage) |

---

## Attack Pattern Detection

### Pattern 1: Lateral Movement via PsExec

```
Timeline Pattern:
1. 4624 Type 3 (Network logon) from workstation → server
2. 7045 (Service installed) - PSEXESVC or random name
3. 4688 (Process created) - cmd.exe or powershell.exe
4. 4624 Type 3 repeated to additional hosts

XQL Query:
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter event_id in (4624, 7045)
| fields _time, agent_hostname, event_id, actor_effective_username,
         action_evtlog_message
| sort asc _time
```

### Pattern 2: Kerberoasting Attack

```
Timeline Pattern:
1. 4769 (Service Ticket Requested) with RC4 encryption (0x17)
2. Multiple 4769 events from same source in short time
3. Targets: service accounts with SPNs

XQL Query:
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter event_id = 4769
| filter action_evtlog_message contains "0x17"  // RC4 encryption
| comp count() as ticket_count by agent_hostname, actor_effective_username
| filter ticket_count >= 5
| sort desc ticket_count
```

### Pattern 3: Credential Dumping (LSASS Access)

```
Timeline Pattern:
1. 4688 (Process Created) - rundll32.exe, procdump.exe, or unknown binary
2. 4663 (Object Access) - LSASS process accessed
3. 4658 (Handle Closed) - Handle to LSASS closed

XQL Query:
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter event_id = 4663
| filter action_evtlog_message contains "lsass.exe"
| fields _time, agent_hostname, actor_effective_username, action_evtlog_message
| sort desc _time
```

### Pattern 4: Pass-the-Hash

```
Timeline Pattern:
1. 4624 Type 3 with NTLM authentication (not Kerberos)
2. Logon Account ≠ Machine Account
3. Source IP = internal workstation
4. Multiple targets in short time

Key Indicators:
- Authentication Package: NTLM (not Kerberos)
- Logon Type: 3 (Network)
- Key Length: 0 (NTLMv1) or 128 (NTLMv2)
```

### Pattern 5: Persistence via Scheduled Task

```
Timeline Pattern:
1. 4698 (Scheduled Task Created)
2. Task runs as SYSTEM or privileged account
3. Action contains suspicious path or encoded command
4. 4688 (Process Created) when task executes

XQL Query:
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter event_id in (4698, 4699, 4700, 4701, 4702)
| fields _time, agent_hostname, event_id, action_evtlog_message
| sort asc _time
```

---

## Your Tasks

### Task 1: Build Event Parser (30 min)

Create a Python function that parses Windows Security events and extracts key fields.

```python
def parse_security_event(event_xml: str) -> dict:
    """
    Parse Windows Security event XML and extract:
    - Event ID
    - Timestamp
    - Computer name
    - Account name (subject and target)
    - Logon type (for 4624/4625)
    - Source IP/workstation
    - Process information (for 4688)

    Returns structured dict for analysis.
    """
    # TODO: Implement
    pass
```

### Task 2: Detect Brute Force (20 min)

Implement detection for brute force attacks using event patterns.

```python
def detect_brute_force(events: list, threshold: int = 5, window_minutes: int = 5) -> list:
    """
    Detect brute force attacks by finding:
    - Multiple 4625 (failed logon) events
    - From same source
    - Within time window
    - Followed by 4624 (success) = CRITICAL

    Returns list of detected attack patterns.
    """
    # TODO: Implement
    pass
```

### Task 3: Build Lateral Movement Detector (20 min)

Detect lateral movement patterns across multiple hosts.

```python
def detect_lateral_movement(events: list) -> list:
    """
    Detect lateral movement by finding:
    - Type 3 logons from workstation to multiple servers
    - Service installations (7045) after network logon
    - Remote execution patterns

    Returns list of potential lateral movement chains.
    """
    # TODO: Implement
    pass
```

### Task 4: Timeline Generator (20 min)

Build an attack timeline from correlated events.

```python
def generate_timeline(events: list, anchor_event: dict) -> str:
    """
    Generate attack timeline starting from anchor event:
    1. Find related events (same account, same source IP)
    2. Extend backwards (how did attacker get in?)
    3. Extend forwards (what did attacker do?)
    4. Format as readable timeline

    Returns formatted timeline string.
    """
    # TODO: Implement
    pass
```

---

## Sample Data

Use the provided sample data in `data/event_samples/` for testing:
- `security_events.json` - Sample 4624, 4625, 4688 events
- `powershell_events.json` - Sample 4104 script blocks
- `attack_scenario.json` - Full attack simulation events

---

## Hints

<details>
<summary>Hint 1: Parsing Event XML</summary>

```python
import xml.etree.ElementTree as ET

def parse_event(event_xml):
    root = ET.fromstring(event_xml)
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    event_id = root.find('.//e:EventID', ns).text
    time_created = root.find('.//e:TimeCreated', ns).get('SystemTime')

    # Event-specific data is in EventData
    data = {}
    for item in root.findall('.//e:Data', ns):
        name = item.get('Name')
        value = item.text
        data[name] = value

    return {
        'event_id': int(event_id),
        'timestamp': time_created,
        'data': data
    }
```

</details>

<details>
<summary>Hint 2: Brute Force Detection Logic</summary>

```python
from collections import defaultdict
from datetime import datetime, timedelta

def detect_brute_force(events, threshold=5, window_minutes=5):
    # Group failed logons by target account and source
    failed_by_source = defaultdict(list)

    for event in events:
        if event['event_id'] == 4625:
            key = (event['data'].get('TargetUserName'),
                   event['data'].get('IpAddress'))
            failed_by_source[key].append(event)

    attacks = []
    for key, failures in failed_by_source.items():
        if len(failures) >= threshold:
            # Check if within time window
            times = sorted([e['timestamp'] for e in failures])
            # ... additional time window logic
            attacks.append({
                'target_user': key[0],
                'source_ip': key[1],
                'failure_count': len(failures),
                'first_failure': times[0],
                'last_failure': times[-1]
            })

    return attacks
```

</details>

<details>
<summary>Hint 3: Lateral Movement Indicators</summary>

Look for this sequence:
```
1. 4624 Type 3 to Server A from Workstation X
2. 7045 on Server A (new service)
3. 4688 on Server A (process from service)
4. 4624 Type 3 to Server B from Server A  ← Movement!
5. Repeat...
```

Key fields to correlate:
- `SubjectUserName` / `TargetUserName`
- `IpAddress` / `WorkstationName`
- Time proximity (usually within minutes)

</details>

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           WINDOWS EVENT LOG ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Analysis Period: 2026-01-01 00:00 - 2026-01-07 23:59
Events Analyzed: 45,231
Hosts: 12

━━━━━ CRITICAL FINDINGS ━━━━━

🔴 BRUTE FORCE ATTACK DETECTED
   Target: svc_backup@CORP.LOCAL
   Source: 192.168.1.105
   Failed Attempts: 47 in 3 minutes
   Outcome: SUCCESS after failures
   Technique: T1110.001 (Password Guessing)
   Action: Reset password, investigate source

🔴 LATERAL MOVEMENT CHAIN
   Path: WKS-042 → SRV-FILE01 → SRV-DC01
   User: admin_temp
   Method: PsExec (PSEXESVC installed)
   Technique: T1021.002 (SMB/Admin Shares)
   Timeline:
     09:15:32 - Initial access to SRV-FILE01
     09:15:45 - Service PSEXESVC installed
     09:16:02 - cmd.exe spawned
     09:17:11 - Lateral to SRV-DC01
   Action: Isolate hosts, analyze for persistence

🔴 SCHEDULED TASK PERSISTENCE
   Task: WindowsUpdate_Check
   Host: SRV-FILE01
   Action: powershell.exe -enc JABjAGw...
   Run As: SYSTEM
   Technique: T1053.005 (Scheduled Task)
   Action: Remove task, analyze encoded command

━━━━━ HIGH SEVERITY ━━━━━

🟠 SERVICE INSTALLATION
   Host: WKS-105
   Service: svcupdate
   Path: C:\Users\Public\svc.exe
   Technique: T1543.003 (Windows Service)
   Action: Analyze binary, check persistence

🟠 KERBEROASTING SUSPECTED
   Source: WKS-042
   User: jsmith
   Service Tickets Requested: 23 in 2 minutes
   Encryption: RC4 (weak)
   Technique: T1558.003 (Kerberoasting)
   Action: Rotate service account passwords

━━━━━ ATTACK TIMELINE ━━━━━

09:00:00 ──┬─ Failed RDP login (4625) to WKS-042 from 192.168.1.200
09:05:23 ──┼─ Failed RDP login (4625) x5
09:12:45 ──┼─ Successful login (4624) Type 10 - RDP
09:13:02 ──┼─ Privilege assigned (4672) - SeDebugPrivilege
09:14:30 ──┼─ PowerShell execution (4104) - Mimikatz detected
09:15:32 ──┼─ Lateral to SRV-FILE01 (4624) Type 3
09:15:45 ──┼─ Service installed (7045) - PSEXESVC
09:16:02 ──┼─ Process created (4688) - cmd.exe
09:17:11 ──┼─ Lateral to SRV-DC01 (4624) Type 3
09:18:00 ──┴─ DCSync detected (4662) - Replication

━━━━━ RECOMMENDATIONS ━━━━━

1. IMMEDIATE: Disable compromised accounts
2. IMMEDIATE: Isolate WKS-042, SRV-FILE01, SRV-DC01
3. HIGH: Reset all service account passwords
4. HIGH: Force password reset for admin_temp
5. MEDIUM: Enable Kerberos AES encryption (disable RC4)
6. MEDIUM: Review scheduled tasks across all servers
```

---

## Bonus Challenges

1. **EVTX Parser**: Parse actual .evtx files using python-evtx library
2. **Sigma Correlation**: Implement multi-event Sigma rule detection
3. **ML Anomaly Detection**: Train model on normal logon patterns, detect anomalies
4. **Real-time Alerting**: Build streaming processor for live event feeds

---

## Resources

- [Windows Security Audit Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [MITRE ATT&CK - Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [SANS Hunt Evil Poster](https://www.sans.org/posters/hunt-evil/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Detection rule examples

---

*Next: Lab 10c - Windows Registry Forensics*

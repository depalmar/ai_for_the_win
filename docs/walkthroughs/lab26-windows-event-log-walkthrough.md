# Lab 26: Windows Event Log Analysis Walkthrough

Step-by-step guide to analyzing Windows Event Logs for threat hunting and incident response.

## Overview

This walkthrough guides you through:
1. Parsing Windows Security, System, and PowerShell logs
2. Detecting lateral movement and privilege escalation
3. Correlating events to build attack timelines
4. Using AI to identify suspicious patterns

**Difficulty:** Intermediate
**Time:** 90 minutes
**Prerequisites:** Lab 25 (DFIR Fundamentals)

---

## Key Event IDs Reference

### Authentication Events (Security Log)

| Event ID | Name | What to Look For |
|----------|------|------------------|
| **4624** | Successful Logon | Logon Type 3 from unexpected IPs |
| **4625** | Failed Logon | Brute force patterns |
| **4648** | Explicit Credential Logon | Pass-the-hash attacks |
| **4672** | Special Privileges | Admin privs to unexpected accounts |
| **4768** | Kerberos TGT | Kerberoasting, Golden Ticket |

### Process Events

| Event ID | Name | Detection Use |
|----------|------|---------------|
| **4688** | Process Created | Command line logging |
| **4697** | Service Installed | Malicious service persistence |
| **4698** | Scheduled Task Created | Persistence via schtasks |

---

## Exercise 1: Build Event Parser (TODO 1)

### Implementation

```python
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List

def parse_security_event(event_xml: str) -> dict:
    """
    Parse Windows Security event XML and extract key fields.

    Returns structured dict with:
    - event_id, timestamp, computer_name
    - account names (subject/target)
    - logon type, source IP
    - process information
    """
    root = ET.fromstring(event_xml)
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Extract system info
    event_id = int(root.find('.//e:EventID', ns).text)
    time_created = root.find('.//e:TimeCreated', ns).get('SystemTime')
    computer = root.find('.//e:Computer', ns).text

    # Extract event data
    data = {}
    for item in root.findall('.//e:Data', ns):
        name = item.get('Name')
        value = item.text
        if name:
            data[name] = value

    return {
        'event_id': event_id,
        'timestamp': time_created,
        'computer': computer,
        'target_user': data.get('TargetUserName'),
        'target_domain': data.get('TargetDomainName'),
        'subject_user': data.get('SubjectUserName'),
        'logon_type': data.get('LogonType'),
        'source_ip': data.get('IpAddress'),
        'workstation': data.get('WorkstationName'),
        'process_name': data.get('ProcessName'),
        'command_line': data.get('CommandLine'),
        'raw_data': data
    }
```

---

## Exercise 2: Detect Brute Force (TODO 2)

### Attack Pattern

```
Brute force attack pattern:
1. Multiple 4625 (failed logon) events
2. From same source IP
3. Within short time window
4. Followed by 4624 (success) = CRITICAL
```

### Implementation

```python
from collections import defaultdict
from datetime import timedelta

def detect_brute_force(events: list, threshold: int = 5, window_minutes: int = 5) -> list:
    """Detect brute force attacks from event patterns."""

    # Group failed logons by target account and source
    failed_by_source = defaultdict(list)
    successful_logons = []

    for event in events:
        if event['event_id'] == 4625:
            key = (event.get('target_user'), event.get('source_ip'))
            failed_by_source[key].append(event)
        elif event['event_id'] == 4624:
            successful_logons.append(event)

    attacks = []
    for (target_user, source_ip), failures in failed_by_source.items():
        if len(failures) >= threshold:
            # Parse timestamps and check window
            times = sorted([e['timestamp'] for e in failures])
            first_time = datetime.fromisoformat(times[0].replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(times[-1].replace('Z', '+00:00'))

            if (last_time - first_time) <= timedelta(minutes=window_minutes):
                attack = {
                    'target_user': target_user,
                    'source_ip': source_ip,
                    'failure_count': len(failures),
                    'first_failure': times[0],
                    'last_failure': times[-1],
                    'technique': 'T1110 (Brute Force)',
                    'severity': 'HIGH'
                }

                # Check for subsequent success = CRITICAL
                # Must verify success occurred AFTER the failed attempts
                for success in successful_logons:
                    if (success.get('target_user') == target_user and
                        success.get('source_ip') == source_ip):
                        success_time = datetime.fromisoformat(
                            success['timestamp'].replace('Z', '+00:00')
                        )
                        # Only flag if success came after the brute force attempts
                        if success_time > last_time:
                            attack['severity'] = 'CRITICAL'
                            attack['success_time'] = success['timestamp']
                            break

                attacks.append(attack)

    return attacks
```

---

## Exercise 3: Lateral Movement Detection (TODO 3)

### Pattern to Detect

```
Lateral Movement Pattern:
1. 4624 Type 3 (Network logon) from workstation → server
2. 7045 (Service installed) - PSEXESVC or random name
3. 4688 (Process created) - cmd.exe or powershell.exe
4. 4624 Type 3 to additional hosts ← Movement detected!
```

### Implementation

```python
def detect_lateral_movement(events: list) -> list:
    """Detect lateral movement chains across hosts."""

    # Track network logons and service installations
    network_logons = []  # Type 3 logons
    service_installs = []  # Event 7045

    for event in events:
        if event['event_id'] == 4624 and event.get('logon_type') == '3':
            network_logons.append(event)
        elif event['event_id'] == 7045:
            service_installs.append(event)

    # Look for patterns
    lateral_chains = []

    # Group logons by user
    logons_by_user = defaultdict(list)
    for logon in network_logons:
        user = logon.get('target_user')
        if user:
            logons_by_user[user].append(logon)

    # Find users with multiple target hosts
    for user, logons in logons_by_user.items():
        if len(logons) >= 2:
            targets = list(set(l.get('computer') for l in logons if l.get('computer')))
            sources = list(set(l.get('workstation') for l in logons if l.get('workstation')))

            if len(targets) >= 2:
                lateral_chains.append({
                    'user': user,
                    'source_hosts': sources,
                    'target_hosts': targets,
                    'hop_count': len(targets),
                    'technique': 'T1021.002 (SMB/Admin Shares)',
                    'severity': 'HIGH' if len(targets) >= 3 else 'MEDIUM',
                    'events': logons
                })

    return lateral_chains
```

---

## Exercise 4: Timeline Generator (TODO 4)

### Implementation

```python
def generate_timeline(events: list, anchor_event: dict) -> str:
    """Generate attack timeline starting from anchor event."""

    anchor_user = anchor_event.get('target_user') or anchor_event.get('subject_user')
    anchor_ip = anchor_event.get('source_ip')
    anchor_time = anchor_event.get('timestamp')

    # Find related events
    related = []
    for event in events:
        is_related = (
            event.get('target_user') == anchor_user or
            event.get('subject_user') == anchor_user or
            event.get('source_ip') == anchor_ip
        )
        if is_related:
            related.append(event)

    # Sort by timestamp
    related.sort(key=lambda x: x.get('timestamp', ''))

    # Build timeline
    timeline_lines = [
        "━━━━━ ATTACK TIMELINE ━━━━━",
        f"Anchor Event: {anchor_event['event_id']} at {anchor_time}",
        f"User: {anchor_user}",
        f"Source IP: {anchor_ip}",
        ""
    ]

    for event in related:
        event_desc = format_event_for_timeline(event)
        timeline_lines.append(f"{event['timestamp']} ── {event_desc}")

    return '\n'.join(timeline_lines)

def format_event_for_timeline(event: dict) -> str:
    """Format event for timeline display."""
    event_id = event['event_id']

    descriptions = {
        4624: f"Successful logon (Type {event.get('logon_type', '?')})",
        4625: f"Failed logon attempt",
        4672: f"Privilege assigned - {event.get('raw_data', {}).get('PrivilegeList', 'unknown')}",
        4688: f"Process created - {event.get('process_name', 'unknown')}",
        4697: f"Service installed",
        4698: f"Scheduled task created",
        7045: f"New service installed",
    }

    return descriptions.get(event_id, f"Event {event_id}")
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           WINDOWS EVENT LOG ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Analysis Period: 2026-01-01 00:00 - 2026-01-07 23:59
Events Analyzed: 45,231

━━━━━ CRITICAL FINDINGS ━━━━━

🔴 BRUTE FORCE ATTACK DETECTED
   Target: svc_backup@CORP.LOCAL
   Source: 192.168.1.105
   Failed Attempts: 47 in 3 minutes
   Outcome: SUCCESS after failures
   Technique: T1110.001 (Password Guessing)

🔴 LATERAL MOVEMENT CHAIN
   Path: WKS-042 → SRV-FILE01 → SRV-DC01
   User: admin_temp
   Method: PsExec (PSEXESVC installed)
   Technique: T1021.002 (SMB/Admin Shares)

━━━━━ RECOMMENDATIONS ━━━━━

1. IMMEDIATE: Disable compromised accounts
2. IMMEDIATE: Isolate affected hosts
3. HIGH: Reset service account passwords
```

---

## Resources

- [Windows Security Audit Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [MITRE ATT&CK - Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [SANS Hunt Evil Poster](https://www.sans.org/posters/hunt-evil/)

---

*Next: Lab 27 - Windows Registry Forensics Walkthrough*

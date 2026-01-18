# Lab 28: Live Response Techniques Walkthrough

Step-by-step guide to live response techniques for active incident investigation.

## Overview

This walkthrough guides you through:
1. Executing live response collection from compromised systems
2. Capturing volatile data in correct order of volatility
3. Building automated live response scripts
4. Triaging findings in real-time during an incident

**Difficulty:** Intermediate-Advanced
**Time:** 90 minutes
**Prerequisites:** Labs 25-27 (DFIR series)

---

## Order of Volatility

Collect in this order (most volatile first):

| Priority | Data Type | Volatility |
|----------|-----------|------------|
| 1 | Memory (RAM) | Power dependent |
| 2 | Network State | Seconds-minutes |
| 3 | Running Processes | Seconds-minutes |
| 4 | Disk | Days-years |
| 5 | Logs, Registry | Days-months |

---

## Exercise 1: Build Live Response Script (TODO 1)

### Implementation

```python
from pathlib import Path
from datetime import datetime
import subprocess
import hashlib

def generate_live_response_script(output_path: str, include_memory: bool = True) -> str:
    """
    Generate a PowerShell live response script.

    Creates timestamped output folder and collects data in order of volatility.
    """

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    script = f'''
# Live Response Collection Script
# Generated: {datetime.now().isoformat()}
# Output Path: {output_path}

$ErrorActionPreference = "SilentlyContinue"
$Timestamp = "{timestamp}"
$OutputBase = "{output_path}\\$Timestamp"

# Create output directory
New-Item -ItemType Directory -Path $OutputBase -Force | Out-Null
Write-Host "Collecting to: $OutputBase"

# ==========================================
# 1. MEMORY (if tools available)
# ==========================================
'''

    if include_memory:
        script += '''
Write-Host "[1/7] Memory acquisition..."
if (Test-Path "E:\\Tools\\winpmem_mini_x64.exe") {
    & E:\\Tools\\winpmem_mini_x64.exe "$OutputBase\\memory.raw"
}
'''

    script += '''
# ==========================================
# 2. NETWORK STATE
# ==========================================
Write-Host "[2/7] Collecting network state..."

Get-NetTCPConnection | Select-Object LocalAddress, LocalPort,
    RemoteAddress, RemotePort, State, OwningProcess,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Export-Csv -Path "$OutputBase\\netstat.csv" -NoTypeInformation

Get-DnsClientCache | Export-Csv -Path "$OutputBase\\dns_cache.csv" -NoTypeInformation
Get-NetNeighbor | Export-Csv -Path "$OutputBase\\arp_cache.csv" -NoTypeInformation

# ==========================================
# 3. RUNNING PROCESSES
# ==========================================
Write-Host "[3/7] Collecting process information..."

Get-Process | Select-Object Id, ProcessName, Path, StartTime,
    @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} |
    Export-Csv -Path "$OutputBase\\processes.csv" -NoTypeInformation

Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv -Path "$OutputBase\\services.csv" -NoTypeInformation

# ==========================================
# 4. SCHEDULED TASKS
# ==========================================
Write-Host "[4/7] Collecting scheduled tasks..."

Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{N='Actions';E={$_.Actions.Execute}} |
    Export-Csv -Path "$OutputBase\\scheduled_tasks.csv" -NoTypeInformation

# ==========================================
# 5. PERSISTENCE LOCATIONS
# ==========================================
Write-Host "[5/7] Checking persistence locations..."

$runKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
)

$persistenceData = @()
foreach ($path in $runKeys) {
    if (Test-Path $path) {
        Get-ItemProperty $path | Get-Member -MemberType NoteProperty |
            Where-Object {$_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider')} |
            ForEach-Object {
                $persistenceData += [PSCustomObject]@{
                    Path = $path
                    Name = $_.Name
                    Value = (Get-ItemProperty $path).$($_.Name)
                }
            }
    }
}
$persistenceData | Export-Csv -Path "$OutputBase\\run_keys.csv" -NoTypeInformation

# ==========================================
# 6. RECENT FILES / TEMP EXECUTABLES
# ==========================================
Write-Host "[6/7] Scanning for suspicious files..."

@("$env:TEMP", "C:\\Windows\\Temp", "C:\\Users\\Public") | ForEach-Object {
    Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.Extension -in '.exe','.dll','.ps1','.bat'} |
        Select-Object FullName, CreationTime, LastWriteTime, Length
} | Export-Csv -Path "$OutputBase\\temp_executables.csv" -NoTypeInformation

# ==========================================
# 7. CREATE COLLECTION SUMMARY
# ==========================================
Write-Host "[7/7] Creating summary..."

$summary = @{
    CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    OutputPath = $OutputBase
}
$summary | ConvertTo-Json | Out-File "$OutputBase\\collection_summary.json"

Write-Host "Collection complete: $OutputBase"
'''

    # Write script to file
    script_path = Path(output_path) / f'live_response_{timestamp}.ps1'
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script)

    return str(script_path)
```

---

## Exercise 2: Remote Collection Tool (TODO 2)

### Implementation

```python
import subprocess
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

def remote_collection(
    target_hosts: List[str],
    credential: Dict,
    output_share: str,
    collection_type: str = "full"
) -> Dict:
    """
    Execute remote live response collection.

    Args:
        target_hosts: List of hostnames/IPs
        credential: Dict with username and password
        output_share: UNC path for evidence storage
        collection_type: "quick" or "full"
    """
    results = {}

    # Quick collection: network + processes only
    if collection_type == "quick":
        commands = [
            'Get-NetTCPConnection | ConvertTo-Json',
            'Get-Process | Select-Object Id, ProcessName, Path | ConvertTo-Json'
        ]
    else:
        # Full collection
        commands = [
            'Get-NetTCPConnection | ConvertTo-Json',
            'Get-DnsClientCache | ConvertTo-Json',
            'Get-Process | Select-Object Id, ProcessName, Path, StartTime | ConvertTo-Json',
            'Get-Service | ConvertTo-Json',
            'Get-ScheduledTask | ConvertTo-Json'
        ]

    def collect_from_host(host: str) -> Dict:
        """Collect from single host."""
        host_results = {
            'host': host,
            'status': 'pending',
            'data': {}
        }

        try:
            for cmd in commands:
                # Build PowerShell remoting command
                ps_cmd = f'''
                $cred = New-Object PSCredential("{credential['username']}",
                    (ConvertTo-SecureString "{credential['password']}" -AsPlainText -Force))
                Invoke-Command -ComputerName {host} -Credential $cred -ScriptBlock {{
                    {cmd}
                }}
                '''

                result = subprocess.run(
                    ['powershell', '-Command', ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    host_results['data'][cmd[:30]] = result.stdout

            host_results['status'] = 'success'

        except subprocess.TimeoutExpired:
            host_results['status'] = 'timeout'
        except Exception as e:
            host_results['status'] = 'error'
            host_results['error'] = str(e)

        return host_results

    # Collect from all hosts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(collect_from_host, host): host
            for host in target_hosts
        }

        for future in as_completed(futures):
            host = futures[future]
            results[host] = future.result()

    return results
```

---

## Exercise 3: Triage Analyzer (TODO 3)

### Implementation

```python
import pandas as pd
import json

KNOWN_BAD_PORTS = [4444, 5555, 6666, 8888, 31337]
SUSPICIOUS_PROCESSES = ['nc', 'ncat', 'netcat', 'nmap', 'mimikatz', 'procdump']

def triage_analysis(collection_path: str) -> Dict:
    """
    Analyze live response collection for indicators.

    Returns findings by category and severity.
    """
    findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }

    collection = Path(collection_path)

    # Analyze network connections
    netstat_file = collection / 'netstat.csv'
    if netstat_file.exists():
        df = pd.read_csv(netstat_file)

        # Check for known bad ports
        bad_port_conns = df[df['RemotePort'].isin(KNOWN_BAD_PORTS)]
        for _, conn in bad_port_conns.iterrows():
            findings['critical'].append({
                'type': 'suspicious_connection',
                'details': f"{conn['ProcessName']} connected to port {conn['RemotePort']}",
                'remote_address': conn['RemoteAddress']
            })

        # Check for external connections from unusual processes
        external = df[~df['RemoteAddress'].str.startswith('10.', na=True)]
        for _, conn in external.iterrows():
            if conn['ProcessName'] in SUSPICIOUS_PROCESSES:
                findings['critical'].append({
                    'type': 'suspicious_process_network',
                    'details': f"{conn['ProcessName']} has external connection",
                    'remote_address': conn['RemoteAddress']
                })

    # Analyze processes
    process_file = collection / 'processes.csv'
    if process_file.exists():
        df = pd.read_csv(process_file)

        for _, proc in df.iterrows():
            proc_name = str(proc.get('ProcessName', '')).lower()
            proc_path = str(proc.get('Path', '')).lower()

            # Check for suspicious process names
            if proc_name in SUSPICIOUS_PROCESSES:
                findings['critical'].append({
                    'type': 'suspicious_process',
                    'details': f"Suspicious process: {proc_name}",
                    'path': proc_path
                })

            # Check for processes in unusual paths
            if proc_path and any(p in proc_path for p in ['\\temp\\', '\\public\\']):
                findings['high'].append({
                    'type': 'unusual_process_path',
                    'details': f"Process in suspicious location: {proc_name}",
                    'path': proc_path
                })

    # Analyze persistence
    runkeys_file = collection / 'run_keys.csv'
    if runkeys_file.exists():
        df = pd.read_csv(runkeys_file)

        for _, entry in df.iterrows():
            value = str(entry.get('Value', '')).lower()
            if any(p in value for p in ['\\temp\\', '\\public\\', 'powershell -enc']):
                findings['high'].append({
                    'type': 'suspicious_persistence',
                    'details': f"Suspicious Run key: {entry.get('Name')}",
                    'value': entry.get('Value')
                })

    return findings
```

---

## Exercise 4: Timeline Correlator (TODO 4)

### Implementation

```python
from datetime import datetime
from typing import List, Dict

def build_attack_timeline(triage_results: Dict) -> List[Dict]:
    """
    Build attack timeline from triage findings.

    Correlates process start times, network connections, and file creation.
    """
    timeline = []

    # Add critical findings first
    for finding in triage_results.get('critical', []):
        timeline.append({
            'timestamp': finding.get('timestamp', 'Unknown'),
            'severity': 'CRITICAL',
            'event_type': finding['type'],
            'details': finding['details'],
            'context': finding
        })

    # Add high findings
    for finding in triage_results.get('high', []):
        timeline.append({
            'timestamp': finding.get('timestamp', 'Unknown'),
            'severity': 'HIGH',
            'event_type': finding['type'],
            'details': finding['details'],
            'context': finding
        })

    # Sort by timestamp
    timeline.sort(key=lambda x: x.get('timestamp', 'Z'))

    return timeline

def format_timeline_report(timeline: List[Dict]) -> str:
    """Format timeline as readable report."""
    lines = [
        "━━━━━ ATTACK TIMELINE ━━━━━",
        ""
    ]

    for event in timeline:
        severity_icon = "🔴" if event['severity'] == 'CRITICAL' else "🟠"
        lines.append(f"{event['timestamp']} ─┬─ {severity_icon} {event['event_type']}")
        lines.append(f"                  └─ {event['details']}")
        lines.append("")

    return '\n'.join(lines)
```

---

## Quick Triage Checklist

```
┌────────────────────────────────────────────────────────────────┐
│              LIVE RESPONSE QUICK TRIAGE                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  □ NETWORK                                                     │
│    □ Connections to known bad IPs?                             │
│    □ Unusual outbound ports (4444, 8080)?                      │
│    □ Beaconing pattern (regular intervals)?                    │
│                                                                │
│  □ PROCESSES                                                   │
│    □ Unsigned binaries running?                                │
│    □ System binaries from wrong path?                          │
│    □ Encoded PowerShell commands?                              │
│                                                                │
│  □ PERSISTENCE                                                 │
│    □ Unknown Run key entries?                                  │
│    □ New services in user-writable paths?                      │
│    □ Suspicious scheduled tasks?                               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Resources

- [SANS Digital Forensics Cheat Sheets](https://www.sans.org/posters/)
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/)
- [Velociraptor](https://docs.velociraptor.app/)

---

*Series Complete! See Labs 30-36 for advanced DFIR topics.*

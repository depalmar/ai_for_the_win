# Lab 27: Windows Registry Forensics Walkthrough

Step-by-step guide to registry analysis for persistence hunting and forensic investigation.

## Overview

This walkthrough guides you through:
1. Understanding Windows Registry structure and hive files
2. Hunting for persistence mechanisms
3. Extracting forensic artifacts (UserAssist, ShimCache, MRU)
4. Using AI to analyze suspicious registry entries

**Difficulty:** Intermediate
**Time:** 75 minutes
**Prerequisites:** Lab 25 (DFIR Fundamentals)

---

## Registry Persistence Locations

### Critical - Check First

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

### High - Service Persistence

```
HKLM\SYSTEM\CurrentControlSet\Services\<servicename>
  └── ImagePath   → Binary location
  └── Start       → 2=Automatic, 3=Manual
  └── Description → Often blank for malware
```

---

## Exercise 1: Registry Persistence Scanner (TODO 1)

### Implementation

```python
import codecs
import re
from datetime import datetime
from typing import Dict, List, Optional

# For live registry (Windows)
try:
    import winreg
except ImportError:
    winreg = None

# For offline hives
try:
    from Registry import Registry
except ImportError:
    Registry = None

PERSISTENCE_LOCATIONS = {
    'critical': [
        ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
    ],
    'high': [
        ('HKLM', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        ('HKLM', r'SYSTEM\CurrentControlSet\Services'),
    ],
    'medium': [
        ('HKLM', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        ('HKCU', r'SOFTWARE\Classes\CLSID'),
    ]
}

SUSPICIOUS_PATHS = [
    '\\users\\public\\',
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\programdata\\',
    '\\downloads\\',
]

def scan_persistence_locations(hive_path: str = None) -> List[Dict]:
    """
    Scan registry for persistence mechanisms.

    Args:
        hive_path: Path to offline hive file (None for live registry)

    Returns:
        List of findings with location, entries, risk_level, technique
    """
    findings = []

    if hive_path and Registry:
        findings = scan_offline_hive(hive_path)
    elif winreg:
        findings = scan_live_registry()

    return findings

def scan_offline_hive(hive_path: str) -> List[Dict]:
    """Parse offline registry hive for persistence."""
    findings = []

    try:
        reg = Registry.Registry(hive_path)

        # Check Run keys in SOFTWARE hive
        run_paths = [
            r'Microsoft\Windows\CurrentVersion\Run',
            r'Microsoft\Windows\CurrentVersion\RunOnce',
        ]

        for path in run_paths:
            try:
                key = reg.open(path)
                entries = []

                for value in key.values():
                    entry = {
                        'name': value.name(),
                        'value': value.value(),
                        'type': value.value_type_str()
                    }

                    # Check for suspicious indicators
                    entry['suspicious'] = is_suspicious_path(str(value.value()))
                    entries.append(entry)

                if entries:
                    findings.append({
                        'location': path,
                        'entries': entries,
                        'risk_level': 'critical',
                        'technique': 'T1547.001 (Registry Run Keys)'
                    })

            except Exception:
                continue

    except Exception as e:
        print(f"Error parsing hive: {e}")

    return findings

def is_suspicious_path(path: str) -> bool:
    """Check if path is in suspicious location."""
    path_lower = path.lower()
    return any(sp in path_lower for sp in SUSPICIOUS_PATHS)
```

---

## Exercise 2: UserAssist Decoder (TODO 2)

### Background

UserAssist tracks program execution and is ROT13 encoded.

```
Location: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

Example:
  P:\Hfref\nqzva\Qbjaybnqf\zvzvxngm.rkr  (encoded)
  C:\Users\admin\Downloads\mimikatz.exe    (decoded)
```

### Implementation

```python
def rot13_decode(encoded_string: str) -> str:
    """Decode ROT13 encoded UserAssist values."""
    return codecs.decode(encoded_string, 'rot_13')

def decode_userassist(hive_path: str) -> List[Dict]:
    """
    Parse UserAssist registry key and decode ROT13 values.

    Returns list of:
    - decoded_path: actual file path
    - run_count: number of executions
    - last_run: timestamp of last execution
    """
    results = []

    if not Registry:
        print("python-registry not installed")
        return results

    try:
        reg = Registry.Registry(hive_path)

        # UserAssist GUIDs
        userassist_guids = [
            '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',  # Executables
            '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}',  # Shortcuts
        ]

        base_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

        for guid in userassist_guids:
            try:
                key_path = f'{base_path}\\{guid}\\Count'
                key = reg.open(key_path)

                for value in key.values():
                    encoded_name = value.name()
                    decoded_name = rot13_decode(encoded_name)

                    # Parse binary data for run count and timestamps
                    data = value.value()
                    if len(data) >= 68:
                        run_count = int.from_bytes(data[4:8], 'little')

                        # Parse FILETIME (bytes 60-68) - 100ns intervals since 1601
                        filetime = int.from_bytes(data[60:68], 'little')
                        if filetime > 0:
                            # Convert FILETIME to datetime
                            epoch_diff = 116444736000000000  # 1601 to 1970
                            timestamp = datetime.utcfromtimestamp(
                                (filetime - epoch_diff) / 10000000
                            )
                            last_run = timestamp.isoformat() + 'Z'
                        else:
                            last_run = None

                        results.append({
                            'encoded_path': encoded_name,
                            'decoded_path': decoded_name,
                            'run_count': run_count,
                            'last_run': last_run,
                            'guid': guid
                        })

            except Exception:
                continue

    except Exception as e:
        print(f"Error parsing UserAssist: {e}")

    return results
```

---

## Exercise 3: Service Analyzer (TODO 3)

### Red Flags to Detect

- ImagePath in user-writable locations
- No Description
- ServiceDll in unusual location
- Random/suspicious service names

### Implementation

```python
def analyze_services(hive_path: str) -> List[Dict]:
    """
    Analyze SYSTEM hive services for suspicious entries.

    Returns list of suspicious services with risk scores.
    """
    suspicious_services = []

    if not Registry:
        return suspicious_services

    try:
        reg = Registry.Registry(hive_path)
        services_key = reg.open(r'ControlSet001\Services')

        for service in services_key.subkeys():
            service_info = {
                'name': service.name(),
                'risk_score': 0,
                'indicators': []
            }

            # Get service properties
            image_path = None
            description = None
            start_type = None
            service_dll = None

            for value in service.values():
                if value.name() == 'ImagePath':
                    image_path = value.value()
                elif value.name() == 'Description':
                    description = value.value()
                elif value.name() == 'Start':
                    start_type = value.value()

            # Check for ServiceDll
            try:
                params = service.subkey('Parameters')
                for value in params.values():
                    if value.name() == 'ServiceDll':
                        service_dll = value.value()
            except Exception:
                pass

            service_info['image_path'] = image_path
            service_info['description'] = description
            service_info['start_type'] = start_type
            service_info['service_dll'] = service_dll

            # Risk scoring
            if image_path and is_suspicious_path(image_path):
                service_info['risk_score'] += 30
                service_info['indicators'].append('Suspicious image path')

            if not description:
                service_info['risk_score'] += 10
                service_info['indicators'].append('No description')

            if service_dll and is_suspicious_path(service_dll):
                service_info['risk_score'] += 30
                service_info['indicators'].append('Suspicious ServiceDll')

            # Check for random-looking names
            if re.match(r'^[a-z]{8,}$', service.name().lower()):
                service_info['risk_score'] += 15
                service_info['indicators'].append('Random-looking name')

            if service_info['risk_score'] >= 20:
                suspicious_services.append(service_info)

    except Exception as e:
        print(f"Error analyzing services: {e}")

    return suspicious_services
```

---

## Exercise 4: Timeline Builder (TODO 4)

### Implementation

```python
def build_registry_timeline(hive_paths: Dict[str, str]) -> List[Dict]:
    """
    Build timeline from multiple registry artifacts.

    Args:
        hive_paths: Dict mapping hive type to file path
                   e.g., {'NTUSER': 'path/to/NTUSER.DAT', 'SYSTEM': 'path/to/SYSTEM'}

    Returns:
        Chronologically sorted list of events.
    """
    events = []

    # Extract UserAssist (execution times)
    if 'NTUSER' in hive_paths:
        userassist = decode_userassist(hive_paths['NTUSER'])
        for entry in userassist:
            if entry.get('last_run'):
                events.append({
                    'timestamp': entry['last_run'],
                    'source': 'UserAssist',
                    'artifact': entry['decoded_path'],
                    'details': f"Executed {entry['run_count']} times"
                })

    # Extract service creation (if timestamps available)
    if 'SYSTEM' in hive_paths:
        services = analyze_services(hive_paths['SYSTEM'])
        for svc in services:
            if svc['risk_score'] >= 20:
                events.append({
                    'timestamp': 'Unknown',
                    'source': 'Services',
                    'artifact': svc['name'],
                    'details': f"Suspicious service: {', '.join(svc['indicators'])}"
                })

    # Sort by timestamp where available
    events.sort(key=lambda x: x.get('timestamp', 'Z'))

    return events
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           WINDOWS REGISTRY FORENSICS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Hives Analyzed: SYSTEM, SOFTWARE, NTUSER.DAT

━━━━━ PERSISTENCE MECHANISMS ━━━━━

🔴 CRITICAL: Malicious Run Key Entry
   Location: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   Name: WindowsUpdateCheck
   Value: C:\Users\Public\update.exe -silent
   Technique: T1547.001 (Registry Run Keys)

🔴 CRITICAL: Sticky Keys Backdoor
   Location: HKLM\...\Image File Execution Options\sethc.exe
   Debugger: cmd.exe
   Technique: T1546.008 (Accessibility Features)

━━━━━ EXECUTION ARTIFACTS ━━━━━

UserAssist (Decoded):
  C:\Users\admin\Downloads\mimikatz.exe
    Run Count: 3
    Last Run: 2026-01-05 14:23:45

━━━━━ RECOMMENDATIONS ━━━━━

1. IMMEDIATE: Delete malicious Run key entries
2. IMMEDIATE: Remove IFEO debugger backdoors
3. HIGH: Delete malicious binaries
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
    $_.PathName -like "*Temp*"
} | Select-Object Name, PathName, State

# Export registry hive for offline analysis
reg save HKLM\SYSTEM C:\forensics\SYSTEM.hiv
```

---

## Resources

- [Windows Registry Reference](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [SANS Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)
- [python-registry](https://github.com/williballenthin/python-registry)

---

*Next: Lab 28 - Live Response Walkthrough*

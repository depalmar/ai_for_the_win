# Lab 13: Memory Forensics AI - Solution Walkthrough

## Overview

Build an AI-powered memory forensics analysis system using Volatility3 for process injection detection, credential extraction, and automated artifact analysis.

**Time:** 4-5 hours
**Difficulty:** Advanced

---

## Task 1: Volatility3 Integration

### Setting Up Memory Analysis

```python
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import os

@dataclass
class MemoryImage:
    path: str
    profile: Optional[str] = None
    size_bytes: int = 0
    format: str = "raw"

class Volatility3Analyzer:
    def __init__(self, volatility_path: str = "vol"):
        self.vol_path = volatility_path
        self.cache_dir = Path(".vol_cache")
        self.cache_dir.mkdir(exist_ok=True)

    def _run_plugin(self, image_path: str, plugin: str,
                    extra_args: list = None) -> dict:
        """Run a Volatility3 plugin and return parsed output."""

        cmd = [
            self.vol_path,
            "-f", image_path,
            "-r", "json",  # JSON output
            plugin
        ]

        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                return {'error': result.stderr, 'plugin': plugin}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            return {'error': 'Plugin timeout', 'plugin': plugin}
        except json.JSONDecodeError as e:
            return {'error': f'JSON parse error: {e}', 'raw': result.stdout}

    def get_process_list(self, image_path: str) -> list[dict]:
        """Get list of processes from memory image."""
        result = self._run_plugin(image_path, "windows.pslist.PsList")

        if 'error' in result:
            return []

        processes = []
        for row in result.get('rows', []):
            processes.append({
                'pid': row[0],
                'ppid': row[1],
                'name': row[2],
                'offset': row[3],
                'threads': row[4],
                'handles': row[5],
                'create_time': row[8] if len(row) > 8 else None
            })

        return processes

    def detect_hidden_processes(self, image_path: str) -> list[dict]:
        """Detect hidden/unlinked processes."""
        # Compare pslist vs psscan
        pslist = self._run_plugin(image_path, "windows.pslist.PsList")
        psscan = self._run_plugin(image_path, "windows.psscan.PsScan")

        pslist_pids = set(row[0] for row in pslist.get('rows', []))
        psscan_pids = set(row[0] for row in psscan.get('rows', []))

        hidden_pids = psscan_pids - pslist_pids

        hidden = []
        for row in psscan.get('rows', []):
            if row[0] in hidden_pids:
                hidden.append({
                    'pid': row[0],
                    'name': row[1],
                    'offset': row[2],
                    'reason': 'Hidden from pslist (DKOM)'
                })

        return hidden

    def get_network_connections(self, image_path: str) -> list[dict]:
        """Extract network connections."""
        result = self._run_plugin(image_path, "windows.netscan.NetScan")

        if 'error' in result:
            return []

        connections = []
        for row in result.get('rows', []):
            connections.append({
                'offset': row[0],
                'protocol': row[1],
                'local_addr': row[2],
                'local_port': row[3],
                'foreign_addr': row[4],
                'foreign_port': row[5],
                'state': row[6],
                'pid': row[7],
                'owner': row[8]
            })

        return connections

    def dump_process(self, image_path: str, pid: int,
                    output_dir: str) -> Optional[str]:
        """Dump process executable."""
        os.makedirs(output_dir, exist_ok=True)

        result = self._run_plugin(
            image_path,
            "windows.pslist.PsList",
            ["--pid", str(pid), "--dump"]
        )

        # Find dumped file
        for f in Path(output_dir).glob(f"*{pid}*.exe"):
            return str(f)

        return None

# Initialize analyzer
vol = Volatility3Analyzer()

# Analyze memory image
image_path = "memory.dmp"
processes = vol.get_process_list(image_path)
print(f"Found {len(processes)} processes")

# Check for hidden processes
hidden = vol.detect_hidden_processes(image_path)
if hidden:
    print(f"ALERT: Found {len(hidden)} hidden processes!")
    for h in hidden:
        print(f"  - PID {h['pid']}: {h['name']}")
```

---

## Task 2: Process Injection Detection

### Identifying Injected Code

```python
class InjectionDetector:
    def __init__(self, vol_analyzer: Volatility3Analyzer):
        self.vol = vol_analyzer
        self.suspicious_indicators = []

    def detect_malfind(self, image_path: str) -> list[dict]:
        """Detect suspicious memory regions using malfind."""
        result = self.vol._run_plugin(image_path, "windows.malfind.Malfind")

        if 'error' in result:
            return []

        findings = []
        for row in result.get('rows', []):
            findings.append({
                'pid': row[0],
                'process': row[1],
                'address': row[2],
                'protection': row[3],
                'data': row[4] if len(row) > 4 else None,
                'disasm': row[5] if len(row) > 5 else None
            })

        return findings

    def detect_hollowing(self, image_path: str) -> list[dict]:
        """Detect process hollowing indicators."""

        findings = []
        processes = self.vol.get_process_list(image_path)

        for proc in processes:
            # Get VAD (Virtual Address Descriptor) info
            vad_result = self.vol._run_plugin(
                image_path,
                "windows.vadinfo.VadInfo",
                ["--pid", str(proc['pid'])]
            )

            if 'error' in vad_result:
                continue

            # Look for suspicious VAD characteristics
            for vad in vad_result.get('rows', []):
                protection = vad[4] if len(vad) > 4 else ''

                # Executable memory not backed by file
                if 'EXECUTE' in str(protection) and 'PAGE_EXECUTE' in str(protection):
                    file_name = vad[6] if len(vad) > 6 else None
                    if not file_name:
                        findings.append({
                            'type': 'process_hollowing_indicator',
                            'pid': proc['pid'],
                            'process': proc['name'],
                            'vad_address': vad[0],
                            'protection': protection,
                            'reason': 'Executable VAD without file backing'
                        })

        return findings

    def detect_dll_injection(self, image_path: str) -> list[dict]:
        """Detect DLL injection indicators."""

        findings = []
        result = self.vol._run_plugin(image_path, "windows.dlllist.DllList")

        if 'error' in result:
            return []

        # Track DLLs by process
        dlls_by_process = {}
        for row in result.get('rows', []):
            pid = row[0]
            dll_path = row[2] if len(row) > 2 else ''

            if pid not in dlls_by_process:
                dlls_by_process[pid] = []
            dlls_by_process[pid].append(dll_path)

        # Look for suspicious DLLs
        suspicious_paths = [
            r'\temp\\',
            r'\appdata\\local\\temp',
            r'\users\\public',
            r'\\.\pipe\\',
        ]

        for pid, dlls in dlls_by_process.items():
            for dll in dlls:
                dll_lower = dll.lower()
                for sus_path in suspicious_paths:
                    if sus_path in dll_lower:
                        findings.append({
                            'type': 'suspicious_dll',
                            'pid': pid,
                            'dll_path': dll,
                            'reason': f'DLL loaded from suspicious path: {sus_path}'
                        })

        return findings

    def analyze_all_injections(self, image_path: str) -> dict:
        """Comprehensive injection analysis."""

        analysis = {
            'malfind': self.detect_malfind(image_path),
            'hollowing': self.detect_hollowing(image_path),
            'dll_injection': self.detect_dll_injection(image_path),
            'summary': {}
        }

        # Calculate summary
        total_findings = (
            len(analysis['malfind']) +
            len(analysis['hollowing']) +
            len(analysis['dll_injection'])
        )

        affected_pids = set()
        for category in ['malfind', 'hollowing', 'dll_injection']:
            for finding in analysis[category]:
                affected_pids.add(finding.get('pid'))

        analysis['summary'] = {
            'total_findings': total_findings,
            'affected_processes': len(affected_pids),
            'risk_level': 'CRITICAL' if total_findings > 5 else 'HIGH' if total_findings > 0 else 'LOW'
        }

        return analysis

# Run injection detection
injection_detector = InjectionDetector(vol)
injections = injection_detector.analyze_all_injections(image_path)

print(f"Risk Level: {injections['summary']['risk_level']}")
print(f"Total Findings: {injections['summary']['total_findings']}")
```

---

## Task 3: Credential Extraction

### Detecting Credential Dumping

```python
class CredentialAnalyzer:
    def __init__(self, vol_analyzer: Volatility3Analyzer):
        self.vol = vol_analyzer

    def extract_lsass_info(self, image_path: str) -> dict:
        """Analyze LSASS process for credential dumping indicators."""

        analysis = {
            'lsass_found': False,
            'lsass_pid': None,
            'suspicious_access': [],
            'handles_to_lsass': []
        }

        # Find LSASS
        processes = self.vol.get_process_list(image_path)
        for proc in processes:
            if proc['name'].lower() == 'lsass.exe':
                analysis['lsass_found'] = True
                analysis['lsass_pid'] = proc['pid']
                break

        if not analysis['lsass_pid']:
            return analysis

        # Check for handles to LSASS (indicates potential credential access)
        handles_result = self.vol._run_plugin(
            image_path,
            "windows.handles.Handles",
            ["--pid", str(analysis['lsass_pid'])]
        )

        # Look for suspicious processes with handles to LSASS
        # In production, use handles plugin to find processes accessing LSASS

        return analysis

    def detect_mimikatz_artifacts(self, image_path: str) -> list[dict]:
        """Detect Mimikatz-related artifacts in memory."""

        findings = []

        # Search for Mimikatz strings in memory
        strings_to_find = [
            'mimikatz',
            'sekurlsa',
            'kerberos::',
            'lsadump::',
            'privilege::debug',
            'token::elevate'
        ]

        # Use yarascan for pattern matching
        for pattern in strings_to_find:
            result = self.vol._run_plugin(
                image_path,
                "windows.strings.Strings",
                ["--string", pattern]
            )

            if result.get('rows'):
                findings.append({
                    'pattern': pattern,
                    'matches': len(result['rows']),
                    'locations': [row[0] for row in result['rows'][:5]]
                })

        return findings

    def analyze_sam_secrets(self, image_path: str) -> dict:
        """Extract SAM/LSA secrets indicators."""

        # This would typically use hashdump plugin
        result = self.vol._run_plugin(image_path, "windows.hashdump.Hashdump")

        if 'error' in result:
            return {'available': False, 'error': result['error']}

        return {
            'available': True,
            'hash_count': len(result.get('rows', [])),
            'note': 'Hashes extracted - handle with care'
        }

# Analyze credentials
cred_analyzer = CredentialAnalyzer(vol)
lsass_info = cred_analyzer.extract_lsass_info(image_path)
mimikatz = cred_analyzer.detect_mimikatz_artifacts(image_path)

if mimikatz:
    print("WARNING: Mimikatz artifacts detected!")
    for finding in mimikatz:
        print(f"  - Pattern '{finding['pattern']}': {finding['matches']} matches")
```

---

## Task 4: AI-Powered Analysis

### LLM Integration for Forensic Analysis

```python
import anthropic

class AIForensicAnalyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def analyze_process_tree(self, processes: list[dict]) -> str:
        """AI analysis of process relationships."""

        # Build process tree
        tree_data = []
        for proc in processes:
            tree_data.append({
                'name': proc['name'],
                'pid': proc['pid'],
                'ppid': proc['ppid'],
                'create_time': proc.get('create_time')
            })

        prompt = f"""Analyze this Windows process tree from a memory forensics perspective:

```json
{json.dumps(tree_data, indent=2)}
```

Look for:
1. Suspicious parent-child relationships (e.g., Word spawning PowerShell)
2. Processes that shouldn't exist or have unusual names
3. Evidence of process injection or hollowing
4. Lateral movement indicators
5. Persistence mechanisms

Provide a structured analysis with:
- Suspicious findings (with PIDs)
- Risk assessment
- Recommended next steps for investigation"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def analyze_network_artifacts(self, connections: list[dict]) -> str:
        """AI analysis of network connections."""

        prompt = f"""Analyze these network connections from a memory forensics investigation:

```json
{json.dumps(connections[:50], indent=2)}
```

Identify:
1. C2 (Command & Control) indicators
2. Data exfiltration patterns
3. Lateral movement (internal connections)
4. Suspicious ports/protocols
5. Known malicious IPs (flag for TI lookup)

Provide:
- High-risk connections requiring immediate investigation
- IOCs to block/investigate
- Recommended containment actions"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def analyze_injection_findings(self, injections: dict) -> str:
        """AI analysis of injection detection results."""

        prompt = f"""Analyze these memory injection detection findings:

## Malfind Results (suspicious memory regions)
{json.dumps(injections['malfind'][:10], indent=2)}

## Process Hollowing Indicators
{json.dumps(injections['hollowing'][:10], indent=2)}

## DLL Injection Indicators
{json.dumps(injections['dll_injection'][:10], indent=2)}

## Summary
{json.dumps(injections['summary'], indent=2)}

Provide:
1. Prioritized list of processes to investigate
2. Likely attack techniques being used (map to MITRE ATT&CK)
3. Indicators of the malware family if identifiable
4. Evidence preservation recommendations
5. Containment priorities"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def generate_forensic_report(self, all_findings: dict) -> str:
        """Generate comprehensive forensic report."""

        prompt = f"""Generate a formal memory forensics analysis report:

## Analysis Findings
{json.dumps(all_findings, indent=2, default=str)}

Create a professional forensic report with:

1. **Executive Summary** - Key findings for leadership
2. **Technical Findings** - Detailed analysis results
3. **Timeline Reconstruction** - Order of events if determinable
4. **Indicators of Compromise** - Actionable IOCs
5. **MITRE ATT&CK Mapping** - Techniques observed
6. **Recommendations** - Immediate and long-term actions
7. **Evidence Handling Notes** - Chain of custody considerations

Format as a formal report suitable for legal/compliance purposes."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# AI-powered analysis
ai_analyzer = AIForensicAnalyzer()

# Analyze process tree
process_analysis = ai_analyzer.analyze_process_tree(processes)
print("Process Tree Analysis:")
print(process_analysis)

# Analyze injections
if injections['summary']['total_findings'] > 0:
    injection_analysis = ai_analyzer.analyze_injection_findings(injections)
    print("\nInjection Analysis:")
    print(injection_analysis)
```

---

## Task 5: Complete Analysis Pipeline

### Integrated Memory Forensics System

```python
class MemoryForensicsPipeline:
    def __init__(self):
        self.vol = Volatility3Analyzer()
        self.injection_detector = InjectionDetector(self.vol)
        self.cred_analyzer = CredentialAnalyzer(self.vol)
        self.ai_analyzer = AIForensicAnalyzer()

    def analyze_image(self, image_path: str) -> dict:
        """Complete memory image analysis."""

        print(f"Analyzing memory image: {image_path}")
        results = {
            'image_path': image_path,
            'timestamp': datetime.now().isoformat(),
            'findings': {}
        }

        # Step 1: Process enumeration
        print("[1/5] Enumerating processes...")
        processes = self.vol.get_process_list(image_path)
        results['findings']['processes'] = {
            'count': len(processes),
            'data': processes
        }

        # Step 2: Hidden process detection
        print("[2/5] Detecting hidden processes...")
        hidden = self.vol.detect_hidden_processes(image_path)
        results['findings']['hidden_processes'] = hidden

        # Step 3: Injection detection
        print("[3/5] Detecting code injection...")
        injections = self.injection_detector.analyze_all_injections(image_path)
        results['findings']['injections'] = injections

        # Step 4: Network analysis
        print("[4/5] Analyzing network connections...")
        connections = self.vol.get_network_connections(image_path)
        results['findings']['network'] = {
            'count': len(connections),
            'connections': connections
        }

        # Step 5: Credential analysis
        print("[5/5] Analyzing credential artifacts...")
        mimikatz = self.cred_analyzer.detect_mimikatz_artifacts(image_path)
        results['findings']['credentials'] = {
            'mimikatz_indicators': mimikatz
        }

        # Calculate overall risk
        risk_score = 0
        if hidden:
            risk_score += 30
        if injections['summary']['total_findings'] > 0:
            risk_score += 40
        if mimikatz:
            risk_score += 30

        results['risk_score'] = min(risk_score, 100)
        results['risk_level'] = (
            'CRITICAL' if risk_score >= 70 else
            'HIGH' if risk_score >= 40 else
            'MEDIUM' if risk_score >= 20 else 'LOW'
        )

        return results

    def generate_report(self, results: dict) -> str:
        """Generate AI-powered forensic report."""
        return self.ai_analyzer.generate_forensic_report(results)

# Run full analysis
pipeline = MemoryForensicsPipeline()
results = pipeline.analyze_image("memory.dmp")

print(f"\nRisk Level: {results['risk_level']}")
print(f"Risk Score: {results['risk_score']}/100")

# Generate report
report = pipeline.generate_report(results)
print("\n" + "="*60)
print("FORENSIC ANALYSIS REPORT")
print("="*60)
print(report)
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Volatility not found | Install with pip, verify PATH |
| Profile not detected | Use `windows.info` to determine OS |
| Slow analysis | Use SSD, increase memory |
| Plugin errors | Update Volatility, check symbols |
| Large images | Process in chunks, use filtering |

---

## Next Steps

- Add YARA rule scanning integration
- Build timeline correlation with other artifacts
- Add automated malware family classification
- Integrate with sandbox for dynamic analysis
- Create automated IOC extraction

# Lab 11: Ransomware Detection - Solution Walkthrough

## Overview

Build an AI-powered ransomware detection system using entropy analysis, behavioral patterns, and ransom note analysis.

**Time:** 3-4 hours
**Difficulty:** Advanced

---

## Task 1: Entropy Analysis

### Detecting Encrypted Files

```python
import math
import os
from pathlib import Path
from collections import Counter

class EntropyAnalyzer:
    def __init__(self, high_entropy_threshold: float = 7.5):
        self.threshold = high_entropy_threshold

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_file(self, file_path: str) -> dict:
        """Analyze file entropy."""
        path = Path(file_path)

        with open(path, 'rb') as f:
            content = f.read()

        entropy = self.calculate_entropy(content)

        # Analyze header entropy (first 256 bytes)
        header_entropy = self.calculate_entropy(content[:256])

        # Analyze chunks for entropy distribution
        chunk_size = 4096
        chunk_entropies = []
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            if len(chunk) >= 256:
                chunk_entropies.append(self.calculate_entropy(chunk))

        return {
            'file_path': str(path),
            'file_size': len(content),
            'overall_entropy': round(entropy, 3),
            'header_entropy': round(header_entropy, 3),
            'chunk_entropy_avg': round(sum(chunk_entropies) / len(chunk_entropies), 3) if chunk_entropies else 0,
            'chunk_entropy_std': round(self._std(chunk_entropies), 3) if chunk_entropies else 0,
            'is_high_entropy': entropy >= self.threshold,
            'likely_encrypted': entropy >= self.threshold and header_entropy >= 7.0
        }

    def _std(self, values: list) -> float:
        """Calculate standard deviation."""
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def scan_directory(self, directory: str, extensions: list = None) -> list[dict]:
        """Scan directory for high-entropy files."""
        results = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                if extensions and not any(file.endswith(ext) for ext in extensions):
                    continue

                file_path = os.path.join(root, file)
                try:
                    analysis = self.analyze_file(file_path)
                    if analysis['is_high_entropy']:
                        results.append(analysis)
                except Exception as e:
                    print(f"Error analyzing {file_path}: {e}")

        return results

# Analyze files
analyzer = EntropyAnalyzer(high_entropy_threshold=7.5)

# Single file analysis
result = analyzer.analyze_file("suspicious_document.docx")
print(f"Entropy: {result['overall_entropy']}")
print(f"Likely encrypted: {result['likely_encrypted']}")

# Directory scan
encrypted_files = analyzer.scan_directory(
    "/path/to/documents",
    extensions=['.docx', '.xlsx', '.pdf', '.txt']
)
print(f"Found {len(encrypted_files)} potentially encrypted files")
```

---

## Task 2: Behavioral Detection

### Monitoring File System Activity

```python
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict
import json

@dataclass
class FileEvent:
    timestamp: datetime
    event_type: str  # create, modify, delete, rename
    file_path: str
    process_name: str
    process_id: int

class BehavioralDetector:
    def __init__(self):
        # Detection thresholds
        self.rapid_modification_threshold = 50  # files per minute
        self.extension_change_threshold = 10  # suspicious renames
        self.mass_delete_threshold = 20  # deletions per minute

        # Suspicious extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt',
            '.enc', '.locky', '.zepto', '.cerber', '.wannacry',
            '.ryuk', '.conti', '.lockbit', '.blackcat'
        ]

        # Tracking
        self.events_by_process: dict[int, list[FileEvent]] = defaultdict(list)
        self.alerts = []

    def process_event(self, event: FileEvent):
        """Process a file system event."""
        self.events_by_process[event.process_id].append(event)
        self._check_behaviors(event.process_id)

    def _check_behaviors(self, process_id: int):
        """Check for ransomware-like behaviors."""
        events = self.events_by_process[process_id]
        now = datetime.now()
        recent_window = timedelta(minutes=1)

        # Get recent events
        recent_events = [e for e in events if now - e.timestamp <= recent_window]

        if not recent_events:
            return

        process_name = recent_events[0].process_name

        # Check 1: Rapid file modifications
        modifications = [e for e in recent_events if e.event_type == 'modify']
        if len(modifications) >= self.rapid_modification_threshold:
            self._raise_alert('rapid_modification', process_id, process_name, {
                'count': len(modifications),
                'threshold': self.rapid_modification_threshold
            })

        # Check 2: Suspicious extension changes
        renames = [e for e in recent_events if e.event_type == 'rename']
        suspicious_renames = [
            e for e in renames
            if any(e.file_path.endswith(ext) for ext in self.ransomware_extensions)
        ]
        if len(suspicious_renames) >= self.extension_change_threshold:
            self._raise_alert('suspicious_rename', process_id, process_name, {
                'count': len(suspicious_renames),
                'extensions': list(set(
                    Path(e.file_path).suffix for e in suspicious_renames
                ))
            })

        # Check 3: Mass deletion
        deletions = [e for e in recent_events if e.event_type == 'delete']
        if len(deletions) >= self.mass_delete_threshold:
            self._raise_alert('mass_deletion', process_id, process_name, {
                'count': len(deletions),
                'threshold': self.mass_delete_threshold
            })

        # Check 4: Shadow copy deletion (specific commands)
        # Would integrate with process monitoring

    def _raise_alert(self, alert_type: str, process_id: int,
                     process_name: str, details: dict):
        """Raise a ransomware detection alert."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'process_id': process_id,
            'process_name': process_name,
            'severity': 'CRITICAL',
            'details': details
        }
        self.alerts.append(alert)
        print(f"ALERT: {alert_type} detected - PID {process_id} ({process_name})")

    def get_alerts(self) -> list[dict]:
        return self.alerts

# Initialize detector
detector = BehavioralDetector()

# Simulate events (in production, integrate with file system watcher)
events = [
    FileEvent(datetime.now(), 'modify', '/docs/file1.docx.locked', 'suspicious.exe', 1234),
    FileEvent(datetime.now(), 'modify', '/docs/file2.xlsx.locked', 'suspicious.exe', 1234),
    # ... more events
]

for event in events:
    detector.process_event(event)

print(f"Alerts raised: {len(detector.get_alerts())}")
```

---

## Task 3: Ransom Note Detection

### AI-Powered Note Analysis

````python
import anthropic
import re

class RansomNoteAnalyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()

        # Common ransom note patterns
        self.ransom_patterns = [
            r'bitcoin|btc|cryptocurrency|wallet',
            r'decrypt|encrypted|locked',
            r'pay.*\$|payment',
            r'restore.*files',
            r'tor.*onion',
            r'24.*hours|48.*hours|deadline',
            r'private.*key|decryption.*key'
        ]

        # Common ransom note filenames
        self.note_filenames = [
            'readme.txt', 'how_to_decrypt.txt', 'restore_files.txt',
            'decrypt_instructions.html', 'read_me.txt', '_readme.txt',
            'how_to_recover.txt', 'ransom_note.txt'
        ]

    def detect_ransom_note(self, file_path: str) -> dict:
        """Detect if a file is likely a ransom note."""
        path = Path(file_path)

        # Check filename
        filename_match = path.name.lower() in [n.lower() for n in self.note_filenames]

        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return {'is_ransom_note': False, 'error': 'Could not read file'}

        # Check patterns
        pattern_matches = []
        for pattern in self.ransom_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                pattern_matches.append(pattern)

        # Calculate confidence
        confidence = len(pattern_matches) / len(self.ransom_patterns)
        if filename_match:
            confidence += 0.2

        is_ransom_note = confidence >= 0.3 or len(pattern_matches) >= 3

        return {
            'file_path': str(path),
            'is_ransom_note': is_ransom_note,
            'confidence': min(confidence, 1.0),
            'pattern_matches': pattern_matches,
            'filename_match': filename_match
        }

    def analyze_note(self, content: str) -> dict:
        """Use AI to extract intelligence from ransom note."""

        prompt = f"""Analyze this suspected ransom note and extract intelligence:

```
{content[:3000]}
```

Extract the following information (return JSON):
1. "ransomware_family": Identified or suspected ransomware family
2. "bitcoin_addresses": List of Bitcoin wallet addresses
3. "contact_methods": Email addresses, Tor sites, etc.
4. "ransom_amount": Demanded payment amount
5. "deadline": Payment deadline if mentioned
6. "threats": What they threaten to do
7. "file_types_targeted": Types of files mentioned as encrypted
8. "decryption_claims": What they claim about decryption
9. "language_indicators": Language/origin indicators
10. "ttps": Notable tactics, techniques, procedures

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            analysis = {'raw_analysis': response.content[0].text}

        return analysis

    def identify_ransomware_family(self, indicators: dict) -> str:
        """Identify ransomware family from indicators."""

        prompt = f"""Based on these indicators, identify the ransomware family:

## Indicators
- File extension used: {indicators.get('extension', 'unknown')}
- Ransom note filename: {indicators.get('note_filename', 'unknown')}
- Bitcoin addresses: {indicators.get('bitcoin_addresses', [])}
- Contact emails: {indicators.get('emails', [])}
- Encryption behavior: {indicators.get('behavior', 'unknown')}

Known ransomware families to consider:
- LockBit, BlackCat/ALPHV, Conti, REvil, Ryuk, Maze, DarkSide,
- Hive, BlackBasta, Royal, Play, Clop, Akira

Return:
1. Most likely family (or "Unknown" if uncertain)
2. Confidence level (high/medium/low)
3. Key identifying factors
4. Recommended resources for this family"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Analyze ransom note
analyzer = RansomNoteAnalyzer()

# Detect ransom note
detection = analyzer.detect_ransom_note("readme.txt")
print(f"Is ransom note: {detection['is_ransom_note']} (confidence: {detection['confidence']:.2f})")

if detection['is_ransom_note']:
    content = Path("readme.txt").read_text()
    intelligence = analyzer.analyze_note(content)
    print(json.dumps(intelligence, indent=2))
````

---

## Task 4: Automated Response

### Containment Actions

```python
import subprocess
from datetime import datetime

class RansomwareResponder:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.actions_log = []

    def log_action(self, action: str, target: str, result: str):
        """Log response action."""
        self.actions_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'target': target,
            'result': result,
            'dry_run': self.dry_run
        })

    def kill_process(self, process_id: int) -> bool:
        """Terminate malicious process."""
        if self.dry_run:
            self.log_action('kill_process', str(process_id), 'DRY_RUN')
            return True

        try:
            subprocess.run(['kill', '-9', str(process_id)], check=True)
            self.log_action('kill_process', str(process_id), 'SUCCESS')
            return True
        except subprocess.CalledProcessError as e:
            self.log_action('kill_process', str(process_id), f'FAILED: {e}')
            return False

    def isolate_network(self, hostname: str) -> bool:
        """Isolate host from network (requires EDR integration)."""
        if self.dry_run:
            self.log_action('network_isolation', hostname, 'DRY_RUN')
            return True

        # In production, call EDR API
        # Example: CrowdStrike, Carbon Black, SentinelOne
        self.log_action('network_isolation', hostname, 'REQUIRES_EDR_API')
        return False

    def disable_user(self, username: str) -> bool:
        """Disable user account in AD."""
        if self.dry_run:
            self.log_action('disable_user', username, 'DRY_RUN')
            return True

        # In production, use AD/LDAP
        # subprocess.run(['net', 'user', username, '/active:no'], check=True)
        self.log_action('disable_user', username, 'REQUIRES_AD_ACCESS')
        return False

    def block_iocs(self, iocs: list[dict]) -> dict:
        """Block IOCs in security tools."""
        results = {'blocked': [], 'failed': []}

        for ioc in iocs:
            if self.dry_run:
                results['blocked'].append(ioc)
                continue

            # In production, integrate with:
            # - Firewall API
            # - EDR block list
            # - DNS sinkhole
            # - Proxy blocklist

        self.log_action('block_iocs', str(len(iocs)),
                       f"Blocked: {len(results['blocked'])}")
        return results

    def create_snapshot(self, volume: str) -> bool:
        """Create volume snapshot for forensics."""
        if self.dry_run:
            self.log_action('create_snapshot', volume, 'DRY_RUN')
            return True

        # In production, use cloud provider APIs or VSS
        self.log_action('create_snapshot', volume, 'REQUIRES_IMPLEMENTATION')
        return False

    def generate_response_report(self) -> str:
        """Generate response actions report."""
        report = ["# Ransomware Response Actions Report"]
        report.append(f"\nGenerated: {datetime.now().isoformat()}")
        report.append(f"Mode: {'DRY RUN' if self.dry_run else 'LIVE'}")

        report.append("\n## Actions Taken\n")
        for action in self.actions_log:
            report.append(f"- **{action['timestamp']}** - {action['action']}")
            report.append(f"  - Target: {action['target']}")
            report.append(f"  - Result: {action['result']}")

        return "\n".join(report)

# Initialize responder (dry run mode for safety)
responder = RansomwareResponder(dry_run=True)

# Example response
responder.kill_process(1234)
responder.isolate_network("infected-workstation")
responder.block_iocs([
    {'type': 'ip', 'value': '192.168.1.100'},
    {'type': 'domain', 'value': 'malicious.com'}
])

print(responder.generate_response_report())
```

---

## Task 5: Complete Detection Pipeline

### Integrated Ransomware Detection System

```python
class RansomwareDetectionSystem:
    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()
        self.behavioral_detector = BehavioralDetector()
        self.note_analyzer = RansomNoteAnalyzer()
        self.responder = RansomwareResponder(dry_run=True)
        self.client = anthropic.Anthropic()

    def analyze_incident(self, directory: str) -> dict:
        """Comprehensive ransomware incident analysis."""

        results = {
            'timestamp': datetime.now().isoformat(),
            'directory': directory,
            'findings': {},
            'risk_score': 0,
            'recommendations': []
        }

        # 1. Entropy analysis
        encrypted_files = self.entropy_analyzer.scan_directory(directory)
        results['findings']['encrypted_files'] = len(encrypted_files)

        # 2. Check for ransom notes
        ransom_notes = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                detection = self.note_analyzer.detect_ransom_note(file_path)
                if detection['is_ransom_note']:
                    ransom_notes.append(detection)

        results['findings']['ransom_notes'] = ransom_notes

        # 3. Behavioral alerts
        results['findings']['behavioral_alerts'] = self.behavioral_detector.get_alerts()

        # 4. Calculate risk score
        risk_score = 0
        if encrypted_files:
            risk_score += min(50, len(encrypted_files))
        if ransom_notes:
            risk_score += 30
        if self.behavioral_detector.get_alerts():
            risk_score += 20

        results['risk_score'] = min(100, risk_score)

        # 5. AI recommendations
        results['recommendations'] = self._generate_recommendations(results)

        return results

    def _generate_recommendations(self, analysis: dict) -> list[str]:
        """Generate AI-powered recommendations."""

        prompt = f"""Based on this ransomware incident analysis, provide immediate recommendations:

## Analysis Results
- Encrypted files found: {analysis['findings']['encrypted_files']}
- Ransom notes detected: {len(analysis['findings']['ransom_notes'])}
- Behavioral alerts: {len(analysis['findings']['behavioral_alerts'])}
- Risk score: {analysis['risk_score']}/100

Provide 5-7 prioritized, actionable recommendations for the incident response team.
Format as a numbered list."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse recommendations
        text = response.content[0].text
        recommendations = [
            line.strip() for line in text.split('\n')
            if line.strip() and (line.strip()[0].isdigit() or line.strip().startswith('-'))
        ]

        return recommendations

# Run detection
system = RansomwareDetectionSystem()
results = system.analyze_incident("/path/to/suspicious/directory")

print(f"Risk Score: {results['risk_score']}/100")
print(f"Encrypted Files: {results['findings']['encrypted_files']}")
print(f"\nRecommendations:")
for rec in results['recommendations']:
    print(f"  {rec}")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| High false positives | Tune entropy threshold, add file type whitelist |
| Missed detections | Lower thresholds, add more behavioral rules |
| Slow scanning | Use parallel processing, skip large files |
| Note parsing errors | Add more patterns, use fuzzy matching |
| Response failures | Verify permissions, test in dry-run mode |

---

## Next Steps

- Add machine learning classifier for ransomware families
- Integrate with backup verification
- Build real-time file system monitoring
- Add decryptor availability checking
- Create incident playbook automation

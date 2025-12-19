#!/usr/bin/env python3
"""
Lab 11: AI-Powered Ransomware Detection & Response
Complete solution implementation.
"""

import os
import re
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from anthropic import Anthropic


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class FileEvent:
    """Represents a file system event."""
    id: int
    timestamp: str
    process_name: str
    process_id: int
    operation: str
    file_path: str
    file_extension: str
    entropy: float
    size_bytes: int
    label: str = "unknown"


@dataclass
class RansomNoteIntel:
    """Extracted intelligence from ransom note."""
    ransomware_family: str
    threat_actor: Optional[str]
    bitcoin_addresses: List[str]
    monero_addresses: List[str]
    onion_urls: List[str]
    email_addresses: List[str]
    ransom_amount: Optional[str]
    deadline: Optional[str]
    exfiltration_claimed: bool
    mitre_techniques: List[str]
    confidence: float


@dataclass
class IncidentContext:
    """Context about the ransomware incident."""
    affected_hosts: List[str] = field(default_factory=list)
    affected_files: int = 0
    ransomware_family: str = "unknown"
    encryption_progress: float = 0.0
    lateral_movement_detected: bool = False
    exfiltration_detected: bool = False
    shadow_deletion_detected: bool = False


# =============================================================================
# Ransomware Behavior Detector
# =============================================================================

class RansomwareBehaviorDetector:
    """Detects ransomware behavior from file system events."""

    # Entropy threshold for encrypted content (7.0+ is highly random)
    ENCRYPTION_ENTROPY_THRESHOLD = 7.5

    # Known ransomware extensions
    RANSOMWARE_EXTENSIONS = {
        '.locked', '.encrypted', '.crypto', '.crypt',
        '.locky', '.cerber', '.zepto', '.odin',
        '.thor', '.aesir', '.zzzzz', '.crypted',
        '.enc', '.cryptolocker', '.crinf', '.r5a',
        '.XRNT', '.XTBL', '.crypt', '.R16M01D05',
        '.pzdc', '.good', '.LOL!', '.OMG!',
        '.RDM', '.RRK', '.encryptedRSA', '.crysis',
        '.dharma', '.wallet', '.onion', '.arena',
        '.phobos', '.alphv', '.lockbit'
    }

    # Shadow copy deletion commands
    SHADOW_DELETE_PATTERNS = [
        r'vssadmin.*delete.*shadows',
        r'wmic.*shadowcopy.*delete',
        r'bcdedit.*recoveryenabled.*no',
        r'wbadmin.*delete.*catalog'
    ]

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        self.baseline_stats = {}

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_events(self, events: List[FileEvent]) -> Dict:
        """Analyze file events for ransomware behavior."""
        results = {
            "is_ransomware": False,
            "confidence": 0.0,
            "indicators": [],
            "affected_files": 0,
            "encryption_pattern": False,
            "shadow_deletion": False,
            "ransom_note": False,
            "mitre_techniques": []
        }

        # Check for encryption patterns
        encryption_score = self.detect_encryption_pattern(events)
        if encryption_score > 0.5:
            results["encryption_pattern"] = True
            results["indicators"].append(f"Encryption pattern detected (score: {encryption_score:.2f})")
            results["mitre_techniques"].append("T1486 - Data Encrypted for Impact")

        # Check for shadow deletion
        if self.detect_shadow_deletion(events):
            results["shadow_deletion"] = True
            results["indicators"].append("Shadow copy deletion detected")
            results["mitre_techniques"].append("T1490 - Inhibit System Recovery")

        # Check for ransom note creation
        ransom_note_events = self.detect_ransom_note(events)
        if ransom_note_events:
            results["ransom_note"] = True
            results["indicators"].append(f"Ransom note(s) created: {len(ransom_note_events)}")

        # Count affected files
        affected = [e for e in events if e.label.startswith("ransomware")]
        results["affected_files"] = len(affected)

        # Calculate overall confidence
        score = 0.0
        if results["encryption_pattern"]:
            score += 0.4
        if results["shadow_deletion"]:
            score += 0.3
        if results["ransom_note"]:
            score += 0.3

        results["confidence"] = min(score, 1.0)
        results["is_ransomware"] = results["confidence"] >= self.threshold

        return results

    def detect_encryption_pattern(self, events: List[FileEvent]) -> float:
        """Detect mass encryption patterns."""
        high_entropy_writes = 0
        total_writes = 0
        extension_changes = 0

        for event in events:
            if event.operation == "WRITE":
                total_writes += 1
                if event.entropy >= self.ENCRYPTION_ENTROPY_THRESHOLD:
                    high_entropy_writes += 1
                if event.file_extension.lower() in self.RANSOMWARE_EXTENSIONS:
                    extension_changes += 1

        if total_writes == 0:
            return 0.0

        entropy_ratio = high_entropy_writes / total_writes
        extension_ratio = extension_changes / total_writes

        return (entropy_ratio * 0.6) + (extension_ratio * 0.4)

    def detect_shadow_deletion(self, events: List[FileEvent]) -> bool:
        """Detect VSS/shadow copy deletion attempts."""
        for event in events:
            if event.operation == "EXECUTE":
                for pattern in self.SHADOW_DELETE_PATTERNS:
                    if re.search(pattern, event.file_path, re.IGNORECASE):
                        return True
        return False

    def detect_ransom_note(self, events: List[FileEvent]) -> List[FileEvent]:
        """Detect ransom note creation."""
        ransom_patterns = [
            r'readme.*restore',
            r'how.*decrypt',
            r'recover.*files',
            r'ransom.*note',
            r'decrypt.*instruction',
            r'your.*files.*encrypted'
        ]

        matches = []
        for event in events:
            if event.operation == "CREATE":
                filename = os.path.basename(event.file_path).lower()
                for pattern in ransom_patterns:
                    if re.search(pattern, filename, re.IGNORECASE):
                        matches.append(event)
                        break

        return matches


# =============================================================================
# Ransom Note Analyzer
# =============================================================================

class RansomNoteAnalyzer:
    """LLM-powered ransom note analysis."""

    # Regex patterns for IOC extraction
    BTC_PATTERN = r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'
    XMR_PATTERN = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ONION_PATTERN = r'\b[a-z2-7]{16,56}\.onion\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    def __init__(self):
        self.client = Anthropic()

    def analyze(self, note_content: str) -> RansomNoteIntel:
        """Analyze ransom note and extract intelligence."""
        # Extract IOCs with regex first
        iocs = self.extract_iocs(note_content)

        # Use LLM for deeper analysis
        prompt = f"""Analyze this ransom note and extract intelligence:

RANSOM NOTE:
{note_content}

Provide a JSON response with:
1. ransomware_family: Identify the ransomware family (LockBit, BlackCat, Conti, REvil, etc.)
2. threat_actor: Any threat actor attribution clues
3. ransom_amount: The demanded ransom amount
4. deadline: Payment deadline mentioned
5. exfiltration_claimed: Whether they claim to have stolen data (true/false)
6. sophistication: Rate sophistication (low/medium/high)
7. language_indicators: Notable language patterns for attribution
8. mitre_techniques: MITRE ATT&CK techniques evidenced

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            analysis = {
                "ransomware_family": "unknown",
                "threat_actor": None,
                "ransom_amount": None,
                "deadline": None,
                "exfiltration_claimed": False,
                "sophistication": "medium",
                "language_indicators": [],
                "mitre_techniques": ["T1486"]
            }

        return RansomNoteIntel(
            ransomware_family=analysis.get("ransomware_family", "unknown"),
            threat_actor=analysis.get("threat_actor"),
            bitcoin_addresses=iocs.get("bitcoin", []),
            monero_addresses=iocs.get("monero", []),
            onion_urls=iocs.get("onion", []),
            email_addresses=iocs.get("email", []),
            ransom_amount=analysis.get("ransom_amount"),
            deadline=analysis.get("deadline"),
            exfiltration_claimed=analysis.get("exfiltration_claimed", False),
            mitre_techniques=analysis.get("mitre_techniques", ["T1486"]),
            confidence=0.8 if analysis.get("ransomware_family") != "unknown" else 0.5
        )

    def extract_iocs(self, note_content: str) -> Dict[str, List[str]]:
        """Extract indicators of compromise from note."""
        return {
            "bitcoin": list(set(re.findall(self.BTC_PATTERN, note_content))),
            "monero": list(set(re.findall(self.XMR_PATTERN, note_content))),
            "onion": list(set(re.findall(self.ONION_PATTERN, note_content))),
            "email": list(set(re.findall(self.EMAIL_PATTERN, note_content)))
        }


# =============================================================================
# Ransomware Responder
# =============================================================================

class RansomwareResponder:
    """Automated ransomware incident response."""

    def __init__(self, auto_contain: bool = False):
        self.auto_contain = auto_contain
        self.client = Anthropic()

    def assess_severity(self, context: IncidentContext) -> Tuple[str, str]:
        """Assess incident severity."""
        if context.exfiltration_detected or context.lateral_movement_detected:
            return "CRITICAL", "Data exfiltration or lateral movement detected"
        elif context.encryption_progress > 50:
            return "CRITICAL", "Significant encryption in progress"
        elif context.shadow_deletion_detected:
            return "HIGH", "Recovery inhibition detected"
        elif context.affected_files > 100:
            return "HIGH", "Large number of files affected"
        else:
            return "MEDIUM", "Limited scope ransomware activity"

    def generate_playbook(self, context: IncidentContext) -> List[Dict]:
        """Generate response playbook based on incident context."""
        severity, _ = self.assess_severity(context)

        playbook = [
            {
                "action": "ALERT",
                "priority": 1,
                "description": f"Ransomware incident detected - Severity: {severity}",
                "automated": True
            },
            {
                "action": "ISOLATE_HOST",
                "priority": 2,
                "description": "Network isolate affected hosts",
                "automated": self.auto_contain,
                "targets": context.affected_hosts
            },
            {
                "action": "PRESERVE_EVIDENCE",
                "priority": 3,
                "description": "Capture memory dump and forensic images",
                "automated": False
            },
            {
                "action": "IDENTIFY_SCOPE",
                "priority": 4,
                "description": "Determine full scope of encryption",
                "automated": True
            }
        ]

        if context.lateral_movement_detected:
            playbook.append({
                "action": "SCAN_NETWORK",
                "priority": 5,
                "description": "Scan for lateral movement indicators",
                "automated": True
            })

        if context.exfiltration_detected:
            playbook.append({
                "action": "DATA_BREACH_PROTOCOL",
                "priority": 6,
                "description": "Initiate data breach response protocol",
                "automated": False
            })

        playbook.append({
            "action": "RECOVERY_ASSESSMENT",
            "priority": 10,
            "description": "Assess backup availability and recovery options",
            "automated": False
        })

        return playbook

    def generate_report(self, context: IncidentContext, intel: RansomNoteIntel) -> str:
        """Generate incident report using LLM."""
        prompt = f"""Generate a ransomware incident report based on this data:

INCIDENT CONTEXT:
- Affected Hosts: {context.affected_hosts}
- Affected Files: {context.affected_files}
- Ransomware Family: {context.ransomware_family}
- Encryption Progress: {context.encryption_progress}%
- Lateral Movement: {context.lateral_movement_detected}
- Data Exfiltration: {context.exfiltration_detected}
- Shadow Deletion: {context.shadow_deletion_detected}

THREAT INTELLIGENCE:
- Family: {intel.ransomware_family}
- Bitcoin Addresses: {intel.bitcoin_addresses}
- Onion URLs: {intel.onion_urls}
- Ransom Demand: {intel.ransom_amount}
- Data Theft Claimed: {intel.exfiltration_claimed}
- MITRE Techniques: {intel.mitre_techniques}

Generate a structured incident report with:
1. Executive Summary
2. Technical Analysis
3. Impact Assessment
4. Response Actions Taken
5. Recovery Recommendations
6. IOCs for Blocking"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text


# =============================================================================
# Main Detection Pipeline
# =============================================================================

class RansomwareDetectionPipeline:
    """End-to-end ransomware detection and response."""

    def __init__(self):
        self.behavior_detector = RansomwareBehaviorDetector()
        self.note_analyzer = RansomNoteAnalyzer()
        self.responder = RansomwareResponder()

    def process_events(self, events: List[Dict]) -> Dict:
        """Process file system events through detection pipeline."""
        # Convert to FileEvent objects
        file_events = [
            FileEvent(
                id=e["id"],
                timestamp=e["timestamp"],
                process_name=e["process_name"],
                process_id=e["process_id"],
                operation=e["operation"],
                file_path=e["file_path"],
                file_extension=e["file_extension"],
                entropy=e["entropy"],
                size_bytes=e["size_bytes"],
                label=e.get("label", "unknown")
            )
            for e in events
        ]

        # Detect ransomware behavior
        detection_result = self.behavior_detector.analyze_events(file_events)

        result = {
            "detection": detection_result,
            "intel": None,
            "response": None
        }

        if detection_result["is_ransomware"]:
            # Create incident context
            context = IncidentContext(
                affected_hosts=["WORKSTATION-001"],
                affected_files=detection_result["affected_files"],
                ransomware_family="unknown",
                encryption_progress=50.0,
                shadow_deletion_detected=detection_result["shadow_deletion"]
            )

            # Generate response playbook
            result["response"] = self.responder.generate_playbook(context)

        return result


# =============================================================================
# Demo
# =============================================================================

def main():
    """Demo the ransomware detection pipeline."""
    print("=" * 60)
    print("Lab 11: Ransomware Detection & Response")
    print("=" * 60)

    # Load sample events
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "file_events.json")
    if os.path.exists(data_path):
        with open(data_path) as f:
            data = json.load(f)
            events = data["events"]
    else:
        print("Sample data not found, using inline example")
        events = [
            {
                "id": 1,
                "timestamp": "2024-01-15T15:00:00Z",
                "process_name": "svchost.exe",
                "process_id": 6789,
                "operation": "WRITE",
                "file_path": "C:\\Users\\victim\\Documents\\file.xlsx.locked",
                "file_extension": ".locked",
                "entropy": 7.98,
                "size_bytes": 234567,
                "label": "ransomware_encryption"
            }
        ]

    # Run detection pipeline
    pipeline = RansomwareDetectionPipeline()
    result = pipeline.process_events(events)

    print("\n[Detection Results]")
    print(f"  Ransomware Detected: {result['detection']['is_ransomware']}")
    print(f"  Confidence: {result['detection']['confidence']:.0%}")
    print(f"  Affected Files: {result['detection']['affected_files']}")

    if result['detection']['indicators']:
        print("\n[Indicators]")
        for indicator in result['detection']['indicators']:
            print(f"  - {indicator}")

    if result['detection']['mitre_techniques']:
        print("\n[MITRE ATT&CK Techniques]")
        for technique in result['detection']['mitre_techniques']:
            print(f"  - {technique}")

    if result['response']:
        print("\n[Response Playbook]")
        for action in result['response']:
            auto = "[AUTO]" if action.get("automated") else "[MANUAL]"
            print(f"  {action['priority']}. {auto} {action['action']}: {action['description']}")

    # Analyze ransom note if available
    note_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "ransom_notes", "lockbit_note.txt"
    )
    if os.path.exists(note_path):
        print("\n[Ransom Note Analysis]")
        with open(note_path) as f:
            note_content = f.read()

        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs(note_content)

        print(f"  Bitcoin Addresses: {len(iocs['bitcoin'])}")
        print(f"  Onion URLs: {len(iocs['onion'])}")
        print(f"  Email Addresses: {len(iocs['email'])}")


if __name__ == "__main__":
    main()

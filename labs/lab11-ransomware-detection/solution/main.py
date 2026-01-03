#!/usr/bin/env python3
"""
Lab 11: AI-Powered Ransomware Detection & Response
Complete solution implementation.

OVERVIEW
========
This lab teaches how to build an AI-powered ransomware detection system that:
1. Analyzes file system events for ransomware behavior patterns
2. Uses entropy analysis to detect encrypted files
3. Extracts IOCs (Indicators of Compromise) from ransom notes
4. Generates automated incident response playbooks
5. Creates comprehensive incident reports using LLMs

KEY CONCEPTS
============
- Entropy Analysis: Encrypted data has high entropy (randomness) near 8.0
- Behavioral Detection: Looking for patterns like mass file encryption
- IOC Extraction: Finding bitcoin addresses, onion URLs, emails in ransom notes
- MITRE ATT&CK: Mapping ransomware behaviors to attack techniques

LEARNING OBJECTIVES
===================
1. Understand how entropy can detect encrypted content
2. Build behavioral detectors for ransomware patterns
3. Use regex + LLMs for IOC extraction
4. Generate automated incident response workflows
"""

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from anthropic import Anthropic

# =============================================================================
# Data Classes
# =============================================================================
# These dataclasses define the structure of our data. Using dataclasses gives us
# automatic __init__, __repr__, and other methods, making code cleaner.


@dataclass
class FileEvent:
    """
    Represents a file system event from endpoint telemetry.

    In real-world scenarios, these events come from EDR (Endpoint Detection
    and Response) tools like CrowdStrike, Carbon Black, or Microsoft Defender.

    Attributes:
        id: Unique event identifier
        timestamp: When the event occurred (ISO 8601 format)
        process_name: Name of the process that performed the action
        process_id: Operating system process ID (PID)
        operation: Type of operation (READ, WRITE, CREATE, DELETE, EXECUTE)
        file_path: Full path to the affected file
        file_extension: File extension (e.g., ".docx", ".locked")
        entropy: Shannon entropy of file contents (0.0 to 8.0)
        size_bytes: Size of the file in bytes
        label: Classification label (for training/evaluation)
    """

    id: int
    timestamp: str
    process_name: str
    process_id: int
    operation: str
    file_path: str
    file_extension: str
    entropy: float  # 0.0 = no randomness, 8.0 = maximum randomness
    size_bytes: int
    label: str = "unknown"


@dataclass
class RansomNoteIntel:
    """
    Intelligence extracted from a ransom note.

    Ransom notes contain valuable threat intelligence including:
    - Payment addresses (Bitcoin, Monero)
    - Communication channels (Tor sites, emails)
    - Threat actor attribution clues
    - Indicators for threat hunting

    Attributes:
        ransomware_family: Identified ransomware variant (LockBit, BlackCat, etc.)
        threat_actor: Attributed threat group if known
        bitcoin_addresses: BTC wallet addresses for payment
        monero_addresses: XMR wallet addresses (privacy coin)
        onion_urls: Tor hidden service URLs for victim portal
        email_addresses: Contact emails mentioned
        ransom_amount: Demanded payment amount
        deadline: Payment deadline mentioned in note
        exfiltration_claimed: Whether attackers claim to have stolen data
        mitre_techniques: MITRE ATT&CK technique IDs
        confidence: Confidence score (0.0 to 1.0)
    """

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
    """
    Context about an ongoing ransomware incident.

    This context is built up during detection and used to:
    - Assess incident severity
    - Generate appropriate response playbooks
    - Create incident reports

    Attributes:
        affected_hosts: List of compromised hostnames/IPs
        affected_files: Count of encrypted files
        ransomware_family: Identified variant
        encryption_progress: Percentage of target files encrypted (0-100)
        lateral_movement_detected: Whether attackers moved to other systems
        exfiltration_detected: Whether data theft was detected
        shadow_deletion_detected: Whether backup deletion was attempted
    """

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
    """
    Detects ransomware behavior from file system events using behavioral analysis.

    This detector looks for patterns that indicate ransomware activity:
    1. High entropy file writes (encrypted content)
    2. Known ransomware file extensions (.locked, .encrypted, etc.)
    3. Shadow copy deletion commands
    4. Ransom note creation

    DETECTION APPROACH
    ==================
    Ransomware detection uses multiple signals combined:
    - Entropy analysis catches encrypted content
    - Extension tracking catches known variants
    - Command monitoring catches recovery inhibition
    - File name patterns catch ransom notes

    Each signal contributes to an overall confidence score.
    """

    # Entropy threshold for encrypted content
    # Encrypted/compressed data typically has entropy > 7.5
    # Normal documents usually have entropy between 4.0-6.0
    ENCRYPTION_ENTROPY_THRESHOLD = 7.5

    # Known ransomware file extensions
    # These are extensions added by various ransomware families
    # Keeping this list updated is crucial for detection
    RANSOMWARE_EXTENSIONS = {
        ".locked",
        ".encrypted",
        ".crypto",
        ".crypt",
        ".locky",
        ".cerber",
        ".zepto",
        ".odin",  # Locky variants
        ".thor",
        ".aesir",
        ".zzzzz",
        ".crypted",  # Locky variants
        ".enc",
        ".cryptolocker",
        ".crinf",
        ".r5a",
        ".XRNT",
        ".XTBL",
        ".crypt",
        ".R16M01D05",
        ".pzdc",
        ".good",
        ".LOL!",
        ".OMG!",
        ".RDM",
        ".RRK",
        ".encryptedRSA",
        ".crysis",
        ".dharma",
        ".wallet",
        ".onion",
        ".arena",  # Dharma/CrySis
        ".phobos",
        ".alphv",
        ".lockbit",  # Modern variants
    }

    # Shadow copy deletion command patterns
    # Ransomware often deletes Volume Shadow Copies to prevent recovery
    # These commands are MITRE ATT&CK technique T1490
    SHADOW_DELETE_PATTERNS = [
        r"vssadmin.*delete.*shadows",  # Windows built-in
        r"wmic.*shadowcopy.*delete",  # WMI method
        r"bcdedit.*recoveryenabled.*no",  # Disable recovery mode
        r"wbadmin.*delete.*catalog",  # Delete backup catalog
    ]

    def __init__(self, threshold: float = 0.8):
        """
        Initialize the detector.

        Args:
            threshold: Confidence threshold for ransomware classification (0.0-1.0)
                      Lower values = more sensitive but more false positives
                      Higher values = fewer false positives but might miss attacks
        """
        self.threshold = threshold
        self.baseline_stats = {}  # For anomaly detection baseline

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Shannon entropy measures the randomness/unpredictability of data.
        - Entropy 0.0: Completely predictable (e.g., file of all zeros)
        - Entropy 8.0: Maximum randomness (encrypted/compressed data)
        - Normal text: Usually 4.0-5.0
        - Normal documents: Usually 5.0-6.5
        - Encrypted/compressed: Usually 7.5-8.0

        FORMULA: H(X) = -Σ p(x) * log2(p(x))

        Args:
            data: Byte content to analyze

        Returns:
            Entropy value between 0.0 and 8.0
        """
        if not data:
            return 0.0

        # Count frequency of each byte value (0-255)
        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        # Calculate probability and entropy for each byte value
        for count in counter.values():
            probability = count / length
            if probability > 0:
                # Shannon entropy formula: -p * log2(p)
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_events(self, events: List[FileEvent]) -> Dict:
        """
        Analyze file events for ransomware behavior.

        This is the main analysis method that combines multiple detection signals:
        1. Encryption pattern detection (entropy + extensions)
        2. Shadow copy deletion detection
        3. Ransom note creation detection

        Each signal contributes to the overall confidence score.

        Args:
            events: List of file system events to analyze

        Returns:
            Dictionary containing:
            - is_ransomware: Boolean classification
            - confidence: Confidence score (0.0-1.0)
            - indicators: List of detection indicators
            - affected_files: Count of affected files
            - encryption_pattern: Whether encryption pattern detected
            - shadow_deletion: Whether shadow deletion detected
            - ransom_note: Whether ransom note detected
            - mitre_techniques: List of MITRE ATT&CK technique IDs
        """
        results = {
            "is_ransomware": False,
            "confidence": 0.0,
            "indicators": [],
            "affected_files": 0,
            "encryption_pattern": False,
            "shadow_deletion": False,
            "ransom_note": False,
            "mitre_techniques": [],
        }

        # SIGNAL 1: Check for encryption patterns
        # High entropy + ransomware extensions = likely encryption
        encryption_score = self.detect_encryption_pattern(events)
        if encryption_score > 0.5:
            results["encryption_pattern"] = True
            results["indicators"].append(
                f"Encryption pattern detected (score: {encryption_score:.2f})"
            )
            # T1486: Data Encrypted for Impact
            results["mitre_techniques"].append("T1486 - Data Encrypted for Impact")

        # SIGNAL 2: Check for shadow copy deletion
        # Attackers delete backups to prevent recovery
        if self.detect_shadow_deletion(events):
            results["shadow_deletion"] = True
            results["indicators"].append("Shadow copy deletion detected")
            # T1490: Inhibit System Recovery
            results["mitre_techniques"].append("T1490 - Inhibit System Recovery")

        # SIGNAL 3: Check for ransom note creation
        # Ransom notes are created to instruct victims on payment
        ransom_note_events = self.detect_ransom_note(events)
        if ransom_note_events:
            results["ransom_note"] = True
            results["indicators"].append(f"Ransom note(s) created: {len(ransom_note_events)}")

        # Count affected files (those labeled as ransomware activity)
        affected = [e for e in events if e.label.startswith("ransomware")]
        results["affected_files"] = len(affected)

        # CALCULATE OVERALL CONFIDENCE
        # Weight different signals based on their reliability
        score = 0.0
        if results["encryption_pattern"]:
            score += 0.4  # Encryption is strong indicator
        if results["shadow_deletion"]:
            score += 0.3  # Shadow deletion is high confidence
        if results["ransom_note"]:
            score += 0.3  # Ransom note is definitive

        results["confidence"] = min(score, 1.0)
        results["is_ransomware"] = results["confidence"] >= self.threshold

        return results

    def detect_encryption_pattern(self, events: List[FileEvent]) -> float:
        """
        Detect mass encryption patterns in file events.

        Ransomware encryption patterns include:
        1. High entropy writes (encrypted content is random)
        2. Ransomware-specific file extensions
        3. High volume of file modifications

        Args:
            events: List of file events

        Returns:
            Score between 0.0 and 1.0 indicating encryption likelihood
        """
        high_entropy_writes = 0
        total_writes = 0
        extension_changes = 0

        for event in events:
            if event.operation == "WRITE":
                total_writes += 1

                # Check for high entropy (encrypted content)
                if event.entropy >= self.ENCRYPTION_ENTROPY_THRESHOLD:
                    high_entropy_writes += 1

                # Check for known ransomware extensions
                if event.file_extension.lower() in self.RANSOMWARE_EXTENSIONS:
                    extension_changes += 1

        if total_writes == 0:
            return 0.0

        # Calculate ratios
        entropy_ratio = high_entropy_writes / total_writes
        extension_ratio = extension_changes / total_writes

        # Combine signals with weights
        # Entropy is weighted higher as it's harder to fake
        return (entropy_ratio * 0.6) + (extension_ratio * 0.4)

    def detect_shadow_deletion(self, events: List[FileEvent]) -> bool:
        """
        Detect Volume Shadow Copy (VSS) deletion attempts.

        Ransomware commonly deletes shadow copies to prevent victims
        from recovering files using Windows backup mechanisms.

        Common commands:
        - vssadmin delete shadows /all /quiet
        - wmic shadowcopy delete
        - bcdedit /set recoveryenabled no

        Args:
            events: List of file events

        Returns:
            True if shadow deletion commands detected
        """
        for event in events:
            if event.operation == "EXECUTE":
                # Check command line against known patterns
                for pattern in self.SHADOW_DELETE_PATTERNS:
                    if re.search(pattern, event.file_path, re.IGNORECASE):
                        return True
        return False

    def detect_ransom_note(self, events: List[FileEvent]) -> List[FileEvent]:
        """
        Detect ransom note file creation.

        Ransom notes typically have filenames like:
        - README_RESTORE_FILES.txt
        - HOW_TO_DECRYPT.html
        - RECOVER_YOUR_DATA.txt
        - !DECRYPT_INSTRUCTIONS!.txt

        Args:
            events: List of file events

        Returns:
            List of events that appear to be ransom note creation
        """
        # Patterns commonly found in ransom note filenames
        ransom_patterns = [
            r"readme.*restore",
            r"how.*decrypt",
            r"recover.*files",
            r"ransom.*note",
            r"decrypt.*instruction",
            r"your.*files.*encrypted",
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
    """
    LLM-powered ransom note analysis for threat intelligence extraction.

    Ransom notes contain valuable intelligence:
    - Ransomware family identification
    - Payment addresses (for tracking/attribution)
    - Communication channels (for threat hunting)
    - Threat actor TTPs and language patterns

    This analyzer combines:
    1. Regex patterns for reliable IOC extraction
    2. LLM analysis for context understanding and family identification
    """

    # Regex patterns for Indicator of Compromise (IOC) extraction
    # These patterns are designed to match cryptocurrency addresses and contact info

    # Bitcoin address pattern (Legacy P2PKH, P2SH, and SegWit bech32)
    BTC_PATTERN = r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"

    # Monero address pattern (privacy-focused cryptocurrency)
    XMR_PATTERN = r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"

    # Tor onion URL pattern (v2 and v3 addresses)
    ONION_PATTERN = r"\b[a-z2-7]{16,56}\.onion\b"

    # Email address pattern
    EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

    def __init__(self):
        """Initialize the analyzer with Anthropic client."""
        self.client = Anthropic()

    def analyze(self, note_content: str) -> RansomNoteIntel:
        """
        Analyze ransom note and extract threat intelligence.

        This method:
        1. Uses regex to extract IOCs (addresses, URLs, emails)
        2. Uses LLM to identify ransomware family and extract context
        3. Combines both for comprehensive intelligence

        Args:
            note_content: Raw text content of the ransom note

        Returns:
            RansomNoteIntel object with extracted intelligence
        """
        # STEP 1: Extract IOCs using reliable regex patterns
        # Regex is preferred for structured data like addresses
        iocs = self.extract_iocs(note_content)

        # STEP 2: Use LLM for contextual analysis
        # LLM excels at understanding language and identifying patterns
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
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse LLM response with fallback for JSON errors
        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            # Fallback if LLM doesn't return valid JSON
            analysis = {
                "ransomware_family": "unknown",
                "threat_actor": None,
                "ransom_amount": None,
                "deadline": None,
                "exfiltration_claimed": False,
                "sophistication": "medium",
                "language_indicators": [],
                "mitre_techniques": ["T1486"],  # Default to encryption technique
            }

        # STEP 3: Combine regex IOCs with LLM analysis
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
            confidence=0.8 if analysis.get("ransomware_family") != "unknown" else 0.5,
        )

    def extract_iocs(self, note_content: str) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise using regex patterns.

        Why regex over LLM for IOC extraction?
        - Cryptocurrency addresses have fixed formats
        - Regex is deterministic and reliable
        - Faster than LLM for structured data
        - No false positives from LLM hallucination

        Args:
            note_content: Raw text of ransom note

        Returns:
            Dictionary mapping IOC type to list of extracted values
        """
        return {
            "bitcoin": list(set(re.findall(self.BTC_PATTERN, note_content))),
            "monero": list(set(re.findall(self.XMR_PATTERN, note_content))),
            "onion": list(set(re.findall(self.ONION_PATTERN, note_content))),
            "email": list(set(re.findall(self.EMAIL_PATTERN, note_content))),
        }


# =============================================================================
# Ransomware Responder
# =============================================================================


class RansomwareResponder:
    """
    Automated ransomware incident response system.

    This responder:
    1. Assesses incident severity based on multiple factors
    2. Generates prioritized response playbooks
    3. Creates comprehensive incident reports

    INCIDENT RESPONSE PHILOSOPHY
    ============================
    Speed is critical in ransomware response:
    - Early detection = less encryption
    - Fast isolation = prevented lateral movement
    - Quick recovery = minimal business impact

    The responder balances automated actions (fast) with
    manual verification (accurate) based on confidence levels.
    """

    def __init__(self, auto_contain: bool = False):
        """
        Initialize the responder.

        Args:
            auto_contain: Whether to automatically isolate hosts
                         Set to True only in mature environments with
                         high confidence detection and rollback capability
        """
        self.auto_contain = auto_contain
        self.client = Anthropic()

    def assess_severity(self, context: IncidentContext) -> Tuple[str, str]:
        """
        Assess incident severity based on impact indicators.

        Severity Levels:
        - CRITICAL: Active exfiltration or lateral movement
        - HIGH: Significant encryption or recovery inhibition
        - MEDIUM: Limited scope, contained activity
        - LOW: Suspicious but unconfirmed

        Args:
            context: Current incident context

        Returns:
            Tuple of (severity_level, reason)
        """
        # CRITICAL: Data exfiltration or lateral movement
        # These indicate advanced attack with potential for massive damage
        if context.exfiltration_detected or context.lateral_movement_detected:
            return "CRITICAL", "Data exfiltration or lateral movement detected"

        # CRITICAL: Significant encryption already occurred
        elif context.encryption_progress > 50:
            return "CRITICAL", "Significant encryption in progress"

        # HIGH: Recovery mechanisms disabled
        elif context.shadow_deletion_detected:
            return "HIGH", "Recovery inhibition detected"

        # HIGH: Many files affected
        elif context.affected_files > 100:
            return "HIGH", "Large number of files affected"

        # MEDIUM: Default for confirmed ransomware
        else:
            return "MEDIUM", "Limited scope ransomware activity"

    def generate_playbook(self, context: IncidentContext) -> List[Dict]:
        """
        Generate incident response playbook based on context.

        Playbook follows industry-standard IR phases:
        1. Detection & Analysis (already done)
        2. Containment (isolate, prevent spread)
        3. Eradication (remove threat)
        4. Recovery (restore systems)
        5. Post-Incident (lessons learned)

        Actions are prioritized and marked as automated or manual
        based on confidence and the auto_contain setting.

        Args:
            context: Current incident context

        Returns:
            List of playbook actions with priority and details
        """
        severity, _ = self.assess_severity(context)

        # Start with core response actions
        playbook = [
            {
                "action": "ALERT",
                "priority": 1,
                "description": f"Ransomware incident detected - Severity: {severity}",
                "automated": True,  # Always alert automatically
            },
            {
                "action": "ISOLATE_HOST",
                "priority": 2,
                "description": "Network isolate affected hosts",
                "automated": self.auto_contain,  # Based on config
                "targets": context.affected_hosts,
            },
            {
                "action": "PRESERVE_EVIDENCE",
                "priority": 3,
                "description": "Capture memory dump and forensic images",
                "automated": False,  # Requires manual forensic process
            },
            {
                "action": "IDENTIFY_SCOPE",
                "priority": 4,
                "description": "Determine full scope of encryption",
                "automated": True,  # Can scan for encrypted files
            },
        ]

        # Add context-specific actions
        if context.lateral_movement_detected:
            playbook.append(
                {
                    "action": "SCAN_NETWORK",
                    "priority": 5,
                    "description": "Scan for lateral movement indicators",
                    "automated": True,
                }
            )

        if context.exfiltration_detected:
            playbook.append(
                {
                    "action": "DATA_BREACH_PROTOCOL",
                    "priority": 6,
                    "description": "Initiate data breach response protocol",
                    "automated": False,  # Requires legal/compliance review
                }
            )

        # Always end with recovery assessment
        playbook.append(
            {
                "action": "RECOVERY_ASSESSMENT",
                "priority": 10,
                "description": "Assess backup availability and recovery options",
                "automated": False,
            }
        )

        return playbook

    def generate_report(self, context: IncidentContext, intel: RansomNoteIntel) -> str:
        """
        Generate comprehensive incident report using LLM.

        The report is structured for multiple audiences:
        - Executive Summary: For leadership
        - Technical Analysis: For IR team
        - Impact Assessment: For business units
        - Response Actions: For documentation
        - Recommendations: For future prevention

        Args:
            context: Incident context
            intel: Extracted threat intelligence

        Returns:
            Formatted incident report string
        """
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
            model="claude-sonnet-4-5",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text


# =============================================================================
# Main Detection Pipeline
# =============================================================================


class RansomwareDetectionPipeline:
    """
    End-to-end ransomware detection and response pipeline.

    This pipeline integrates all components:
    1. Behavior detection (pattern analysis)
    2. Ransom note analysis (IOC extraction)
    3. Incident response (automated playbooks)

    PIPELINE ARCHITECTURE
    =====================

    File Events → Behavior Detector → Detection Result
                                            ↓
                                    [If ransomware detected]
                                            ↓
                              Ransom Note Analyzer (if note found)
                                            ↓
                              Response Playbook Generation
                                            ↓
                                    Incident Report
    """

    def __init__(self):
        """Initialize pipeline components."""
        self.behavior_detector = RansomwareBehaviorDetector()
        self.note_analyzer = RansomNoteAnalyzer()
        self.responder = RansomwareResponder()

    def process_events(self, events: List[Dict]) -> Dict:
        """
        Process file system events through the detection pipeline.

        This is the main entry point for the pipeline. It:
        1. Converts raw event dicts to FileEvent objects
        2. Runs behavioral analysis
        3. If ransomware detected, generates response

        Args:
            events: List of raw event dictionaries

        Returns:
            Dictionary with detection results, intel, and response
        """
        # STEP 1: Convert raw dicts to typed FileEvent objects
        # Type safety helps catch errors early
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
                label=e.get("label", "unknown"),
            )
            for e in events
        ]

        # STEP 2: Run behavioral analysis
        detection_result = self.behavior_detector.analyze_events(file_events)

        result = {"detection": detection_result, "intel": None, "response": None}

        # STEP 3: If ransomware detected, generate response
        if detection_result["is_ransomware"]:
            # Build incident context
            context = IncidentContext(
                affected_hosts=["WORKSTATION-001"],  # In production, extract from events
                affected_files=detection_result["affected_files"],
                ransomware_family="unknown",  # Would be populated from note analysis
                encryption_progress=50.0,  # Would be calculated from file counts
                shadow_deletion_detected=detection_result["shadow_deletion"],
            )

            # Generate automated response playbook
            result["response"] = self.responder.generate_playbook(context)

        return result


# =============================================================================
# Demo / Main Entry Point
# =============================================================================


def main():
    """
    Demonstrate the ransomware detection pipeline.

    This demo:
    1. Loads sample file events (or uses inline examples)
    2. Runs the detection pipeline
    3. Displays detection results and response playbook
    4. Analyzes any ransom notes found
    """
    print("=" * 60)
    print("Lab 11: Ransomware Detection & Response")
    print("=" * 60)

    # Load sample events from data file
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "file_events.json")

    if os.path.exists(data_path):
        with open(data_path) as f:
            data = json.load(f)
            events = data["events"]
    else:
        # Fallback to inline example if data file not found
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
                "entropy": 7.98,  # High entropy = encrypted
                "size_bytes": 234567,
                "label": "ransomware_encryption",
            }
        ]

    # Run the detection pipeline
    pipeline = RansomwareDetectionPipeline()
    result = pipeline.process_events(events)

    # Display detection results
    print("\n[Detection Results]")
    print(f"  Ransomware Detected: {result['detection']['is_ransomware']}")
    print(f"  Confidence: {result['detection']['confidence']:.0%}")
    print(f"  Affected Files: {result['detection']['affected_files']}")

    if result["detection"]["indicators"]:
        print("\n[Indicators]")
        for indicator in result["detection"]["indicators"]:
            print(f"  - {indicator}")

    if result["detection"]["mitre_techniques"]:
        print("\n[MITRE ATT&CK Techniques]")
        for technique in result["detection"]["mitre_techniques"]:
            print(f"  - {technique}")

    if result["response"]:
        print("\n[Response Playbook]")
        for action in result["response"]:
            auto = "[AUTO]" if action.get("automated") else "[MANUAL]"
            print(f"  {action['priority']}. {auto} {action['action']}: " f"{action['description']}")

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

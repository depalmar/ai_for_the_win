#!/usr/bin/env python3
"""
Lab 11: Ransomware Behavior Detection
-------------------------------------
Detects ransomware-like file system behavior using ML and behavioral analysis.

This module implements behavioral detection for ransomware based on:
- File system operation patterns (rapid enumeration, mass writes)
- Entropy analysis (encrypted content detection)
- Extension change monitoring
- Known ransomware indicators

Author: AI Security Training Labs
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np


@dataclass
class FileEvent:
    """Represents a file system event."""

    timestamp: float
    process_name: str
    operation: str  # CREATE, WRITE, DELETE, RENAME
    file_path: str
    file_extension: str
    entropy: float  # 0-8 (8 = random/encrypted)
    size_bytes: int


class RansomwareBehaviorDetector:
    """
    Detects ransomware behavior from file system events.

    Behavioral Indicators:
    - High-volume file operations in short time windows
    - Entropy-based encryption detection (encrypted files have high entropy)
    - Suspicious extension patterns (.encrypted, .locked, etc.)
    - Shadow copy deletion attempts
    - Ransom note creation patterns
    """

    # Known ransomware extensions
    RANSOMWARE_EXTENSIONS = [
        ".encrypted",
        ".locked",
        ".crypted",
        ".enc",
        ".locky",
        ".cerber",
        ".zepto",
        ".odin",
        ".osiris",
        ".aesir",
        ".thor",
        ".zzzzz",
        ".micro",
        ".crypt",
        ".crinf",
        ".r5a",
        ".XRNT",
        ".XTBL",
        ".crypt1",
    ]

    # Suspicious processes often used by ransomware
    SUSPICIOUS_PROCESSES = [
        "vssadmin",
        "wmic",
        "bcdedit",
        "wbadmin",
        "cipher",
        "icacls",
        "takeown",
        "attrib",
    ]

    def __init__(self, threshold: float = 0.8):
        """
        Initialize the behavior detector.

        Args:
            threshold: Detection confidence threshold (0.0-1.0)
        """
        self.threshold = threshold
        self.baseline_stats: Dict = {}
        self.event_buffer: List[FileEvent] = []

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        High entropy (>7.0) typically indicates encrypted or compressed content.
        Random/encrypted data approaches 8.0 (maximum for byte data).

        Args:
            data: Raw bytes to analyze

        Returns:
            Shannon entropy value (0.0-8.0)

        # TODO: Ask your AI assistant:
        # "Write Python code to calculate Shannon entropy for a byte sequence.
        # Use numpy to count byte frequencies, compute probabilities,
        # and apply the entropy formula: -sum(p * log2(p)) for p > 0."
        #
        # Then review and test the generated code.
        """
        pass

    def analyze_events(self, events: List[FileEvent]) -> Dict:
        """
        Analyze file events for ransomware behavior.

        This is the main analysis function that combines multiple detection
        strategies to produce an overall risk assessment.

        Args:
            events: List of file system events to analyze

        Returns:
            Dict containing:
            - is_ransomware: bool
            - confidence: float (0.0-1.0)
            - indicators: List[str] (reasons for detection)
            - encryption_score: float
            - volume_score: float
            - extension_score: float

        # TODO: Ask your AI assistant:
        # "Write Python code to analyze file events for ransomware behavior.
        # Calculate scores for: (1) high-volume operations in time windows,
        # (2) high-entropy file writes, (3) suspicious extension changes,
        # (4) known ransomware process names. Combine into overall confidence."
        #
        # Then review and test the generated code.
        """
        pass

    def detect_encryption_pattern(self, events: List[FileEvent]) -> float:
        """
        Detect mass encryption patterns.

        Ransomware typically shows a pattern of:
        1. Reading a file (getting original content)
        2. Writing high-entropy data (encrypted content)
        3. Optionally renaming with new extension

        Args:
            events: List of file events to analyze

        Returns:
            Score (0.0-1.0) indicating likelihood of encryption activity

        # TODO: Ask your AI assistant:
        # "Write Python code to detect encryption patterns in file events.
        # Look for sequences where files are read then written with high
        # entropy (>7.0). Calculate the ratio of high-entropy writes to
        # total writes as a score."
        #
        # Then review and test the generated code.
        """
        pass

    def detect_shadow_deletion(self, events: List[FileEvent]) -> bool:
        """
        Detect VSS/shadow copy deletion attempts.

        Ransomware commonly deletes shadow copies to prevent recovery:
        - vssadmin delete shadows /all
        - wmic shadowcopy delete
        - bcdedit /set {default} recoveryenabled No

        Args:
            events: List of file events (check process names)

        Returns:
            True if shadow deletion behavior detected

        # TODO: Ask your AI assistant:
        # "Write Python code to detect shadow copy deletion attempts.
        # Check if any event's process_name matches vssadmin, wmic (with
        # shadowcopy context), bcdedit, or wbadmin. Return True if found."
        #
        # Then review and test the generated code.
        """
        pass

    def detect_extension_change(self, events: List[FileEvent]) -> float:
        """
        Detect mass file extension changes.

        Ransomware often renames files with new extensions like:
        - document.docx -> document.docx.encrypted
        - photo.jpg -> photo.jpg.locked

        Args:
            events: List of file events

        Returns:
            Score (0.0-1.0) based on suspicious extension changes

        # TODO: Ask your AI assistant:
        # "Write Python code to detect suspicious extension changes.
        # Count RENAME operations where the new extension matches known
        # ransomware extensions. Return ratio of suspicious renames to
        # total renames."
        #
        # Then review and test the generated code.
        """
        pass

    def build_baseline(self, normal_events: List[FileEvent]) -> None:
        """
        Build baseline statistics from normal activity.

        Use this to establish what "normal" looks like for the environment
        so we can detect deviations.

        Args:
            normal_events: File events from normal system activity

        # TODO: Ask your AI assistant:
        # "Write Python code to build baseline statistics from file events.
        # Calculate: average operations per minute, typical entropy distribution,
        # common file extensions, normal process names. Store in self.baseline_stats."
        #
        # Then review and test the generated code.
        """
        pass

    def detect_anomaly_from_baseline(self, events: List[FileEvent]) -> float:
        """
        Detect deviation from established baseline.

        Args:
            events: Current events to compare against baseline

        Returns:
            Anomaly score (0.0-1.0) indicating deviation from normal

        # TODO: Ask your AI assistant:
        # "Write Python code to detect anomalies from a baseline.
        # Compare current event statistics to self.baseline_stats.
        # Use z-score or percentage deviation to calculate anomaly score."
        #
        # Then review and test the generated code.
        """
        pass


def main():
    """Demo the behavior detector with sample events."""
    # Sample ransomware-like events
    ransomware_events = [
        FileEvent(
            timestamp=1000.0,
            process_name="malware.exe",
            operation="WRITE",
            file_path="/home/user/documents/report.docx.encrypted",
            file_extension=".encrypted",
            entropy=7.9,
            size_bytes=50000,
        ),
        FileEvent(
            timestamp=1000.1,
            process_name="malware.exe",
            operation="WRITE",
            file_path="/home/user/documents/photo.jpg.encrypted",
            file_extension=".encrypted",
            entropy=7.85,
            size_bytes=2000000,
        ),
        FileEvent(
            timestamp=1000.2,
            process_name="vssadmin",
            operation="CREATE",
            file_path="/tmp/cmd_output",
            file_extension=".tmp",
            entropy=2.0,
            size_bytes=100,
        ),
    ]

    detector = RansomwareBehaviorDetector(threshold=0.7)

    # Calculate entropy example
    sample_data = bytes([0x00] * 100)  # Low entropy (all zeros)
    print(f"Sample entropy (zeros): {detector.calculate_entropy(sample_data)}")

    random_data = bytes(np.random.randint(0, 256, 1000))  # High entropy
    print(f"Sample entropy (random): {detector.calculate_entropy(random_data)}")

    # Analyze events
    result = detector.analyze_events(ransomware_events)
    print(f"\nAnalysis result: {result}")


if __name__ == "__main__":
    main()

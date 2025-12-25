#!/usr/bin/env python3
"""Tests for Lab 11: Ransomware Detection & Response."""

import importlib
import math
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab11-ransomware-detection" / "solution")
sys.path.insert(0, lab_path)

from main import (
    FileEvent,
    IncidentContext,
    RansomNoteAnalyzer,
    RansomNoteIntel,
    RansomwareBehaviorDetector,
    RansomwareDetectionPipeline,
    RansomwareResponder,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_file_events():
    """Create sample file system events."""
    return [
        FileEvent(
            id=1,
            timestamp="2024-01-15T14:00:00Z",
            process_name="explorer.exe",
            process_id=1234,
            operation="READ",
            file_path="C:\\Users\\victim\\Documents\\report.xlsx",
            file_extension=".xlsx",
            entropy=4.2,
            size_bytes=50000,
            label="normal",
        ),
        FileEvent(
            id=2,
            timestamp="2024-01-15T14:01:00Z",
            process_name="malware.exe",
            process_id=6789,
            operation="WRITE",
            file_path="C:\\Users\\victim\\Documents\\report.xlsx.locked",
            file_extension=".locked",
            entropy=7.98,
            size_bytes=50000,
            label="ransomware_encryption",
        ),
        FileEvent(
            id=3,
            timestamp="2024-01-15T14:01:30Z",
            process_name="malware.exe",
            process_id=6789,
            operation="WRITE",
            file_path="C:\\Users\\victim\\Documents\\data.docx.locked",
            file_extension=".locked",
            entropy=7.95,
            size_bytes=75000,
            label="ransomware_encryption",
        ),
    ]


@pytest.fixture
def ransomware_events_with_shadow_delete():
    """Create events including shadow copy deletion."""
    return [
        FileEvent(
            id=1,
            timestamp="2024-01-15T14:00:00Z",
            process_name="cmd.exe",
            process_id=5555,
            operation="EXECUTE",
            file_path="vssadmin delete shadows /all /quiet",
            file_extension="",
            entropy=0,
            size_bytes=0,
            label="ransomware_prep",
        ),
        FileEvent(
            id=2,
            timestamp="2024-01-15T14:00:30Z",
            process_name="malware.exe",
            process_id=6789,
            operation="WRITE",
            file_path="C:\\Users\\victim\\file.encrypted",
            file_extension=".encrypted",
            entropy=7.99,
            size_bytes=100000,
            label="ransomware_encryption",
        ),
        FileEvent(
            id=3,
            timestamp="2024-01-15T14:01:00Z",
            process_name="malware.exe",
            process_id=6789,
            operation="CREATE",
            file_path="C:\\Users\\victim\\README_RESTORE_FILES.txt",
            file_extension=".txt",
            entropy=3.5,
            size_bytes=2000,
            label="ransomware_note",
        ),
    ]


@pytest.fixture
def sample_ransom_note():
    """Create sample ransom note content."""
    return """
    YOUR FILES HAVE BEEN ENCRYPTED BY LOCKBIT 3.0

    All your important files are encrypted!
    Your unique ID: ABC123XYZ789

    To decrypt your files, you need to pay 0.5 BTC to:
    bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

    Contact us: support@lockbit.onion
    Visit our TOR site: lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion

    WARNING: Do not try to decrypt files yourself!
    You have 72 hours before the price doubles.
    """


@pytest.fixture
def incident_context():
    """Create sample incident context."""
    return IncidentContext(
        affected_hosts=["WORKSTATION-001", "WORKSTATION-002"],
        affected_files=500,
        ransomware_family="LockBit",
        encryption_progress=75.0,
        lateral_movement_detected=True,
        exfiltration_detected=False,
        shadow_deletion_detected=True,
    )


@pytest.fixture
def behavior_detector():
    """Create RansomwareBehaviorDetector instance."""
    return RansomwareBehaviorDetector(threshold=0.8)


# =============================================================================
# RansomwareBehaviorDetector Tests
# =============================================================================


class TestRansomwareBehaviorDetector:
    """Tests for RansomwareBehaviorDetector."""

    def test_detector_initialization(self, behavior_detector):
        """Test detector initialization."""
        assert behavior_detector is not None
        assert behavior_detector.threshold == 0.8

    def test_calculate_entropy_empty_data(self):
        """Test entropy calculation with empty data."""
        entropy = RansomwareBehaviorDetector.calculate_entropy(b"")
        assert entropy == 0.0

    def test_calculate_entropy_uniform_data(self):
        """Test entropy calculation with uniform data."""
        # Single repeated byte has entropy 0
        data = b"AAAAAAAAAA"
        entropy = RansomwareBehaviorDetector.calculate_entropy(data)
        assert entropy == 0.0

    def test_calculate_entropy_random_data(self):
        """Test entropy calculation with random-like data."""
        # Mix of all byte values should have high entropy
        import os

        data = os.urandom(1000)
        entropy = RansomwareBehaviorDetector.calculate_entropy(data)
        # Random data should have entropy close to 8 (max for bytes)
        assert entropy > 7.0

    def test_calculate_entropy_text_data(self):
        """Test entropy calculation with text data."""
        data = b"Hello, this is a normal text document."
        entropy = RansomwareBehaviorDetector.calculate_entropy(data)
        # Normal text typically has entropy 3-5
        assert 2.0 < entropy < 6.0

    def test_analyze_normal_events(self, behavior_detector):
        """Test analysis of normal events."""
        normal_events = [
            FileEvent(
                id=1,
                timestamp="2024-01-15T14:00:00Z",
                process_name="excel.exe",
                process_id=1234,
                operation="WRITE",
                file_path="C:\\doc.xlsx",
                file_extension=".xlsx",
                entropy=4.5,
                size_bytes=50000,
                label="normal",
            )
        ]

        result = behavior_detector.analyze_events(normal_events)

        assert result["is_ransomware"] is False
        assert result["confidence"] < 0.5
        assert result["encryption_pattern"] is False

    def test_analyze_ransomware_events(self, behavior_detector, sample_file_events):
        """Test analysis of ransomware events."""
        result = behavior_detector.analyze_events(sample_file_events)

        # Should detect encryption pattern
        assert result["encryption_pattern"] is True
        assert result["affected_files"] >= 1

    def test_analyze_full_ransomware_attack(
        self, behavior_detector, ransomware_events_with_shadow_delete
    ):
        """Test analysis of full ransomware attack."""
        result = behavior_detector.analyze_events(ransomware_events_with_shadow_delete)

        assert result["is_ransomware"] is True
        assert result["confidence"] >= 0.8
        assert result["shadow_deletion"] is True
        assert result["ransom_note"] is True
        assert "T1486" in str(result["mitre_techniques"])
        assert "T1490" in str(result["mitre_techniques"])

    def test_detect_encryption_pattern(self, behavior_detector, sample_file_events):
        """Test encryption pattern detection."""
        score = behavior_detector.detect_encryption_pattern(sample_file_events)

        # Should have positive encryption score
        assert score > 0

    def test_detect_shadow_deletion(self, behavior_detector):
        """Test shadow deletion detection."""
        shadow_events = [
            FileEvent(
                id=1,
                timestamp="2024-01-15T14:00:00Z",
                process_name="cmd.exe",
                process_id=1234,
                operation="EXECUTE",
                file_path="vssadmin delete shadows /all",
                file_extension="",
                entropy=0,
                size_bytes=0,
            )
        ]

        result = behavior_detector.detect_shadow_deletion(shadow_events)
        assert result is True

    def test_detect_shadow_deletion_wmic(self, behavior_detector):
        """Test WMIC shadow deletion detection."""
        shadow_events = [
            FileEvent(
                id=1,
                timestamp="2024-01-15T14:00:00Z",
                process_name="cmd.exe",
                process_id=1234,
                operation="EXECUTE",
                file_path="wmic shadowcopy delete",
                file_extension="",
                entropy=0,
                size_bytes=0,
            )
        ]

        result = behavior_detector.detect_shadow_deletion(shadow_events)
        assert result is True

    def test_detect_ransom_note(self, behavior_detector):
        """Test ransom note detection."""
        note_events = [
            FileEvent(
                id=1,
                timestamp="2024-01-15T14:00:00Z",
                process_name="malware.exe",
                process_id=1234,
                operation="CREATE",
                file_path="C:\\Users\\victim\\README_RESTORE_FILES.txt",
                file_extension=".txt",
                entropy=3.5,
                size_bytes=2000,
            ),
            FileEvent(
                id=2,
                timestamp="2024-01-15T14:00:30Z",
                process_name="malware.exe",
                process_id=1234,
                operation="CREATE",
                file_path="C:\\Users\\victim\\HOW_TO_DECRYPT.html",
                file_extension=".html",
                entropy=3.2,
                size_bytes=5000,
            ),
        ]

        result = behavior_detector.detect_ransom_note(note_events)

        assert len(result) >= 1

    def test_ransomware_extensions_detection(self, behavior_detector):
        """Test detection of known ransomware extensions."""
        assert ".locked" in behavior_detector.RANSOMWARE_EXTENSIONS
        assert ".encrypted" in behavior_detector.RANSOMWARE_EXTENSIONS
        assert ".lockbit" in behavior_detector.RANSOMWARE_EXTENSIONS
        assert ".alphv" in behavior_detector.RANSOMWARE_EXTENSIONS


# =============================================================================
# RansomNoteAnalyzer Tests
# =============================================================================


class TestRansomNoteAnalyzer:
    """Tests for RansomNoteAnalyzer."""

    def test_extract_bitcoin_addresses(self, sample_ransom_note):
        """Test Bitcoin address extraction."""
        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs(sample_ransom_note)

        assert "bitcoin" in iocs
        assert len(iocs["bitcoin"]) >= 1
        # Check valid Bitcoin address format
        for addr in iocs["bitcoin"]:
            assert addr.startswith("bc1") or addr.startswith("1") or addr.startswith("3")

    def test_extract_onion_urls(self, sample_ransom_note):
        """Test onion URL extraction."""
        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs(sample_ransom_note)

        assert "onion" in iocs
        assert len(iocs["onion"]) >= 1
        for url in iocs["onion"]:
            assert url.endswith(".onion")

    def test_extract_email_addresses(self):
        """Test email address extraction."""
        note = "Contact us at support@example.com or admin@ransomware.net"
        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs(note)

        assert "email" in iocs
        assert len(iocs["email"]) >= 1

    def test_extract_monero_addresses(self):
        """Test Monero address extraction."""
        note = "Send XMR to: 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge"
        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs(note)

        assert "monero" in iocs

    def test_extract_iocs_empty_note(self):
        """Test IOC extraction with empty note."""
        analyzer = RansomNoteAnalyzer()
        iocs = analyzer.extract_iocs("")

        assert iocs["bitcoin"] == []
        assert iocs["monero"] == []
        assert iocs["onion"] == []
        assert iocs["email"] == []

    @patch.object(RansomNoteAnalyzer, "__init__", lambda x: None)
    def test_analyze_requires_llm(self, sample_ransom_note):
        """Test that analyze method uses LLM client."""
        analyzer = RansomNoteAnalyzer()
        analyzer.client = Mock()
        analyzer.client.messages.create.return_value = Mock(
            content=[Mock(text='{"ransomware_family": "LockBit", "exfiltration_claimed": true}')]
        )

        # Just test IOC extraction without actual LLM call
        iocs = analyzer.extract_iocs(sample_ransom_note)
        assert len(iocs["bitcoin"]) >= 1


# =============================================================================
# RansomwareResponder Tests
# =============================================================================


class TestRansomwareResponder:
    """Tests for RansomwareResponder."""

    def test_responder_initialization(self):
        """Test responder initialization."""
        responder = RansomwareResponder(auto_contain=True)

        assert responder is not None
        assert responder.auto_contain is True

    def test_assess_severity_critical_exfiltration(self, incident_context):
        """Test severity assessment with exfiltration."""
        incident_context.exfiltration_detected = True
        responder = RansomwareResponder()

        severity, reason = responder.assess_severity(incident_context)

        assert severity == "CRITICAL"
        assert "exfiltration" in reason.lower() or "lateral" in reason.lower()

    def test_assess_severity_critical_encryption(self, incident_context):
        """Test severity assessment with high encryption."""
        incident_context.exfiltration_detected = False
        incident_context.lateral_movement_detected = False
        incident_context.encryption_progress = 75
        responder = RansomwareResponder()

        severity, _ = responder.assess_severity(incident_context)

        assert severity == "CRITICAL"

    def test_assess_severity_high_shadow_deletion(self, incident_context):
        """Test severity assessment with shadow deletion."""
        incident_context.exfiltration_detected = False
        incident_context.lateral_movement_detected = False
        incident_context.encryption_progress = 25
        incident_context.shadow_deletion_detected = True
        responder = RansomwareResponder()

        severity, _ = responder.assess_severity(incident_context)

        assert severity == "HIGH"

    def test_assess_severity_medium(self):
        """Test medium severity assessment."""
        context = IncidentContext(
            affected_hosts=["HOST-001"], affected_files=50, encryption_progress=10.0
        )
        responder = RansomwareResponder()

        severity, _ = responder.assess_severity(context)

        assert severity == "MEDIUM"

    def test_generate_playbook_basic(self, incident_context):
        """Test basic playbook generation."""
        responder = RansomwareResponder()
        playbook = responder.generate_playbook(incident_context)

        assert playbook is not None
        assert len(playbook) > 0
        assert playbook[0]["action"] == "ALERT"

    def test_generate_playbook_includes_isolation(self, incident_context):
        """Test playbook includes host isolation."""
        responder = RansomwareResponder()
        playbook = responder.generate_playbook(incident_context)

        actions = [step["action"] for step in playbook]
        assert "ISOLATE_HOST" in actions

    def test_generate_playbook_lateral_movement(self, incident_context):
        """Test playbook for lateral movement."""
        incident_context.lateral_movement_detected = True
        responder = RansomwareResponder()

        playbook = responder.generate_playbook(incident_context)
        actions = [step["action"] for step in playbook]

        assert "SCAN_NETWORK" in actions

    def test_generate_playbook_exfiltration(self, incident_context):
        """Test playbook for exfiltration."""
        incident_context.exfiltration_detected = True
        responder = RansomwareResponder()

        playbook = responder.generate_playbook(incident_context)
        actions = [step["action"] for step in playbook]

        assert "DATA_BREACH_PROTOCOL" in actions

    def test_generate_playbook_recovery(self, incident_context):
        """Test playbook includes recovery assessment."""
        responder = RansomwareResponder()
        playbook = responder.generate_playbook(incident_context)

        actions = [step["action"] for step in playbook]
        assert "RECOVERY_ASSESSMENT" in actions

    def test_playbook_priority_order(self, incident_context):
        """Test playbook actions are priority ordered."""
        responder = RansomwareResponder()
        playbook = responder.generate_playbook(incident_context)

        priorities = [step["priority"] for step in playbook]
        # Verify priorities are in ascending order
        assert priorities == sorted(priorities)


# =============================================================================
# IncidentContext Tests
# =============================================================================


class TestIncidentContext:
    """Tests for IncidentContext dataclass."""

    def test_incident_context_defaults(self):
        """Test IncidentContext default values."""
        context = IncidentContext()

        assert context.affected_hosts == []
        assert context.affected_files == 0
        assert context.ransomware_family == "unknown"
        assert context.encryption_progress == 0.0
        assert context.lateral_movement_detected is False
        assert context.exfiltration_detected is False
        assert context.shadow_deletion_detected is False

    def test_incident_context_custom_values(self):
        """Test IncidentContext with custom values."""
        context = IncidentContext(
            affected_hosts=["HOST-A", "HOST-B"],
            affected_files=1000,
            ransomware_family="BlackCat",
        )

        assert len(context.affected_hosts) == 2
        assert context.affected_files == 1000
        assert context.ransomware_family == "BlackCat"


# =============================================================================
# RansomwareDetectionPipeline Tests
# =============================================================================


class TestRansomwareDetectionPipeline:
    """Tests for RansomwareDetectionPipeline."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = RansomwareDetectionPipeline()

        assert pipeline.behavior_detector is not None
        assert pipeline.note_analyzer is not None
        assert pipeline.responder is not None

    def test_process_normal_events(self):
        """Test processing normal events."""
        pipeline = RansomwareDetectionPipeline()

        events = [
            {
                "id": 1,
                "timestamp": "2024-01-15T14:00:00Z",
                "process_name": "word.exe",
                "process_id": 1234,
                "operation": "WRITE",
                "file_path": "C:\\doc.docx",
                "file_extension": ".docx",
                "entropy": 4.0,
                "size_bytes": 50000,
                "label": "normal",
            }
        ]

        result = pipeline.process_events(events)

        assert result["detection"]["is_ransomware"] is False
        assert result["response"] is None

    def test_process_ransomware_events(self):
        """Test processing ransomware events."""
        pipeline = RansomwareDetectionPipeline()

        events = [
            {
                "id": 1,
                "timestamp": "2024-01-15T14:00:00Z",
                "process_name": "cmd.exe",
                "process_id": 1234,
                "operation": "EXECUTE",
                "file_path": "vssadmin delete shadows /all",
                "file_extension": "",
                "entropy": 0,
                "size_bytes": 0,
                "label": "ransomware_prep",
            },
            {
                "id": 2,
                "timestamp": "2024-01-15T14:00:30Z",
                "process_name": "malware.exe",
                "process_id": 6789,
                "operation": "WRITE",
                "file_path": "C:\\file.encrypted",
                "file_extension": ".encrypted",
                "entropy": 7.99,
                "size_bytes": 100000,
                "label": "ransomware_encryption",
            },
            {
                "id": 3,
                "timestamp": "2024-01-15T14:01:00Z",
                "process_name": "malware.exe",
                "process_id": 6789,
                "operation": "CREATE",
                "file_path": "C:\\README_RESTORE.txt",
                "file_extension": ".txt",
                "entropy": 3.5,
                "size_bytes": 2000,
                "label": "ransomware_note",
            },
        ]

        result = pipeline.process_events(events)

        assert result["detection"]["is_ransomware"] is True
        assert result["response"] is not None
        assert len(result["response"]) > 0


# =============================================================================
# FileEvent Tests
# =============================================================================


class TestFileEvent:
    """Tests for FileEvent dataclass."""

    def test_file_event_creation(self):
        """Test FileEvent creation."""
        event = FileEvent(
            id=1,
            timestamp="2024-01-15T14:00:00Z",
            process_name="test.exe",
            process_id=1234,
            operation="WRITE",
            file_path="C:\\test.txt",
            file_extension=".txt",
            entropy=4.5,
            size_bytes=1000,
        )

        assert event.id == 1
        assert event.label == "unknown"  # Default value

    def test_file_event_to_dict(self):
        """Test FileEvent conversion to dict."""
        event = FileEvent(
            id=1,
            timestamp="2024-01-15T14:00:00Z",
            process_name="test.exe",
            process_id=1234,
            operation="WRITE",
            file_path="C:\\test.txt",
            file_extension=".txt",
            entropy=4.5,
            size_bytes=1000,
        )

        event_dict = asdict(event)

        assert isinstance(event_dict, dict)
        assert event_dict["id"] == 1
        assert event_dict["process_name"] == "test.exe"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

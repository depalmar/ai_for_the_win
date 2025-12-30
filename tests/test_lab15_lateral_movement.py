#!/usr/bin/env python3
"""Tests for Lab 15: AI-Powered Lateral Movement Detection."""

import json
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(
    Path(__file__).parent.parent / "labs" / "lab15-lateral-movement-detection" / "solution"
)
sys.path.insert(0, lab_path)

from main import (
    AttackPath,
    AttackPathAnalyzer,
    AuthAnomalyDetector,
    AuthEvent,
    LateralMovementAlert,
    LateralMovementPipeline,
    RemoteExecEvent,
    RemoteExecutionDetector,
    setup_llm,
)

# =============================================================================
# Fixtures - Sample Data
# =============================================================================


@pytest.fixture
def sample_auth_events():
    """Create sample authentication events for baseline building."""
    base_time = datetime(2024, 1, 15, 9, 0, 0)
    events = []

    # Normal baseline events - user jsmith on workstation01
    for i in range(10):
        events.append(
            AuthEvent(
                timestamp=(base_time + timedelta(hours=i)).isoformat() + "Z",
                event_id=4624,
                source_ip="192.168.1.10",
                target_host="workstation01",
                username="jsmith",
                domain="CORP",
                logon_type=2,
                status="success",
                workstation_name="WORKSTATION01",
            )
        )

    # Normal baseline - user mjohnson on workstation02
    for i in range(5):
        events.append(
            AuthEvent(
                timestamp=(base_time + timedelta(hours=i, minutes=30)).isoformat() + "Z",
                event_id=4624,
                source_ip="192.168.1.11",
                target_host="workstation02",
                username="mjohnson",
                domain="CORP",
                logon_type=2,
                status="success",
                workstation_name="WORKSTATION02",
            )
        )

    return events


@pytest.fixture
def suspicious_auth_events():
    """Create suspicious authentication events for anomaly detection."""
    base_time = datetime(2024, 1, 15, 22, 0, 0)  # Late night
    return [
        # User accessing new host from new IP at unusual time
        AuthEvent(
            timestamp=(base_time).isoformat() + "Z",
            event_id=4624,
            source_ip="192.168.1.50",
            target_host="dc01",
            username="jsmith",
            domain="CORP",
            logon_type=3,  # Network logon - suspicious
            status="success",
            workstation_name="UNKNOWN",
        ),
        # Administrator RDP access
        AuthEvent(
            timestamp=(base_time + timedelta(minutes=5)).isoformat() + "Z",
            event_id=4624,
            source_ip="192.168.1.50",
            target_host="dc01",
            username="administrator",
            domain="CORP",
            logon_type=10,  # RemoteInteractive - RDP
            status="success",
            workstation_name="UNKNOWN",
        ),
    ]


@pytest.fixture
def password_spraying_events():
    """Create events simulating password spraying attack."""
    base_time = datetime(2024, 1, 15, 22, 10, 0)
    events = []

    # Many failed attempts from single IP to multiple users
    usernames = [
        "admin",
        "administrator",
        "svc_backup",
        "svc_sql",
        "jsmith",
        "mjohnson",
        "bwilliams",
        "asmith",
        "dgarcia",
        "helpdesk",
    ]

    for i, username in enumerate(usernames):
        events.append(
            AuthEvent(
                timestamp=(base_time + timedelta(seconds=i * 5)).isoformat() + "Z",
                event_id=4625,  # Failed logon
                source_ip="192.168.1.99",
                target_host="dc01",
                username=username,
                domain="CORP",
                logon_type=3,
                status="failure",
                workstation_name="UNKNOWN",
            )
        )

    return events


@pytest.fixture
def credential_stuffing_events():
    """Create events simulating credential stuffing attack (rapid attempts)."""
    base_time = datetime(2024, 1, 15, 22, 0, 0)
    events = []

    # Many rapid attempts from single IP (more than 1 per 2 seconds)
    for i in range(20):
        events.append(
            AuthEvent(
                timestamp=(base_time + timedelta(seconds=i)).isoformat() + "Z",
                event_id=4624,
                source_ip="192.168.1.88",
                target_host="server01",
                username="testuser",
                domain="CORP",
                logon_type=3,
                status="success",
                workstation_name="UNKNOWN",
            )
        )

    return events


@pytest.fixture
def sample_system_events():
    """Create sample system events for remote execution detection."""
    base_time = datetime(2024, 1, 15, 22, 1, 30)
    return [
        # PsExec service creation
        {
            "timestamp": base_time.isoformat() + "Z",
            "event_id": 7045,
            "service_name": "PSEXESVC",
            "source_host": "workstation01",
            "target_host": "server01",
            "computer_name": "server01",
            "username": "jsmith",
            "service_file_name": "%SystemRoot%\\PSEXESVC.exe",
        },
        # SMB admin share access
        {
            "timestamp": (base_time + timedelta(minutes=1)).isoformat() + "Z",
            "event_id": 5140,
            "share_name": "ADMIN$",
            "source_ip": "192.168.1.50",
            "target_host": "server02",
            "computer_name": "server02",
            "username": "jsmith",
        },
        # WMI execution
        {
            "timestamp": (base_time + timedelta(minutes=2)).isoformat() + "Z",
            "event_id": 5857,
            "operation": "Win32_Process::Create",
            "source_host": "server01",
            "target_host": "dc01",
            "computer_name": "dc01",
            "username": "jsmith",
            "commandline": "cmd.exe /c net user",
        },
        # Process from WMI provider
        {
            "timestamp": (base_time + timedelta(minutes=3)).isoformat() + "Z",
            "event_id": 4688,
            "parent_process_name": "wmiprvse.exe",
            "source_host": "unknown",
            "target_host": "exchange",
            "computer_name": "exchange",
            "username": "administrator",
            "commandline": "powershell.exe -enc base64string",
        },
    ]


@pytest.fixture
def winrm_events():
    """Create WinRM/PowerShell remoting events."""
    base_time = datetime(2024, 1, 15, 22, 5, 0)
    return [
        # PowerShell remoting
        {
            "timestamp": base_time.isoformat() + "Z",
            "event_id": 4103,
            "script_block": "Invoke-Command -ComputerName server01 -ScriptBlock {whoami}",
            "source_host": "workstation01",
            "target_host": "server01",
            "computer_name": "server01",
            "username": "jsmith",
        },
        # WinRM connection
        {
            "timestamp": (base_time + timedelta(minutes=1)).isoformat() + "Z",
            "event_id": 91,
            "source_ip": "192.168.1.10",
            "target_host": "server02",
            "computer_name": "server02",
            "username": "admin",
        },
    ]


@pytest.fixture
def remote_exec_events():
    """Create RemoteExecEvent objects for attack path analysis."""
    base_time = datetime(2024, 1, 15, 22, 0, 0)
    return [
        RemoteExecEvent(
            timestamp=(base_time).isoformat() + "Z",
            source_host="workstation01",
            target_host="server01",
            exec_type="psexec",
            username="jsmith",
            command="cmd.exe",
            success=True,
        ),
        RemoteExecEvent(
            timestamp=(base_time + timedelta(minutes=5)).isoformat() + "Z",
            source_host="server01",
            target_host="dc01",
            exec_type="wmi",
            username="jsmith",
            command="net user",
            success=True,
        ),
        RemoteExecEvent(
            timestamp=(base_time + timedelta(minutes=10)).isoformat() + "Z",
            source_host="dc01",
            target_host="fileserver",
            exec_type="psexec",
            username="administrator",
            command="dir",
            success=True,
        ),
        RemoteExecEvent(
            timestamp=(base_time + timedelta(minutes=15)).isoformat() + "Z",
            source_host="dc01",
            target_host="sql01",
            exec_type="wmi",
            username="administrator",
            command="query",
            success=True,
        ),
    ]


@pytest.fixture
def sample_attack_path():
    """Create a sample AttackPath for testing."""
    return AttackPath(
        path=["workstation01", "server01", "dc01", "fileserver"],
        start_time="2024-01-15T22:00:00Z",
        end_time="2024-01-15T22:30:00Z",
        techniques=["psexec", "wmi"],
        confidence=0.85,
        risk_score=0.75,
    )


@pytest.fixture
def auth_detector():
    """Create AuthAnomalyDetector instance."""
    return AuthAnomalyDetector(baseline_hours=24)


@pytest.fixture
def exec_detector():
    """Create RemoteExecutionDetector instance."""
    return RemoteExecutionDetector()


@pytest.fixture
def path_analyzer():
    """Create AttackPathAnalyzer instance."""
    return AttackPathAnalyzer()


# =============================================================================
# AuthEvent Dataclass Tests
# =============================================================================


class TestAuthEvent:
    """Tests for AuthEvent dataclass."""

    def test_auth_event_creation(self):
        """Test AuthEvent creation with all fields."""
        event = AuthEvent(
            timestamp="2024-01-15T09:00:00Z",
            event_id=4624,
            source_ip="192.168.1.10",
            target_host="workstation01",
            username="jsmith",
            domain="CORP",
            logon_type=2,
            status="success",
            workstation_name="WS01",
            process_name="explorer.exe",
        )

        assert event.timestamp == "2024-01-15T09:00:00Z"
        assert event.event_id == 4624
        assert event.source_ip == "192.168.1.10"
        assert event.target_host == "workstation01"
        assert event.username == "jsmith"
        assert event.domain == "CORP"
        assert event.logon_type == 2
        assert event.status == "success"
        assert event.workstation_name == "WS01"
        assert event.process_name == "explorer.exe"

    def test_auth_event_defaults(self):
        """Test AuthEvent default values."""
        event = AuthEvent(
            timestamp="2024-01-15T09:00:00Z",
            event_id=4624,
            source_ip="192.168.1.10",
            target_host="workstation01",
            username="jsmith",
            domain="CORP",
            logon_type=2,
            status="success",
        )

        assert event.workstation_name == ""
        assert event.process_name == ""


# =============================================================================
# RemoteExecEvent Dataclass Tests
# =============================================================================


class TestRemoteExecEvent:
    """Tests for RemoteExecEvent dataclass."""

    def test_remote_exec_event_creation(self):
        """Test RemoteExecEvent creation."""
        event = RemoteExecEvent(
            timestamp="2024-01-15T22:00:00Z",
            source_host="workstation01",
            target_host="server01",
            exec_type="psexec",
            username="admin",
            command="cmd.exe /c whoami",
            success=True,
        )

        assert event.timestamp == "2024-01-15T22:00:00Z"
        assert event.source_host == "workstation01"
        assert event.target_host == "server01"
        assert event.exec_type == "psexec"
        assert event.username == "admin"
        assert event.command == "cmd.exe /c whoami"
        assert event.success is True

    def test_remote_exec_event_defaults(self):
        """Test RemoteExecEvent default values."""
        event = RemoteExecEvent(
            timestamp="2024-01-15T22:00:00Z",
            source_host="ws01",
            target_host="srv01",
            exec_type="wmi",
            username="user1",
        )

        assert event.command == ""
        assert event.success is True


# =============================================================================
# AttackPath Dataclass Tests
# =============================================================================


class TestAttackPath:
    """Tests for AttackPath dataclass."""

    def test_attack_path_creation(self, sample_attack_path):
        """Test AttackPath creation."""
        assert sample_attack_path.path == ["workstation01", "server01", "dc01", "fileserver"]
        assert sample_attack_path.start_time == "2024-01-15T22:00:00Z"
        assert sample_attack_path.end_time == "2024-01-15T22:30:00Z"
        assert "psexec" in sample_attack_path.techniques
        assert "wmi" in sample_attack_path.techniques
        assert sample_attack_path.confidence == 0.85
        assert sample_attack_path.risk_score == 0.75

    def test_attack_path_defaults(self):
        """Test AttackPath default values."""
        path = AttackPath(
            path=["host1", "host2"],
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T10:30:00Z",
        )

        assert path.techniques == []
        assert path.confidence == 0.0
        assert path.risk_score == 0.0


# =============================================================================
# LateralMovementAlert Dataclass Tests
# =============================================================================


class TestLateralMovementAlert:
    """Tests for LateralMovementAlert dataclass."""

    def test_alert_creation(self):
        """Test LateralMovementAlert creation."""
        alert = LateralMovementAlert(
            timestamp="2024-01-15T22:00:00Z",
            alert_type="attack_path",
            source_host="workstation01",
            target_host="dc01",
            username="jsmith",
            indicators=["Path: ws01 -> srv01 -> dc01"],
            severity="critical",
            mitre_techniques=["T1021", "T1570"],
        )

        assert alert.timestamp == "2024-01-15T22:00:00Z"
        assert alert.alert_type == "attack_path"
        assert alert.source_host == "workstation01"
        assert alert.target_host == "dc01"
        assert alert.username == "jsmith"
        assert len(alert.indicators) == 1
        assert alert.severity == "critical"
        assert "T1021" in alert.mitre_techniques


# =============================================================================
# AuthAnomalyDetector Tests
# =============================================================================


class TestAuthAnomalyDetector:
    """Tests for AuthAnomalyDetector."""

    def test_detector_initialization(self, auth_detector):
        """Test detector initialization."""
        assert auth_detector is not None
        assert auth_detector.baseline_hours == 24
        assert auth_detector.baseline_built is False
        assert len(auth_detector.user_patterns) == 0

    def test_detector_logon_types(self, auth_detector):
        """Test logon type mappings are correct."""
        assert auth_detector.LOGON_TYPES[2] == "Interactive"
        assert auth_detector.LOGON_TYPES[3] == "Network"
        assert auth_detector.LOGON_TYPES[10] == "RemoteInteractive"
        assert 3 in auth_detector.SUSPICIOUS_LOGON_TYPES
        assert 10 in auth_detector.SUSPICIOUS_LOGON_TYPES

    def test_build_baseline(self, auth_detector, sample_auth_events):
        """Test baseline building."""
        auth_detector.build_baseline(sample_auth_events)

        assert auth_detector.baseline_built is True
        assert len(auth_detector.user_patterns) > 0

        # Check jsmith pattern
        jsmith_key = "corp\\jsmith"
        assert jsmith_key in auth_detector.user_patterns
        assert "workstation01" in auth_detector.user_patterns[jsmith_key]["hosts"]
        assert "192.168.1.10" in auth_detector.user_patterns[jsmith_key]["source_ips"]
        assert 2 in auth_detector.user_patterns[jsmith_key]["logon_types"]

    def test_build_baseline_only_successful_logons(self, auth_detector):
        """Test that baseline only includes successful logons (4624)."""
        events = [
            AuthEvent(
                timestamp="2024-01-15T09:00:00Z",
                event_id=4625,  # Failed logon
                source_ip="192.168.1.10",
                target_host="workstation01",
                username="jsmith",
                domain="CORP",
                logon_type=2,
                status="failure",
            ),
            AuthEvent(
                timestamp="2024-01-15T09:05:00Z",
                event_id=4624,  # Successful logon
                source_ip="192.168.1.10",
                target_host="workstation01",
                username="mjohnson",
                domain="CORP",
                logon_type=2,
                status="success",
            ),
        ]

        auth_detector.build_baseline(events)

        # Only mjohnson should be in baseline
        assert "corp\\mjohnson" in auth_detector.user_patterns
        assert "corp\\jsmith" not in auth_detector.user_patterns

    def test_detect_anomalies_new_user(self, auth_detector, sample_auth_events):
        """Test detection of new user anomaly."""
        auth_detector.build_baseline(sample_auth_events)

        new_user_event = AuthEvent(
            timestamp="2024-01-15T22:00:00Z",
            event_id=4624,
            source_ip="192.168.1.100",
            target_host="server01",
            username="new_attacker",
            domain="CORP",
            logon_type=3,
            status="success",
        )

        anomalies = auth_detector.detect_anomalies(new_user_event)

        assert len(anomalies) >= 1
        assert any(a["type"] == "new_user" for a in anomalies)

    def test_detect_anomalies_new_host(self, auth_detector, sample_auth_events):
        """Test detection of new host access anomaly."""
        auth_detector.build_baseline(sample_auth_events)

        # jsmith accessing a new host
        new_host_event = AuthEvent(
            timestamp="2024-01-15T22:00:00Z",
            event_id=4624,
            source_ip="192.168.1.10",
            target_host="dc01",  # New host for jsmith
            username="jsmith",
            domain="CORP",
            logon_type=3,
            status="success",
        )

        anomalies = auth_detector.detect_anomalies(new_host_event)

        assert any(a["type"] == "new_host" for a in anomalies)

    def test_detect_anomalies_new_source_ip(self, auth_detector, sample_auth_events):
        """Test detection of new source IP anomaly."""
        auth_detector.build_baseline(sample_auth_events)

        # jsmith from a new IP
        new_ip_event = AuthEvent(
            timestamp="2024-01-15T12:00:00Z",
            event_id=4624,
            source_ip="192.168.1.99",  # New IP for jsmith
            target_host="workstation01",
            username="jsmith",
            domain="CORP",
            logon_type=2,
            status="success",
        )

        anomalies = auth_detector.detect_anomalies(new_ip_event)

        assert any(a["type"] == "new_source_ip" for a in anomalies)

    def test_detect_anomalies_suspicious_logon_type(self, auth_detector, sample_auth_events):
        """Test detection of suspicious logon type."""
        auth_detector.build_baseline(sample_auth_events)

        # Network logon is suspicious
        network_logon_event = AuthEvent(
            timestamp="2024-01-15T12:00:00Z",
            event_id=4624,
            source_ip="192.168.1.10",
            target_host="workstation01",
            username="jsmith",
            domain="CORP",
            logon_type=3,  # Network logon
            status="success",
        )

        anomalies = auth_detector.detect_anomalies(network_logon_event)

        assert any(a["type"] == "suspicious_logon_type" for a in anomalies)

    def test_detect_anomalies_failed_logon(self, auth_detector, sample_auth_events):
        """Test detection of failed logon."""
        auth_detector.build_baseline(sample_auth_events)

        failed_event = AuthEvent(
            timestamp="2024-01-15T12:00:00Z",
            event_id=4625,  # Failed logon
            source_ip="192.168.1.10",
            target_host="workstation01",
            username="jsmith",
            domain="CORP",
            logon_type=2,
            status="failure",
        )

        anomalies = auth_detector.detect_anomalies(failed_event)

        assert any(a["type"] == "failed_logon" for a in anomalies)

    def test_detect_credential_abuse_password_spraying(
        self, auth_detector, password_spraying_events
    ):
        """Test password spraying detection."""
        abuse = auth_detector.detect_credential_abuse(password_spraying_events)

        assert len(abuse) >= 1
        assert any(a["type"] == "password_spraying" for a in abuse)

        spraying_alert = next(a for a in abuse if a["type"] == "password_spraying")
        assert spraying_alert["severity"] == "high"
        assert spraying_alert["source_ip"] == "192.168.1.99"
        assert len(spraying_alert["affected_users"]) > 3

    def test_detect_credential_abuse_credential_stuffing(
        self, auth_detector, credential_stuffing_events
    ):
        """Test credential stuffing detection (rapid attempts)."""
        abuse = auth_detector.detect_credential_abuse(credential_stuffing_events)

        assert len(abuse) >= 1
        assert any(a["type"] == "credential_stuffing" for a in abuse)

    def test_calculate_risk_score(self, auth_detector, sample_auth_events, suspicious_auth_events):
        """Test risk score calculation."""
        auth_detector.build_baseline(sample_auth_events)

        # Get anomalies for suspicious event
        suspicious_event = suspicious_auth_events[0]
        anomalies = auth_detector.detect_anomalies(suspicious_event)

        risk_score = auth_detector.calculate_risk_score(suspicious_event, anomalies)

        assert 0.0 <= risk_score <= 1.0
        assert risk_score > 0  # Should have some risk due to anomalies

    def test_calculate_risk_score_admin_account(self, auth_detector):
        """Test risk score is higher for admin accounts."""
        admin_event = AuthEvent(
            timestamp="2024-01-15T22:00:00Z",
            event_id=4624,
            source_ip="192.168.1.50",
            target_host="dc01",
            username="administrator",
            domain="CORP",
            logon_type=10,  # RDP
            status="success",
        )

        normal_event = AuthEvent(
            timestamp="2024-01-15T22:00:00Z",
            event_id=4624,
            source_ip="192.168.1.50",
            target_host="dc01",
            username="regularuser",
            domain="CORP",
            logon_type=10,
            status="success",
        )

        admin_score = auth_detector.calculate_risk_score(admin_event, [])
        normal_score = auth_detector.calculate_risk_score(normal_event, [])

        assert admin_score > normal_score


# =============================================================================
# RemoteExecutionDetector Tests
# =============================================================================


class TestRemoteExecutionDetector:
    """Tests for RemoteExecutionDetector."""

    def test_detector_initialization(self, exec_detector):
        """Test detector initialization."""
        assert exec_detector is not None
        assert len(exec_detector.known_admin_tools) == 0
        assert isinstance(exec_detector.exec_history, defaultdict)

    def test_psexec_services_defined(self, exec_detector):
        """Test that PsExec service names are defined."""
        assert "psexesvc" in exec_detector.PSEXEC_SERVICES
        assert "paexec" in exec_detector.PSEXEC_SERVICES
        assert "smbexec" in exec_detector.PSEXEC_SERVICES

    def test_detect_psexec_service_creation(self, exec_detector, sample_system_events):
        """Test PsExec detection via service creation."""
        detections = exec_detector.detect_psexec(sample_system_events)

        psexec_detections = [d for d in detections if d.exec_type == "psexec"]
        assert len(psexec_detections) >= 1

        # Verify detection details
        detection = psexec_detections[0]
        assert detection.source_host == "workstation01"
        assert detection.target_host == "server01"
        assert detection.username == "jsmith"

    def test_detect_psexec_smb_share(self, exec_detector, sample_system_events):
        """Test detection of SMB admin share access."""
        detections = exec_detector.detect_psexec(sample_system_events)

        smb_detections = [d for d in detections if d.exec_type == "smb_admin_share"]
        assert len(smb_detections) >= 1

        detection = smb_detections[0]
        assert detection.target_host == "server02"

    def test_detect_wmi_exec(self, exec_detector, sample_system_events):
        """Test WMI execution detection."""
        detections = exec_detector.detect_wmi_exec(sample_system_events)

        assert len(detections) >= 1

        # Check for Win32_Process detection
        wmi_detections = [d for d in detections if d.exec_type == "wmi"]
        assert len(wmi_detections) >= 1

        detection = wmi_detections[0]
        assert detection.source_host == "server01"
        assert detection.target_host == "dc01"

    def test_detect_wmi_process_from_wmiprvse(self, exec_detector, sample_system_events):
        """Test detection of processes spawned by WmiPrvSE.exe."""
        detections = exec_detector.detect_wmi_exec(sample_system_events)

        wmi_process_detections = [d for d in detections if d.exec_type == "wmi_process"]
        assert len(wmi_process_detections) >= 1

    def test_detect_winrm_exec(self, exec_detector, winrm_events):
        """Test WinRM/PowerShell remoting detection."""
        detections = exec_detector.detect_winrm_exec(winrm_events)

        assert len(detections) >= 1

        winrm_detections = [d for d in detections if d.exec_type == "winrm"]
        assert len(winrm_detections) >= 2  # One for PS remoting, one for connection

    def test_detect_winrm_powershell_commands(self, exec_detector):
        """Test detection of specific PowerShell remoting commands."""
        events = [
            {
                "timestamp": "2024-01-15T22:00:00Z",
                "event_id": 4104,
                "script_block": "Enter-PSSession -ComputerName DC01",
                "source_host": "ws01",
                "target_host": "dc01",
                "computer_name": "dc01",
                "username": "admin",
            },
            {
                "timestamp": "2024-01-15T22:01:00Z",
                "event_id": 4103,
                "payload": "New-PSSession -ComputerName Server01",
                "source_host": "ws01",
                "target_host": "server01",
                "computer_name": "server01",
                "username": "admin",
            },
        ]

        detections = exec_detector.detect_winrm_exec(events)

        assert len(detections) >= 2

    def test_detect_all_remote_exec(self, exec_detector, sample_system_events, winrm_events):
        """Test combined detection of all remote execution types."""
        all_events = sample_system_events + winrm_events
        detections = exec_detector.detect_all_remote_exec(all_events)

        # Should have detections from multiple categories
        exec_types = set(d.exec_type for d in detections)
        assert len(exec_types) >= 2

    def test_detect_all_remote_exec_sorted(self, exec_detector, sample_system_events):
        """Test that detections are sorted by timestamp."""
        detections = exec_detector.detect_all_remote_exec(sample_system_events)

        if len(detections) > 1:
            timestamps = [d.timestamp for d in detections]
            assert timestamps == sorted(timestamps)

    def test_empty_events(self, exec_detector):
        """Test handling of empty event list."""
        assert exec_detector.detect_psexec([]) == []
        assert exec_detector.detect_wmi_exec([]) == []
        assert exec_detector.detect_winrm_exec([]) == []
        assert exec_detector.detect_all_remote_exec([]) == []


# =============================================================================
# AttackPathAnalyzer Tests
# =============================================================================


class TestAttackPathAnalyzer:
    """Tests for AttackPathAnalyzer."""

    def test_analyzer_initialization(self, path_analyzer):
        """Test analyzer initialization."""
        assert path_analyzer is not None
        assert isinstance(path_analyzer.graph, defaultdict)
        assert "dc01" in path_analyzer.high_value_targets
        assert "sql01" in path_analyzer.high_value_targets
        assert "fileserver" in path_analyzer.high_value_targets
        assert "exchange" in path_analyzer.high_value_targets

    def test_build_graph(self, path_analyzer, remote_exec_events):
        """Test graph building from events."""
        path_analyzer.build_graph(remote_exec_events)

        # Check edges are created
        assert "workstation01" in path_analyzer.graph
        assert "server01" in path_analyzer.graph["workstation01"]
        assert "dc01" in path_analyzer.graph["server01"]
        assert "fileserver" in path_analyzer.graph["dc01"]
        assert "sql01" in path_analyzer.graph["dc01"]

    def test_build_graph_edge_data(self, path_analyzer, remote_exec_events):
        """Test that graph edges contain correct data."""
        path_analyzer.build_graph(remote_exec_events)

        edges = path_analyzer.graph["workstation01"]["server01"]
        assert len(edges) >= 1

        edge = edges[0]
        assert "timestamp" in edge
        assert "technique" in edge
        assert "username" in edge
        assert edge["technique"] == "psexec"

    def test_find_attack_paths(self, path_analyzer, remote_exec_events):
        """Test finding attack paths to high-value targets."""
        path_analyzer.build_graph(remote_exec_events)
        paths = path_analyzer.find_attack_paths()

        # Should find paths to dc01, fileserver, sql01
        assert len(paths) >= 1

        # Check path to high-value target
        hvt_paths = [
            p
            for p in paths
            if any(hvt in p.path[-1].lower() for hvt in path_analyzer.high_value_targets)
        ]
        assert len(hvt_paths) >= 1

    def test_find_attack_paths_from_start_host(self, path_analyzer, remote_exec_events):
        """Test finding attack paths from specific start host."""
        path_analyzer.build_graph(remote_exec_events)
        paths = path_analyzer.find_attack_paths(start_host="workstation01")

        # All paths should start from workstation01
        for path in paths:
            assert path.path[0] == "workstation01"

    def test_find_attack_paths_max_depth(self, path_analyzer, remote_exec_events):
        """Test max depth parameter."""
        path_analyzer.build_graph(remote_exec_events)

        # With depth 2, should have shorter paths
        paths = path_analyzer.find_attack_paths(max_depth=2)

        for path in paths:
            assert len(path.path) <= 3  # max_depth + 1

    def test_identify_pivot_points(self, path_analyzer, remote_exec_events):
        """Test identification of pivot points."""
        path_analyzer.build_graph(remote_exec_events)
        pivots = path_analyzer.identify_pivot_points()

        assert len(pivots) >= 1

        # server01 should be a pivot (incoming from ws01, outgoing to dc01)
        pivot_hosts = [p["host"] for p in pivots]
        # dc01 has incoming and outgoing connections
        assert "dc01" in pivot_hosts

    def test_identify_pivot_points_centrality(self, path_analyzer, remote_exec_events):
        """Test pivot point centrality calculation."""
        path_analyzer.build_graph(remote_exec_events)
        pivots = path_analyzer.identify_pivot_points()

        for pivot in pivots:
            assert "centrality" in pivot
            assert pivot["centrality"] == pivot["incoming"] * pivot["outgoing"]

    def test_calculate_path_risk_length(self, path_analyzer, remote_exec_events):
        """Test path risk increases with length."""
        path_analyzer.build_graph(remote_exec_events)

        short_path = ["host1", "host2"]
        long_path = ["host1", "host2", "host3", "host4", "host5"]

        short_risk = path_analyzer.calculate_path_risk(short_path)
        long_risk = path_analyzer.calculate_path_risk(long_path)

        assert long_risk > short_risk

    def test_calculate_path_risk_high_value_target(self, path_analyzer, remote_exec_events):
        """Test path risk increases with high-value targets."""
        path_analyzer.build_graph(remote_exec_events)

        normal_path = ["host1", "host2"]
        hvt_path = ["host1", "dc01"]

        normal_risk = path_analyzer.calculate_path_risk(normal_path)
        hvt_risk = path_analyzer.calculate_path_risk(hvt_path)

        assert hvt_risk > normal_risk

    def test_visualize_graph(self, path_analyzer, remote_exec_events):
        """Test graph visualization data generation."""
        path_analyzer.build_graph(remote_exec_events)
        viz = path_analyzer.visualize_graph()

        assert "nodes" in viz
        assert "edges" in viz
        assert len(viz["nodes"]) >= 4  # At least 4 hosts in our events
        assert len(viz["edges"]) >= 3  # At least 3 connections

    def test_visualize_graph_node_types(self, path_analyzer, remote_exec_events):
        """Test that high-value targets are marked in visualization."""
        path_analyzer.build_graph(remote_exec_events)
        viz = path_analyzer.visualize_graph()

        # Find dc01 node
        dc01_node = next((n for n in viz["nodes"] if n["id"] == "dc01"), None)
        assert dc01_node is not None
        assert dc01_node["type"] == "high_value"

        # Find regular node
        ws01_node = next((n for n in viz["nodes"] if n["id"] == "workstation01"), None)
        assert ws01_node is not None
        assert ws01_node["type"] == "normal"

    def test_visualize_graph_edge_details(self, path_analyzer, remote_exec_events):
        """Test that edges contain technique information."""
        path_analyzer.build_graph(remote_exec_events)
        viz = path_analyzer.visualize_graph()

        for edge in viz["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "techniques" in edge
            assert "count" in edge


# =============================================================================
# LateralMovementPipeline Tests
# =============================================================================


class TestLateralMovementPipeline:
    """Tests for LateralMovementPipeline."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = LateralMovementPipeline()

        assert pipeline.auth_detector is not None
        assert pipeline.exec_detector is not None
        assert pipeline.path_analyzer is not None
        assert pipeline.llm is None  # Not initialized until needed

    def test_pipeline_with_provider(self):
        """Test pipeline initialization with specific provider."""
        pipeline = LateralMovementPipeline(llm_provider="anthropic")

        assert pipeline.llm_provider == "anthropic"

    def test_analyze_auth_events(self):
        """Test analysis of authentication events."""
        pipeline = LateralMovementPipeline()

        # Create minimal auth events
        auth_events = [
            {
                "timestamp": "2024-01-15T09:00:00Z",
                "event_id": 4624,
                "source_ip": "192.168.1.10",
                "target_host": "ws01",
                "username": "jsmith",
                "domain": "CORP",
                "logon_type": 2,
                "status": "success",
            }
        ] * 20  # Need enough for baseline

        # Add suspicious event
        auth_events.append(
            {
                "timestamp": "2024-01-15T22:00:00Z",
                "event_id": 4625,
                "source_ip": "192.168.1.99",
                "target_host": "dc01",
                "username": "admin",
                "domain": "CORP",
                "logon_type": 3,
                "status": "failure",
            }
        )

        results = pipeline.analyze(auth_events, [])

        assert "auth_anomalies" in results
        assert "credential_abuse" in results
        assert "alerts" in results

    def test_analyze_system_events(self):
        """Test analysis of system events for remote execution."""
        pipeline = LateralMovementPipeline()

        # Minimal auth events for baseline
        auth_events = [
            {
                "timestamp": "2024-01-15T09:00:00Z",
                "event_id": 4624,
                "source_ip": "192.168.1.10",
                "target_host": "ws01",
                "username": "jsmith",
                "domain": "CORP",
                "logon_type": 2,
                "status": "success",
            }
        ] * 10

        system_events = [
            {
                "timestamp": "2024-01-15T22:00:00Z",
                "event_id": 7045,
                "service_name": "PSEXESVC",
                "source_host": "ws01",
                "target_host": "srv01",
                "computer_name": "srv01",
                "username": "jsmith",
                "service_file_name": "%SystemRoot%\\PSEXESVC.exe",
            }
        ]

        results = pipeline.analyze(auth_events, system_events)

        assert "remote_executions" in results
        assert len(results["remote_executions"]) >= 1

    def test_analyze_attack_paths(self):
        """Test attack path detection in analysis."""
        pipeline = LateralMovementPipeline()

        auth_events = [
            {
                "timestamp": "2024-01-15T09:00:00Z",
                "event_id": 4624,
                "source_ip": "192.168.1.10",
                "target_host": "ws01",
                "username": "jsmith",
                "domain": "CORP",
                "logon_type": 2,
                "status": "success",
            }
        ] * 10

        system_events = [
            {
                "timestamp": "2024-01-15T22:00:00Z",
                "event_id": 7045,
                "service_name": "PSEXESVC",
                "source_host": "ws01",
                "target_host": "srv01",
                "computer_name": "srv01",
                "username": "jsmith",
            },
            {
                "timestamp": "2024-01-15T22:05:00Z",
                "event_id": 5857,
                "operation": "Win32_Process::Create",
                "source_host": "srv01",
                "target_host": "dc01",
                "computer_name": "dc01",
                "username": "jsmith",
                "commandline": "cmd",
            },
        ]

        results = pipeline.analyze(auth_events, system_events)

        assert "attack_paths" in results
        assert "pivot_points" in results

    def test_analyze_generates_alerts(self):
        """Test that analysis generates alerts for high-risk events."""
        pipeline = LateralMovementPipeline()

        # Create high-risk scenario
        auth_events = [
            {
                "timestamp": "2024-01-15T09:00:00Z",
                "event_id": 4624,
                "source_ip": "192.168.1.10",
                "target_host": "ws01",
                "username": "jsmith",
                "domain": "CORP",
                "logon_type": 2,
                "status": "success",
            }
        ] * 50

        # Add password spraying
        for i, user in enumerate(
            ["admin", "administrator", "svc1", "svc2", "user1", "user2", "user3"]
        ):
            auth_events.append(
                {
                    "timestamp": f"2024-01-15T22:10:{i:02d}Z",
                    "event_id": 4625,
                    "source_ip": "192.168.1.99",
                    "target_host": "dc01",
                    "username": user,
                    "domain": "CORP",
                    "logon_type": 3,
                    "status": "failure",
                }
            )

        results = pipeline.analyze(auth_events, [])

        assert len(results["alerts"]) >= 1

    def test_generate_report(self):
        """Test report generation."""
        pipeline = LateralMovementPipeline()

        # Create mock results
        results = {
            "auth_anomalies": [{"event": {"timestamp": "t1"}, "anomalies": [], "risk_score": 0.5}],
            "credential_abuse": [{"type": "password_spraying", "description": "test"}],
            "remote_executions": [],
            "attack_paths": [
                AttackPath(
                    path=["ws01", "dc01"],
                    start_time="2024-01-15T22:00:00Z",
                    end_time="2024-01-15T22:30:00Z",
                    techniques=["psexec"],
                    risk_score=0.8,
                )
            ],
            "pivot_points": [{"host": "srv01", "incoming": 2, "outgoing": 3, "is_pivot": True}],
            "alerts": [],
        }

        report = pipeline.generate_report(results)

        assert "LATERAL MOVEMENT DETECTION REPORT" in report
        assert "SUMMARY" in report
        assert "Authentication Anomalies: 1" in report
        assert "Attack Paths: 1" in report

    def test_generate_report_critical_alerts(self):
        """Test report includes critical alerts section."""
        pipeline = LateralMovementPipeline()

        critical_alert = LateralMovementAlert(
            timestamp="2024-01-15T22:00:00Z",
            alert_type="attack_path",
            source_host="ws01",
            target_host="dc01",
            username="admin",
            indicators=["Path detected"],
            severity="critical",
            mitre_techniques=["T1021"],
        )

        results = {
            "auth_anomalies": [],
            "credential_abuse": [],
            "remote_executions": [],
            "attack_paths": [],
            "pivot_points": [],
            "alerts": [critical_alert],
        }

        report = pipeline.generate_report(results)

        assert "CRITICAL ALERTS" in report

    @pytest.mark.requires_api
    def test_llm_analyze_attack_path(self, sample_attack_path):
        """Test LLM analysis of attack path (requires API key)."""
        pipeline = LateralMovementPipeline()

        result = pipeline.llm_analyze_attack_path(sample_attack_path)

        if "error" not in result:
            assert "attack_description" in result or "threat_actor_profile" in result

    def test_llm_analyze_attack_path_no_llm(self, sample_attack_path):
        """Test LLM analysis returns error when no LLM available."""
        pipeline = LateralMovementPipeline()
        pipeline.llm = None  # Ensure LLM is not initialized

        # Patch _init_llm to keep LLM as None (simulating no API available)
        with patch.object(pipeline, "_init_llm", lambda: None):
            result = pipeline.llm_analyze_attack_path(sample_attack_path)

            assert "error" in result


# =============================================================================
# setup_llm Tests
# =============================================================================


class TestSetupLLM:
    """Tests for setup_llm function."""

    def test_setup_llm_no_keys(self):
        """Test setup_llm raises error when no API keys are set."""
        with patch.dict("os.environ", {}, clear=True):
            with patch.dict(
                "os.environ", {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "", "GOOGLE_API_KEY": ""}
            ):
                # Remove any existing keys
                import os

                orig_anthropic = os.environ.pop("ANTHROPIC_API_KEY", None)
                orig_openai = os.environ.pop("OPENAI_API_KEY", None)
                orig_google = os.environ.pop("GOOGLE_API_KEY", None)

                try:
                    with pytest.raises(ValueError, match="No API key found"):
                        setup_llm("auto")
                finally:
                    # Restore keys
                    if orig_anthropic:
                        os.environ["ANTHROPIC_API_KEY"] = orig_anthropic
                    if orig_openai:
                        os.environ["OPENAI_API_KEY"] = orig_openai
                    if orig_google:
                        os.environ["GOOGLE_API_KEY"] = orig_google

    def test_setup_llm_unknown_provider(self):
        """Test setup_llm raises error for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            setup_llm("unknown_provider")

    @pytest.mark.requires_api
    def test_setup_llm_anthropic(self):
        """Test setup_llm with Anthropic provider."""
        import os

        if not os.getenv("ANTHROPIC_API_KEY"):
            pytest.skip("ANTHROPIC_API_KEY not set")

        provider, client = setup_llm("anthropic")
        assert provider == "anthropic"
        assert client is not None

    @pytest.mark.requires_api
    def test_setup_llm_openai(self):
        """Test setup_llm with OpenAI provider."""
        import os

        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("OPENAI_API_KEY not set")

        provider, client = setup_llm("openai")
        assert provider == "openai"
        assert client is not None

    @pytest.mark.requires_api
    def test_setup_llm_google(self):
        """Test setup_llm with Google provider."""
        import os

        if not os.getenv("GOOGLE_API_KEY"):
            pytest.skip("GOOGLE_API_KEY not set")

        provider, client = setup_llm("google")
        assert provider == "google"
        assert client is not None


# =============================================================================
# Integration Tests with Sample Data
# =============================================================================


class TestIntegration:
    """Integration tests using sample data files."""

    @pytest.fixture
    def sample_data(self):
        """Load sample data from data files."""
        data_path = (
            Path(__file__).parent.parent
            / "labs"
            / "lab15-lateral-movement-detection"
            / "data"
            / "auth_events.json"
        )

        if data_path.exists():
            with open(data_path, "r") as f:
                return json.load(f)
        return None

    def test_full_pipeline_with_sample_data(self, sample_data):
        """Test full pipeline with actual sample data."""
        if sample_data is None:
            pytest.skip("Sample data not available")

        pipeline = LateralMovementPipeline()

        results = pipeline.analyze(
            sample_data.get("auth_events", []), sample_data.get("system_events", [])
        )

        # Verify all result keys are present
        assert "alerts" in results
        assert "attack_paths" in results
        assert "pivot_points" in results
        assert "auth_anomalies" in results
        assert "credential_abuse" in results
        assert "remote_executions" in results

        # Should detect suspicious activity in sample data
        assert len(results["remote_executions"]) > 0
        assert len(results["alerts"]) > 0

    def test_sample_data_password_spraying(self, sample_data):
        """Test that sample data triggers password spraying detection."""
        if sample_data is None:
            pytest.skip("Sample data not available")

        pipeline = LateralMovementPipeline()
        results = pipeline.analyze(
            sample_data.get("auth_events", []), sample_data.get("system_events", [])
        )

        # Sample data contains password spraying attempts
        spraying = [a for a in results["credential_abuse"] if a.get("type") == "password_spraying"]
        assert len(spraying) >= 1

    def test_sample_data_attack_paths(self, sample_data):
        """Test attack path detection with sample data."""
        if sample_data is None:
            pytest.skip("Sample data not available")

        pipeline = LateralMovementPipeline()
        results = pipeline.analyze(
            sample_data.get("auth_events", []), sample_data.get("system_events", [])
        )

        # Sample data should show lateral movement paths
        assert len(results["attack_paths"]) > 0

        # Paths should lead to high-value targets
        hvt_paths = [
            p
            for p in results["attack_paths"]
            if any(hvt in p.path[-1].lower() for hvt in ["dc01", "sql01", "fileserver", "exchange"])
        ]
        assert len(hvt_paths) > 0


# =============================================================================
# Edge Cases Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_events(self):
        """Test pipeline handles empty event lists."""
        pipeline = LateralMovementPipeline()
        results = pipeline.analyze([], [])

        assert results["alerts"] == []
        assert results["attack_paths"] == []
        assert results["auth_anomalies"] == []
        assert results["remote_executions"] == []

    def test_malformed_auth_event(self):
        """Test pipeline handles malformed auth events."""
        pipeline = LateralMovementPipeline()

        malformed_events = [
            {"timestamp": "2024-01-15T09:00:00Z"},  # Missing required fields
            {},  # Completely empty
            {"event_id": "not_an_int"},  # Wrong type
        ]

        # Should not raise exception
        results = pipeline.analyze(malformed_events, [])
        assert "alerts" in results

    def test_malformed_system_event(self):
        """Test pipeline handles malformed system events."""
        pipeline = LateralMovementPipeline()

        malformed_events = [
            {"event_id": 7045},  # Missing other fields
            {},  # Completely empty
        ]

        # Should not raise exception
        results = pipeline.analyze([], malformed_events)
        assert "remote_executions" in results

    def test_invalid_timestamp(self):
        """Test handling of invalid timestamps."""
        detector = AuthAnomalyDetector()

        events = [
            AuthEvent(
                timestamp="invalid-timestamp",
                event_id=4624,
                source_ip="192.168.1.10",
                target_host="ws01",
                username="jsmith",
                domain="CORP",
                logon_type=2,
                status="success",
            )
        ]

        # Should not raise exception
        detector.build_baseline(events)
        anomalies = detector.detect_anomalies(events[0])
        assert isinstance(anomalies, list)

    def test_empty_username(self):
        """Test handling of empty username."""
        detector = AuthAnomalyDetector()

        event = AuthEvent(
            timestamp="2024-01-15T09:00:00Z",
            event_id=4624,
            source_ip="192.168.1.10",
            target_host="ws01",
            username="",
            domain="CORP",
            logon_type=2,
            status="success",
        )

        anomalies = detector.detect_anomalies(event)
        assert isinstance(anomalies, list)

    def test_graph_with_single_node(self):
        """Test attack path analysis with minimal graph."""
        analyzer = AttackPathAnalyzer()

        events = [
            RemoteExecEvent(
                timestamp="2024-01-15T22:00:00Z",
                source_host="ws01",
                target_host="srv01",
                exec_type="psexec",
                username="admin",
            )
        ]

        analyzer.build_graph(events)
        paths = analyzer.find_attack_paths()
        pivots = analyzer.identify_pivot_points()

        # Should not raise exception
        assert isinstance(paths, list)
        assert isinstance(pivots, list)

    def test_circular_path_handling(self):
        """Test handling of circular paths in graph."""
        analyzer = AttackPathAnalyzer()

        # Create circular dependencies
        events = [
            RemoteExecEvent(
                timestamp="t1", source_host="a", target_host="b", exec_type="psexec", username="u"
            ),
            RemoteExecEvent(
                timestamp="t2", source_host="b", target_host="c", exec_type="psexec", username="u"
            ),
            RemoteExecEvent(
                timestamp="t3", source_host="c", target_host="a", exec_type="psexec", username="u"
            ),
        ]

        analyzer.build_graph(events)

        # Should not infinite loop
        paths = analyzer.find_attack_paths(max_depth=10)
        assert isinstance(paths, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

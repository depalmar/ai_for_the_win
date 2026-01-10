#!/usr/bin/env python3
"""Tests for Lab 19: AI-Powered Cloud Security."""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab45-cloud-security-ai" / "solution")
sys.path.insert(0, lab_path)

from main import (  # noqa: E402
    CloudEvent,
    CloudSecurityReport,
    CloudThreat,
    CloudTrailAnalyzer,
    GCPSecurityAnalyzer,
    MultiCloudAnalyzer,
    create_sample_cloudtrail_events,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_cloudtrail_events():
    """Create sample CloudTrail events for testing."""
    return [
        {
            "eventID": "evt-001",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "backdoor-user"},
        },
        {
            "eventID": "evt-002",
            "eventTime": "2024-01-15T10:01:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {
                "userName": "backdoor-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    ]


@pytest.fixture
def privilege_escalation_events():
    """Create events that trigger privilege escalation detection."""
    return [
        {
            "eventID": "evt-priv-001",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "attacker"},
            "sourceIPAddress": "203.0.113.50",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "malicious-user"},
        },
        {
            "eventID": "evt-priv-002",
            "eventTime": "2024-01-15T10:01:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser", "userName": "attacker"},
            "sourceIPAddress": "203.0.113.50",
            "awsRegion": "us-east-1",
            "requestParameters": {
                "userName": "malicious-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    ]


@pytest.fixture
def defense_evasion_events():
    """Create events that trigger defense evasion detection."""
    return [
        {
            "eventID": "evt-def-001",
            "eventTime": "2024-01-15T10:05:00Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "userIdentity": {"type": "IAMUser", "userName": "backdoor-user"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"name": "main-trail"},
        },
    ]


@pytest.fixture
def data_exfiltration_events():
    """Create events that trigger data exfiltration detection."""
    return [
        {
            "eventID": "evt-exfil-001",
            "eventTime": "2024-01-15T10:10:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "userIdentity": {"type": "IAMUser", "userName": "backdoor-user"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {
                "bucketName": "company-sensitive-data",
                "bucketPolicy": {
                    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
                },
            },
        },
    ]


@pytest.fixture
def reconnaissance_events():
    """Create events that trigger reconnaissance detection (rapid enumeration).

    Needs 10+ recon actions within 5 minutes (300 seconds).
    Using 20 second intervals for 11 events = 200 seconds total (under 300s threshold).
    """
    base_time = datetime(2024, 1, 15, 9, 0, 0)
    recon_actions = [
        "ListUsers",
        "ListRoles",
        "ListPolicies",
        "ListBuckets",
        "DescribeInstances",
        "DescribeSecurityGroups",
        "ListAccessKeys",
        "GetBucketAcl",
        "GetAccountSummary",
        "GetUser",
        "ListUsers",
    ]

    events = []
    for i, action in enumerate(recon_actions):
        events.append(
            {
                "eventID": f"evt-recon-{i:03d}",
                "eventTime": (base_time + timedelta(seconds=20 * i)).isoformat() + "Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": action,
                "userIdentity": {"type": "IAMUser", "userName": "recon-user"},
                "sourceIPAddress": "91.234.56.78",
                "awsRegion": "us-east-1",
            }
        )
    return events


@pytest.fixture
def sample_gcp_findings():
    """Create sample GCP Security Command Center findings."""
    return [
        {
            "createTime": "2024-01-15T12:00:00Z",
            "severity": "HIGH",
            "category": "IAM_ANOMALY",
            "description": "Service account key created outside normal hours",
            "recommendation": "Review service account key creation",
            "mitreTechniques": ["T1078"],
        },
        {
            "createTime": "2024-01-15T13:00:00Z",
            "severity": "MEDIUM",
            "category": "FIREWALL_RULE",
            "description": "Overly permissive firewall rule detected",
            "recommendation": "Restrict firewall rule scope",
            "mitreTechniques": ["T1562"],
        },
    ]


@pytest.fixture
def multi_cloud_data(sample_cloudtrail_events, sample_gcp_findings):
    """Create multi-cloud data structure."""
    return {
        "aws": {"events": sample_cloudtrail_events},
        "gcp": {"findings": sample_gcp_findings},
    }


@pytest.fixture
def cloudtrail_analyzer():
    """Create CloudTrailAnalyzer instance."""
    return CloudTrailAnalyzer()


@pytest.fixture
def gcp_analyzer():
    """Create GCPSecurityAnalyzer instance."""
    return GCPSecurityAnalyzer()


@pytest.fixture
def multi_cloud_analyzer():
    """Create MultiCloudAnalyzer instance."""
    return MultiCloudAnalyzer()


# =============================================================================
# CloudEvent Tests
# =============================================================================


class TestCloudEvent:
    """Tests for CloudEvent dataclass."""

    def test_cloud_event_creation(self):
        """Test CloudEvent creation."""
        event = CloudEvent(
            event_id="test-001",
            timestamp="2024-01-15T10:00:00Z",
            cloud_provider="aws",
            event_type="iam.amazonaws.com",
            source_ip="192.168.1.100",
            user_identity="admin",
            resource="iam",
            action="CreateUser",
            result="success",
            region="us-east-1",
        )

        assert event.event_id == "test-001"
        assert event.cloud_provider == "aws"
        assert event.action == "CreateUser"
        assert event.raw_data == {}

    def test_cloud_event_with_raw_data(self):
        """Test CloudEvent with raw_data field."""
        raw = {"key": "value", "nested": {"data": 123}}
        event = CloudEvent(
            event_id="test-002",
            timestamp="2024-01-15T10:00:00Z",
            cloud_provider="gcp",
            event_type="compute.instances.insert",
            source_ip="10.0.0.1",
            user_identity="service-account",
            resource="vm",
            action="write",
            result="success",
            region="us-east1",
            raw_data=raw,
        )

        assert event.raw_data == raw
        assert event.raw_data["nested"]["data"] == 123


# =============================================================================
# CloudThreat Tests
# =============================================================================


class TestCloudThreat:
    """Tests for CloudThreat dataclass."""

    def test_cloud_threat_creation(self):
        """Test CloudThreat creation."""
        threat = CloudThreat(
            threat_id="AWS-0001",
            timestamp="2024-01-15T10:00:00Z",
            cloud_provider="aws",
            threat_type="Privilege Escalation",
            severity="critical",
        )

        assert threat.threat_id == "AWS-0001"
        assert threat.severity == "critical"
        assert threat.affected_resources == []
        assert threat.indicators == []
        assert threat.mitre_techniques == []

    def test_cloud_threat_with_full_data(self):
        """Test CloudThreat with all fields populated."""
        threat = CloudThreat(
            threat_id="GCP-0001",
            timestamp="2024-01-15T14:00:00Z",
            cloud_provider="gcp",
            threat_type="Identity - Unusual Access",
            severity="high",
            affected_resources=["vm-01", "bucket-01"],
            indicators=["Unusual location", "Multiple IPs"],
            mitre_techniques=["T1078", "T1110"],
            recommendation="Review user activity and reset credentials",
        )

        assert len(threat.affected_resources) == 2
        assert len(threat.indicators) == 2
        assert "T1078" in threat.mitre_techniques


# =============================================================================
# CloudSecurityReport Tests
# =============================================================================


class TestCloudSecurityReport:
    """Tests for CloudSecurityReport dataclass."""

    def test_report_creation(self):
        """Test CloudSecurityReport creation."""
        report = CloudSecurityReport(
            report_id="report_20240115_100000",
            timestamp="2024-01-15T10:00:00Z",
            clouds_analyzed=["AWS", "Azure"],
            total_events=100,
            threats_detected=[],
            risk_score=0.0,
            summary="No threats detected",
        )

        assert "AWS" in report.clouds_analyzed
        assert report.total_events == 100
        assert report.risk_score == 0.0

    def test_report_with_threats(self):
        """Test CloudSecurityReport with threats."""
        threat = CloudThreat(
            threat_id="TEST-0001",
            timestamp="2024-01-15T10:00:00Z",
            cloud_provider="aws",
            threat_type="Test Threat",
            severity="high",
        )
        report = CloudSecurityReport(
            report_id="report_20240115_100000",
            timestamp="2024-01-15T10:00:00Z",
            clouds_analyzed=["AWS"],
            total_events=50,
            threats_detected=[threat],
            risk_score=25.0,
            summary="Detected 1 threat",
        )

        assert len(report.threats_detected) == 1
        assert report.risk_score == 25.0


# =============================================================================
# CloudTrailAnalyzer Tests
# =============================================================================


class TestCloudTrailAnalyzer:
    """Tests for CloudTrailAnalyzer."""

    def test_analyzer_initialization(self, cloudtrail_analyzer):
        """Test analyzer initialization."""
        assert cloudtrail_analyzer is not None
        assert cloudtrail_analyzer.events == []
        assert len(cloudtrail_analyzer.user_activity) == 0

    def test_parse_event(self, cloudtrail_analyzer):
        """Test parsing a raw CloudTrail event."""
        raw_event = {
            "eventID": "test-event-001",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "testuser"},
            "sourceIPAddress": "192.168.1.100",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "newuser"},
        }

        event = cloudtrail_analyzer.parse_event(raw_event)

        assert isinstance(event, CloudEvent)
        assert event.event_id == "test-event-001"
        assert event.cloud_provider == "aws"
        assert event.action == "CreateUser"
        assert event.user_identity == "testuser"
        assert event.source_ip == "192.168.1.100"
        assert event.region == "us-east-1"
        assert event.result == "success"

    def test_parse_event_with_error(self, cloudtrail_analyzer):
        """Test parsing event with error code."""
        raw_event = {
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "testuser"},
            "sourceIPAddress": "192.168.1.100",
            "awsRegion": "us-east-1",
            "errorCode": "AccessDenied",
        }

        event = cloudtrail_analyzer.parse_event(raw_event)

        assert event.result == "failure"

    def test_parse_event_fallback_user_identity(self, cloudtrail_analyzer):
        """Test parsing event with fallback user identity fields."""
        # Test principalId fallback
        raw_event = {
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "AssumedRole", "principalId": "AROA123:session-name"},
            "sourceIPAddress": "192.168.1.100",
            "awsRegion": "us-east-1",
        }

        event = cloudtrail_analyzer.parse_event(raw_event)
        assert "AROA123" in event.user_identity

    def test_load_events(self, cloudtrail_analyzer, sample_cloudtrail_events, capsys):
        """Test loading CloudTrail events."""
        cloudtrail_analyzer.load_events(sample_cloudtrail_events)

        assert len(cloudtrail_analyzer.events) == 2
        assert "admin" in cloudtrail_analyzer.user_activity

        captured = capsys.readouterr()
        assert "Loaded 2 CloudTrail events" in captured.out

    def test_detect_privilege_escalation(self, cloudtrail_analyzer, privilege_escalation_events):
        """Test privilege escalation detection."""
        cloudtrail_analyzer.load_events(privilege_escalation_events)

        threats = cloudtrail_analyzer.detect_privilege_escalation()

        assert len(threats) >= 1
        threat = threats[0]
        assert threat.cloud_provider == "aws"
        assert "Privilege Escalation" in threat.threat_type
        assert threat.severity == "critical"
        assert "T1098" in threat.mitre_techniques or "T1136" in threat.mitre_techniques

    def test_detect_defense_evasion(self, cloudtrail_analyzer, defense_evasion_events):
        """Test defense evasion detection."""
        cloudtrail_analyzer.load_events(defense_evasion_events)

        threats = cloudtrail_analyzer.detect_defense_evasion()

        assert len(threats) >= 1
        threat = threats[0]
        assert "Defense Evasion" in threat.threat_type
        assert threat.severity == "critical"
        assert "T1562.001" in threat.mitre_techniques or "T1070" in threat.mitre_techniques

    def test_detect_defense_evasion_delete_trail(self, cloudtrail_analyzer):
        """Test detection of DeleteTrail action."""
        events = [
            {
                "eventTime": "2024-01-15T10:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "DeleteTrail",
                "userIdentity": {"type": "IAMUser", "userName": "attacker"},
                "sourceIPAddress": "185.234.72.19",
                "awsRegion": "us-east-1",
            }
        ]
        cloudtrail_analyzer.load_events(events)

        threats = cloudtrail_analyzer.detect_defense_evasion()

        assert len(threats) >= 1
        assert "DeleteTrail" in threats[0].threat_type

    def test_detect_data_exfiltration(self, cloudtrail_analyzer, data_exfiltration_events):
        """Test data exfiltration detection."""
        cloudtrail_analyzer.load_events(data_exfiltration_events)

        threats = cloudtrail_analyzer.detect_data_exfiltration()

        assert len(threats) >= 1
        threat = threats[0]
        assert "Data Exposure" in threat.threat_type or "Public Bucket" in threat.threat_type
        assert threat.severity == "high"
        assert "company-sensitive-data" in threat.affected_resources

    def test_detect_reconnaissance(self, cloudtrail_analyzer, reconnaissance_events):
        """Test reconnaissance detection (rapid enumeration)."""
        cloudtrail_analyzer.load_events(reconnaissance_events)

        threats = cloudtrail_analyzer.detect_reconnaissance()

        assert len(threats) >= 1
        threat = threats[0]
        assert "Reconnaissance" in threat.threat_type
        assert threat.severity == "medium"
        assert "T1087" in threat.mitre_techniques or "T1580" in threat.mitre_techniques

    def test_detect_reconnaissance_slow_enumeration(self, cloudtrail_analyzer):
        """Test that slow enumeration does not trigger reconnaissance alert."""
        base_time = datetime(2024, 1, 15, 9, 0, 0)
        events = []
        for i in range(10):
            events.append(
                {
                    "eventTime": (base_time + timedelta(minutes=i * 10)).isoformat() + "Z",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "ListUsers",
                    "userIdentity": {"userName": "slow-user"},
                    "sourceIPAddress": "10.0.0.1",
                    "awsRegion": "us-east-1",
                }
            )

        cloudtrail_analyzer.load_events(events)
        threats = cloudtrail_analyzer.detect_reconnaissance()

        # Should not detect since duration > 5 minutes
        assert len(threats) == 0

    def test_analyze_full(self, cloudtrail_analyzer):
        """Test full analysis with combined events."""
        # Create events that trigger multiple detection methods
        events = [
            # Privilege escalation
            {
                "eventTime": "2024-01-15T10:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "185.234.72.19",
                "awsRegion": "us-east-1",
                "requestParameters": {"userName": "backdoor"},
            },
            {
                "eventTime": "2024-01-15T10:01:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachUserPolicy",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "185.234.72.19",
                "awsRegion": "us-east-1",
                "requestParameters": {
                    "userName": "backdoor",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            },
            # Defense evasion
            {
                "eventTime": "2024-01-15T10:05:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "userIdentity": {"userName": "backdoor"},
                "sourceIPAddress": "185.234.72.19",
                "awsRegion": "us-east-1",
            },
        ]

        cloudtrail_analyzer.load_events(events)
        threats = cloudtrail_analyzer.analyze()

        assert len(threats) >= 2  # At least priv esc and defense evasion

    def test_threat_id_generation(self, cloudtrail_analyzer):
        """Test that threat IDs are unique and properly formatted."""
        id1 = cloudtrail_analyzer._generate_threat_id()
        id2 = cloudtrail_analyzer._generate_threat_id()

        assert id1 != id2
        assert id1.startswith("AWS-")
        assert id2.startswith("AWS-")

    def test_high_risk_actions_defined(self, cloudtrail_analyzer):
        """Test that high risk actions are defined."""
        assert "CreateUser" in cloudtrail_analyzer.HIGH_RISK_ACTIONS
        assert "CreateAccessKey" in cloudtrail_analyzer.HIGH_RISK_ACTIONS
        assert "StopLogging" in cloudtrail_analyzer.HIGH_RISK_ACTIONS

    def test_recon_actions_defined(self, cloudtrail_analyzer):
        """Test that reconnaissance actions are defined."""
        assert "DescribeInstances" in cloudtrail_analyzer.RECON_ACTIONS
        assert "ListBuckets" in cloudtrail_analyzer.RECON_ACTIONS
        assert "ListUsers" in cloudtrail_analyzer.RECON_ACTIONS


# =============================================================================
# GCPSecurityAnalyzer Tests
# =============================================================================


class TestGCPSecurityAnalyzer:
    """Tests for GCPSecurityAnalyzer."""

    def test_analyzer_initialization(self, gcp_analyzer):
        """Test analyzer initialization."""
        assert gcp_analyzer is not None
        assert gcp_analyzer.findings == []

    def test_load_findings(self, gcp_analyzer, sample_gcp_findings):
        """Test loading GCP SCC findings."""
        gcp_analyzer.load_findings(sample_gcp_findings)

        assert len(gcp_analyzer.findings) == 2

    def test_analyze(self, gcp_analyzer, sample_gcp_findings):
        """Test GCP analysis."""
        gcp_analyzer.load_findings(sample_gcp_findings)

        threats = gcp_analyzer.analyze()

        assert len(threats) == 2
        assert all(t.cloud_provider == "gcp" for t in threats)
        assert any("IAM_ANOMALY" in t.threat_type for t in threats)
        assert any("FIREWALL_RULE" in t.threat_type for t in threats)

    def test_analyze_preserves_mitre_techniques(self, gcp_analyzer):
        """Test that MITRE techniques are preserved from findings."""
        findings = [
            {
                "createTime": "2024-01-15T12:00:00Z",
                "severity": "HIGH",
                "category": "TEST",
                "description": "Test finding",
                "recommendation": "Fix it",
                "mitreTechniques": ["T1078", "T1098"],
            }
        ]

        gcp_analyzer.load_findings(findings)
        threats = gcp_analyzer.analyze()

        assert len(threats) == 1
        assert "T1078" in threats[0].mitre_techniques
        assert "T1098" in threats[0].mitre_techniques

    def test_threat_id_generation(self, gcp_analyzer):
        """Test GCP threat ID generation."""
        id1 = gcp_analyzer._generate_threat_id()
        id2 = gcp_analyzer._generate_threat_id()

        assert id1 != id2
        assert id1.startswith("GCP-")
        assert id2.startswith("GCP-")


# =============================================================================
# MultiCloudAnalyzer Tests
# =============================================================================


class TestMultiCloudAnalyzer:
    """Tests for MultiCloudAnalyzer."""

    def test_analyzer_initialization(self, multi_cloud_analyzer):
        """Test analyzer initialization."""
        assert multi_cloud_analyzer is not None
        assert multi_cloud_analyzer.aws_analyzer is not None
        assert multi_cloud_analyzer.gcp_analyzer is not None
        assert multi_cloud_analyzer.llm is None  # Not initialized until needed

    def test_load_cloud_data(self, multi_cloud_analyzer, multi_cloud_data):
        """Test loading data from all cloud providers."""
        multi_cloud_analyzer.load_cloud_data(multi_cloud_data)

        assert len(multi_cloud_analyzer.aws_analyzer.events) == 2
        assert len(multi_cloud_analyzer.gcp_analyzer.findings) == 2

    def test_load_cloud_data_partial(self, multi_cloud_analyzer):
        """Test loading partial cloud data."""
        data = {"aws": {"events": [{"eventName": "Test"}]}}

        multi_cloud_analyzer.load_cloud_data(data)

        assert len(multi_cloud_analyzer.aws_analyzer.events) == 1

    def test_correlate_cross_cloud_same_ip(self, multi_cloud_analyzer):
        """Test cross-cloud correlation by IP address."""
        threats = [
            CloudThreat(
                threat_id="AWS-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test AWS Threat",
                severity="high",
                indicators=["Source IP: 185.234.72.19"],
            ),
            CloudThreat(
                threat_id="GCP-0001",
                timestamp="2024-01-15T10:05:00Z",
                cloud_provider="gcp",
                threat_type="Test GCP Threat",
                severity="high",
                indicators=["IP: 185.234.72.19"],
            ),
        ]

        correlated = multi_cloud_analyzer.correlate_cross_cloud(threats)

        assert len(correlated) >= 1
        threat = correlated[0]
        assert threat.cloud_provider == "multi-cloud"
        assert "Cross-Cloud Attack" in threat.threat_type
        assert threat.severity == "critical"

    def test_correlate_cross_cloud_no_correlation(self, multi_cloud_analyzer):
        """Test that threats with different IPs are not correlated."""
        threats = [
            CloudThreat(
                threat_id="AWS-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test AWS Threat",
                severity="high",
                indicators=["Source IP: 10.0.0.1"],
            ),
            CloudThreat(
                threat_id="GCP-0001",
                timestamp="2024-01-15T10:05:00Z",
                cloud_provider="gcp",
                threat_type="Test GCP Threat",
                severity="high",
                indicators=["IP: 192.168.1.1"],
            ),
        ]

        correlated = multi_cloud_analyzer.correlate_cross_cloud(threats)

        # No correlation since IPs are different
        assert len(correlated) == 0

    def test_calculate_risk_score_empty(self, multi_cloud_analyzer):
        """Test risk score calculation with no threats."""
        score = multi_cloud_analyzer.calculate_risk_score([])
        assert score == 0.0

    def test_calculate_risk_score_critical(self, multi_cloud_analyzer):
        """Test risk score calculation with critical threat."""
        threats = [
            CloudThreat(
                threat_id="TEST-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test",
                severity="critical",
            )
        ]

        score = multi_cloud_analyzer.calculate_risk_score(threats)
        assert score == 40.0  # Critical = 40 points

    def test_calculate_risk_score_mixed(self, multi_cloud_analyzer):
        """Test risk score calculation with mixed severities."""
        threats = [
            CloudThreat(
                threat_id="TEST-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test 1",
                severity="critical",
            ),
            CloudThreat(
                threat_id="TEST-0002",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test 2",
                severity="high",
            ),
            CloudThreat(
                threat_id="TEST-0003",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test 3",
                severity="medium",
            ),
            CloudThreat(
                threat_id="TEST-0004",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test 4",
                severity="low",
            ),
        ]

        score = multi_cloud_analyzer.calculate_risk_score(threats)
        # 40 (critical) + 25 (high) + 10 (medium) + 5 (low) = 80
        assert score == 80.0

    def test_calculate_risk_score_multi_cloud_boost(self, multi_cloud_analyzer):
        """Test risk score boost for multi-cloud threats."""
        threats = [
            CloudThreat(
                threat_id="MULTI-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="multi-cloud",
                threat_type="Cross-Cloud Attack",
                severity="critical",
            )
        ]

        score = multi_cloud_analyzer.calculate_risk_score(threats)
        # 40 * 1.5 = 60
        assert score == 60.0

    def test_calculate_risk_score_capped(self, multi_cloud_analyzer):
        """Test that risk score is capped at 100."""
        threats = [
            CloudThreat(
                threat_id=f"TEST-{i:04d}",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type=f"Test {i}",
                severity="critical",
            )
            for i in range(5)
        ]

        score = multi_cloud_analyzer.calculate_risk_score(threats)
        # 5 * 40 = 200, but capped at 100
        assert score == 100.0

    def test_analyze_all(self, multi_cloud_analyzer, multi_cloud_data):
        """Test full multi-cloud analysis."""
        multi_cloud_analyzer.load_cloud_data(multi_cloud_data)

        report = multi_cloud_analyzer.analyze_all()

        assert isinstance(report, CloudSecurityReport)
        assert report.report_id.startswith("report_")
        assert len(report.clouds_analyzed) >= 1
        assert report.total_events >= 0
        assert 0 <= report.risk_score <= 100

    def test_analyze_all_with_cross_cloud_correlation(self, multi_cloud_analyzer):
        """Test analysis with events from same IP across clouds."""
        data = {
            "aws": {
                "events": [
                    {
                        "eventTime": "2024-01-15T10:00:00Z",
                        "eventSource": "cloudtrail.amazonaws.com",
                        "eventName": "StopLogging",
                        "userIdentity": {"userName": "attacker"},
                        "sourceIPAddress": "185.234.72.19",
                        "awsRegion": "us-east-1",
                    }
                ]
            },
        }

        multi_cloud_analyzer.load_cloud_data(data)
        report = multi_cloud_analyzer.analyze_all()

        # Check that analysis completed successfully
        assert report is not None

    def test_generate_report(self, multi_cloud_analyzer):
        """Test report generation."""
        threats = [
            CloudThreat(
                threat_id="AWS-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test AWS Threat",
                severity="critical",
                indicators=["Indicator 1", "Indicator 2"],
            ),
            CloudThreat(
                threat_id="GCP-0001",
                timestamp="2024-01-15T10:05:00Z",
                cloud_provider="gcp",
                threat_type="Test GCP Threat",
                severity="high",
                indicators=["GCP Indicator"],
            ),
        ]

        report = multi_cloud_analyzer.generate_report(threats)

        assert "MULTI-CLOUD SECURITY REPORT" in report
        assert "AWS" in report.upper()
        assert "GCP" in report.upper()
        assert "Total Threats: 2" in report

    @pytest.mark.requires_api
    def test_llm_analyze_threats(self, multi_cloud_analyzer):
        """Test LLM-based threat analysis (requires API key)."""
        threats = [
            CloudThreat(
                threat_id="AWS-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Privilege Escalation",
                severity="critical",
                indicators=["User created backdoor account"],
            )
        ]

        result = multi_cloud_analyzer.llm_analyze_threats(threats)

        assert isinstance(result, dict)
        if "error" not in result:
            assert "summary" in result or "attack_narrative" in result

    def test_llm_analyze_threats_no_api(self):
        """Test LLM analysis when no API is available."""
        analyzer = MultiCloudAnalyzer()
        analyzer.llm = None  # Ensure LLM is not initialized

        # Patch _init_llm to keep LLM as None (simulating no API available)
        with patch.object(analyzer, "_init_llm", lambda: None):
            threats = [
                CloudThreat(
                    threat_id="AWS-0001",
                    timestamp="2024-01-15T10:00:00Z",
                    cloud_provider="aws",
                    threat_type="Test",
                    severity="high",
                )
            ]

            result = analyzer.llm_analyze_threats(threats)

            assert "error" in result


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_sample_cloudtrail_events(self):
        """Test sample event creation."""
        events = create_sample_cloudtrail_events()

        assert len(events) == 4
        assert events[0]["eventName"] == "CreateUser"
        assert events[1]["eventName"] == "CreateAccessKey"
        assert events[2]["eventName"] == "AttachUserPolicy"
        assert events[3]["eventName"] == "StopLogging"

    def test_sample_events_have_required_fields(self):
        """Test that sample events have all required fields."""
        events = create_sample_cloudtrail_events()

        required_fields = [
            "eventTime",
            "eventSource",
            "eventName",
            "userIdentity",
            "sourceIPAddress",
            "awsRegion",
        ]

        for event in events:
            for field in required_fields:
                assert field in event, f"Missing field: {field}"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the cloud security module."""

    def test_full_pipeline_with_sample_data(self):
        """Test complete pipeline with sample CloudTrail data."""
        analyzer = MultiCloudAnalyzer()
        events = create_sample_cloudtrail_events()

        analyzer.load_cloud_data({"aws": {"events": events}})
        report = analyzer.analyze_all()

        assert report is not None
        assert len(report.threats_detected) >= 2  # Should detect multiple threats
        assert "AWS" in report.clouds_analyzed
        assert report.risk_score > 0

    def test_full_pipeline_with_real_data_files(self):
        """Test pipeline with data files from lab."""
        data_dir = Path(__file__).parent.parent / "labs" / "lab19-cloud-security-ai" / "data"

        if not data_dir.exists():
            pytest.skip("Data directory not found")

        cloud_data = {}

        cloudtrail_file = data_dir / "cloudtrail_events.json"
        if cloudtrail_file.exists():
            with open(cloudtrail_file, "r") as f:
                cloud_data["aws"] = json.load(f)

        if not cloud_data:
            pytest.skip("No data files found")

        analyzer = MultiCloudAnalyzer()
        analyzer.load_cloud_data(cloud_data)
        report = analyzer.analyze_all()

        assert report is not None
        assert isinstance(report, CloudSecurityReport)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_events(self, cloudtrail_analyzer):
        """Test analysis with empty events list."""
        cloudtrail_analyzer.load_events([])

        threats = cloudtrail_analyzer.analyze()
        assert threats == []

    def test_malformed_event(self, cloudtrail_analyzer):
        """Test handling of malformed events."""
        events = [{"incomplete": "event"}]

        cloudtrail_analyzer.load_events(events)

        # Should not crash
        threats = cloudtrail_analyzer.analyze()
        assert isinstance(threats, list)

    def test_empty_gcp_findings(self, gcp_analyzer):
        """Test GCP analysis with no findings."""
        gcp_analyzer.load_findings([])

        threats = gcp_analyzer.analyze()
        assert threats == []

    def test_event_with_missing_timestamp(self, cloudtrail_analyzer):
        """Test event parsing with missing timestamp."""
        events = [
            {
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "userIdentity": {"userName": "test"},
                "sourceIPAddress": "10.0.0.1",
                "awsRegion": "us-east-1",
            }
        ]

        cloudtrail_analyzer.load_events(events)

        # Should handle missing timestamp gracefully
        assert len(cloudtrail_analyzer.events) == 1

    def test_reconnaissance_with_invalid_timestamps(self, cloudtrail_analyzer):
        """Test reconnaissance detection with invalid timestamps."""
        events = []
        for _ in range(12):
            events.append(
                {
                    "eventTime": "invalid-timestamp",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "ListUsers",
                    "userIdentity": {"userName": "test-user"},
                    "sourceIPAddress": "10.0.0.1",
                    "awsRegion": "us-east-1",
                }
            )

        cloudtrail_analyzer.load_events(events)

        # Should handle invalid timestamps gracefully
        threats = cloudtrail_analyzer.detect_reconnaissance()
        assert isinstance(threats, list)

    def test_multi_cloud_with_empty_data(self, multi_cloud_analyzer):
        """Test multi-cloud analyzer with empty data."""
        multi_cloud_analyzer.load_cloud_data({})

        report = multi_cloud_analyzer.analyze_all()

        assert report is not None
        assert len(report.threats_detected) == 0
        assert report.risk_score == 0.0

    def test_unknown_severity(self, multi_cloud_analyzer):
        """Test risk score with unknown severity."""
        threats = [
            CloudThreat(
                threat_id="TEST-0001",
                timestamp="2024-01-15T10:00:00Z",
                cloud_provider="aws",
                threat_type="Test",
                severity="unknown",
            )
        ]

        score = multi_cloud_analyzer.calculate_risk_score(threats)
        # Unknown severity defaults to 5
        assert score == 5.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

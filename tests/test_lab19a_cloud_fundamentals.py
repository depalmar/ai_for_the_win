"""Tests for Lab 19a: Cloud Security Fundamentals."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0,
    str(Path(__file__).parent.parent / "labs" / "lab19a-cloud-security-fundamentals" / "solution"),
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        CloudThreatDetector,
        CloudTrailEvent,
        CloudTrailParser,
        IAMAnalyzer,
    )


def test_cloudtrail_parser():
    """Test CloudTrail event parsing."""
    from main import CloudTrailParser

    parser = CloudTrailParser()

    raw_event = {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
        "sourceIPAddress": "203.0.113.50",
    }

    event = parser.parse_event(raw_event)

    assert event.event_name == "CreateAccessKey"
    assert event.source_ip == "203.0.113.50"


def test_cloudtrail_high_risk_detection():
    """Test high-risk event detection."""
    from main import CloudTrailParser

    parser = CloudTrailParser()

    raw_event = {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "userIdentity": {"type": "IAMUser", "userName": "attacker"},
        "sourceIPAddress": "185.220.101.1",
    }

    event = parser.parse_event(raw_event)
    is_high_risk = parser.is_high_risk(event)

    assert is_high_risk is True


def test_iam_analyzer_overly_permissive():
    """Test detection of overly permissive IAM policies."""
    from main import IAMAnalyzer

    analyzer = IAMAnalyzer()

    risky_policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    findings = analyzer.check_overly_permissive(risky_policy)

    assert len(findings) > 0
    assert any(f.severity == "CRITICAL" for f in findings)


def test_iam_analyzer_safe_policy():
    """Test that safe policies don't trigger."""
    from main import IAMAnalyzer

    analyzer = IAMAnalyzer()

    safe_policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
        ]
    }

    findings = analyzer.check_overly_permissive(safe_policy)

    # Should have no critical findings
    assert not any(f.severity == "CRITICAL" for f in findings)


def test_cloud_threat_detector_classification():
    """Test threat classification by tactic."""
    from main import CloudThreatDetector

    detector = CloudThreatDetector()

    assert detector.classify_event("StopLogging") == "DEFENSE_EVASION"
    assert detector.classify_event("CreateAccessKey") == "PERSISTENCE"


def test_cloud_threat_detector_severity():
    """Test severity assignment."""
    from main import CloudThreatDetector

    detector = CloudThreatDetector()

    assert detector.get_severity("StopLogging") == "CRITICAL"
    assert detector.get_severity("CreateAccessKey") == "HIGH"

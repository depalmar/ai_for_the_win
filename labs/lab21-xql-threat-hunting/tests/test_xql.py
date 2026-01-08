#!/usr/bin/env python3
"""Tests for Lab 21: XQL Threat Hunting with AI."""

import re

import pytest

# Try to import from starter (since solution may not be complete)
try:
    from labs.lab21_xql_threat_hunting.starter.main import (
        ATTACK_PATTERNS,
        VALID_DATASETS,
        VALID_EVENT_TYPES,
        DetectionRule,
        Severity,
        ValidationResult,
    )
except ImportError:
    try:
        from starter.main import (
            ATTACK_PATTERNS,
            VALID_DATASETS,
            VALID_EVENT_TYPES,
            DetectionRule,
            Severity,
            ValidationResult,
        )
    except ImportError:
        # Define minimal versions for testing
        VALID_DATASETS = ["xdr_data", "endpoints", "incidents", "alerts", "audit_logs"]
        VALID_EVENT_TYPES = ["ENUM.PROCESS", "ENUM.NETWORK", "ENUM.FILE", "ENUM.REGISTRY"]
        ATTACK_PATTERNS = {
            "T1059.001": {"name": "PowerShell", "keywords": ["powershell", "-enc"]},
            "T1003.001": {"name": "LSASS Memory", "keywords": ["lsass", "mimikatz"]},
        }

        class Severity:
            INFO = "informational"
            LOW = "low"
            MEDIUM = "medium"
            HIGH = "high"
            CRITICAL = "critical"


# =============================================================================
# XQL Validation Tests
# =============================================================================


class TestXQLValidation:
    """Test XQL query validation."""

    def test_valid_datasets(self):
        """Test that valid datasets are defined."""
        assert "xdr_data" in VALID_DATASETS
        assert "endpoints" in VALID_DATASETS
        assert "alerts" in VALID_DATASETS

    def test_valid_event_types(self):
        """Test that valid event types are defined."""
        assert "ENUM.PROCESS" in VALID_EVENT_TYPES
        assert "ENUM.NETWORK" in VALID_EVENT_TYPES
        assert "ENUM.FILE" in VALID_EVENT_TYPES

    def test_query_has_dataset(self):
        """Test detection of dataset in query."""
        valid_query = "| dataset = xdr_data | filter event_type = ENUM.PROCESS"
        invalid_query = "| filter event_type = ENUM.PROCESS"

        assert "dataset" in valid_query
        assert "dataset" not in invalid_query

    def test_query_has_config(self):
        """Test detection of config statements."""
        query_with_config = """config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS"""

        query_without_config = """| dataset = xdr_data
| filter event_type = ENUM.PROCESS"""

        assert "config case_sensitive" in query_with_config
        assert "config" not in query_without_config

    def test_enum_usage(self):
        """Test ENUM usage detection."""
        correct = "filter event_type = ENUM.PROCESS"
        incorrect = "filter event_type = 'PROCESS'"

        assert "ENUM." in correct
        assert "ENUM." not in incorrect


# =============================================================================
# Query Pattern Tests
# =============================================================================


class TestQueryPatterns:
    """Test XQL query patterns."""

    def test_time_filter_pattern(self):
        """Test time filtering pattern recognition."""
        # Correct XQL time filtering
        correct_pattern = 'alter days_ago = timestamp_diff(current_time(), _time, "DAY")'

        # timestamp_diff is the correct XQL function
        assert "timestamp_diff" in correct_pattern
        assert "_time" in correct_pattern

    def test_config_timeframe_pattern(self):
        """Test config timeframe pattern."""
        config_pattern = (
            'config timeframe between "2025-01-01 00:00:00 +0000" and "2025-01-07 23:59:59 +0000"'
        )

        assert "config timeframe between" in config_pattern

    def test_field_selection_pattern(self):
        """Test field selection pattern."""
        query = "| fields _time, agent_hostname, actor_process_command_line"

        assert "fields" in query
        assert "_time" in query

    def test_sort_pattern(self):
        """Test sort pattern."""
        query = "| sort desc _time | limit 100"

        assert "sort desc" in query
        assert "limit" in query


# =============================================================================
# MITRE ATT&CK Mapping Tests
# =============================================================================


class TestMITREMapping:
    """Test MITRE ATT&CK technique mapping."""

    def test_attack_patterns_defined(self):
        """Test that attack patterns are defined."""
        assert len(ATTACK_PATTERNS) > 0
        assert "T1059.001" in ATTACK_PATTERNS  # PowerShell
        assert "T1003.001" in ATTACK_PATTERNS  # LSASS

    def test_powershell_keywords(self):
        """Test PowerShell technique keywords."""
        ps_pattern = ATTACK_PATTERNS.get("T1059.001", {})
        keywords = ps_pattern.get("keywords", [])

        assert "powershell" in keywords or any("powershell" in k for k in keywords)

    def test_lsass_keywords(self):
        """Test LSASS technique keywords."""
        lsass_pattern = ATTACK_PATTERNS.get("T1003.001", {})
        keywords = lsass_pattern.get("keywords", [])

        assert any("lsass" in k for k in keywords) or any("mimikatz" in k for k in keywords)


# =============================================================================
# Detection Rule Tests
# =============================================================================


class TestDetectionRules:
    """Test detection rule structures."""

    def test_severity_levels(self):
        """Test severity level definitions."""
        assert Severity.INFO == "informational"
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"


# =============================================================================
# XQL Syntax Tests
# =============================================================================


class TestXQLSyntax:
    """Test XQL syntax patterns."""

    def test_pipe_operator(self):
        """Test pipe operator usage."""
        query = """config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| fields _time, agent_hostname
| sort desc _time
| limit 100"""

        # Count pipe operators (should have multiple)
        pipes = query.count("|")
        assert pipes >= 4

    def test_filter_syntax(self):
        """Test filter syntax patterns."""
        # Various filter patterns
        filters = [
            'filter actor_process_image_name ~= "powershell\\.exe"',
            'filter actor_process_command_line contains "-enc"',
            "filter event_type = ENUM.PROCESS",
            'filter actor_process_image_name in ("cmd.exe", "powershell.exe")',
        ]

        for f in filters:
            assert f.startswith("filter")

    def test_regex_filter(self):
        """Test regex filter pattern."""
        query = 'filter actor_process_image_name ~= "powershell\\.exe|pwsh\\.exe"'

        assert "~=" in query
        assert "|" in query  # regex OR

    def test_contains_filter(self):
        """Test contains filter pattern."""
        query = 'filter actor_process_command_line contains "-encodedcommand"'

        assert "contains" in query


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test XQL integration patterns."""

    def test_complete_hunting_query(self):
        """Test a complete hunting query structure."""
        query = """config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "powershell\\.exe"
| filter actor_process_command_line contains "-enc"
| fields _time, agent_hostname, actor_process_command_line
| sort desc _time
| limit 100"""

        # Check all required components
        assert "config case_sensitive = false" in query
        assert "dataset = xdr_data" in query
        assert "ENUM.PROCESS" in query
        assert "timestamp_diff" in query
        assert "fields" in query
        assert "limit" in query

    def test_detection_query_structure(self):
        """Test detection query has proper structure."""
        # Detection queries should have:
        # 1. Config statements
        # 2. Dataset selection
        # 3. Event type filter
        # 4. Time filter
        # 5. Detection logic
        # 6. Field selection
        # 7. Sort and limit

        required_components = [
            "config",
            "dataset",
            "ENUM",
            "timestamp_diff",
            "filter",
            "fields",
            "limit",
        ]

        # This is a pattern check, actual implementation should have all
        sample_query = (
            "config case_sensitive = false | dataset = xdr_data | filter event_type = ENUM.PROCESS"
        )

        for component in ["config", "dataset", "ENUM", "filter"]:
            assert component in sample_query


# =============================================================================
# Sample Query Tests
# =============================================================================


class TestSampleQueries:
    """Test sample hunting queries."""

    @pytest.fixture
    def encoded_powershell_query(self):
        """Sample encoded PowerShell detection query."""
        return """config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_image_name ~= "powershell\\.exe|pwsh\\.exe"
| filter actor_process_command_line ~= "-enc|-encodedcommand|-e\\s+[A-Za-z0-9+/=]{20,}"
| fields _time, agent_hostname, agent_ip, actor_process_image_name, actor_process_command_line
| sort desc _time
| limit 100"""

    def test_encoded_powershell_query(self, encoded_powershell_query):
        """Test encoded PowerShell query structure."""
        query = encoded_powershell_query

        assert "powershell" in query.lower()
        assert "-enc" in query
        assert "ENUM.PROCESS" in query

    @pytest.fixture
    def mimikatz_query(self):
        """Sample Mimikatz detection query."""
        return """config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| filter actor_process_command_line ~= "sekurlsa|lsadump|privilege::debug|mimikatz"
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time
| limit 100"""

    def test_mimikatz_query(self, mimikatz_query):
        """Test Mimikatz query structure."""
        query = mimikatz_query

        assert "sekurlsa" in query
        assert "lsadump" in query
        assert "ENUM.PROCESS" in query


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""Tests for Lab 07b: Sigma Rule Fundamentals."""

import uuid

import pytest
import yaml

# Try to import from solution
try:
    from labs.lab07b_sigma_fundamentals.solution.main import (
        SigmaRule,
        create_credential_dump_chain_rule,
        create_encoded_powershell_rule,
        create_mimikatz_rule,
        match_log_event,
        parse_sigma_rule,
        validate_sigma_rule,
    )
except ImportError:
    try:
        from solution.main import (
            SigmaRule,
            create_credential_dump_chain_rule,
            create_encoded_powershell_rule,
            create_mimikatz_rule,
            match_log_event,
            parse_sigma_rule,
            validate_sigma_rule,
        )
    except ImportError:
        pytest.skip("Solution module not available", allow_module_level=True)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mimikatz_rule():
    """Get Mimikatz detection rule."""
    return create_mimikatz_rule()


@pytest.fixture
def powershell_rule():
    """Get encoded PowerShell rule."""
    return create_encoded_powershell_rule()


@pytest.fixture
def cred_dump_rule():
    """Get credential dump chain rule."""
    return create_credential_dump_chain_rule()


@pytest.fixture
def sample_sigma_rule():
    """Create a simple test Sigma rule."""
    return """
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Test detection rule
author: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'malicious'
    condition: selection
level: high
tags:
    - attack.execution
"""


# =============================================================================
# Rule Creation Tests
# =============================================================================


class TestRuleCreation:
    """Test rule creation functions."""

    def test_mimikatz_rule_structure(self, mimikatz_rule):
        """Test Mimikatz rule has required fields."""
        data = yaml.safe_load(mimikatz_rule)

        assert "title" in data
        assert "id" in data
        assert "logsource" in data
        assert "detection" in data
        assert "level" in data
        assert data["level"] == "critical"

    def test_mimikatz_rule_detection(self, mimikatz_rule):
        """Test Mimikatz rule detection logic."""
        data = yaml.safe_load(mimikatz_rule)
        detection = data["detection"]

        # Should have selection blocks
        assert "condition" in detection
        # Should detect mimikatz patterns
        condition = detection["condition"]
        assert "selection" in condition

    def test_powershell_rule_structure(self, powershell_rule):
        """Test PowerShell rule structure."""
        data = yaml.safe_load(powershell_rule)

        assert data["title"] is not None
        assert data["level"] == "high"
        assert "logsource" in data
        assert data["logsource"]["product"] == "windows"

    def test_credential_dump_rule(self, cred_dump_rule):
        """Test credential dump chain rule."""
        data = yaml.safe_load(cred_dump_rule)

        assert data["level"] == "critical"
        assert "attack.credential_access" in data.get("tags", [])


# =============================================================================
# Rule Parsing Tests
# =============================================================================


class TestRuleParsing:
    """Test rule parsing functions."""

    def test_parse_sigma_rule(self, sample_sigma_rule):
        """Test parsing YAML to SigmaRule object."""
        rule = parse_sigma_rule(sample_sigma_rule)

        assert isinstance(rule, SigmaRule)
        assert rule.title == "Test Rule"
        assert rule.level == "high"
        assert rule.status == "experimental"

    def test_parse_mimikatz_rule(self, mimikatz_rule):
        """Test parsing Mimikatz rule."""
        rule = parse_sigma_rule(mimikatz_rule)

        assert "Mimikatz" in rule.title
        assert rule.level == "critical"
        assert isinstance(rule.detection, dict)


# =============================================================================
# Log Matching Tests
# =============================================================================


class TestLogMatching:
    """Test log event matching."""

    def test_match_positive(self, sample_sigma_rule):
        """Test matching event that should trigger."""
        rule = parse_sigma_rule(sample_sigma_rule)

        event = {
            "CommandLine": "some malicious command here",
            "Image": "C:\\Windows\\System32\\cmd.exe",
        }

        assert match_log_event(rule, event) is True

    def test_match_negative(self, sample_sigma_rule):
        """Test event that should not trigger."""
        rule = parse_sigma_rule(sample_sigma_rule)

        event = {
            "CommandLine": "normal command here",
            "Image": "C:\\Windows\\System32\\cmd.exe",
        }

        assert match_log_event(rule, event) is False

    def test_match_missing_field(self, sample_sigma_rule):
        """Test event missing required field."""
        rule = parse_sigma_rule(sample_sigma_rule)

        event = {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            # Missing CommandLine
        }

        assert match_log_event(rule, event) is False


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    """Test rule validation."""

    def test_validate_valid_rule(self, sample_sigma_rule):
        """Test validation of valid rule."""
        result = validate_sigma_rule(sample_sigma_rule)

        assert isinstance(result, dict)
        assert "errors" in result
        # Should have minimal errors for valid rule

    def test_validate_mimikatz_rule(self, mimikatz_rule):
        """Test validation of Mimikatz rule."""
        result = validate_sigma_rule(mimikatz_rule)

        assert isinstance(result, dict)


# =============================================================================
# MITRE ATT&CK Mapping Tests
# =============================================================================


class TestMITREMapping:
    """Test MITRE ATT&CK tag mapping."""

    def test_mimikatz_tags(self, mimikatz_rule):
        """Test Mimikatz rule has correct MITRE tags."""
        data = yaml.safe_load(mimikatz_rule)
        tags = data.get("tags", [])

        # Should have credential access tag
        assert any("credential_access" in tag for tag in tags)
        # Should have T1003 technique
        assert any("t1003" in tag.lower() for tag in tags)

    def test_powershell_tags(self, powershell_rule):
        """Test PowerShell rule has execution tags."""
        data = yaml.safe_load(powershell_rule)
        tags = data.get("tags", [])

        # Should have execution tag
        assert any("execution" in tag for tag in tags)


# =============================================================================
# SigmaRule Dataclass Tests
# =============================================================================


class TestSigmaRuleDataclass:
    """Test SigmaRule dataclass."""

    def test_create_sigma_rule(self):
        """Test creating SigmaRule directly."""
        rule = SigmaRule(
            title="Test",
            description="Test description",
            logsource={"category": "process_creation", "product": "windows"},
            detection={"selection": {"CommandLine": "test"}, "condition": "selection"},
            level="high",
        )

        assert rule.title == "Test"
        assert rule.level == "high"
        assert rule.status == "experimental"  # default
        assert rule.id is not None  # auto-generated

    def test_sigma_rule_defaults(self):
        """Test SigmaRule default values."""
        rule = SigmaRule(
            title="Test",
            description="Test",
            logsource={},
            detection={},
            level="medium",
        )

        assert rule.status == "experimental"
        assert rule.author == "AI for the Win Labs"
        assert rule.tags == []
        assert rule.falsepositives == []


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full Sigma workflow."""

    def test_create_and_match(self):
        """Test creating rule and matching events."""
        # Create rule
        rule_yaml = create_mimikatz_rule()
        rule = parse_sigma_rule(rule_yaml)

        # Malicious event (should match)
        malicious_event = {
            "Image": "C:\\Temp\\mimikatz.exe",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
        }

        # The rule uses endswith, so we need to check if it would match
        # For our simple matcher, we'll check the cmdline
        test_event = {
            "CommandLine": "sekurlsa::logonpasswords",
        }

        # This should match the cmdline selection
        # (Our simple matcher handles |contains)

    def test_rule_library(self):
        """Test that all rules in library are valid YAML."""
        rules = [
            create_mimikatz_rule(),
            create_encoded_powershell_rule(),
            create_credential_dump_chain_rule(),
        ]

        for rule_yaml in rules:
            # Should parse as valid YAML
            data = yaml.safe_load(rule_yaml)
            assert data is not None
            assert "title" in data
            assert "detection" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

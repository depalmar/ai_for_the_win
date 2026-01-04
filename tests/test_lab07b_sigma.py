"""Tests for Lab 07b: Sigma Rule Fundamentals."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab07b-sigma-fundamentals" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        SAMPLE_RULES,
        SigmaRule,
        match_log_event,
        parse_sigma_rule,
    )


def test_sample_rules_defined():
    """Test that sample rules are defined."""
    from main import SAMPLE_RULES

    assert len(SAMPLE_RULES) > 0


def test_sigma_rule_dataclass():
    """Test SigmaRule dataclass structure."""
    from main import SigmaRule

    rule = SigmaRule(
        title="Test Rule",
        description="A test rule",
        logsource={"product": "windows"},
        detection={"selection": {"EventID": 4688}},
        level="medium",
    )

    assert rule.title == "Test Rule"
    assert rule.level == "medium"


def test_parse_sigma_rule():
    """Test parsing a Sigma rule."""
    from main import parse_sigma_rule

    yaml_content = """
    title: Suspicious PowerShell
    description: Detects suspicious PowerShell execution
    logsource:
        product: windows
        service: powershell
    detection:
        selection:
            ScriptBlockText|contains:
                - 'Invoke-Expression'
                - 'IEX'
        condition: selection
    level: medium
    """

    rule = parse_sigma_rule(yaml_content)

    assert rule.title == "Suspicious PowerShell"
    assert rule.level == "medium"
    assert "selection" in rule.detection


def test_match_log_event_positive():
    """Test matching a log event that should trigger."""
    from main import match_log_event, parse_sigma_rule

    yaml_content = """
    title: Test Rule
    description: Test
    logsource:
        product: windows
    detection:
        selection:
            EventID: 4688
            CommandLine|contains: 'powershell'
        condition: selection
    level: high
    """

    rule = parse_sigma_rule(yaml_content)

    event = {
        "EventID": 4688,
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass",
    }

    assert match_log_event(rule, event) is True


def test_match_log_event_negative():
    """Test matching a log event that should not trigger."""
    from main import match_log_event, parse_sigma_rule

    yaml_content = """
    title: Test Rule
    description: Test
    logsource:
        product: windows
    detection:
        selection:
            EventID: 4688
            CommandLine|contains: 'mimikatz'
        condition: selection
    level: high
    """

    rule = parse_sigma_rule(yaml_content)

    event = {
        "EventID": 4688,
        "CommandLine": "notepad.exe document.txt",
    }

    assert match_log_event(rule, event) is False

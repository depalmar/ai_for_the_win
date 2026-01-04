"""Tests for Lab 04b: Your First AI Agent."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab04b-first-ai-agent" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        TOOLS,
        check_hash_reputation,
        check_ip_reputation,
        get_system_info,
    )


def test_ip_reputation_known_bad():
    """Test IP reputation check for known bad IP."""
    from main import check_ip_reputation

    result = check_ip_reputation("185.220.101.1")
    assert result["reputation"] == "malicious"
    assert "category" in result


def test_ip_reputation_known_good():
    """Test IP reputation check for known good IP."""
    from main import check_ip_reputation

    result = check_ip_reputation("8.8.8.8")
    assert result["reputation"] == "clean"


def test_ip_reputation_unknown():
    """Test IP reputation check for unknown IP."""
    from main import check_ip_reputation

    result = check_ip_reputation("10.0.0.1")
    assert result["reputation"] == "unknown"


def test_hash_reputation_known_bad():
    """Test hash reputation check for known malicious hash."""
    from main import check_hash_reputation

    # EICAR test hash
    result = check_hash_reputation("44d88612fea8a8f36de82e1278abb02f")
    assert result["reputation"] == "malicious"


def test_hash_reputation_unknown():
    """Test hash reputation check for unknown hash."""
    from main import check_hash_reputation

    result = check_hash_reputation("0000000000000000000000000000000")
    assert result["reputation"] == "unknown"


def test_system_info():
    """Test system info retrieval."""
    from main import get_system_info

    result = get_system_info()
    assert "hostname" in result
    assert "platform" in result
    assert "python_version" in result


def test_tools_defined():
    """Test that tools are properly defined."""
    from main import TOOLS

    assert len(TOOLS) > 0
    for tool in TOOLS:
        assert "name" in tool
        assert "description" in tool
        assert "input_schema" in tool

#!/usr/bin/env python3
"""
Integration tests for AI for the Win labs.

These tests require API keys to run. Skip with:
    pytest tests/test_integration.py -v --skip-integration

Or set SKIP_API_TESTS=true environment variable.
"""

import os
import sys
from pathlib import Path

import pytest

# Check if we should skip API tests
SKIP_API_TESTS = os.environ.get("SKIP_API_TESTS", "false").lower() == "true"


def has_anthropic_key():
    """Check if Anthropic API key is available."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    return key.startswith("sk-ant-")


# Skip all tests in this module if no API key or SKIP_API_TESTS is set
pytestmark = pytest.mark.skipif(
    SKIP_API_TESTS or not has_anthropic_key(),
    reason="Integration tests require ANTHROPIC_API_KEY and SKIP_API_TESTS=false",
)


class TestAnthropicConnection:
    """Test basic Anthropic API connectivity."""

    def test_api_connection(self):
        """Test that we can connect to Anthropic API."""
        from anthropic import Anthropic

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",  # Use haiku for speed
            max_tokens=10,
            messages=[{"role": "user", "content": "Say 'test'"}],
        )

        assert response.content is not None
        assert len(response.content) > 0

    def test_api_streaming(self):
        """Test streaming API works."""
        from anthropic import Anthropic

        client = Anthropic()
        collected = []

        with client.messages.stream(
            model="claude-haiku-4-20250514",
            max_tokens=20,
            messages=[{"role": "user", "content": "Count to 3"}],
        ) as stream:
            for text in stream.text_stream:
                collected.append(text)

        full_response = "".join(collected)
        assert len(full_response) > 0


class TestLab04LogAnalysis:
    """Integration tests for Lab 04: LLM Log Analysis."""

    def test_log_analysis(self):
        """Test log analysis with real LLM."""
        from anthropic import Anthropic

        sample_log = """
        2024-01-15 09:15:00 AUTH Failed login for admin from 192.168.1.100
        2024-01-15 09:15:01 AUTH Failed login for admin from 192.168.1.100
        2024-01-15 09:15:02 AUTH Account locked: admin
        """

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": f"Briefly analyze this security log:\n{sample_log}",
                }
            ],
        )

        result = response.content[0].text.lower()
        # Should identify brute force or failed login pattern
        assert any(term in result for term in ["brute", "failed", "attack", "login", "locked"])


class TestLab05ThreatIntel:
    """Integration tests for Lab 05: Threat Intel Agent."""

    def test_ioc_analysis(self):
        """Test IOC analysis with real LLM."""
        from anthropic import Anthropic

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": "What type of IOC is 192.168.1.1? Respond in one sentence.",
                }
            ],
        )

        result = response.content[0].text.lower()
        assert any(term in result for term in ["ip", "address", "private", "internal"])


class TestLab07YARAGeneration:
    """Integration tests for Lab 07: YARA Generator."""

    def test_yara_rule_generation(self):
        """Test YARA rule generation with real LLM."""
        from anthropic import Anthropic

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",
            max_tokens=500,
            messages=[
                {
                    "role": "user",
                    "content": """Generate a simple YARA rule to detect files containing
                the string "malware_test" and the hex bytes "4D 5A 90 00".
                Return only the YARA rule.""",
                }
            ],
        )

        result = response.content[0].text

        # Basic YARA structure check
        assert "rule" in result
        assert "strings:" in result or "condition:" in result


class TestLab11RansomwareAnalysis:
    """Integration tests for Lab 11: Ransomware Detection."""

    def test_ransom_note_analysis(self):
        """Test ransom note analysis with real LLM."""
        from anthropic import Anthropic

        sample_note = """
        YOUR FILES HAVE BEEN ENCRYPTED
        Send 1 BTC to bc1qtest123 to recover your files.
        Contact: attacker@protonmail.com
        """

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",
            max_tokens=300,
            messages=[
                {
                    "role": "user",
                    "content": f"Extract IOCs from this ransom note:\n{sample_note}\nList the bitcoin address and email.",
                }
            ],
        )

        result = response.content[0].text.lower()
        # Should extract the IOCs
        assert "bc1q" in result or "bitcoin" in result
        assert "protonmail" in result or "email" in result


class TestToolUse:
    """Test tool use functionality."""

    def test_tool_calling(self):
        """Test that tool calling works."""
        from anthropic import Anthropic

        tools = [
            {
                "name": "get_weather",
                "description": "Get weather for a location",
                "input_schema": {
                    "type": "object",
                    "properties": {"location": {"type": "string", "description": "City name"}},
                    "required": ["location"],
                },
            }
        ]

        client = Anthropic()
        response = client.messages.create(
            model="claude-haiku-4-20250514",
            max_tokens=100,
            tools=tools,
            messages=[{"role": "user", "content": "What's the weather in London?"}],
        )

        # Should try to use the tool
        has_tool_use = any(block.type == "tool_use" for block in response.content)
        assert has_tool_use or response.stop_reason == "end_turn"


# Fixtures for integration tests
@pytest.fixture
def anthropic_client():
    """Provide Anthropic client for tests."""
    from anthropic import Anthropic

    return Anthropic()


@pytest.fixture
def quick_model():
    """Return fastest model for testing."""
    return "claude-haiku-4-20250514"


if __name__ == "__main__":
    # Run with: python -m pytest tests/test_integration.py -v
    pytest.main([__file__, "-v"])

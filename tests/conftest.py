#!/usr/bin/env python3
"""Pytest configuration and shared fixtures for AI Security Labs tests."""

import sys
from pathlib import Path

import pytest

# Add labs directory to path
LABS_DIR = Path(__file__).parent.parent / "labs"
sys.path.insert(0, str(LABS_DIR))


@pytest.fixture(scope="session")
def labs_dir():
    """Return the labs directory path."""
    return LABS_DIR


@pytest.fixture(scope="session")
def test_data_dir(tmp_path_factory):
    """Create a shared temporary directory for test data."""
    return tmp_path_factory.mktemp("test_data")


@pytest.fixture
def mock_llm():
    """Create a mock LLM for testing without API calls."""

    class MockLLM:
        def invoke(self, messages):
            class Response:
                content = "Mock LLM response for testing."

            return Response()

    return MockLLM()


@pytest.fixture
def mock_api_key(monkeypatch):
    """Set a mock API key for testing."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-api-key-for-testing")

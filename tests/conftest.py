#!/usr/bin/env python3
"""Pytest configuration and shared fixtures for AI Security Labs tests."""

import os
import sys
from pathlib import Path

import pytest

# Add labs directory to path
LABS_DIR = Path(__file__).parent.parent / "labs"
sys.path.insert(0, str(LABS_DIR))


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "requires_api: Tests that require an LLM API key (ANTHROPIC, OPENAI, or GOOGLE)"
    )
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line("markers", "integration: Integration tests")


def pytest_collection_modifyitems(config, items):
    """Skip tests marked with requires_api if no API key or LangChain is available."""
    # Check if any LLM API key is available
    has_api_key = any(
        [
            os.environ.get("ANTHROPIC_API_KEY"),
            os.environ.get("OPENAI_API_KEY"),
            os.environ.get("GOOGLE_API_KEY"),
        ]
    )

    # Check if LangChain is available
    try:
        from langchain_anthropic import ChatAnthropic

        has_langchain = True
    except ImportError:
        has_langchain = False

    # Tests require both API key AND LangChain
    can_run_api_tests = has_api_key and has_langchain

    if not can_run_api_tests:
        if not has_api_key:
            reason = (
                "No LLM API key available (ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)"
            )
        else:
            reason = "LangChain not installed (pip install langchain langchain-anthropic)"
        skip_api = pytest.mark.skip(reason=reason)
        for item in items:
            # Check for requires_api marker on item or any parent (class)
            if item.get_closest_marker("requires_api"):
                item.add_marker(skip_api)


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

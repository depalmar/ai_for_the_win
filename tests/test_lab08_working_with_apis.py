"""Tests for Lab 00g: Working with APIs."""

import os
import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab00g-working-with-apis" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import basic_get_request, get_api_key, rate_limited_requests, safe_request


def test_get_api_key():
    """Test API key retrieval from environment."""
    from main import get_api_key

    # Set test key
    os.environ["TEST_KEY_12345"] = "secret_value"

    # Should retrieve
    key = get_api_key("TEST_KEY_12345")
    assert key == "secret_value"

    # Should return None for missing
    missing = get_api_key("NONEXISTENT_KEY_ABCDEF")
    assert missing is None

    # Cleanup
    del os.environ["TEST_KEY_12345"]


@pytest.mark.requires_api
def test_basic_get_request():
    """Test basic GET request (requires internet)."""
    from main import basic_get_request

    result = basic_get_request("https://httpbin.org/get")
    assert result is not None
    assert "origin" in result


@pytest.mark.requires_api
def test_safe_request_handles_errors():
    """Test that safe_request handles errors gracefully."""
    from main import safe_request

    # Invalid URL should return None, not raise
    result = safe_request("https://this-domain-does-not-exist-12345.invalid")
    assert result is None


def test_rate_limited_structure():
    """Test rate limiting function structure."""
    from main import rate_limited_requests

    # Should accept list of URLs and return list
    # Can't test timing without real requests
    assert callable(rate_limited_requests)

#!/usr/bin/env python3
"""Pytest configuration and shared fixtures for AI Security Labs tests."""

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Labs directory path
LABS_DIR = Path(__file__).parent.parent / "labs"

# Module cache for imported lab modules (keyed by full path to avoid conflicts)
_lab_module_cache: dict[str, Any] = {}


def import_lab_module(lab_name: str, module_name: str = "main", subdir: str = "solution") -> Any:
    """
    Import a module from a specific lab's directory, bypassing Python's module cache.

    This solves the problem where multiple test files trying to `from main import ...`
    all get the same cached module, even after manipulating sys.path.

    Args:
        lab_name: The lab directory name (e.g., "lab00f-hello-world-ml")
        module_name: The module to import (default: "main")
        subdir: The subdirectory within the lab (default: "solution")

    Returns:
        The imported module object

    Example:
        lab = import_lab_module("lab00f-hello-world-ml")
        features = lab.extract_features("test message")
    """
    module_path = LABS_DIR / lab_name / subdir / f"{module_name}.py"

    if not module_path.exists():
        raise FileNotFoundError(f"Module not found: {module_path}")

    # Use full path as cache key to handle same module name in different labs
    cache_key = str(module_path)

    if cache_key not in _lab_module_cache:
        # Create a unique module name to avoid conflicts with Python's sys.modules
        unique_name = f"_lab_test_{lab_name.replace('-', '_')}_{module_name}"

        spec = importlib.util.spec_from_file_location(unique_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module spec from {module_path}")

        module = importlib.util.module_from_spec(spec)
        # Don't add to sys.modules to avoid pollution
        spec.loader.exec_module(module)
        _lab_module_cache[cache_key] = module

    return _lab_module_cache[cache_key]


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "requires_api: Tests that require an LLM API key (ANTHROPIC, OPENAI, or GOOGLE)"
    )
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line("markers", "integration: Integration tests")


def pytest_runtest_setup(item):
    """
    Reset sys.path and clear 'main' module cache before each test.

    Problem: All test files call sys.path.insert() at module load time during pytest
    collection. By the time tests run, sys.path contains ALL lab directories.
    When tests do 'from main import X', Python may find the wrong main.py.

    Solution: Before each test, remove all lab solution directories from sys.path,
    then add only the correct lab's directory based on the test file name.
    """
    # Remove 'main' from module cache
    if "main" in sys.modules:
        del sys.modules["main"]

    # Remove all lab solution directories from sys.path
    labs_str = str(LABS_DIR)
    sys.path[:] = [p for p in sys.path if labs_str not in p or "solution" not in p]

    # Determine which lab this test belongs to from the test file name
    # e.g., test_lab00f_hello_world_ml.py -> lab00f-hello-world-ml
    test_file = Path(item.fspath).stem  # e.g., "test_lab00f_hello_world_ml"
    if test_file.startswith("test_lab"):
        # Extract lab identifier: test_lab00f_hello_world_ml -> lab00f_hello_world_ml
        lab_part = test_file[5:]  # Remove "test_"

        # Convert underscores to hyphens and find matching lab directory
        lab_name_pattern = lab_part.replace("_", "-")

        # Find the actual lab directory (handles naming variations)
        for lab_dir in LABS_DIR.iterdir():
            if lab_dir.is_dir() and lab_dir.name.startswith(lab_name_pattern.split("-")[0]):
                # Check if this is likely the right lab
                lab_normalized = lab_dir.name.replace("-", "_")
                if lab_normalized.startswith(lab_part.split("_")[0]):
                    solution_dir = lab_dir / "solution"
                    if solution_dir.exists():
                        sys.path.insert(0, str(solution_dir))
                        break


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

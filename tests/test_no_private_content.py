#!/usr/bin/env python3
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
r"""
Test to ensure no private content or local paths are committed.

This test prevents accidental commits of:
- Private review reports (CURRICULUM_REVIEW_REPORT.md)
- Internal documentation (*_INTERNAL.md)
- Files containing local developer paths (c:\Users\depal\...)
- Temporary files meant for local use only
"""

import re
from pathlib import Path

import pytest

# Patterns for files that should never be committed
PRIVATE_FILE_PATTERNS = [
    "**/CURRICULUM_REVIEW_REPORT.md",
    "**/*_INTERNAL.md",
    "**/*_PRIVATE.md",
    "**/TODO_PRIVATE.md",
    "**/NOTES_PRIVATE.md",
]

# Local path patterns that should never appear in committed files
LOCAL_PATH_PATTERNS = [
    r"c:\\Users\\depal",  # Windows local path
    r"C:\\Users\\depal",  # Windows local path (caps)
    r"/Users/depal",  # Mac local path (if applicable)
    r"\\depal\\",  # Any depal username reference
]

# Directories to skip checking
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    "dist",
    "build",
    ".egg-info",
    ".ipynb_checkpoints",
    ".claude",  # Local settings
}

# File extensions to check for local paths
TEXT_EXTENSIONS = {
    ".md",
    ".py",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".sh",
    ".bash",
    ".rst",
    ".toml",
    ".ini",
    ".cfg",
}


def should_skip_path(path: Path) -> bool:
    """Check if path should be skipped."""
    return any(part in SKIP_DIRS for part in path.parts)


def test_no_private_files():
    """Ensure no private files are committed."""
    root = Path(".")
    found_private_files = []

    for pattern in PRIVATE_FILE_PATTERNS:
        for file in root.glob(pattern):
            if not should_skip_path(file):
                found_private_files.append(str(file))

    assert not found_private_files, (
        f"Found {len(found_private_files)} private file(s) that should not be committed:\n"
        + "\n".join(f"  - {f}" for f in found_private_files)
        + "\n\nThese files should be added to .gitignore or removed."
    )


def test_no_local_paths_in_files():
    """Ensure no files contain local developer paths."""
    root = Path(".")
    files_with_local_paths = []

    # Compile regex patterns
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in LOCAL_PATH_PATTERNS]

    # Check all text files
    for file in root.rglob("*"):
        if not file.is_file() or should_skip_path(file):
            continue

        # Skip this test file itself (it contains examples)
        if file.name == "test_no_private_content.py":
            continue

        if file.suffix not in TEXT_EXTENSIONS:
            continue

        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check for local path patterns
            for pattern in compiled_patterns:
                if pattern.search(content):
                    # Get the matching line for better error reporting
                    matching_lines = [
                        (i + 1, line.strip())
                        for i, line in enumerate(content.split("\n"))
                        if pattern.search(line)
                    ]

                    files_with_local_paths.append(
                        {
                            "file": str(file),
                            "pattern": pattern.pattern,
                            "lines": matching_lines[:3],  # Show first 3 matches
                        }
                    )
                    break  # Only report once per file

        except Exception:
            # Skip files that can't be read
            continue

    if files_with_local_paths:
        error_msg = (
            f"Found {len(files_with_local_paths)} file(s) containing local developer paths:\n\n"
        )

        for item in files_with_local_paths:
            error_msg += f"  {item['file']}\n"
            error_msg += f"    Pattern: {item['pattern']}\n"
            error_msg += "    Lines:\n"
            for line_num, line_text in item["lines"]:
                error_msg += f"      L{line_num}: {line_text[:80]}...\n"
            error_msg += "\n"

        error_msg += (
            "Local paths should be replaced with:\n"
            "  - Relative paths (e.g., 'docs/file.md')\n"
            "  - Generic placeholders (e.g., '/path/to/repo')\n"
            "  - Environment variables (e.g., '$HOME/.config')\n"
        )

        pytest.fail(error_msg)


def test_gitignore_includes_private_patterns():
    """Ensure .gitignore includes patterns for private files."""
    gitignore = Path(".gitignore")

    if not gitignore.exists():
        pytest.skip(".gitignore not found")

    with open(gitignore, "r") as f:
        gitignore_content = f.read()

    # These patterns should be in .gitignore
    expected_patterns = [
        "*_PRIVATE.md",
        "*_INTERNAL.md",
        "CURRICULUM_REVIEW_REPORT.md",
    ]

    missing_patterns = []
    for pattern in expected_patterns:
        # Check if pattern or commented version exists
        if pattern not in gitignore_content and f"# {pattern}" not in gitignore_content:
            missing_patterns.append(pattern)

    if missing_patterns:
        patterns_list = "\n".join(f"  {p}" for p in missing_patterns)
        pytest.fail(f"The following patterns should be added to .gitignore:\n{patterns_list}")


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v"])

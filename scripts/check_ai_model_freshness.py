#!/usr/bin/env python3
"""
Check AI model references for freshness.

AI models update frequently - this script flags outdated model references.

Usage:
    python scripts/check_ai_model_freshness.py
    python scripts/check_ai_model_freshness.py --strict
"""

import re
import sys
from pathlib import Path

# Current model versions (update these when new models release)
# Last updated: January 2026
CURRENT_MODELS = {
    # Anthropic Claude
    "claude": {
        "current": ["claude-3-5-sonnet", "claude-3-5-haiku", "claude-opus-4", "claude-sonnet-4"],
        "outdated": [
            "claude-2",
            "claude-instant",
            "claude-3-opus",
            "claude-3-sonnet",
            "claude-3-haiku",
        ],
        "note": "Claude 3.5 Sonnet is current workhorse; Claude 4 (Opus/Sonnet) released late 2025",
    },
    # OpenAI GPT
    "gpt": {
        "current": ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini", "o1", "o1-mini", "o1-pro"],
        "outdated": ["gpt-3.5-turbo", "gpt-4-0314", "gpt-4-0613", "text-davinci"],
        "note": "GPT-4o is current default; o1 series for reasoning",
    },
    # Google Gemini
    "gemini": {
        "current": ["gemini-2.0", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        "outdated": ["gemini-pro", "gemini-1.0", "bard", "palm"],
        "note": "Gemini 2.0 released Dec 2024; 1.5 Pro still widely used",
    },
    # Meta Llama
    "llama": {
        "current": ["llama-3.3", "llama-3.2", "llama-3.1"],
        "outdated": ["llama-2", "llama-1", "llama-3.0"],
        "note": "Llama 3.3 70B released Dec 2024",
    },
    # Mistral
    "mistral": {
        "current": ["mistral-large", "mistral-medium", "mixtral-8x22b", "codestral"],
        "outdated": ["mistral-7b-v0.1", "mixtral-8x7b"],
        "note": "Mistral Large 2 released 2024",
    },
}

# Files to check for model references
MODEL_REFERENCE_PATTERNS = [
    "labs/**/README.md",
    "docs/guides/*.md",
    "notebooks/*.ipynb",
    "*.md",
]


def find_model_references(content: str) -> list[dict]:
    """Find AI model references in content."""
    issues = []

    for family, info in CURRENT_MODELS.items():
        for outdated in info["outdated"]:
            # Case-insensitive search for outdated models with word boundaries
            # Use \b to avoid matching substrings (e.g., 'palm' in 'depalmar')
            pattern = re.compile(r"\b" + re.escape(outdated) + r"\b", re.IGNORECASE)
            matches = pattern.findall(content)
            if matches:
                issues.append(
                    {
                        "family": family,
                        "outdated_model": outdated,
                        "current_options": info["current"],
                        "note": info["note"],
                        "count": len(matches),
                    }
                )

    return issues


def check_file(filepath: Path) -> list[str]:
    """Check a file for outdated model references."""
    issues = []

    if not filepath.exists():
        return []

    try:
        content = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []  # Skip binary files

    model_issues = find_model_references(content)

    for issue in model_issues:
        issues.append(
            f"{filepath.name}: References outdated '{issue['outdated_model']}' "
            f"({issue['count']}x). Current: {', '.join(issue['current_options'][:3])}"
        )

    return issues


def main():
    """Run model freshness checks."""
    strict = "--strict" in sys.argv
    project_root = Path(__file__).parent.parent

    all_issues = []
    files_checked = 0

    print("Checking AI model references for freshness...\n")

    # Check all markdown files
    for pattern in ["**/*.md"]:
        for filepath in project_root.glob(pattern):
            # Skip node_modules, .git, etc.
            if any(part.startswith(".") or part == "node_modules" for part in filepath.parts):
                continue

            issues = check_file(filepath)
            files_checked += 1

            if issues:
                all_issues.extend(issues)

    # Check notebooks
    for filepath in project_root.glob("notebooks/*.ipynb"):
        issues = check_file(filepath)
        files_checked += 1
        if issues:
            all_issues.extend(issues)

    print(f"Checked {files_checked} files\n")

    if all_issues:
        print(f"Found {len(all_issues)} outdated model references:\n")
        for issue in all_issues[:20]:  # Limit output
            print(f"  - {issue}")
        if len(all_issues) > 20:
            print(f"  ... and {len(all_issues) - 20} more")

        print("\n" + "=" * 60)
        print("Current Model Reference Guide:")
        print("=" * 60)
        for family, info in CURRENT_MODELS.items():
            print(f"\n{family.upper()}:")
            print(f"  Current: {', '.join(info['current'][:4])}")
            print(f"  Note: {info['note']}")

        return 1 if strict else 0
    else:
        print("All AI model references appear current")
        return 0


if __name__ == "__main__":
    sys.exit(main())

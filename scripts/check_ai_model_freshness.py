#!/usr/bin/env python3
"""
Check AI model references for freshness.

AI models update frequently - this script flags model references that are retired,
retiring, or outdated.

Two checks:

1. Retired and retiring model IDs (DEPRECATED_MODELS). An ID used as a string literal
   in code (.py, .json, .yaml, .toml, or a notebook code cell) is an ERROR and makes the
   script exit 1: requests to it already fail, or will on the listed date. Mentions in
   prose (Markdown, comments, docstrings, notebook markdown cells) are warnings, so
   historical notes can stay.
2. Outdated model families in Markdown (CURRENT_MODELS[...]["outdated"]): warnings.

Warnings only fail the run with --strict.

Usage:
    python scripts/check_ai_model_freshness.py
    python scripts/check_ai_model_freshness.py --strict
"""

import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import NamedTuple

# Retired and retiring model IDs, copied from each provider's deprecation page.
# Last verified: 2026-11-20 (web search, then a direct read of each page).
# IMPORTANT: re-verify with a web search before updating (see CLAUDE.md).
#
# Key: the API model ID as the provider writes it. Dated snapshots of it
# (-20250929, -2025-08-07, @20250929) match too.
# Value: (retirement or shutdown date, the provider's recommended replacement).
# A date on or before today means retired (requests fail); a later date means retiring.
DEPRECATED_MODELS: dict[str, tuple[str, str]] = {
    # Anthropic - https://platform.claude.com/docs/en/about-claude/model-deprecations
    "claude-sonnet-4-5": ("2026-11-30", "claude-sonnet-5-5"),
    "claude-sonnet-4.5": ("2026-11-30", "claude-sonnet-5-5"),  # dotted form is not a valid ID
    "claude-sonnet-4": ("2026-06-15", "claude-sonnet-5-5"),
    "claude-opus-4-1": ("2026-08-05", "claude-opus-4-8"),
    "claude-opus-4": ("2026-06-15", "claude-opus-4-8"),
    "claude-3-7-sonnet": ("2026-02-19", "claude-sonnet-5-5"),
    "claude-3-5-sonnet": ("2025-10-28", "claude-sonnet-5-5"),
    "claude-3-5-haiku": ("2026-02-19", "claude-haiku-4-5-20251001"),
    "claude-3-haiku": ("2026-04-20", "claude-haiku-4-5-20251001"),
    "claude-3-opus": ("2026-01-05", "claude-opus-4-8"),
    "claude-3-sonnet": ("2025-07-21", "claude-sonnet-5-5"),
    # OpenAI - https://developers.openai.com/api/docs/deprecations
    "gpt-5": ("2026-12-11", "gpt-6.1-sol"),
    "gpt-5-mini": ("2026-12-11", "gpt-6.1-terra"),
    "gpt-5-nano": ("2026-12-11", "gpt-6-luna"),
    "gpt-5-pro": ("2026-12-11", "gpt-6.1-sol"),
    "o3": ("2026-12-11", "gpt-6.1-sol"),
    "o3-pro": ("2026-12-11", "gpt-6.1-sol"),
    "o3-mini": ("2026-10-23", "gpt-5.6-sol"),
    "o1": ("2026-10-23", "gpt-5.6-sol"),
    "o1-pro": ("2026-10-23", "gpt-5.6-sol"),
    # Google - https://ai.google.dev/gemini-api/docs/deprecations
    "gemini-2.5-pro": ("2026-12-01", "gemini-3.8-flash"),
    "gemini-2.5-flash": ("2026-12-01", "gemini-3.5-flash-lite"),
    "gemini-3-pro-preview": ("2026-03-09", "gemini-3.1-pro-preview"),
}

# Current model versions, shown in the report as a reference guide.
# Last updated: 2026-11-20 (via web search)
# IMPORTANT: Always verify with web search before updating - AI model landscape changes rapidly
CURRENT_MODELS = {
    # Anthropic Claude - https://platform.claude.com/docs/en/about-claude/models/overview
    "claude": {
        "current": [
            "claude-sonnet-5-5",
            "claude-opus-5-5",
            "claude-haiku-5-5",
            "claude-fable-5-2",
        ],
        "outdated": [
            "claude-2",
            "claude-instant",
        ],
        "note": (
            "Sonnet 4.5 retires 2026-11-30; Sonnet 4 and Opus 4 retired 2026-06-15; "
            "Claude 3 series retired"
        ),
    },
    # OpenAI GPT - https://developers.openai.com/api/docs/models
    "gpt": {
        "current": ["gpt-6.2-sol", "gpt-6.2-astra", "gpt-6.1-terra", "gpt-6-luna"],
        "outdated": ["gpt-3.5-turbo", "gpt-4-0314", "gpt-4-0613", "text-davinci"],
        "note": "GPT-5 and o3 shut down 2026-12-11; o1 and o3-mini shut down 2026-10-23",
    },
    # Google Gemini - https://ai.google.dev/gemini-api/docs/models
    "gemini": {
        "current": ["gemini-3.8-flash", "gemini-3.5-flash-lite"],
        "outdated": ["gemini-pro", "gemini-1.0", "bard", "palm"],
        "note": "Gemini 2.5 Pro and Flash shut down 2026-12-01; Gemini 3.8 Flash is stable",
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

CODE_SUFFIXES = {".py", ".ipynb", ".json", ".yaml", ".yml", ".toml"}
PROSE_SUFFIXES = {".md"}
SKIP_DIRS = {"node_modules", "venv", "__pycache__"}
# Files that list deprecated IDs on purpose
SKIP_FILES = {"scripts/check_ai_model_freshness.py", "tests/test_ai_model_freshness.py"}

_SNAPSHOT = r"(?:-\d{8}|-\d{4}-\d{2}-\d{2}|@\d{8})?"
# Not preceded by a word character or "-"; not followed by one, or by ".<digit>".
# So "gpt-5" does not match "gpt-5.2" or "gpt-5-mini", and "claude-sonnet-4" does not
# match "claude-sonnet-4-5", but a sentence ending in "gpt-5." still matches.
_DEPRECATED_PATTERNS = [
    (
        model_id,
        re.compile(r"(?<![\w-])(" + re.escape(model_id) + _SNAPSHOT + r")(?![\w-]|\.\d)"),
    )
    for model_id in DEPRECATED_MODELS
]


class Finding(NamedTuple):
    """One retired or retiring model ID found in a file."""

    path: str
    location: str  # "line 12" or "cell 3, line 4"
    model_id: str  # as written, e.g. claude-sonnet-4-20250514
    base_id: str  # key in DEPRECATED_MODELS
    is_error: bool  # string literal in code (vs. prose)


def deprecation_status(base_id: str, today: date) -> str:
    """Describe a deprecated model's status, e.g. 'retired 2026-06-15; use X'."""
    retire_on, replacement = DEPRECATED_MODELS[base_id]
    retire_date = date.fromisoformat(retire_on)
    if retire_date <= today:
        status = f"retired {retire_on}"
    else:
        status = f"retires {retire_on} (in {(retire_date - today).days} days)"
    return f"{status}; use {replacement}"


def scan_text(text: str, is_code: bool) -> list[tuple[int, str, str, bool]]:
    """Find deprecated model IDs in text.

    Returns (line_number, model_id_as_written, base_id, is_error) tuples. In code,
    an ID inside quotes is an error; an unquoted one (comment, docstring) is a warning.
    """
    found = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for base_id, pattern in _DEPRECATED_PATTERNS:
            for match in pattern.finditer(line):
                before = line[match.start() - 1] if match.start() > 0 else ""
                after = line[match.end()] if match.end() < len(line) else ""
                # "\" covers the escaped quotes of code embedded in JSON strings
                quoted = before in ('"', "'") and after in ('"', "'", "\\")
                found.append((line_no, match.group(1), base_id, is_code and quoted))
    return found


def scan_file(filepath: Path, project_root: Path) -> list[Finding]:
    """Find deprecated model IDs in one file."""
    rel = filepath.relative_to(project_root).as_posix()
    try:
        content = filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError, OSError):
        return []

    if filepath.suffix == ".ipynb":
        try:
            cells = json.loads(content).get("cells", [])
        except json.JSONDecodeError:
            return []
        findings = []
        for cell_no, cell in enumerate(cells):
            source = cell.get("source", "")
            text = "".join(source) if isinstance(source, list) else source
            is_code = cell.get("cell_type") == "code"
            for line_no, model_id, base_id, is_error in scan_text(text, is_code):
                location = f"cell {cell_no}, line {line_no}"
                findings.append(Finding(rel, location, model_id, base_id, is_error))
        return findings

    is_code = filepath.suffix in CODE_SUFFIXES
    return [
        Finding(rel, f"line {line_no}", model_id, base_id, is_error)
        for line_no, model_id, base_id, is_error in scan_text(content, is_code)
    ]


def iter_files(project_root: Path):
    """Yield code and prose files to scan, skipping hidden and vendored directories."""
    for filepath in sorted(project_root.rglob("*")):
        if filepath.suffix not in CODE_SUFFIXES | PROSE_SUFFIXES or not filepath.is_file():
            continue
        rel = filepath.relative_to(project_root)
        if any(part.startswith(".") or part in SKIP_DIRS for part in rel.parts):
            continue
        if rel.as_posix() in SKIP_FILES:
            continue
        yield filepath


def find_model_references(content: str) -> list[dict]:
    """Find outdated model-family references in content."""
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
    """Check a file for outdated model-family references."""
    issues = []

    if not filepath.exists():
        return []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return []  # Skip binary or locked files

    model_issues = find_model_references(content)

    for issue in model_issues:
        issues.append(
            f"{filepath.name}: References outdated '{issue['outdated_model']}' "
            f"({issue['count']}x). Current: {', '.join(issue['current_options'][:3])}"
        )

    return issues


def _print_findings(title: str, findings: list[Finding], today: date, limit: int) -> None:
    print(f"{title}:\n")
    for f in findings[:limit]:
        status = deprecation_status(f.base_id, today)
        print(f"  - {f.path} ({f.location}): '{f.model_id}' {status}")
    if len(findings) > limit:
        print(f"  ... and {len(findings) - limit} more")
    print()


def main() -> int:
    """Run model freshness checks."""
    strict = "--strict" in sys.argv
    project_root = Path(__file__).parent.parent
    today = date.today()

    print(f"Checking AI model references for freshness (as of {today.isoformat()})...\n")

    files_checked = 0
    findings: list[Finding] = []
    outdated_issues: list[str] = []
    for filepath in iter_files(project_root):
        files_checked += 1
        findings.extend(scan_file(filepath, project_root))
        if filepath.suffix in PROSE_SUFFIXES or filepath.suffix == ".ipynb":
            outdated_issues.extend(check_file(filepath))

    errors = [f for f in findings if f.is_error]
    prose = [f for f in findings if not f.is_error]

    print(f"Checked {files_checked} files\n")

    if errors:
        title = f"ERROR: {len(errors)} retired or retiring model IDs used in code"
        _print_findings(title, errors, today, limit=50)
    if prose:
        title = (
            f"Warning: {len(prose)} mentions of retired or retiring model IDs in prose "
            "(fine if historical; update copy-paste code samples)"
        )
        _print_findings(title, prose, today, limit=10)
    if outdated_issues:
        print(f"Warning: {len(outdated_issues)} outdated model-family references:\n")
        for issue in outdated_issues[:20]:
            print(f"  - {issue}")
        if len(outdated_issues) > 20:
            print(f"  ... and {len(outdated_issues) - 20} more")
        print()

    if not (errors or prose or outdated_issues):
        print("All AI model references appear current")
        return 0

    print("=" * 60)
    print("Current Model Reference Guide:")
    print("=" * 60)
    for family, info in CURRENT_MODELS.items():
        print(f"\n{family.upper()}:")
        print(f"  Current: {', '.join(info['current'][:4])}")
        print(f"  Note: {info['note']}")

    if errors:
        return 1
    print("\nNo retired or retiring model IDs in code (warnings only)")
    return 1 if strict else 0


if __name__ == "__main__":
    sys.exit(main())

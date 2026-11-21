#!/usr/bin/env python3
"""
Check threat intelligence files for freshness.

Distinguishes between:
- Historical context (timelines, evolution) - old dates allowed
- Current threat sections - must have 2024+ dates

Also reads each file's "Updated <Month> <Year>" stamp near the top. A stamp older
than STAMP_MAX_AGE_DAYS is reported as a note; with --strict it counts as an issue.
It is a note by default so the CI job does not start failing unrelated pull requests
on a calendar date. Run /update-threat-intel when a note appears.

Usage:
    python scripts/check_threat_intel_freshness.py
    python scripts/check_threat_intel_freshness.py --strict
"""

import re
import sys
from datetime import date
from pathlib import Path

# Files that contain threat intelligence
THREAT_INTEL_FILES = [
    "labs/lab30-ransomware-fundamentals/README.md",
    "labs/lab31-ransomware-detection/README.md",
    "labs/lab37-ai-powered-threat-actors/README.md",
    "labs/lab40-llm-security-testing/README.md",
    "docs/guides/threat-landscape-2025.md",
]

# Section headers that indicate CURRENT content (must have recent dates)
CURRENT_SECTIONS = [
    r"current.*threats?",
    r"active.*threats?",
    r"202[5-9].*threats?",
    r"key.*202[5-9]",
    r"known.*attack.*groups",
    r"current.*active",
]

# Section headers that indicate HISTORICAL content (old dates OK)
HISTORICAL_SECTIONS = [
    r"evolution",
    r"timeline",
    r"history",
    r"background",
    r"milestones?",
]

# Minimum year for "current" sections
CURRENT_YEAR_MIN = 2024

# An "Updated <Month> <Year>" stamp older than this many days is reported
STAMP_MAX_AGE_DAYS = 180
STAMP_SEARCH_LINES = 15

MONTHS = {
    name: number
    for number, name in enumerate(
        [
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
        ],
        start=1,
    )
}

# Matches "Updated January 2026", "Last updated: November 2026", "Updated 2026-11-21"
STAMP_PATTERN = re.compile(
    r"\b(?:last\s+)?updated\b[:*\s]*"
    r"(?:(?P<month>[a-z]+)\s+(?P<year>20\d{2})|(?P<iso>20\d{2}-\d{2})(?:-\d{2})?)",
    re.IGNORECASE,
)


def extract_years(text: str) -> list[int]:
    """Extract 4-digit years from text."""
    years = re.findall(r"\b(19\d{2}|20\d{2})\b", text)
    return [int(y) for y in years]


def get_section_type(header: str) -> str:
    """Determine if a section header indicates current or historical content."""
    header_lower = header.lower()

    for pattern in CURRENT_SECTIONS:
        if re.search(pattern, header_lower):
            return "current"

    for pattern in HISTORICAL_SECTIONS:
        if re.search(pattern, header_lower):
            return "historical"

    return "unknown"


def find_update_stamp(content: str) -> date | None:
    """Return the first "Updated <Month> <Year>" stamp near the top of a file, if any."""
    head = "\n".join(content.split("\n")[:STAMP_SEARCH_LINES])
    for match in STAMP_PATTERN.finditer(head):
        if match.group("iso"):
            year, month = (int(part) for part in match.group("iso").split("-"))
            return date(year, month, 1)
        month = MONTHS.get(match.group("month").lower())
        if month:
            return date(int(match.group("year")), month, 1)
    return None


def check_stamp(filepath: Path, label: str, today: date | None = None) -> str | None:
    """Return a note when a file's update stamp is missing or older than the limit."""
    if not filepath.exists():
        return None
    today = today or date.today()
    stamp = find_update_stamp(filepath.read_text(encoding="utf-8"))
    if stamp is None:
        return f"{label}: no 'Updated <Month> <Year>' stamp in the first lines"
    age = (today - stamp).days
    if age > STAMP_MAX_AGE_DAYS:
        return (
            f"{label}: stamped 'Updated {stamp:%B %Y}', {age} days ago "
            f"(limit {STAMP_MAX_AGE_DAYS})"
        )
    return None


def check_file(filepath: Path, strict: bool = False) -> list[str]:
    """Check a file for threat intel freshness issues."""
    issues = []

    if not filepath.exists():
        return [f"File not found: {filepath}"]

    content = filepath.read_text(encoding="utf-8")
    lines = content.split("\n")

    current_section = None
    current_section_type = "unknown"
    section_start_line = 0
    section_years = []

    for i, line in enumerate(lines, 1):
        # Check for section headers
        if line.startswith("#"):
            # Analyze previous section if it was "current"
            if current_section_type == "current" and section_years:
                max_year = max(section_years)
                if max_year < CURRENT_YEAR_MIN:
                    issues.append(
                        f"{filepath.name}:{section_start_line}: "
                        f"Section '{current_section}' has no dates >= {CURRENT_YEAR_MIN} "
                        f"(max found: {max_year})"
                    )

            # Start new section
            current_section = line.lstrip("#").strip()
            current_section_type = get_section_type(current_section)
            section_start_line = i
            section_years = []

        # Collect years in current section
        years = extract_years(line)
        section_years.extend(years)

    # Check last section
    if current_section_type == "current" and section_years:
        max_year = max(section_years)
        if max_year < CURRENT_YEAR_MIN:
            issues.append(
                f"{filepath.name}:{section_start_line}: "
                f"Section '{current_section}' has no dates >= {CURRENT_YEAR_MIN} "
                f"(max found: {max_year})"
            )

    # Strict mode: check that file has at least one 2025+ date
    if strict:
        all_years = extract_years(content)
        if not any(y >= 2025 for y in all_years):
            issues.append(f"{filepath.name}: No 2025+ dates found - may be stale")

    return issues


def main():
    """Run freshness checks on all threat intel files."""
    strict = "--strict" in sys.argv
    project_root = Path(__file__).parent.parent

    all_issues = []
    stamp_notes = []
    files_checked = 0

    print("Checking threat intelligence freshness...\n")

    for rel_path in THREAT_INTEL_FILES:
        filepath = project_root / rel_path
        issues = check_file(filepath, strict)
        stamp_note = check_stamp(filepath, rel_path)
        if stamp_note:
            stamp_notes.append(stamp_note)
            if strict:
                issues.append(stamp_note)

        if filepath.exists():
            files_checked += 1
            if issues:
                all_issues.extend(issues)
                print(f"WARN: {rel_path}")
                for issue in issues:
                    print(f"  - {issue}")
            elif stamp_note:
                print(f"NOTE: {rel_path}")
                print(f"  - {stamp_note}")
            else:
                print(f"OK: {rel_path}")

    print(f"\nChecked {files_checked} files")

    if stamp_notes and not strict:
        print(
            f"\n{len(stamp_notes)} file(s) have an old or missing update stamp "
            "(a note, not a failure; --strict makes it fail)"
        )

    if all_issues:
        print(f"\nFound {len(all_issues)} potential freshness issues")
        print("\nTo fix: Run /update-threat-intel or manually update with web search")
        return 1
    else:
        if stamp_notes:
            print("\nNo section-date issues; see the update-stamp notes above")
        else:
            print("\nAll threat intel appears current")
        return 0


if __name__ == "__main__":
    sys.exit(main())

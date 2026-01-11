#!/usr/bin/env python3
"""
Check threat intelligence files for freshness.

Distinguishes between:
- Historical context (timelines, evolution) - old dates allowed
- Current threat sections - must have 2024+ dates

Usage:
    python scripts/check_threat_intel_freshness.py
    python scripts/check_threat_intel_freshness.py --strict
"""

import re
import sys
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
    files_checked = 0

    print("Checking threat intelligence freshness...\n")

    for rel_path in THREAT_INTEL_FILES:
        filepath = project_root / rel_path
        issues = check_file(filepath, strict)

        if filepath.exists():
            files_checked += 1
            if issues:
                all_issues.extend(issues)
                print(f"WARN: {rel_path}")
                for issue in issues:
                    print(f"  - {issue}")
            else:
                print(f"OK: {rel_path}")

    print(f"\nChecked {files_checked} files")

    if all_issues:
        print(f"\nFound {len(all_issues)} potential freshness issues")
        print("\nTo fix: Run /update-threat-intel or manually update with web search")
        return 1
    else:
        print("\nAll threat intel appears current")
        return 0


if __name__ == "__main__":
    sys.exit(main())

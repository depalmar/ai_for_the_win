#!/usr/bin/env python3
"""
Test Lab Data Integrity

This test validates that all data files documented in lab READMEs actually exist.
Run this test to catch missing data files before they cause issues for students.

Usage:
    pytest tests/test_lab_data_integrity.py -v
"""

import re
from pathlib import Path

import pytest

# Get the labs directory
REPO_ROOT = Path(__file__).parent.parent
LABS_DIR = REPO_ROOT / "labs"


def extract_data_files_from_readme(readme_path: Path) -> list[str]:
    """
    Extract data file paths from a lab's README.md.

    Looks for the "Files" section and extracts ONLY paths under data/ directories.
    Handles tree-style file listings like:
        ├── data/
        │   ├── file1.csv
        │   └── file2.json
        └── tests/
    """
    if not readme_path.exists():
        return []

    content = readme_path.read_text(encoding="utf-8")

    # Find the Files section (```...```)
    files_section_match = re.search(
        r"## 📁 Files.*?```\s*(.*?)\s*```",
        content,
        re.DOTALL | re.IGNORECASE
    )

    if not files_section_match:
        # Try alternate pattern without emoji
        files_section_match = re.search(
            r"## Files.*?```\s*(.*?)\s*```",
            content,
            re.DOTALL | re.IGNORECASE
        )

    if not files_section_match:
        return []

    files_block = files_section_match.group(1)
    lines = files_block.split("\n")

    # Find the data/ section and extract only DIRECT files within it
    data_files = []
    in_data_section = False

    for i, line in enumerate(lines):
        # Check if this is the data/ directory line (├── data/ or └── data/)
        if re.search(r"[├└]── data/?$", line.rstrip()):
            in_data_section = True
            continue

        if in_data_section:
            # Check if we've exited the data section
            # Exit conditions:
            # 1. A new root-level directory (├── or └── without leading │)
            # 2. End of indented section

            # If line starts with ├── or └── (no leading │), we've exited data/
            if re.match(r"^[├└]──", line):
                in_data_section = False
                continue

            # If the line doesn't have │ at the start, we might have exited
            if line.strip() and not line.startswith("│"):
                in_data_section = False
                continue

            # We're inside data/ - extract files
            # Match patterns like: │   ├── filename.ext or │   └── filename.ext
            file_match = re.search(r"│\s+[├└]── ([^\s#]+\.\w+)", line)
            if file_match:
                filename = file_match.group(1)
                # Skip comments
                if "#" not in filename:
                    data_files.append(filename)

    return list(set(data_files))  # Remove duplicates


def get_all_labs() -> list[Path]:
    """Get all lab directories that have README.md files."""
    if not LABS_DIR.exists():
        return []
    return sorted([d for d in LABS_DIR.iterdir() if d.is_dir() and (d / "README.md").exists()])


def get_actual_data_files(lab_dir: Path) -> set[str]:
    """Get all files that actually exist in the lab's data directory."""
    data_dir = lab_dir / "data"
    if not data_dir.exists():
        return set()

    files = set()
    for f in data_dir.rglob("*"):
        if f.is_file():
            # Get relative path from data dir
            rel_path = f.relative_to(data_dir)
            files.add(str(rel_path))
            files.add(f.name)  # Also add just the filename

    return files


# Collect all labs for parametrized testing
ALL_LABS = get_all_labs()


class TestLabDataIntegrity:
    """Tests to verify lab data files exist as documented."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_lab_has_readme(self, lab_dir: Path):
        """Each lab should have a README.md file."""
        readme = lab_dir / "README.md"
        assert readme.exists(), f"Lab {lab_dir.name} is missing README.md"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_documented_data_files_exist(self, lab_dir: Path):
        """All data files documented in README should exist."""
        readme_path = lab_dir / "README.md"
        documented_files = extract_data_files_from_readme(readme_path)

        if not documented_files:
            pytest.skip(f"No data files documented in {lab_dir.name} README")

        actual_files = get_actual_data_files(lab_dir)
        data_dir = lab_dir / "data"

        missing_files = []
        for doc_file in documented_files:
            # Check if file exists (by name or path)
            file_exists = (
                doc_file in actual_files or
                (data_dir / doc_file).exists()
            )
            if not file_exists:
                missing_files.append(doc_file)

        if missing_files:
            pytest.fail(
                f"Lab {lab_dir.name} has missing data files:\n"
                f"  Documented but missing: {missing_files}\n"
                f"  Actual files present: {sorted(actual_files)}"
            )


class TestLabStructure:
    """Tests to verify lab directory structure."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_lab_has_starter_code(self, lab_dir: Path):
        """Labs with solution code should have starter code."""
        solution_dir = lab_dir / "solution"
        starter_dir = lab_dir / "starter"

        if solution_dir.exists():
            assert starter_dir.exists(), (
                f"Lab {lab_dir.name} has solution/ but no starter/ directory"
            )

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_data_dir_not_empty_if_exists(self, lab_dir: Path):
        """If a data directory exists, it should contain files."""
        data_dir = lab_dir / "data"

        if data_dir.exists():
            files = list(data_dir.rglob("*"))
            data_files = [f for f in files if f.is_file()]
            assert len(data_files) > 0, (
                f"Lab {lab_dir.name} has empty data/ directory"
            )


class TestDataFileQuality:
    """Tests to verify data file quality."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_csv_files_have_headers(self, lab_dir: Path):
        """CSV files should have header rows."""
        data_dir = lab_dir / "data"
        if not data_dir.exists():
            pytest.skip(f"No data directory in {lab_dir.name}")

        csv_files = list(data_dir.glob("*.csv"))
        if not csv_files:
            pytest.skip(f"No CSV files in {lab_dir.name}")

        for csv_file in csv_files:
            content = csv_file.read_text(encoding="utf-8")
            lines = content.strip().split("\n")

            assert len(lines) >= 2, (
                f"CSV file {csv_file.name} in {lab_dir.name} has no data rows"
            )

            # Check header doesn't look like data
            header = lines[0]
            assert not header[0].isdigit(), (
                f"CSV file {csv_file.name} in {lab_dir.name} may be missing header"
            )

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_json_files_are_valid(self, lab_dir: Path):
        """JSON files should be valid JSON."""
        import json

        data_dir = lab_dir / "data"
        if not data_dir.exists():
            pytest.skip(f"No data directory in {lab_dir.name}")

        json_files = list(data_dir.glob("*.json"))
        if not json_files:
            pytest.skip(f"No JSON files in {lab_dir.name}")

        for json_file in json_files:
            try:
                content = json_file.read_text(encoding="utf-8")
                json.loads(content)
            except json.JSONDecodeError as e:
                pytest.fail(
                    f"Invalid JSON in {json_file.name} ({lab_dir.name}): {e}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

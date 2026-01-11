"""
Curriculum Integrity Tests

Validates that all curriculum content is consistent, links work,
and references are correct. Run with: pytest tests/test_curriculum_integrity.py -v
"""

import json
import re
from pathlib import Path

import pytest

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent


class TestLabStructure:
    """Test lab folder structure and consistency."""

    def get_lab_folders(self):
        """Get all lab folders sorted by number."""
        labs_dir = PROJECT_ROOT / "labs"
        return sorted(
            [d for d in labs_dir.iterdir() if d.is_dir() and d.name.startswith("lab")],
            key=lambda x: int(re.search(r"lab(\d+)", x.name).group(1)),
        )

    def test_all_labs_have_readme(self):
        """Every lab must have a README.md."""
        for lab in self.get_lab_folders():
            readme = lab / "README.md"
            assert readme.exists(), f"Missing README.md in {lab.name}"

    def test_lab_header_matches_folder(self):
        """Lab README header must match folder number."""
        pattern = re.compile(r"^#\s*Lab\s*(\d+)", re.IGNORECASE)

        for lab in self.get_lab_folders():
            readme = lab / "README.md"
            if not readme.exists():
                continue

            folder_num = int(re.search(r"lab(\d+)", lab.name).group(1))
            content = readme.read_text(encoding="utf-8")
            first_line = content.split("\n")[0]

            match = pattern.match(first_line)
            if match:
                header_num = int(match.group(1))
                assert header_num == folder_num, (
                    f"{lab.name}: Header says 'Lab {header_num}' "
                    f"but folder is lab{folder_num:02d}"
                )

    def test_no_gaps_in_lab_numbering(self):
        """Lab numbers should be sequential with no gaps."""
        labs = self.get_lab_folders()
        numbers = [int(re.search(r"lab(\d+)", lab.name).group(1)) for lab in labs]

        expected = list(range(min(numbers), max(numbers) + 1))
        missing = set(expected) - set(numbers)

        assert not missing, f"Missing lab numbers: {sorted(missing)}"

    def test_next_lab_references_exist(self):
        """Next lab references should point to existing labs."""
        pattern = re.compile(r"\*\*Next Lab\*\*.*?\[Lab\s*(\d+)", re.IGNORECASE)

        for lab in self.get_lab_folders():
            readme = lab / "README.md"
            if not readme.exists():
                continue

            content = readme.read_text(encoding="utf-8")
            matches = pattern.findall(content)

            for next_num in matches:
                matching = list(PROJECT_ROOT.glob(f"labs/lab{int(next_num):02d}-*"))
                assert matching, f"{lab.name}: References Lab {next_num} which doesn't exist"


class TestWalkthroughLinks:
    """Test walkthrough file references."""

    def test_walkthrough_references_exist(self):
        """All walkthrough references in README should exist."""
        readme = PROJECT_ROOT / "docs" / "walkthroughs" / "README.md"
        if not readme.exists():
            pytest.skip("Walkthrough README not found")

        content = readme.read_text(encoding="utf-8")

        # Find markdown links to .md files
        pattern = re.compile(r"\]\(\./([^)]+\.md)\)")
        matches = pattern.findall(content)

        walkthroughs_dir = PROJECT_ROOT / "docs" / "walkthroughs"
        for ref in matches:
            file_path = walkthroughs_dir / ref
            assert file_path.exists(), f"Missing walkthrough: {ref}"

    def test_walkthrough_naming_convention(self):
        """Walkthrough files should follow labXX-*-walkthrough.md pattern."""
        pattern = re.compile(r"lab(\d+)-.*-walkthrough\.md")
        walkthroughs_dir = PROJECT_ROOT / "docs" / "walkthroughs"

        for file in walkthroughs_dir.glob("lab*-walkthrough.md"):
            match = pattern.match(file.name)
            assert match, f"Invalid walkthrough name format: {file.name}"


class TestNotebookLinks:
    """Test Colab notebook references."""

    def test_notebook_colab_links_match_filename(self):
        """Notebook Colab links should reference the correct file."""
        notebooks_dir = PROJECT_ROOT / "notebooks"

        for notebook in notebooks_dir.glob("lab*.ipynb"):
            content = notebook.read_text(encoding="utf-8")

            # Find Colab links
            pattern = re.compile(
                r"colab\.research\.google\.com/github/[^/]+/[^/]+/blob/main/notebooks/([^)\"]+\.ipynb)"
            )
            matches = pattern.findall(content)

            for ref in matches:
                # The Colab link should reference this notebook or a valid one
                ref_path = notebooks_dir / ref
                assert (
                    ref_path.exists()
                ), f"{notebook.name}: Colab link references non-existent {ref}"

    def test_notebook_title_matches_filename(self):
        """Notebook title should match the lab number in filename."""
        notebooks_dir = PROJECT_ROOT / "notebooks"
        title_pattern = re.compile(r"#\s*Lab\s*(\d+)")
        filename_pattern = re.compile(r"lab(\d+)")

        for notebook in notebooks_dir.glob("lab*.ipynb"):
            try:
                data = json.loads(notebook.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            # Get lab number from filename
            filename_match = filename_pattern.search(notebook.name)
            if not filename_match:
                continue
            file_num = int(filename_match.group(1))

            # Find first markdown cell with title
            for cell in data.get("cells", []):
                if cell.get("cell_type") == "markdown":
                    source = "".join(cell.get("source", []))
                    title_match = title_pattern.search(source)
                    if title_match:
                        title_num = int(title_match.group(1))
                        assert title_num == file_num, (
                            f"{notebook.name}: Title says 'Lab {title_num}' "
                            f"but filename is lab{file_num}"
                        )
                        break

    def test_notebook_next_lab_references_valid(self):
        """Next Lab references should use valid lab numbers (not old format like 00a, 03b)."""
        notebooks_dir = PROJECT_ROOT / "notebooks"

        # Old format patterns that should NOT appear
        old_format_pattern = re.compile(r"\bLab\s*(\d{2}[a-z])\b", re.IGNORECASE)

        # Valid lab numbers (current format)
        existing_labs = {
            int(re.search(r"lab(\d+)", d.name).group(1))
            for d in (PROJECT_ROOT / "labs").iterdir()
            if d.is_dir() and d.name.startswith("lab")
        }

        for notebook in notebooks_dir.glob("lab*.ipynb"):
            content = notebook.read_text(encoding="utf-8")

            # Check for old format references
            old_refs = old_format_pattern.findall(content)
            assert not old_refs, (
                f"{notebook.name}: Contains old lab format references: {old_refs}. "
                f"Update to new numbering (e.g., Lab 01, Lab 10, etc.)"
            )


class TestCTFChallenges:
    """Test CTF challenge consistency."""

    def test_achievement_flag_count_matches_challenges(self):
        """Completionist achievement should match total challenge count."""
        ctf_dir = PROJECT_ROOT / "ctf-challenges"
        achievements_file = ctf_dir / "achievements.json"

        if not achievements_file.exists():
            pytest.skip("achievements.json not found")

        # Count challenges
        challenge_count = 0
        for level in ["beginner", "intermediate", "advanced"]:
            level_dir = ctf_dir / level
            if level_dir.exists():
                challenge_count += len([d for d in level_dir.iterdir() if d.is_dir()])

        # Check achievements
        data = json.loads(achievements_file.read_text(encoding="utf-8"))
        for achievement in data.get("achievements", []):
            if achievement.get("id") == "completionist":
                req = achievement.get("requirement", {})
                flags_required = req.get("flags_captured", 0)
                assert flags_required == challenge_count, (
                    f"Completionist requires {flags_required} flags "
                    f"but there are {challenge_count} challenges"
                )

    def test_all_challenges_have_readme(self):
        """Every challenge must have README.md."""
        ctf_dir = PROJECT_ROOT / "ctf-challenges"

        for level in ["beginner", "intermediate", "advanced"]:
            level_dir = ctf_dir / level
            if not level_dir.exists():
                continue

            for challenge in level_dir.iterdir():
                if challenge.is_dir():
                    readme = challenge / "README.md"
                    assert readme.exists(), f"Missing README.md in {level}/{challenge.name}"

    def test_all_challenges_have_data(self):
        """Every challenge must have a challenge/ data folder."""
        ctf_dir = PROJECT_ROOT / "ctf-challenges"

        for level in ["beginner", "intermediate", "advanced"]:
            level_dir = ctf_dir / level
            if not level_dir.exists():
                continue

            for challenge in level_dir.iterdir():
                if challenge.is_dir():
                    data_dir = challenge / "challenge"
                    assert (
                        data_dir.exists()
                    ), f"Missing challenge/ folder in {level}/{challenge.name}"


class TestPackageVersions:
    """Test that documented package versions are not extremely outdated."""

    def test_anthropic_version_current(self):
        """Anthropic package version should be reasonably current."""
        guides_dir = PROJECT_ROOT / "docs" / "guides"

        for guide in guides_dir.glob("*.md"):
            content = guide.read_text(encoding="utf-8")

            # Find anthropic version pins (exclude langchain-anthropic which is a different package)
            pattern = re.compile(r"(?<!langchain-)anthropic>=(\d+)\.(\d+)")
            matches = pattern.findall(content)

            for major, minor in matches:
                major, minor = int(major), int(minor)
                # Should be at least version 0.30.0 (as of late 2025)
                assert major > 0 or minor >= 30, (
                    f"{guide.name}: anthropic>={major}.{minor} is outdated. "
                    f"Update to >=0.40.0 or higher."
                )


class TestPrerequisiteChain:
    """Test that lab prerequisites form valid chains."""

    def test_prerequisites_reference_existing_labs(self):
        """Lab prerequisites should reference labs that exist."""
        prereq_pattern = re.compile(r"(?:Prerequisites?|Requires?).*?Lab\s*(\d+)", re.IGNORECASE)

        labs_dir = PROJECT_ROOT / "labs"
        existing_labs = {
            int(re.search(r"lab(\d+)", d.name).group(1))
            for d in labs_dir.iterdir()
            if d.is_dir() and d.name.startswith("lab")
        }

        for lab_dir in labs_dir.iterdir():
            if not lab_dir.is_dir() or not lab_dir.name.startswith("lab"):
                continue

            readme = lab_dir / "README.md"
            if not readme.exists():
                continue

            content = readme.read_text(encoding="utf-8")
            matches = prereq_pattern.findall(content)

            for prereq_num in matches:
                prereq_num = int(prereq_num)
                assert prereq_num in existing_labs, (
                    f"{lab_dir.name}: References prerequisite Lab {prereq_num} "
                    f"which doesn't exist"
                )


class TestIndexMdConsistency:
    """Test docs/index.md lab navigator consistency."""

    def test_index_lab_cards_match_folders(self):
        """Lab cards in index.md should match actual lab folders."""
        index_file = PROJECT_ROOT / "docs" / "index.md"
        if not index_file.exists():
            pytest.skip("docs/index.md not found")

        content = index_file.read_text(encoding="utf-8")

        # Find lab card patterns: href="labs/labXX-..."
        href_pattern = re.compile(r'href="labs/(lab\d+-[^"]+)"')
        matches = href_pattern.findall(content)

        labs_dir = PROJECT_ROOT / "labs"
        for href in matches:
            # Extract lab folder name
            lab_folder = labs_dir / href
            assert lab_folder.exists() or any(
                labs_dir.glob(f"{href.split('-')[0]}*")
            ), f"index.md references non-existent lab: {href}"

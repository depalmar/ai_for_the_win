"""
Test lab naming consistency across README files, notebooks, and walkthroughs.

Ensures that all references use the correct naming conventions:
- Lab directories: labXX-name (lowercase, hyphen, no space)
- Lab references: "Lab XX" in text (capital L, space, two digits)
- No legacy numbering (Lab 29, 31, 32, etc. should be Lab 10, 11, 12, etc.)
"""

import json
import re
from pathlib import Path

import pytest

# Map of legacy lab numbers to current lab numbers (for detection)
# CRITICAL: Only includes labs that were ACTUALLY renamed in the beginner section
# Many advanced labs (38-50) still use their original numbers correctly
LEGACY_TO_CURRENT = {
    "29": "10",  # Phishing Classifier (renamed)
    "32": "12",  # Anomaly Detection (renamed)
    "33": "13",  # ML vs LLM (renamed)
    "34": "14",  # First AI Agent (renamed)
    "35": "15",  # LLM Log Analysis (renamed)
    "36": "16",  # Threat Intel Agent (renamed)
    # Lab 39 and 42 are complex:
    # - Lab 17 is "Embeddings & Vectors" (new beginner lab)
    # - Lab 39 is "Adversarial ML" (was always 39, never renamed)
    # - Lab 18 is "Security RAG" (was Lab 42 in old structure)
    # - Lab 42 is "Fine-Tuning" (was always 42, never renamed)
    # We can't detect these automatically without deep context
    # Lab 21, 22, 23 are OK as-is (YARA, Vuln Scanner, Detection Pipeline)
    # Lab 31 is context-dependent (could be Lab 02 or Lab 11)
    # Labs 38-50 are OK as-is (advanced section, never renamed)
}

# Valid lab numbers (based on current structure)
VALID_LAB_NUMBERS = set(range(0, 51))  # Labs 00-50


def get_lab_dirs():
    """Get all lab directories."""
    root = Path(__file__).parent.parent
    labs_dir = root / "labs"
    return sorted(labs_dir.glob("lab*"))


def get_notebooks():
    """Get all notebook files."""
    root = Path(__file__).parent.parent
    notebooks_dir = root / "notebooks"
    return sorted(notebooks_dir.glob("lab*.ipynb"))


def get_readme_files():
    """Get all README files in labs."""
    return [lab_dir / "README.md" for lab_dir in get_lab_dirs() if (lab_dir / "README.md").exists()]


class TestLabDirectoryNaming:
    """Test that lab directories follow naming conventions."""

    @pytest.mark.parametrize("lab_dir", get_lab_dirs())
    def test_lab_directory_naming_convention(self, lab_dir):
        """Lab directories should be named labXX-name (lowercase, hyphen, no space)."""
        dir_name = lab_dir.name

        # Should start with "lab" (lowercase)
        assert dir_name.startswith("lab"), f"{dir_name} should start with 'lab' (lowercase)"

        # Should not have capital L
        assert not dir_name.startswith("Lab"), f"{dir_name} should use lowercase 'lab', not 'Lab'"

        # Should not have space after number
        match = re.match(r"lab(\d+)(.)", dir_name)
        if match:
            separator = match.group(2)
            assert (
                separator == "-"
            ), f"{dir_name} should use hyphen (-), not space or other separator"


class TestReadmeFolderPaths:
    """Test that README file tree sections show correct folder names."""

    @pytest.mark.parametrize("readme_path", get_readme_files())
    def test_no_legacy_folder_names_in_code_blocks(self, readme_path):
        """README code blocks should not show 'Lab XX-name/' folder paths."""
        content = readme_path.read_text(encoding="utf-8")

        # Find code blocks with folder structure
        code_blocks = re.findall(r"```(.*?)```", content, re.DOTALL)

        for block in code_blocks:
            # Look for "Lab XX-" pattern (capital L, space, digits, hyphen)
            matches = re.findall(r"(Lab \d+-[\w-]+/)", block)

            assert not matches, (
                f"{readme_path.name} contains incorrect folder path(s) in code block: {matches}\n"
                f"Should use 'labXX-name/' (lowercase, hyphen) not 'Lab XX-name/'"
            )


class TestReadmeLabReferences:
    """Test that README files don't use legacy lab numbers."""

    @pytest.mark.parametrize("readme_path", get_readme_files())
    def test_no_legacy_lab_numbers_in_links(self, readme_path):
        """README files should not reference legacy lab numbers in links."""
        content = readme_path.read_text(encoding="utf-8")

        # Find markdown links like [Lab XX: ...](../Lab XX-...)
        link_pattern = r"\[([^\]]+)\]\(\.\./(Lab \d+-[^)]+)\)"
        matches = re.findall(link_pattern, content)

        legacy_refs = []
        for link_text, link_path in matches:
            # Check if path uses "Lab XX-" instead of "labXX-"
            if link_path.startswith("Lab "):
                legacy_refs.append((link_text, link_path))

        assert not legacy_refs, (
            f"{readme_path.name} contains legacy lab number reference(s): {legacy_refs}\n"
            f"Links should use '../labXX-name/' not '../Lab XX-name/'"
        )

    @pytest.mark.parametrize("readme_path", get_readme_files())
    def test_no_wrong_lab_numbers(self, readme_path):
        """README files should not reference wrong lab numbers (29→10, 35→15, etc.)."""
        # Extract this README's own lab number
        parent_dir = readme_path.parent.name
        match = re.match(r"lab(\d+)-", parent_dir)
        own_lab_num = match.group(1) if match else None

        content = readme_path.read_text(encoding="utf-8")

        # Find references to legacy lab numbers
        wrong_refs = []
        for legacy_num, current_num in LEGACY_TO_CURRENT.items():
            # Skip if this README IS the lab being checked
            if own_lab_num == legacy_num:
                continue

            # Look for "Lab XX" followed by some context
            pattern = rf"\bLab {legacy_num}\b(?!-)"  # Not followed by hyphen (allows "Lab 29-old-name" in docs)
            matches = re.finditer(pattern, content)

            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace("\n", " ")
                wrong_refs.append(
                    f"Lab {legacy_num} (should be Lab {current_num}): ...{context}..."
                )

        assert (
            not wrong_refs
        ), f"{readme_path.name} contains references to old lab numbers:\n" + "\n".join(wrong_refs)


class TestNotebookLabReferences:
    """Test that notebooks don't use legacy lab numbers."""

    @pytest.mark.parametrize("notebook_path", get_notebooks())
    def test_no_legacy_lab_numbers_in_notebooks(self, notebook_path):
        """Notebooks should not reference legacy lab numbers."""
        # Extract the lab number from the notebook filename
        match = re.match(r"lab(\d+)_", notebook_path.name)
        notebook_lab_num = match.group(1) if match else None

        with open(notebook_path, "r", encoding="utf-8") as f:
            notebook = json.load(f)

        wrong_refs = []

        for cell_idx, cell in enumerate(notebook.get("cells", [])):
            if cell.get("cell_type") == "markdown":
                source = cell.get("source", [])
                content = "".join(source) if isinstance(source, list) else source

                # Skip the first cell if it contains this lab's own title
                if cell_idx == 0 and notebook_lab_num:
                    first_line = content.split("\n")[0] if content else ""
                    if f"# Lab {notebook_lab_num}:" in first_line:
                        continue  # Skip this lab's own title

                # Check for legacy lab numbers
                for legacy_num, current_num in LEGACY_TO_CURRENT.items():
                    # Don't flag if this IS the legacy numbered lab using its own number
                    if notebook_lab_num == legacy_num:
                        continue

                    pattern = rf"\bLab {legacy_num}\b"
                    if re.search(pattern, content):
                        # Get context
                        lines = content.split("\\n")
                        for line in lines:
                            if f"Lab {legacy_num}" in line:
                                wrong_refs.append(
                                    f"Lab {legacy_num} (should be Lab {current_num}): {line.strip()}"
                                )

        assert (
            not wrong_refs
        ), f"{notebook_path.name} contains references to old lab numbers:\n" + "\n".join(wrong_refs)


def test_walkthrough_naming_convention():
    """Walkthrough files should use labXX-name-walkthrough.md naming."""
    root = Path(__file__).parent.parent
    walkthroughs_dir = root / "docs" / "walkthroughs"

    if not walkthroughs_dir.exists():
        pytest.skip("Walkthroughs directory not found")

    walkthrough_files = list(walkthroughs_dir.glob("*.md"))

    for walkthrough_path in walkthrough_files:
        filename = walkthrough_path.name

        # Skip non-lab walkthroughs
        if not filename.startswith("lab"):
            continue

        # Should start with "lab" (lowercase)
        assert filename.startswith("lab"), f"{filename} should start with 'lab' (lowercase)"

        # Should not start with "Lab"
        assert not filename.startswith("Lab"), f"{filename} should use lowercase 'lab', not 'Lab'"

        # Should use hyphen
        match = re.match(r"lab(\d+)(.)", filename)
        if match:
            separator = match.group(2)
            assert separator == "-", f"{filename} should use hyphen (-) after lab number"

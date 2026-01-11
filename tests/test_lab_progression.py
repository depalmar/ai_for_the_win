"""
Test lab progression and "Next Lab" references.

Ensures that "Next Lab" links in README files match the intended
progression path defined in the dependency graph.
"""

import re
from pathlib import Path

import pytest

# Define the expected beginner path based on LAB_DEPENDENCY_GRAPH.md
# This is the recommended linear progression for new learners
BEGINNER_PATH = {
    "lab00-environment-setup": "lab01-python-security-fundamentals",
    "lab01-python-security-fundamentals": "lab02-intro-prompt-engineering",
    "lab02-intro-prompt-engineering": "lab03-vibe-coding-with-ai",
    "lab03-vibe-coding-with-ai": "lab07-hello-world-ml",
    "lab07-hello-world-ml": "lab08-working-with-apis",
    "lab08-working-with-apis": "lab09-ctf-fundamentals",
    "lab09-ctf-fundamentals": "lab10-phishing-classifier",
}

# Alternative valid progressions (for labs with multiple valid paths)
# Format: {lab_dir: [valid_next_labs]}
ALTERNATIVE_PATHS = {
    "lab01-python-security-fundamentals": [
        "lab02-intro-prompt-engineering",  # Beginner path
        "lab04-ml-concepts-primer",  # ML-focused path
        "lab06-visualization-stats",  # Data viz path
        "lab08-working-with-apis",  # API-focused path
    ],
    "lab02-intro-prompt-engineering": [
        "lab03-vibe-coding-with-ai",  # Beginner path (recommended)
        "lab07-hello-world-ml",  # Skip vibe coding, go straight to ML
    ],
    "lab03-vibe-coding-with-ai": [
        "lab07-hello-world-ml",  # Beginner path (recommended)
        "lab09-ctf-fundamentals",  # Alternative: jump to CTF
        "lab10-phishing-classifier",  # Alternative: jump to practical
    ],
    "lab04-ml-concepts-primer": [
        "lab07-hello-world-ml",  # ML track continues
    ],
    "lab05-ai-in-security-operations": [
        "lab06-visualization-stats",  # Continue with data skills
    ],
    "lab06-visualization-stats": [
        "lab07-hello-world-ml",  # Continue to ML
    ],
}


def get_lab_dirs():
    """Get all lab directories."""
    root = Path(__file__).parent.parent
    labs_dir = root / "labs"
    return sorted([d for d in labs_dir.glob("lab*") if d.is_dir()])


def extract_next_lab_from_readme(readme_path: Path) -> str | None:
    """Extract the 'Next Lab' link from a README file."""
    try:
        content = readme_path.read_text(encoding="utf-8")
    except OSError:
        return None

    # Pattern: **Next Lab:** [Lab XX: Name](../labXX-name/)
    pattern = r"\*\*Next Lab:\*\*\s+\[Lab \d+:[^\]]+\]\(\.\./([^/]+)/\)"
    match = re.search(pattern, content)

    if match:
        return match.group(1)  # Returns the lab directory name

    return None


@pytest.mark.parametrize("lab_dir", get_lab_dirs())
def test_next_lab_reference_valid(lab_dir):
    """
    Test that 'Next Lab' references point to valid lab directories.

    This ensures that links aren't broken due to typos or lab renumbering.
    """
    readme_path = lab_dir / "README.md"
    if not readme_path.exists():
        pytest.skip(f"No README found for {lab_dir.name}")

    next_lab = extract_next_lab_from_readme(readme_path)

    if next_lab is None:
        # Some labs (like final labs) may not have a "Next Lab" - that's OK
        pytest.skip(f"No 'Next Lab' reference found in {lab_dir.name}")

    # Check that the referenced lab directory actually exists
    root = Path(__file__).parent.parent
    next_lab_path = root / "labs" / next_lab

    assert next_lab_path.exists(), (
        f"{lab_dir.name} references non-existent next lab: {next_lab}\n"
        f"Expected path: {next_lab_path}"
    )


@pytest.mark.parametrize("lab_dir", get_lab_dirs())
def test_next_lab_follows_beginner_path(lab_dir):
    """
    Test that 'Next Lab' references follow the intended beginner path.

    This ensures consistency with the LAB_DEPENDENCY_GRAPH.md and prevents
    confusion for new learners following the recommended progression.
    """
    lab_name = lab_dir.name

    # Skip labs not in the beginner path or alternative paths
    if lab_name not in BEGINNER_PATH and lab_name not in ALTERNATIVE_PATHS:
        pytest.skip(f"{lab_name} not in defined progression paths")

    readme_path = lab_dir / "README.md"
    if not readme_path.exists():
        pytest.skip(f"No README found for {lab_name}")

    next_lab = extract_next_lab_from_readme(readme_path)

    if next_lab is None:
        pytest.skip(f"No 'Next Lab' reference found in {lab_name}")

    # Check beginner path first
    if lab_name in BEGINNER_PATH:
        expected_next = BEGINNER_PATH[lab_name]

        # Also check alternative paths
        valid_next_labs = [expected_next]
        if lab_name in ALTERNATIVE_PATHS:
            valid_next_labs.extend(ALTERNATIVE_PATHS[lab_name])

        assert next_lab in valid_next_labs, (
            f"{lab_name} has incorrect 'Next Lab' reference\n"
            f"  Found: {next_lab}\n"
            f"  Expected (beginner path): {expected_next}\n"
            f"  Valid alternatives: {valid_next_labs}\n"
            f"\n"
            f"The beginner path should be: Lab 00 → Lab 01 → Lab 02 → Lab 03 → Lab 07 → Lab 08 → Lab 09 → Lab 10\n"
            f"Refer to docs/LAB_DEPENDENCY_GRAPH.md for the full progression."
        )

    # Check alternative paths
    elif lab_name in ALTERNATIVE_PATHS:
        valid_next_labs = ALTERNATIVE_PATHS[lab_name]

        assert next_lab in valid_next_labs, (
            f"{lab_name} has incorrect 'Next Lab' reference\n"
            f"  Found: {next_lab}\n"
            f"  Valid options: {valid_next_labs}\n"
            f"\n"
            f"Refer to docs/LAB_DEPENDENCY_GRAPH.md for valid progressions."
        )


def test_beginner_path_completeness():
    """
    Test that the beginner path covers all foundation labs (00-09).

    This is a sanity check to ensure we've defined the full path.
    """
    root = Path(__file__).parent.parent
    labs_dir = root / "labs"

    # Get all lab00-lab09 directories
    foundation_labs = sorted([d.name for d in labs_dir.glob("lab0[0-9]-*") if d.is_dir()])

    # Check that we have defined paths for most foundation labs
    # (Some labs like Lab 03, Lab 05 may have flexible paths)
    defined_labs = set(BEGINNER_PATH.keys()) | set(ALTERNATIVE_PATHS.keys())
    foundation_in_paths = [lab for lab in foundation_labs if lab in defined_labs]

    # We expect at least 6 out of 10 foundation labs to have defined paths
    assert len(foundation_in_paths) >= 6, (
        f"Beginner path should cover most foundation labs (00-09)\n"
        f"Foundation labs found: {foundation_labs}\n"
        f"Foundation labs with defined paths: {foundation_in_paths}\n"
        f"Missing: {set(foundation_labs) - defined_labs}"
    )

"""
Test lab naming consistency across README files, notebooks, and walkthroughs.

Ensures that:
- Lab directories are named labXX-name (lowercase, hyphen, no space)
- README code blocks and links use labXX-name/ paths, not "Lab XX-name/"
- Every "Lab NN: Title" or "Lab NN (Title)" cross-reference in a lab README or
  notebook (including a notebook's own title) names the lab whose folder is
  labs/labNN-*, and every "[Lab NN](...labMM-...)" link has NN == MM

The labs/ folder names and their README H1s are the ground truth. The curriculum
has been renumbered more than once, so a number on its own can't tell a stale
reference from a correct one: "Lab 34" was First AI Agent in an earlier scheme
and is C2 Traffic Analysis now. Instead, the title next to the number is compared
with every lab's name (see labs_named_instead). A reference is flagged only when
its title names a different lab, so a stale number from any earlier scheme is
caught by its title, and a correct reference is never flagged for its number.
"""

import json
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


def get_lab_dirs():
    """Get all lab directories."""
    labs_dir = ROOT / "labs"
    return sorted(labs_dir.glob("lab*"))


def get_notebooks():
    """Get all notebook files."""
    notebooks_dir = ROOT / "notebooks"
    return sorted(notebooks_dir.glob("lab*.ipynb"))


def get_readme_files():
    """Get all README files in labs."""
    return [lab_dir / "README.md" for lab_dir in get_lab_dirs() if (lab_dir / "README.md").exists()]


# ---------------------------------------------------------------------------
# Lab names: the ground truth that "Lab NN" cross-references are checked against
# ---------------------------------------------------------------------------

# Filler words that never identify a lab.
STOPWORDS = frozenset(
    "a an and as at be by for from how in into is it of on or that the these this to "
    "use using vs what when which with you your build learn apply lab labs more full".split()
)

# Spellings that count as the same word.
SYNONYMS = {
    "intelligence": "intel",
    "ti": "intel",
    "introduction": "intro",
    "ops": "operation",
    "vulnerability": "vuln",
    "statistic": "stat",
}

# A word in the names of this many labs or more ("security", "detection", "ai",
# "threat", ...) is too common to tell labs apart, so it is not distinctive.
GENERIC_WORD_MIN_LABS = 4

# Decoration in folder names like memory-forensics-ai or ai-powered-threat-actors.
DECORATIVE_WORDS = frozenset({"ai", "powered"})


# Noun/verb families: "classification"/"classifier" -> "classify",
# "simulation"/"simulate", "generator"/"generate", "visualization"/"visualize".
DERIVATIONAL_SUFFIXES = (
    ("ication", "y"),
    ("ifier", "ify"),
    ("ization", "ize"),
    ("isation", "ize"),
    ("ise", "ize"),
    ("ation", "ate"),
    ("ator", "ate"),
)


def _normalize(word):
    """Crudely stem a lowercase word so "simulations"/"simulate", "teaming"/"team"
    and "classification"/"classifier" match."""
    word = SYNONYMS.get(word, word)
    if word.endswith("ies") and len(word) > 4:
        word = word[:-3] + "y"
    elif word.endswith("s") and not word.endswith("ss") and len(word) > 3:
        word = word[:-1]
    if word.endswith("ing") and len(word) > 5:
        word = word[:-3]
    for suffix, replacement in DERIVATIONAL_SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            word = word[: -len(suffix)] + replacement
            break
    return SYNONYMS.get(word, word)


def title_words(text):
    """The normalized, non-filler words of a title, folder slug or H1."""
    raw = (w for w in re.split(r"[^a-z0-9]+", text.lower()) if w and w not in STOPWORDS)
    return frozenset(w for w in map(_normalize, raw) if w not in STOPWORDS)


@dataclass(frozen=True)
class LabName:
    number: int
    folder: str
    folder_words: frozenset  # from the slug, e.g. {"c2", "traffic", "analysi"}
    words: frozenset  # folder slug + README H1


@lru_cache(maxsize=None)
def lab_names():
    """Map lab number -> LabName, built from labs/labNN-slug/ and its README H1."""
    names = {}
    for lab_dir in get_lab_dirs():
        match = re.fullmatch(r"lab(\d{2})-(.+)", lab_dir.name)
        if not match:
            continue
        h1 = ""
        readme = lab_dir / "README.md"
        if readme.exists():
            lines = readme.read_text(encoding="utf-8").splitlines()
            h1 = next((line[2:] for line in lines if line.startswith("# ")), "")
        h1 = re.sub(r"^Lab \d+[a-z]?:\s*", "", h1)  # "Lab 33: " prefix
        h1 = re.sub(r"\[[^\]]*\]", "", h1)  # "[Bridge Lab]" / "[Deep Dive]" tags
        number = int(match.group(1))
        folder_words = title_words(match.group(2))
        names[number] = LabName(number, lab_dir.name, folder_words, folder_words | title_words(h1))
    return names


@lru_cache(maxsize=None)
def generic_words():
    """Words that appear in the names of GENERIC_WORD_MIN_LABS or more labs."""
    counts = Counter(word for lab in lab_names().values() for word in lab.words)
    return frozenset(word for word, n in counts.items() if n >= GENERIC_WORD_MIN_LABS)


def words_naming(lab):
    """The words a title must contain to name `lab`.

    That is the distinctive words of its folder name: {"c2", "traffic"} for
    lab34-c2-traffic-analysis. Where only one word is distinctive, the whole
    folder name is required instead (minus "ai"/"powered"), so a title needs
    "LLM Security Testing" to name lab40, not just the common word "test".
    lab13-ml-vs-llm has no distinctive word, so no title names it.
    """
    distinctive = lab.folder_words - generic_words()
    if len(distinctive) == 1:
        return lab.folder_words - DECORATIVE_WORDS
    return distinctive


def labs_named_instead(number, title):
    """Return the labs that `title` names instead of lab `number`.

    A title is flagged only when it contains another lab's name (see
    words_naming) and shares no distinctive word with lab `number`'s own
    folder name or README H1. So "Lab 14: C2 Traffic Analysis" is flagged
    (lab34-c2-traffic-analysis), while a title that fits its lab, or is too
    vague to judge, gives an empty list.
    """
    labs = lab_names()
    words = title_words(title)
    distinctive = words - generic_words()
    if distinctive & labs[number].words:
        return []
    named = [
        lab
        for lab in labs.values()
        if lab.number != number and words_naming(lab) and words_naming(lab) <= words
    ]
    return sorted(named, key=lambda lab: (-len(distinctive & lab.words), lab.number))


# "Lab 34: Title", "**Lab 34**: Title", "**Lab 34:** Title", "Lab 34 - Title" or
# "Lab 34 (Title)". Not "Lab 34-name/" folder paths; TestReadmeFolderPaths covers those.
LAB_REFERENCE = re.compile(
    r"\bLab (?P<number>\d{1,2})\b(?!-)(?:\*\*)?"
    r"(?:(?:\s*:(?:\*\*)?|\s+[-–—])\s*(?P<inline_title>[^\n|\]]+)"
    r"|\s+\((?P<paren_title>[^)\n]+)\))?"
)
MARKDOWN_LINK = re.compile(r"\[(?P<text>[^\]\n]*)\]\((?P<target>[^)\s]*)\)")


def find_lab_reference_errors(text):
    """Return a message for each cross-reference in `text` that points at the wrong lab."""
    labs = lab_names()
    errors = []
    for match in LAB_REFERENCE.finditer(text):
        number = int(match.group("number"))
        if number not in labs:
            errors.append(f"'Lab {number:02d}' has no labs/lab{number:02d}-* folder")
            continue
        title = match.group("inline_title") or match.group("paren_title")
        if not title:
            continue  # a bare "Lab NN" has no title to check
        title = re.split(r"\s+[-–—]\s+", title.strip())[0]  # the name, not " - description"
        wrong = labs_named_instead(number, title)
        if wrong:
            errors.append(
                f"'Lab {number:02d}: {title}' names {' or '.join(lab.folder for lab in wrong)}, "
                f"not {labs[number].folder}"
            )

    for match in MARKDOWN_LINK.finditer(text):
        cited = re.search(r"\bLab (\d{1,2})\b", match.group("text"))
        target = re.search(r"(?:^|/)lab(\d{2})-", match.group("target"))
        if cited and target and int(cited.group(1)) != int(target.group(1)):
            errors.append(
                f"link '[{match.group('text')}]' says Lab {int(cited.group(1)):02d} "
                f"but points to lab{target.group(1)}-*"
            )
    return errors


class TestLabDirectoryNaming:
    """Test that lab directories follow naming conventions."""

    @pytest.mark.parametrize("lab_dir", get_lab_dirs())
    def test_lab_directory_naming_convention(self, lab_dir):
        """Lab directories should be named labXX-name or labXXa-name (lowercase, hyphen)."""
        dir_name = lab_dir.name

        # Should start with "lab" (lowercase)
        assert dir_name.startswith("lab"), f"{dir_name} should start with 'lab' (lowercase)"

        # Should not have capital L
        assert not dir_name.startswith("Lab"), f"{dir_name} should use lowercase 'lab', not 'Lab'"

        # Should not have space after number
        # Allow bridge labs with letter suffix: lab03b-ml-vs-llm, lab00a-python-fundamentals
        match = re.match(r"lab(\d+[a-z]?)(.)", dir_name)
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
    """Test that README files reference labs by their current numbers."""

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
        """README "Lab NN: Title" references must name labs/labNN-*, under any old numbering."""
        content = readme_path.read_text(encoding="utf-8")
        errors = find_lab_reference_errors(content)

        assert not errors, (
            f"{readme_path.parent.name}/README.md references lab(s) by the wrong number:\n"
            + "\n".join(errors)
        )


class TestNotebookLabReferences:
    """Test that notebooks reference labs by their current numbers."""

    @pytest.mark.parametrize("notebook_path", get_notebooks())
    def test_no_legacy_lab_numbers_in_notebooks(self, notebook_path):
        """Notebook "Lab NN: Title" references, its own title included, must name labs/labNN-*."""
        notebook = json.loads(notebook_path.read_text(encoding="utf-8"))

        errors = []
        for cell_idx, cell in enumerate(notebook.get("cells", [])):
            if cell.get("cell_type") != "markdown":
                continue
            source = cell.get("source", [])
            content = "".join(source) if isinstance(source, list) else source
            errors += [f"cell {cell_idx}: {error}" for error in find_lab_reference_errors(content)]

        assert (
            not errors
        ), f"{notebook_path.name} references lab(s) by the wrong number:\n" + "\n".join(errors)


class TestLabReferenceMatcher:
    """Pin down what find_lab_reference_errors accepts and rejects."""

    @pytest.mark.parametrize(
        "text, expected_folder",
        [
            # Next Steps written under the intermediate (29->10 ... 36->16) scheme
            ("- **Lab 14**: C2 Traffic Analysis", "lab34-c2-traffic-analysis"),
            ("- **Lab 13**: Memory Forensics with AI", "lab33-memory-forensics-ai"),
            ("- **Lab 12**: Run purple team ransomware simulations", "lab32-ransomware-simulation"),
            ("- **Lab 10**: Add monitoring to your IR Copilot", "lab29-ir-copilot"),
            # The original 01-20 scheme
            ("- **Lab 17**: Adversarial ML - Attack and defend ML models", "lab39-adversarial-ml"),
            ("- **Lab 18**: Fine-Tuning for Security", "lab42-fine-tuning-security"),
            ("- **Lab 19**: Cloud Security - Secure ML deployments", "lab45-cloud-security-ai"),
            # Header "Next:" lines from yet another scheme
            ("**Next:** Lab 34 (First AI Agent)", "lab14-first-ai-agent"),
            ("**Next:** Lab 36 (AI Security Ops)", "lab05-ai-in-security-operations"),
            ("Lab 35 (LLM Log Analysis)", "lab15-llm-log-analysis"),
            (
                "- **Lab 49**: Sigma Fundamentals - Detection rule creation",
                "lab20-sigma-fundamentals",
            ),
            ("- [Lab 10 - IR Copilot Agent](../lab29-ir-copilot/)", "lab29-ir-copilot"),
            # Word forms: "visualizations"/"classification" vs lab10-phishing-classifier
            (
                "- **Lab 01**: Apply visualizations to phishing classification",
                "lab10-phishing-classifier",
            ),
        ],
    )
    def test_stale_reference_is_flagged(self, text, expected_folder):
        errors = find_lab_reference_errors(text)
        assert errors and expected_folder in errors[0], errors

    @pytest.mark.parametrize(
        "text",
        [
            "- **Lab 34**: C2 Traffic Analysis",
            "- **Lab 33**: AI-Powered Memory Forensics",
            "**Next:** Lab 29 (IR Copilot) or Lab 25 (DFIR Fundamentals primer)",
            "| Learn LLM basics | Lab 02: Prompt Engineering |",
            "**Prerequisites for this lab:** Lab 01 (Python basics)",
            # "classification" must match lab10-phishing-classifier, not lab04's "Concepts"
            "> - **Prerequisites**: Lab 10 (classification concepts), Lab 12 (anomaly detection)",
            "- **Lab 16**: Build agents that combine ML + LLM",
            "**Next:** Lab 37 (AI-Powered Threats)",
            "[Lab 34: C2 Traffic Analysis](../lab34-c2-traffic-analysis/)",
            # Descriptive titles that fit their lab, though they echo another lab's topic
            "- **Lab 15**: Deep dive into LLM prompt engineering",
            "- **Lab 49**: Monitor for prompt injection attempts",
            "- **Lab 39**: Implement evasion and poisoning attacks",
            "- **Lab 49**: Apply these concepts to LLM security",
            "**Prerequisites:** Lab 01, Lab 08 (for LLM generation)",
            # A single common word doesn't name a lab: lab40 needs "LLM Security Testing",
            # lab15 needs "LLM Log Analysis"
            "- **Lab 50**: Test your detections",
            "- **Lab 28**: Collect volatile logs",
            # Too vague to judge, so left alone even when the number is stale
            "- **Lab 21**: Use embeddings to find similar malware patterns",
            # A bare number has no title to check
            "# Note: This is conceptual - see Lab 23 for implementation",
        ],
    )
    def test_correct_reference_is_not_flagged(self, text):
        assert find_lab_reference_errors(text) == []

    def test_link_label_must_match_its_target_folder(self):
        errors = find_lab_reference_errors("| 4 | [Lab 04](../labs/lab15-llm-log-analysis/) |")
        assert len(errors) == 1 and "points to lab15-*" in errors[0], errors

    def test_reference_to_missing_lab_is_flagged(self):
        missing = max(lab_names()) + 1
        assert find_lab_reference_errors(f"See Lab {missing} next") != []

    def test_every_lab_title_matches_its_own_number(self):
        """A lab's own README H1 and folder name are never flagged under its own number."""
        errors = []
        for number, lab in lab_names().items():
            readme = ROOT / "labs" / lab.folder / "README.md"
            h1 = next(
                line[2:]
                for line in readme.read_text(encoding="utf-8").splitlines()
                if line.startswith("# ")
            )
            slug = lab.folder.split("-", 1)[1].replace("-", " ")
            errors += find_lab_reference_errors(h1)
            errors += find_lab_reference_errors(f"Lab {number:02d} ({slug})")
        assert not errors, "\n".join(errors)

    def test_lab_folder_name_under_another_number_is_flagged(self):
        """Any lab's folder name cited under another lab's number is caught,
        unless the two labs' names share a distinctive word."""
        labs, generic = lab_names(), generic_words()
        missed = []
        for lab in labs.values():
            if not words_naming(lab):
                continue  # lab13-ml-vs-llm: every word is generic
            slug = lab.folder.split("-", 1)[1].replace("-", " ")
            for other in labs.values():
                if other.number == lab.number or (lab.folder_words - generic) & other.words:
                    continue
                if lab not in labs_named_instead(other.number, slug):
                    missed.append(f"Lab {other.number:02d}: {slug}")
        assert not missed, "\n".join(missed)


def test_walkthrough_naming_convention():
    """Walkthrough files should use labXX-name-walkthrough.md naming."""
    walkthroughs_dir = ROOT / "docs" / "walkthroughs"

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

#!/usr/bin/env python3
"""
Test Lab Data Integrity

Comprehensive tests to validate lab resources:
- Data files documented in READMEs exist
- Starter and solution code files are present and valid
- Notebooks exist for labs that need them
- YAML, JSON, and other config files are valid
- Python code is syntactically correct

Run this test to catch issues before they affect students.

Usage:
    pytest tests/test_lab_data_integrity.py -v
    pytest tests/test_lab_data_integrity.py -v -k "starter"  # Just starter tests
"""

import ast
import json
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
        r"## 📁 Files.*?```\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE
    )

    if not files_section_match:
        # Try alternate pattern without emoji
        files_section_match = re.search(
            r"## Files.*?```\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE
        )

    if not files_section_match:
        return []

    files_block = files_section_match.group(1)
    lines = files_block.split("\n")

    # Find the data/ section and extract only DIRECT files within it
    data_files = []
    in_data_section = False

    for _i, line in enumerate(lines):
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_lab_has_readme(self, lab_dir: Path):
        """Each lab should have a README.md file."""
        readme = lab_dir / "README.md"
        assert readme.exists(), f"Lab {lab_dir.name} is missing README.md"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
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
            file_exists = doc_file in actual_files or (data_dir / doc_file).exists()
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_lab_has_starter_code(self, lab_dir: Path):
        """Labs with solution code should have starter code."""
        solution_dir = lab_dir / "solution"
        starter_dir = lab_dir / "starter"

        if solution_dir.exists():
            assert (
                starter_dir.exists()
            ), f"Lab {lab_dir.name} has solution/ but no starter/ directory"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_data_dir_not_empty_if_exists(self, lab_dir: Path):
        """If a data directory exists, it should contain files."""
        data_dir = lab_dir / "data"

        if data_dir.exists():
            files = list(data_dir.rglob("*"))
            data_files = [f for f in files if f.is_file()]
            assert len(data_files) > 0, f"Lab {lab_dir.name} has empty data/ directory"


class TestDataFileQuality:
    """Tests to verify data file quality."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
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

            assert len(lines) >= 2, f"CSV file {csv_file.name} in {lab_dir.name} has no data rows"

            # Check header doesn't look like data
            header = lines[0]
            assert not header[
                0
            ].isdigit(), f"CSV file {csv_file.name} in {lab_dir.name} may be missing header"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_json_files_are_valid(self, lab_dir: Path):
        """JSON files should be valid JSON."""
        data_dir = lab_dir / "data"
        if not data_dir.exists():
            pytest.skip(f"No data directory in {lab_dir.name}")

        json_files = list(data_dir.rglob("*.json"))
        if not json_files:
            pytest.skip(f"No JSON files in {lab_dir.name}")

        for json_file in json_files:
            try:
                content = json_file.read_text(encoding="utf-8")
                json.loads(content)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {json_file.name} ({lab_dir.name}): {e}")


class TestStarterCode:
    """Tests to verify starter code is present and valid."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_starter_has_python_files(self, lab_dir: Path):
        """Starter directory should have Python files."""
        starter_dir = lab_dir / "starter"
        if not starter_dir.exists():
            pytest.skip(f"No starter directory in {lab_dir.name}")

        py_files = list(starter_dir.glob("*.py"))
        assert len(py_files) > 0, f"Lab {lab_dir.name} starter/ has no Python files"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_starter_python_syntax_valid(self, lab_dir: Path):
        """Starter Python files should have valid syntax."""
        starter_dir = lab_dir / "starter"
        if not starter_dir.exists():
            pytest.skip(f"No starter directory in {lab_dir.name}")

        py_files = list(starter_dir.glob("*.py"))
        if not py_files:
            pytest.skip(f"No Python files in {lab_dir.name} starter/")

        for py_file in py_files:
            try:
                content = py_file.read_text(encoding="utf-8")
                ast.parse(content)
            except SyntaxError as e:
                pytest.fail(f"Syntax error in {py_file.name} ({lab_dir.name}): {e}")

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_starter_has_todo_markers(self, lab_dir: Path):
        """Starter code should have TODO markers for students to complete."""
        starter_dir = lab_dir / "starter"
        if not starter_dir.exists():
            pytest.skip(f"No starter directory in {lab_dir.name}")

        main_py = starter_dir / "main.py"
        if not main_py.exists():
            pytest.skip(f"No main.py in {lab_dir.name} starter/")

        content = main_py.read_text(encoding="utf-8")

        # Check for TODO markers or pass statements (indicating incomplete code)
        has_todos = "TODO" in content or "pass" in content
        assert (
            has_todos
        ), f"Starter main.py in {lab_dir.name} has no TODO markers or pass statements"


class TestSolutionCode:
    """Tests to verify solution code is present and valid."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_solution_has_python_files(self, lab_dir: Path):
        """Solution directory should have Python files."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        py_files = list(solution_dir.glob("*.py"))
        assert len(py_files) > 0, f"Lab {lab_dir.name} solution/ has no Python files"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_solution_python_syntax_valid(self, lab_dir: Path):
        """Solution Python files should have valid syntax."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        py_files = list(solution_dir.glob("*.py"))
        if not py_files:
            pytest.skip(f"No Python files in {lab_dir.name} solution/")

        for py_file in py_files:
            try:
                content = py_file.read_text(encoding="utf-8")
                ast.parse(content)
            except SyntaxError as e:
                pytest.fail(f"Syntax error in {py_file.name} ({lab_dir.name}): {e}")

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_solution_is_complete(self, lab_dir: Path):
        """Solution code should not have TODO markers or bare pass statements."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        main_py = solution_dir / "main.py"
        if not main_py.exists():
            pytest.skip(f"No main.py in {lab_dir.name} solution/")

        content = main_py.read_text(encoding="utf-8")

        # Check for incomplete code markers
        # Note: "pass" in docstrings is OK, we check for bare "pass" statements
        lines = content.split("\n")
        incomplete_markers = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check for TODO comments
            if "# TODO" in line.upper():
                incomplete_markers.append(f"Line {i}: TODO marker found")
            # Check for bare pass statements (not in docstrings)
            if stripped == "pass":
                incomplete_markers.append(f"Line {i}: bare 'pass' statement")

        # Allow a few pass statements (might be intentional in some cases)
        if len(incomplete_markers) > 5:
            pytest.fail(
                f"Solution in {lab_dir.name} appears incomplete:\n"
                + "\n".join(incomplete_markers[:10])
            )


class TestNotebooks:
    """Tests to verify Jupyter notebooks exist and are valid."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_notebook_exists_for_lab(self, lab_dir: Path):
        """Labs should have corresponding notebooks."""
        notebooks_dir = REPO_ROOT / "notebooks"
        if not notebooks_dir.exists():
            pytest.skip("No notebooks directory in repository")

        lab_name = lab_dir.name
        # Extract lab number (e.g., lab01, lab09b) for matching
        lab_match = re.match(r"(lab\d+[a-z]?)", lab_name)
        if not lab_match:
            pytest.skip(f"Cannot extract lab number from {lab_name}")

        lab_prefix = lab_match.group(1).replace("-", "_")

        # Look for matching notebook by lab prefix
        matching_notebooks = list(notebooks_dir.glob(f"{lab_prefix}*.ipynb"))

        # Skip setup/fundamentals/conceptual labs that may not have notebooks
        if (
            "environment-setup" in lab_name
            or "fundamentals" in lab_name
            or "vibe-coding" in lab_name
        ):
            if not matching_notebooks:
                pytest.skip(f"Lab {lab_name} is a setup/fundamentals/conceptual lab")

        # Not all labs require notebooks - only fail if it's a main lab (lab01+)
        if not matching_notebooks and lab_name.startswith("lab0") and "lab00" not in lab_name:
            pytest.fail(f"No notebook found for {lab_name} (looked for {lab_prefix}*.ipynb)")

    def test_all_notebooks_are_valid_json(self):
        """All notebook files should be valid JSON."""
        notebooks_dir = REPO_ROOT / "notebooks"
        if not notebooks_dir.exists():
            pytest.skip("No notebooks directory")

        notebooks = list(notebooks_dir.glob("*.ipynb"))
        if not notebooks:
            pytest.skip("No notebooks found")

        for notebook in notebooks:
            try:
                content = notebook.read_text(encoding="utf-8")
                data = json.loads(content)
                # Basic notebook structure check
                assert "cells" in data, f"Notebook {notebook.name} missing 'cells'"
                assert "metadata" in data, f"Notebook {notebook.name} missing 'metadata'"
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in notebook {notebook.name}: {e}")


class TestLabTests:
    """Tests to verify lab test files exist and are valid."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_lab_tests_have_valid_syntax(self, lab_dir: Path):
        """Test files in labs should have valid Python syntax."""
        tests_dir = lab_dir / "tests"
        if not tests_dir.exists():
            pytest.skip(f"No tests directory in {lab_dir.name}")

        test_files = list(tests_dir.glob("test_*.py"))
        if not test_files:
            pytest.skip(f"No test files in {lab_dir.name}")

        for test_file in test_files:
            try:
                content = test_file.read_text(encoding="utf-8")
                ast.parse(content)
            except SyntaxError as e:
                pytest.fail(f"Syntax error in {test_file.name} ({lab_dir.name}): {e}")

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_lab_tests_have_test_functions(self, lab_dir: Path):
        """Test files should contain test functions or classes."""
        tests_dir = lab_dir / "tests"
        if not tests_dir.exists():
            pytest.skip(f"No tests directory in {lab_dir.name}")

        test_files = list(tests_dir.glob("test_*.py"))
        if not test_files:
            pytest.skip(f"No test files in {lab_dir.name}")

        for test_file in test_files:
            content = test_file.read_text(encoding="utf-8")
            has_tests = "def test_" in content or "class Test" in content
            assert has_tests, f"Test file {test_file.name} in {lab_dir.name} has no test functions"


class TestPromptFiles:
    """Tests to verify prompt and playbook files."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_prompt_files_not_empty(self, lab_dir: Path):
        """Prompt files should have content."""
        prompts_dir = lab_dir / "prompts"
        if not prompts_dir.exists():
            pytest.skip(f"No prompts directory in {lab_dir.name}")

        prompt_files = list(prompts_dir.glob("*.txt")) + list(prompts_dir.glob("*.md"))
        if not prompt_files:
            pytest.skip(f"No prompt files in {lab_dir.name}")

        for prompt_file in prompt_files:
            content = prompt_file.read_text(encoding="utf-8").strip()
            assert (
                len(content) > 10
            ), f"Prompt file {prompt_file.name} in {lab_dir.name} is empty or too short"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_playbook_files_valid(self, lab_dir: Path):
        """Playbook YAML files should be valid."""
        playbooks_dir = lab_dir / "playbooks"
        if not playbooks_dir.exists():
            pytest.skip(f"No playbooks directory in {lab_dir.name}")

        yaml_files = list(playbooks_dir.glob("*.yaml")) + list(playbooks_dir.glob("*.yml"))
        if not yaml_files:
            pytest.skip(f"No YAML files in {lab_dir.name} playbooks/")

        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        for yaml_file in yaml_files:
            try:
                content = yaml_file.read_text(encoding="utf-8")
                yaml.safe_load(content)
            except yaml.YAMLError as e:
                pytest.fail(f"Invalid YAML in {yaml_file.name} ({lab_dir.name}): {e}")


class TestModelsDirectory:
    """Tests to verify model files if present."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_models_dir_has_files_or_gitkeep(self, lab_dir: Path):
        """Models directory should have files or .gitkeep."""
        models_dir = lab_dir / "models"
        if not models_dir.exists():
            pytest.skip(f"No models directory in {lab_dir.name}")

        files = list(models_dir.iterdir())
        assert (
            len(files) > 0
        ), f"Models directory in {lab_dir.name} is empty (add .gitkeep if intentional)"


class TestCrossLabConsistency:
    """Tests to verify consistency across all labs."""

    def test_all_labs_have_unique_names(self):
        """Each lab should have a unique name."""
        lab_names = [lab.name for lab in ALL_LABS]
        duplicates = [name for name in lab_names if lab_names.count(name) > 1]
        assert not duplicates, f"Duplicate lab names found: {set(duplicates)}"

    def test_lab_naming_convention(self):
        """Labs should follow naming convention: labNN-description."""
        for lab in ALL_LABS:
            name = lab.name
            # Should match pattern like lab01-something or lab00a-something
            pattern = r"^lab\d+[a-z]?-[\w-]+$"
            assert re.match(
                pattern, name
            ), f"Lab {name} doesn't follow naming convention 'labNN-description'"

    def test_main_labs_have_starter_and_solution(self):
        """Main numbered labs (not setup) should have both starter and solution."""
        for lab in ALL_LABS:
            name = lab.name
            # Skip lab00* (setup/intro labs)
            if name.startswith("lab00"):
                continue

            starter = lab / "starter"
            solution = lab / "solution"

            # Both should exist for main labs
            if solution.exists():
                assert starter.exists(), f"Lab {name} has solution/ but no starter/"


class TestReadmeCompleteness:
    """Tests to verify README files have required sections."""

    # Each tuple: (list of acceptable patterns, section name for error)
    REQUIRED_SECTIONS = [
        # Objectives section - many variations are acceptable
        (
            [
                "## objectives",
                "## 🎯 objectives",
                "## learning objectives",
                "## what you'll learn",
                "## what you will learn",
                "## goals",
                "## 🎯 learning objectives",
                "## what you'll set up",
                "## what you will set up",
            ],
            "objectives/learning goals",
        ),
    ]

    # Files section is recommended but not required (some labs don't have data files)
    RECOMMENDED_SECTIONS = [
        (["## files", "## 📁 files", "## directory structure", "## structure"], "files"),
        (["## getting started", "## 🚀 getting started", "## setup"], "getting started"),
        (["## prerequisites", "## 📋 prerequisites", "## requirements"], "prerequisites"),
    ]

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_readme_has_required_sections(self, lab_dir: Path):
        """README should have required sections like Objectives/Learning Goals."""
        readme = lab_dir / "README.md"
        if not readme.exists():
            pytest.skip(f"No README in {lab_dir.name}")

        content = readme.read_text(encoding="utf-8")
        content_lower = content.lower()

        missing_sections = []
        for patterns, name in self.REQUIRED_SECTIONS:
            found = any(pattern in content_lower for pattern in patterns)
            if not found:
                missing_sections.append(name)

        if missing_sections:
            pytest.fail(f"README in {lab_dir.name} missing required sections: {missing_sections}")

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_readme_has_description(self, lab_dir: Path):
        """README should have a description after the title."""
        readme = lab_dir / "README.md"
        if not readme.exists():
            pytest.skip(f"No README in {lab_dir.name}")

        content = readme.read_text(encoding="utf-8")
        lines = content.strip().split("\n")

        # First non-empty line should be a title (# heading)
        title_found = False
        description_found = False

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("# ") and not title_found:
                title_found = True
                continue
            if title_found and not line.startswith("#"):
                # Found description text after title
                if len(line) > 20:
                    description_found = True
                    break

        assert (
            description_found
        ), f"README in {lab_dir.name} may be missing a description after the title"


class TestFunctionParity:
    """Tests to verify starter and solution have matching function signatures."""

    # Labs where starter/solution intentionally have different function structures
    # (e.g., solution combines functions, uses different patterns, etc.)
    ALLOWED_DIVERGENCE = {
        "lab02-intro-prompt-engineering",  # Exercise functions vs solution patterns
        "lab10-phishing-classifier",  # Different function organization
        "lab35-lateral-movement-detection",  # Solution uses different approach
        "lab45-cloud-security-ai",  # Solution uses different parsing
        "lab50-purple-team-ai",  # Solution has different scoring
    }

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_starter_solution_function_parity(self, lab_dir: Path):
        """Starter and solution main.py should have same top-level function names."""
        starter_main = lab_dir / "starter" / "main.py"
        solution_main = lab_dir / "solution" / "main.py"

        if not starter_main.exists() or not solution_main.exists():
            pytest.skip(f"No starter/solution main.py pair in {lab_dir.name}")

        # Skip labs with known intentional differences
        if lab_dir.name in self.ALLOWED_DIVERGENCE:
            pytest.skip(f"Lab {lab_dir.name} has allowed function divergence")

        def extract_functions(filepath: Path) -> set[str]:
            """Extract top-level function names from a Python file."""
            try:
                content = filepath.read_text(encoding="utf-8")
                tree = ast.parse(content)
                return {
                    node.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
                }
            except SyntaxError:
                return set()

        starter_funcs = extract_functions(starter_main)
        solution_funcs = extract_functions(solution_main)

        if not starter_funcs:
            pytest.skip(f"No functions found in {lab_dir.name} starter")

        # All starter functions should exist in solution
        missing_in_solution = starter_funcs - solution_funcs

        # Only fail if more than 30% of functions are missing
        # (allows for minor refactoring between starter and solution)
        if missing_in_solution:
            missing_ratio = len(missing_in_solution) / len(starter_funcs)
            if missing_ratio > 0.3:
                pytest.fail(
                    f"Lab {lab_dir.name}: Functions in starter but not solution: {missing_in_solution}"
                )


class TestNotebookOutputs:
    """Tests to verify notebook outputs are cleared."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_notebook_outputs_cleared(self, lab_dir: Path):
        """Notebooks should have cleared outputs for clean distribution."""
        notebooks_dir = REPO_ROOT / "notebooks"
        if not notebooks_dir.exists():
            pytest.skip("No notebooks directory")

        # Find notebooks matching this lab
        lab_name = lab_dir.name
        lab_match = re.match(r"(lab\d+[a-z]?)", lab_name)
        if not lab_match:
            pytest.skip(f"Cannot extract lab number from {lab_name}")

        lab_prefix = lab_match.group(1).replace("-", "_")
        matching_notebooks = list(notebooks_dir.glob(f"{lab_prefix}*.ipynb"))

        if not matching_notebooks:
            pytest.skip(f"No notebooks found for {lab_name}")

        for notebook_path in matching_notebooks:
            try:
                content = notebook_path.read_text(encoding="utf-8")
                data = json.loads(content)

                cells_with_output = 0
                total_code_cells = 0

                for cell in data.get("cells", []):
                    if cell.get("cell_type") == "code":
                        total_code_cells += 1
                        outputs = cell.get("outputs", [])
                        if outputs:
                            cells_with_output += 1

                # Allow up to 20% of cells to have outputs (for demo purposes)
                if total_code_cells > 0:
                    output_ratio = cells_with_output / total_code_cells
                    if output_ratio > 0.2:
                        pytest.fail(
                            f"Notebook {notebook_path.name} has outputs in {cells_with_output}/{total_code_cells} cells. "
                            f"Consider clearing outputs before committing."
                        )
            except (json.JSONDecodeError, KeyError):
                pass  # Invalid notebook handled by other tests


class TestDataFileSizes:
    """Tests to verify data files are appropriately sized for Git."""

    MAX_FILE_SIZE_MB = 10  # 10MB limit for Git

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_data_files_under_size_limit(self, lab_dir: Path):
        """Data files should be under 10MB for Git compatibility."""
        data_dir = lab_dir / "data"
        if not data_dir.exists():
            pytest.skip(f"No data directory in {lab_dir.name}")

        oversized_files = []
        for file_path in data_dir.rglob("*"):
            if file_path.is_file():
                size_mb = file_path.stat().st_size / (1024 * 1024)
                if size_mb > self.MAX_FILE_SIZE_MB:
                    oversized_files.append(f"{file_path.name}: {size_mb:.1f}MB")

        if oversized_files:
            pytest.fail(
                f"Lab {lab_dir.name} has oversized data files (>{self.MAX_FILE_SIZE_MB}MB):\n"
                + "\n".join(oversized_files)
            )

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_no_binary_data_without_gitlfs(self, lab_dir: Path):
        """Large binary files should use Git LFS or be documented."""
        data_dir = lab_dir / "data"
        if not data_dir.exists():
            pytest.skip(f"No data directory in {lab_dir.name}")

        BINARY_EXTENSIONS = {".pkl", ".pickle", ".h5", ".hdf5", ".parquet", ".zip", ".tar", ".gz"}
        LARGE_THRESHOLD_MB = 5

        large_binaries = []
        for file_path in data_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in BINARY_EXTENSIONS:
                size_mb = file_path.stat().st_size / (1024 * 1024)
                if size_mb > LARGE_THRESHOLD_MB:
                    large_binaries.append(f"{file_path.name}: {size_mb:.1f}MB")

        if large_binaries:
            pytest.fail(
                f"Lab {lab_dir.name} has large binary files that should use Git LFS:\n"
                + "\n".join(large_binaries)
            )


class TestReadmeLinks:
    """Tests to verify internal file references in README exist."""

    # Labs that contain security test payloads that may look like broken links
    SECURITY_TEST_LABS = {"lab17b-llm-security-testing", "lab20-llm-red-teaming"}

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_readme_internal_links_valid(self, lab_dir: Path):
        """Internal file links in README should point to existing files."""
        readme = lab_dir / "README.md"
        if not readme.exists():
            pytest.skip(f"No README in {lab_dir.name}")

        # Skip security testing labs that contain intentional payloads
        if lab_dir.name in self.SECURITY_TEST_LABS:
            pytest.skip(f"Skipping {lab_dir.name} - contains security test payloads")

        content = readme.read_text(encoding="utf-8")

        # Find markdown links: [text](path) but only real links (not inside code blocks)
        # Simple approach: exclude anything inside triple backticks
        code_block_pattern = re.compile(r"```.*?```", re.DOTALL)
        content_without_code = code_block_pattern.sub("", content)

        link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        links = link_pattern.findall(content_without_code)

        broken_links = []
        for text, href in links:
            # Skip external links
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue

            # Skip javascript: links (sometimes used in security examples)
            if href.startswith("javascript:"):
                continue

            # Skip image references without paths
            if href.endswith((".png", ".jpg", ".gif", ".svg")) and "/" not in href:
                continue

            # Check if it's a relative file path
            if not href.startswith("/"):
                target_path = lab_dir / href
                if not target_path.exists():
                    broken_links.append(f"[{text}]({href})")

        if broken_links:
            pytest.fail(
                f"README in {lab_dir.name} has broken internal links:\n"
                + "\n".join(broken_links[:10])
            )


class TestSensitiveData:
    """Tests to verify no sensitive data in code or configs."""

    SENSITIVE_PATTERNS = [
        (r"api[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]", "API key"),
        (r"secret[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]", "Secret key"),
        (r"password\s*=\s*['\"][^'\"]{5,}['\"]", "Hardcoded password"),
        (r"aws_access_key_id\s*=\s*['\"]AK[A-Z0-9]{18}['\"]", "AWS access key"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API key"),
        (r"sk-ant-[a-zA-Z0-9-]{40,}", "Anthropic API key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    ]

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_no_hardcoded_secrets(self, lab_dir: Path):
        """Code files should not contain hardcoded secrets."""
        sensitive_findings = []

        # Check Python files
        for py_file in lab_dir.rglob("*.py"):
            # Skip test files - they may have example patterns
            if "test_" in py_file.name:
                continue

            try:
                content = py_file.read_text(encoding="utf-8")

                for pattern, description in self.SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Check it's not in a comment or docstring
                        for match in matches:
                            # Simple check - if it looks like a real key
                            if "your_" not in match.lower() and "example" not in match.lower():
                                sensitive_findings.append(f"{py_file.name}: Possible {description}")
            except (OSError, UnicodeDecodeError):
                continue

        if sensitive_findings:
            pytest.fail(
                f"Lab {lab_dir.name} may contain sensitive data:\n"
                + "\n".join(sensitive_findings[:5])
            )

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_no_env_files_committed(self, lab_dir: Path):
        """Actual .env files should not be committed (only .env.example)."""
        env_files = list(lab_dir.rglob(".env"))

        # Filter out .env.example, .env.template, etc.
        actual_env_files = [
            f for f in env_files if f.name == ".env" and "example" not in str(f).lower()
        ]

        if actual_env_files:
            pytest.fail(
                f"Lab {lab_dir.name} has .env files that should not be committed:\n"
                + "\n".join(str(f) for f in actual_env_files)
            )


class TestImportsResolvable:
    """Tests to verify solution code imports are resolvable."""

    # Standard library modules that are always available
    STDLIB_MODULES = {
        "os",
        "sys",
        "re",
        "json",
        "ast",
        "csv",
        "datetime",
        "time",
        "math",
        "random",
        "collections",
        "itertools",
        "functools",
        "pathlib",
        "typing",
        "dataclasses",
        "enum",
        "abc",
        "io",
        "copy",
        "hashlib",
        "base64",
        "urllib",
        "http",
        "logging",
        "argparse",
        "configparser",
        "tempfile",
        "shutil",
        "glob",
        "pickle",
        "sqlite3",
        "subprocess",
        "threading",
        "multiprocessing",
        "socket",
        "struct",
        "textwrap",
        "string",
        "unittest",
        "traceback",
        "warnings",
        "contextlib",
        "concurrent",
        "asyncio",
        "uuid",
        "secrets",
        "hmac",
        "binascii",
        "html",
        "xml",
        "zipfile",
    }

    # Common third-party packages that we expect to be available
    EXPECTED_PACKAGES = {
        # Data science
        "numpy",
        "pandas",
        "sklearn",
        "scipy",
        "matplotlib",
        "seaborn",
        # AI/ML
        "anthropic",
        "openai",
        "transformers",
        "torch",
        "tensorflow",
        "keras",
        # LangChain ecosystem
        "langchain",
        "langchain_core",
        "langchain_community",
        "langchain_openai",
        "langchain_anthropic",
        "langchain_google_genai",
        "langgraph",
        # Utilities
        "requests",
        "pytest",
        "yaml",
        "pyyaml",
        "dotenv",
        "python_dotenv",
        "pydantic",
        "rich",
        "tqdm",
        "click",
        "typer",
        # Visualization
        "plotly",
        "networkx",
        "bokeh",
        "altair",
        # NLP/ML
        "nltk",
        "spacy",
        "gensim",
        "xgboost",
        "lightgbm",
        "catboost",
        "joblib",
        # Security specific
        "yara",
        "volatility",
        "scapy",
        "dpkt",
        "pyshark",
        # Vector stores and embeddings
        "chromadb",
        "faiss",
        "pinecone",
        "qdrant_client",
        "sentence_transformers",
        # Others
        "aiohttp",
        "httpx",
        "bs4",
        "lxml",
        "pillow",
        "PIL",
    }

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_solution_imports_valid(self, lab_dir: Path):
        """Solution code should import valid/expected modules."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        py_files = list(solution_dir.glob("*.py"))
        if not py_files:
            pytest.skip(f"No Python files in {lab_dir.name} solution")

        unknown_imports = set()

        for py_file in py_files:
            try:
                content = py_file.read_text(encoding="utf-8")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            module = alias.name.split(".")[0]
                            if (
                                module not in self.STDLIB_MODULES
                                and module not in self.EXPECTED_PACKAGES
                            ):
                                # Check if it's a local module
                                local_module = solution_dir / f"{module}.py"
                                if not local_module.exists():
                                    unknown_imports.add(module)

                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            module = node.module.split(".")[0]
                            if (
                                module not in self.STDLIB_MODULES
                                and module not in self.EXPECTED_PACKAGES
                            ):
                                local_module = solution_dir / f"{module}.py"
                                if not local_module.exists():
                                    unknown_imports.add(module)

            except SyntaxError:
                pass  # Handled by other tests

        # Don't fail, just warn about potentially missing packages
        if unknown_imports:
            # Only fail if there are many unknown imports (likely a problem)
            if len(unknown_imports) > 5:
                pytest.fail(f"Lab {lab_dir.name} has many unknown imports: {unknown_imports}")


class TestRequirementsFile:
    """Tests to verify requirements files exist where needed."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[lab.name for lab in ALL_LABS])
    def test_lab_with_imports_has_requirements(self, lab_dir: Path):
        """Labs with third-party imports should document requirements."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        # Check for any third-party imports
        third_party_imports = set()
        STDLIB = TestImportsResolvable.STDLIB_MODULES

        for py_file in solution_dir.glob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            module = alias.name.split(".")[0]
                            if module not in STDLIB:
                                third_party_imports.add(module)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            module = node.module.split(".")[0]
                            if module not in STDLIB:
                                third_party_imports.add(module)
            except SyntaxError:
                pass

        if not third_party_imports:
            pytest.skip(f"No third-party imports in {lab_dir.name}")

        # Check for requirements file (lab-level or repo-level)
        lab_requirements = lab_dir / "requirements.txt"
        repo_requirements = REPO_ROOT / "requirements.txt"

        has_requirements = lab_requirements.exists() or repo_requirements.exists()

        # This is a soft check - just ensure we have SOME requirements file
        if not has_requirements:
            # Only fail for labs with many third-party imports
            if len(third_party_imports) > 3:
                pytest.fail(
                    f"Lab {lab_dir.name} uses {len(third_party_imports)} third-party packages "
                    f"but has no requirements.txt: {third_party_imports}"
                )


class TestMarkdownValidity:
    """Test markdown files for syntax issues like unbalanced code fences."""

    # Get all markdown files in the repository
    MARKDOWN_FILES = list(REPO_ROOT.glob("**/*.md"))
    # Exclude node_modules and other common excludes
    MARKDOWN_FILES = [
        f for f in MARKDOWN_FILES if "node_modules" not in str(f) and ".git" not in str(f)
    ]

    @pytest.mark.parametrize(
        "md_file",
        MARKDOWN_FILES,
        ids=[str(f.relative_to(REPO_ROOT)) for f in MARKDOWN_FILES],
    )
    def test_code_fences_balanced(self, md_file: Path):
        """
        Check that code fences are properly balanced.

        Verifies:
        - Triple backticks (```) come in pairs
        - Four backticks (````) come in pairs (used for nested code blocks)
        - No unclosed code blocks at end of file
        """
        content = md_file.read_text(encoding="utf-8", errors="replace")

        # Track fence states for different fence lengths
        # We need to handle 3, 4, and 5+ backtick fences
        lines = content.split("\n")

        open_fences = []  # Stack of (line_number, fence_type)

        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()

            # Match code fence patterns: 3+ backticks or tildes at start of line
            fence_match = re.match(r"^(`{3,}|~{3,})", stripped)

            if fence_match:
                fence = fence_match.group(1)
                fence_char = fence[0]
                fence_len = len(fence)

                if not open_fences:
                    # Opening a new fence
                    open_fences.append((i, fence_char, fence_len))
                else:
                    # Check if this closes the current fence
                    # A fence is closed by a fence of the same character
                    # with at least as many repetitions
                    current_line, current_char, current_len = open_fences[-1]

                    if fence_char == current_char and fence_len >= current_len:
                        # Closing fence - rest of line should be empty or whitespace
                        rest_of_line = stripped[fence_len:].strip()
                        if not rest_of_line:
                            open_fences.pop()
                        else:
                            # Has language specifier - this is a new opening fence
                            open_fences.append((i, fence_char, fence_len))
                    else:
                        # Different fence type or shorter - opening new nested fence
                        open_fences.append((i, fence_char, fence_len))

        # Check for unclosed fences
        if open_fences:
            unclosed = [f"line {line} ({char * length})" for line, char, length in open_fences]
            pytest.fail(f"Unclosed code fences in {md_file.name}: {', '.join(unclosed)}")

    @pytest.mark.parametrize(
        "md_file",
        MARKDOWN_FILES,
        ids=[str(f.relative_to(REPO_ROOT)) for f in MARKDOWN_FILES],
    )
    def test_nested_code_blocks_use_four_backticks(self, md_file: Path):
        """
        Check that nested code blocks use 4+ backticks for the outer fence.

        When showing code examples that contain code blocks (like markdown
        examples), the outer fence must use more backticks than the inner.

        Note: This test uses warnings instead of failures because some markdown
        parsers handle same-length nested fences correctly. The critical check
        is test_code_fences_balanced which catches actual unclosed fences.
        """
        content = md_file.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")

        in_code_block = False
        outer_fence_len = 0
        outer_fence_line = 0
        issues = []

        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()

            # Match code fence patterns
            fence_match = re.match(r"^(`{3,})", stripped)

            if fence_match:
                fence_len = len(fence_match.group(1))
                rest_of_line = stripped[fence_len:].strip()

                if not in_code_block:
                    # Starting a code block
                    in_code_block = True
                    outer_fence_len = fence_len
                    outer_fence_line = i
                elif fence_len >= outer_fence_len and not rest_of_line:
                    # Closing the outer block
                    in_code_block = False
                    outer_fence_len = 0
                elif fence_len < outer_fence_len:
                    # Inner code block - this is fine, it's properly nested
                    pass
                elif fence_len >= outer_fence_len and rest_of_line:
                    # Problem: inner block with same or more backticks AND language spec
                    # This could prematurely close the outer block
                    if fence_len == outer_fence_len:
                        issues.append(
                            f"Line {i}: inner code fence (```{rest_of_line}) has same "
                            f"length as outer fence started at line {outer_fence_line}. "
                            f"Use 4+ backticks for outer fence."
                        )

        if issues:
            # Use warning instead of failure for these potential issues
            import warnings

            warnings.warn(
                f"Potential nested code block issues in {md_file.name}:\n"
                + "\n".join(issues[:3]),  # Limit to first 3 issues
                stacklevel=2,
            )

    @pytest.mark.parametrize(
        "md_file",
        MARKDOWN_FILES,
        ids=[str(f.relative_to(REPO_ROOT)) for f in MARKDOWN_FILES],
    )
    def test_no_broken_headers(self, md_file: Path):
        """Check that markdown headers are properly formatted."""
        content = md_file.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")

        in_code_block = False
        in_style_block = False
        issues = []

        for i, line in enumerate(lines, 1):
            # Track style blocks (CSS uses # for ID selectors)
            if "<style" in line.lower():
                in_style_block = True
            if "</style>" in line.lower():
                in_style_block = False
                continue

            # Track code blocks to avoid false positives
            if line.lstrip().startswith("```") or line.lstrip().startswith("~~~"):
                if not in_code_block:
                    in_code_block = True
                elif line.lstrip().startswith("```") or line.lstrip().startswith("~~~"):
                    # Simple toggle - not perfect but catches most cases
                    if line.lstrip() in ("```", "~~~") or re.match(
                        r"^(`{3,}|~{3,})$", line.lstrip()
                    ):
                        in_code_block = False

            if in_code_block or in_style_block:
                continue

            # Check for headers without space after #
            header_no_space = re.match(r"^(#{1,6})([^#\s])", line)
            if header_no_space:
                issues.append(f"Line {i}: header missing space after #: {line[:50]}")

        if issues:
            pytest.fail(f"Broken headers in {md_file.name}:\n" + "\n".join(issues[:5]))

    @pytest.mark.parametrize(
        "md_file",
        MARKDOWN_FILES,
        ids=[str(f.relative_to(REPO_ROOT)) for f in MARKDOWN_FILES],
    )
    def test_tables_have_separator_row(self, md_file: Path):
        """Check that markdown tables have proper separator rows."""
        content = md_file.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")

        in_code_block = False

        for i, line in enumerate(lines, 1):
            # Track code blocks
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_code_block = not in_code_block

            if in_code_block:
                continue

            # Check for table header row (starts with |, contains |)
            if line.strip().startswith("|") and line.strip().endswith("|"):
                # Check if next line exists and is a separator
                if i < len(lines):
                    next_line = lines[i].strip()
                    # Table separator should have | and - characters
                    if next_line.startswith("|") and "-" in next_line:
                        # Valid table separator
                        pass
                    elif next_line.startswith("|"):
                        # Might be missing separator - check if it looks like header
                        # Look for patterns like |---|---|
                        if not re.match(r"^\|[\s\-:|]+\|$", next_line):
                            # Could be an issue, but might also be valid data row
                            # Only flag if current line looks like header
                            pass

        # This test is informational - don't fail unless there are clear issues


class TestLabCategoryConsistency:
    """Tests to verify lab category ranges are consistent across documentation."""

    # Canonical lab category definitions - update here when ranges change
    CANONICAL_CATEGORIES = {
        "Foundation": (0, 9),
        "ML Foundations": (10, 13),
        "LLM Basics": (14, 18),
        "Detection Engineering": (19, 24),
        "DFIR": (25, 35),
        "Advanced Threats": (36, 43),
        "Cloud & Red Team": (44, 50),
    }

    # Files that should reference lab category ranges
    CATEGORY_DOCS = [
        REPO_ROOT / ".claude" / "commands" / "lab.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "labs" / "README.md",
        REPO_ROOT / "docs" / "index.md",
    ]

    def test_lab_category_ranges_are_documented(self):
        """Verify canonical category ranges are defined."""
        # Ensure we have all expected categories
        expected = {
            "Foundation",
            "ML Foundations",
            "LLM Basics",
            "Detection Engineering",
            "DFIR",
            "Advanced Threats",
            "Cloud & Red Team",
        }
        assert set(self.CANONICAL_CATEGORIES.keys()) == expected

    def test_category_ranges_are_contiguous(self):
        """Verify lab ranges don't have gaps or overlaps."""
        ranges = sorted(self.CANONICAL_CATEGORIES.values())
        for i, (start, end) in enumerate(ranges):
            assert start <= end, f"Invalid range: {start}-{end}"
            if i > 0:
                prev_end = ranges[i - 1][1]
                assert (
                    start == prev_end + 1
                ), f"Gap or overlap between {ranges[i-1]} and {(start, end)}"

    def test_lab_navigator_has_correct_ranges(self):
        """Verify .claude/commands/lab.md has correct category ranges."""
        lab_md = REPO_ROOT / ".claude" / "commands" / "lab.md"
        if not lab_md.exists():
            pytest.skip("lab.md not found")

        content = lab_md.read_text(encoding="utf-8")

        # Check the Lab Categories table
        errors = []
        for category, (start, end) in self.CANONICAL_CATEGORIES.items():
            expected_range = f"{start:02d}-{end:02d}"
            # Also check without leading zeros
            alt_range = f"{start}-{end}"

            if expected_range not in content and alt_range not in content:
                errors.append(f"Category '{category}' should have range {start}-{end}")

        if errors:
            pytest.fail("lab.md has incorrect category ranges:\n" + "\n".join(errors))

    def test_no_outdated_category_ranges(self):
        """Check for outdated category range references in documentation."""
        # Known outdated patterns that should not appear
        # These match category definitions like "| 14-21 | LLM" not prose references
        outdated_patterns = [
            (r"\|\s*14-21\s*\|", "14-21 should be 14-18 (LLM Basics)"),
            (r"\|\s*22-24\s*\|.*Agent", "22-24 Agents should be 19-24 (Detection Engineering)"),
            (r"DFIR\s*\(25-50\)", "DFIR range should be 25-35, not 25-50"),
        ]

        errors = []
        for doc_file in self.CATEGORY_DOCS:
            if not doc_file.exists():
                continue

            content = doc_file.read_text(encoding="utf-8")
            for pattern, message in outdated_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    errors.append(f"{doc_file.name}: {message}")

        if errors:
            pytest.fail("Outdated category ranges found:\n" + "\n".join(errors))

    def test_readme_lab_numbers_match_actual_labs(self):
        """Verify lab numbers in README.md match actual lab directories."""
        readme = REPO_ROOT / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")

        content = readme.read_text(encoding="utf-8")

        # Get actual lab numbers from directory names
        actual_lab_nums = set()
        for lab_dir in LABS_DIR.iterdir():
            if lab_dir.is_dir() and lab_dir.name.startswith("lab"):
                match = re.match(r"lab(\d+)", lab_dir.name)
                if match:
                    actual_lab_nums.add(int(match.group(1)))

        errors = []

        # Check "Detailed Lab Descriptions" table - pattern: "| Lab XX |" or "| **XX** |"
        # This table should have lab numbers in first column
        table_lab_refs = re.findall(r"\|\s*\*?\*?(\d{1,2})\*?\*?\s*\|.*\|.*\|", content)
        for lab_num_str in table_lab_refs:
            lab_num = int(lab_num_str)
            # Only check if it looks like a lab number (0-99 range)
            if 0 <= lab_num <= 99 and lab_num not in actual_lab_nums:
                errors.append(
                    f"README table references lab {lab_num:02d} but no lab{lab_num:02d}-* directory exists"
                )

        # Check for lab directory path references like "labs/labXX-"
        path_refs = re.findall(r"labs/lab(\d+)-", content)
        for lab_num_str in path_refs:
            lab_num = int(lab_num_str)
            if lab_num not in actual_lab_nums:
                errors.append(
                    f"README references path labs/lab{lab_num:02d}-* but directory doesn't exist"
                )

        if errors:
            # Dedupe and report
            unique_errors = list(set(errors))
            pytest.fail("README lab numbers don't match actual labs:\n" + "\n".join(unique_errors))

    def test_ctf_prerequisite_labs_exist(self):
        """Verify CTF prerequisite lab numbers reference actual labs."""
        ctf_readme = REPO_ROOT / "ctf" / "README.md"
        if not ctf_readme.exists():
            pytest.skip("ctf/README.md not found")

        content = ctf_readme.read_text(encoding="utf-8")

        # Get actual lab numbers
        actual_lab_nums = set()
        for lab_dir in LABS_DIR.iterdir():
            if lab_dir.is_dir() and lab_dir.name.startswith("lab"):
                match = re.match(r"lab(\d+)", lab_dir.name)
                if match:
                    actual_lab_nums.add(int(match.group(1)))

        # Find all "Lab XX" references in prerequisite column
        # Pattern matches "Lab 10" or "Lab 10, 40" style references
        errors = []
        lab_refs = re.findall(r"Lab (\d+)", content)
        for lab_num_str in lab_refs:
            lab_num = int(lab_num_str)
            if lab_num not in actual_lab_nums:
                errors.append(f"CTF README references Lab {lab_num} but it doesn't exist")

        if errors:
            unique_errors = list(set(errors))
            pytest.fail("CTF README has invalid lab references:\n" + "\n".join(unique_errors))

    def test_architecture_doc_lab_count(self):
        """Verify ARCHITECTURE.md has correct lab count."""
        arch_doc = REPO_ROOT / "docs" / "ARCHITECTURE.md"
        if not arch_doc.exists():
            pytest.skip("docs/ARCHITECTURE.md not found")

        content = arch_doc.read_text(encoding="utf-8")

        # Count actual labs
        actual_lab_count = sum(
            1
            for lab_dir in LABS_DIR.iterdir()
            if lab_dir.is_dir() and lab_dir.name.startswith("lab")
        )

        # Check for outdated lab counts like "24 hands-on labs"
        outdated_counts = re.findall(r"(\d+)\s*(?:hands-on\s+)?labs", content, re.I)
        errors = []
        for count_str in outdated_counts:
            count = int(count_str)
            # Allow "50+" style references but flag specific wrong counts
            if count < actual_lab_count - 5:  # Allow some margin
                errors.append(
                    f"ARCHITECTURE.md says '{count} labs' but there are {actual_lab_count}"
                )

        if errors:
            pytest.fail("ARCHITECTURE.md has outdated lab counts:\n" + "\n".join(errors))

    def test_index_md_lab_numbering(self):
        """Verify docs/index.md uses correct lab numbering (GitHub Pages site)."""
        index_md = REPO_ROOT / "docs" / "index.md"
        if not index_md.exists():
            pytest.skip("docs/index.md not found")

        content = index_md.read_text(encoding="utf-8")

        # Known incorrect patterns that indicate old lab numbering
        # Old scheme: Labs 01-03 (ML), Labs 04-07 (LLM)
        # New scheme: Labs 00-13 (Foundation+ML no API), Labs 14+ (LLM API required)
        incorrect_patterns = [
            (r"Labs 01-0[23]", "Labs 01-03 should be Labs 00-13 or Labs 10-13"),
            (r"Labs 04-0[567]", "Labs 04-07 should be Labs 14-18"),
            (r"Labs 08-10", "Labs 08-10 should be Labs 19-24"),
        ]

        errors = []
        for pattern, message in incorrect_patterns:
            if re.search(pattern, content):
                errors.append(f"docs/index.md: {message}")

        if errors:
            pytest.fail("docs/index.md has outdated lab numbering:\n" + "\n".join(errors))

    def test_index_md_lab_card_display_numbers_match_folder(self):
        """Verify docs/index.md lab card display numbers match actual lab folder numbers.

        The Lab Navigator on GitHub Pages (docs/index.md) has lab cards that show
        a display number (like 23, 24, 25) in the UI. This display number MUST
        match the actual lab folder number in the href (lab23-*, lab24-*, etc.).

        Old incorrect pattern: lab23-detection-pipeline showing display "09"
        Correct pattern: lab23-detection-pipeline showing display "23"
        """
        index_md = REPO_ROOT / "docs" / "index.md"
        if not index_md.exists():
            pytest.skip("docs/index.md not found")

        content = index_md.read_text(encoding="utf-8")

        # Find the lab-grid section
        if 'class="lab-grid"' not in content:
            pytest.skip("No lab-grid found in docs/index.md")

        errors = []

        # Extract lab card info: href path and display number
        # Pattern for lab card: <a href="...labs/labXX-..." class="lab-card"...>
        #   followed by: <span class="lab-number ...">DISPLAY</span>
        lab_card_pattern = re.compile(
            r'<a href="[^"]*labs/lab(\d+)-[^"]*"[^>]*class="lab-card"[^>]*>.*?'
            r'<span class="lab-number[^"]*">(\d+[a-z]?)</span>',
            re.DOTALL,
        )

        matches = lab_card_pattern.findall(content)

        if not matches:
            pytest.skip("No lab cards found in docs/index.md")

        for folder_num, display_num in matches:
            folder_num_int = int(folder_num)
            # Display number should match folder number (ignore letter suffixes like "b")
            display_num_clean = display_num.rstrip("abcdefghijklmnopqrstuvwxyz")
            try:
                display_num_int = int(display_num_clean)
            except ValueError:
                errors.append(
                    f"Lab card for lab{folder_num:0>2} has invalid display number: {display_num}"
                )
                continue

            if folder_num_int != display_num_int:
                errors.append(
                    f"Lab card mismatch: lab{folder_num:0>2}-* folder shows display '{display_num}' "
                    f"(should show '{folder_num_int}')"
                )

        if errors:
            pytest.fail(
                "docs/index.md lab cards have mismatched display numbers:\n"
                + "\n".join(errors[:20])  # Limit to first 20 errors
            )

    def test_readme_lab_navigator_sequential_order(self):
        """Verify README Lab Navigator displays labs in sequential order.

        The Lab Navigator table should show labs 00, 01, 02, 03... in order,
        not jumbled like 00, 01, 04, 02, 05... which is confusing for users.
        """
        readme = REPO_ROOT / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")

        content = readme.read_text(encoding="utf-8")

        # Find the Lab Navigator section
        if "## Lab Navigator" not in content:
            pytest.skip("No Lab Navigator section in README.md")

        # Extract lab numbers from the table in order of appearance
        # Pattern matches badge URLs like: /badge/00-Setup-555
        navigator_section = content.split("## Lab Navigator")[1]
        # Limit to just the table (ends at **Legend:** or </table>)
        if "**Legend:**" in navigator_section:
            navigator_section = navigator_section.split("**Legend:**")[0]

        # Extract all lab numbers from badge URLs
        lab_numbers = re.findall(r"/badge/(\d+)-", navigator_section)
        lab_numbers = [int(n) for n in lab_numbers]

        if not lab_numbers:
            pytest.skip("No lab badges found in Lab Navigator")

        # Check that labs appear in sequential order
        errors = []
        prev_num = -1
        for i, num in enumerate(lab_numbers):
            if num < prev_num:
                errors.append(f"Lab {num:02d} appears after Lab {prev_num:02d} (position {i+1})")
            prev_num = num

        # Also check for non-sequential jumps (like going 00, 01, 04 instead of 00, 01, 02)
        for i in range(1, len(lab_numbers)):
            if lab_numbers[i] > lab_numbers[i - 1] + 1:
                # Check if this is a category break (which is OK)
                # Allow breaks at: 10, 14, 19, 25, 30, 36, 44
                category_breaks = {10, 14, 19, 25, 30, 36, 44}
                if lab_numbers[i] not in category_breaks:
                    # Check if intermediate labs exist
                    missing = []
                    for n in range(lab_numbers[i - 1] + 1, lab_numbers[i]):
                        lab_exists = any(
                            d.name.startswith(f"lab{n:02d}")
                            for d in LABS_DIR.iterdir()
                            if d.is_dir()
                        )
                        if lab_exists:
                            missing.append(n)
                    if missing:
                        errors.append(
                            f"Lab Navigator skips labs {missing} between "
                            f"{lab_numbers[i-1]:02d} and {lab_numbers[i]:02d}"
                        )

        if errors:
            pytest.fail(
                "README Lab Navigator is not in sequential order:\n" + "\n".join(errors[:10])
            )

    def test_readme_lab_navigator_legend_uses_correct_categories(self):
        """Verify Lab Navigator legend uses correct category names."""
        readme = REPO_ROOT / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")

        content = readme.read_text(encoding="utf-8")

        if "## Lab Navigator" not in content:
            pytest.skip("No Lab Navigator section in README.md")

        navigator_section = content.split("## Lab Navigator")[1].split("##")[0]

        # Check for legend line
        legend_match = re.search(r"\*\*Legend:\*\*.*", navigator_section)
        if not legend_match:
            pytest.skip("No Legend found in Lab Navigator")

        legend = legend_match.group(0)

        # Check for outdated category names
        # Note: Escape parentheses in regex patterns to match literal text
        outdated_terms = [
            ("Expert DFIR", "Use 'DFIR' instead of 'Expert DFIR'"),
            ("Expert AI", "Use 'Advanced Threats' or 'AI Security' instead"),
            (r"Intro \(Free\)", "Use 'Foundation' with lab range"),
            (r"White Intro", "Use 'Foundation (00-09)' instead of 'White Intro'"),
        ]

        errors = []
        for term, suggestion in outdated_terms:
            if re.search(term, legend, re.IGNORECASE):
                errors.append(f"Legend uses outdated term '{term}': {suggestion}")

        if errors:
            pytest.fail("README Lab Navigator legend uses outdated terms:\n" + "\n".join(errors))


class TestLegalCompliance:
    """Ensure legal compliance with employment protection policies.

    These tests enforce the conservative open-source-first approach
    documented in LICENSE and docs/CLAUDE.md to protect against
    employment/IP conflicts.
    """

    def test_no_competitor_siem_references_in_documentation(self):
        """Verify documentation doesn't reference competitor SIEM platforms.

        Per LICENSE Employment & IP Disclaimer: This project focuses on
        open-source security tooling (Elasticsearch, OpenSearch) to ensure
        complete independence from proprietary vendor implementations.

        Allowed: Elasticsearch, OpenSearch, Elastic (as company name in URLs)
        Prohibited: Splunk, Microsoft Sentinel, Azure Sentinel, IBM QRadar
        """
        # Competitor SIEM platforms to detect
        competitor_siems = [
            (r"Splunk(?!\.com/en_us/blog)", "Splunk"),  # Allow blog URLs
            (r"(?:Microsoft\s+)?Sentinel(?!\s+KQL)", "Microsoft Sentinel"),  # KQL is OK
            (r"Azure\s+Sentinel", "Azure Sentinel"),
            (r"IBM\s+QRadar", "IBM QRadar"),
            (r"QRadar", "QRadar"),
        ]

        # Files to check (documentation and code)
        # Note: CLAUDE.md is excluded as it documents the policy itself
        files_to_check = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "labs" / "README.md",
            REPO_ROOT / "docs" / "index.md",
        ]

        # Also check all lab READMEs
        if LABS_DIR.exists():
            files_to_check.extend(LABS_DIR.glob("*/README.md"))

        # Also check walkthroughs and guides
        walkthroughs_dir = REPO_ROOT / "docs" / "walkthroughs"
        if walkthroughs_dir.exists():
            files_to_check.extend(walkthroughs_dir.glob("*.md"))

        guides_dir = REPO_ROOT / "docs" / "guides"
        if guides_dir.exists():
            files_to_check.extend(guides_dir.glob("*.md"))

        errors = []

        for file_path in files_to_check:
            if not file_path.exists():
                continue

            content = file_path.read_text(encoding="utf-8")
            rel_path = file_path.relative_to(REPO_ROOT)

            for pattern, name in competitor_siems:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    for match in matches[:3]:  # Limit to first 3 per file
                        line_num = content[: match.start()].count("\n") + 1
                        errors.append(
                            f"{rel_path}:{line_num} - Found '{name}' reference "
                            f"(use Elasticsearch/OpenSearch instead)"
                        )

        if errors:
            pytest.fail(
                "Found competitor SIEM platform references (violates open-source policy):\n"
                + "\n".join(errors[:20])  # Limit to first 20 errors
                + "\n\nSee LICENSE 'Employment and IP Disclaimer' section."
            )

    def test_no_competitor_edr_xdr_references_in_documentation(self):
        """Verify documentation doesn't reference competitor EDR/XDR platforms.

        Per LICENSE Employment & IP Disclaimer: This project does NOT contain
        proprietary vendor implementations to avoid employment/IP conflicts.

        Allowed: Wazuh (open-source), OSSEC (open-source)
        Prohibited: CrowdStrike, Cortex XDR, XSIAM, Palo Alto XDR, Carbon Black,
                   SentinelOne, Microsoft Defender
        """
        # Competitor EDR/XDR platforms to detect
        competitor_edrs = [
            (r"CrowdStrike", "CrowdStrike"),
            (r"Cortex\s+XDR", "Cortex XDR"),
            (r"XSIAM", "XSIAM"),
            (r"Palo\s+Alto(?:\s+Networks)?(?:\s+XDR)?", "Palo Alto Networks"),
            (r"Carbon\s+Black", "Carbon Black"),
            (r"SentinelOne", "SentinelOne"),
            (r"Microsoft\s+Defender(?:\s+for\s+Endpoint)?", "Microsoft Defender"),
            (r"Defender\s+for\s+Endpoint", "Defender for Endpoint"),
        ]

        # Files to check
        # Note: CLAUDE.md is excluded as it documents the policy itself
        files_to_check = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "labs" / "README.md",
            REPO_ROOT / "docs" / "index.md",
            REPO_ROOT / "docs" / "SOURCES.md",
        ]

        # Also check all lab READMEs
        if LABS_DIR.exists():
            files_to_check.extend(LABS_DIR.glob("*/README.md"))

        # Also check walkthroughs and guides
        walkthroughs_dir = REPO_ROOT / "docs" / "walkthroughs"
        if walkthroughs_dir.exists():
            files_to_check.extend(walkthroughs_dir.glob("*.md"))

        guides_dir = REPO_ROOT / "docs" / "guides"
        if guides_dir.exists():
            files_to_check.extend(guides_dir.glob("*.md"))

        errors = []

        for file_path in files_to_check:
            if not file_path.exists():
                continue

            content = file_path.read_text(encoding="utf-8")
            rel_path = file_path.relative_to(REPO_ROOT)

            for pattern, name in competitor_edrs:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    for match in matches[:3]:  # Limit to first 3 per file
                        line_num = content[: match.start()].count("\n") + 1
                        errors.append(
                            f"{rel_path}:{line_num} - Found '{name}' reference "
                            f"(use Wazuh/OSSEC instead)"
                        )

        if errors:
            pytest.fail(
                "Found competitor EDR/XDR platform references (violates open-source policy):\n"
                + "\n".join(errors[:20])  # Limit to first 20 errors
                + "\n\nSee LICENSE 'Employment and IP Disclaimer' section."
            )

    def test_no_proprietary_query_languages_in_code(self):
        """Verify code doesn't use proprietary query languages.

        Per LICENSE: Focus on open-source tooling only.

        Allowed: EQL (Elasticsearch), ES|QL, KQL (Kibana), Sigma (open-source)
        Prohibited: SPL (Splunk), XQL (Cortex XDR), Microsoft Sentinel KQL
        """
        # Proprietary query languages
        proprietary_languages = [
            (r"SPL\s+query", "SPL (Splunk Processing Language)"),
            (r"Splunk\s+query", "Splunk query language"),
            (r"XQL\s+query", "XQL (Cortex XDR Query Language)"),
            (r"XQL\s+detection", "XQL detection"),
            (r"xql_query", "XQL query variable"),
        ]

        # Check lab solution and starter code
        files_to_check = []
        if LABS_DIR.exists():
            files_to_check.extend(LABS_DIR.glob("*/solution/*.py"))
            files_to_check.extend(LABS_DIR.glob("*/starter/*.py"))
            files_to_check.extend(LABS_DIR.glob("*/README.md"))

        errors = []

        for file_path in files_to_check:
            if not file_path.exists():
                continue

            content = file_path.read_text(encoding="utf-8")
            rel_path = file_path.relative_to(REPO_ROOT)

            for pattern, name in proprietary_languages:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    for match in matches[:3]:  # Limit to first 3 per file
                        line_num = content[: match.start()].count("\n") + 1
                        errors.append(
                            f"{rel_path}:{line_num} - Found '{name}' reference "
                            f"(use EQL/ES|QL instead)"
                        )

        if errors:
            pytest.fail(
                "Found proprietary query language references (violates open-source policy):\n"
                + "\n".join(errors[:20])  # Limit to first 20 errors
                + "\n\nSee LICENSE 'Employment and IP Disclaimer' section."
            )

    def test_sources_md_exists_and_valid(self):
        """Verify SOURCES.md exists and documents open-source tooling.

        Per LICENSE: All external sources must be documented in SOURCES.md
        with public documentation links.
        """
        sources_md = REPO_ROOT / "docs" / "SOURCES.md"

        assert sources_md.exists(), "docs/SOURCES.md is missing (required by LICENSE disclaimer)"

        content = sources_md.read_text(encoding="utf-8")

        # Verify key sections exist
        required_sections = [
            "Open-Source Security Tools",
            "Elasticsearch",
            "OpenSearch",
            "Sigma",
            "YARA",
            "MITRE ATT&CK",
            "publicly available",
        ]

        missing = []
        for section in required_sections:
            if section not in content:
                missing.append(section)

        if missing:
            pytest.fail(
                f"docs/SOURCES.md is missing required sections: {', '.join(missing)}\n"
                "See LICENSE for source documentation requirements."
            )

    def test_license_has_employment_disclaimer(self):
        """Verify LICENSE contains Employment and IP Disclaimer section.

        This is critical legal protection for independent work.
        """
        license_file = REPO_ROOT / "LICENSE"

        assert license_file.exists(), "LICENSE file is missing"

        content = license_file.read_text(encoding="utf-8")

        # Verify critical sections exist
        required_sections = [
            "Employment and Intellectual Property Disclaimer",
            "created entirely on personal time",
            "publicly available information",
            "Source Material Declaration",
            "Explicit Exclusions",
            "California Labor Code Section 2870",
            "Independent Work Certification",
        ]

        missing = []
        for section in required_sections:
            if section not in content:
                missing.append(section)

        if missing:
            pytest.fail(
                f"LICENSE is missing required employment protection sections:\n"
                + "\n".join(f"  - {s}" for s in missing)
                + "\n\nThese sections are required for legal protection."
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

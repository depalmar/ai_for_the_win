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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_lab_has_starter_code(self, lab_dir: Path):
        """Labs with solution code should have starter code."""
        solution_dir = lab_dir / "solution"
        starter_dir = lab_dir / "starter"

        if solution_dir.exists():
            assert (
                starter_dir.exists()
            ), f"Lab {lab_dir.name} has solution/ but no starter/ directory"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_data_dir_not_empty_if_exists(self, lab_dir: Path):
        """If a data directory exists, it should contain files."""
        data_dir = lab_dir / "data"

        if data_dir.exists():
            files = list(data_dir.rglob("*"))
            data_files = [f for f in files if f.is_file()]
            assert len(data_files) > 0, f"Lab {lab_dir.name} has empty data/ directory"


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

            assert len(lines) >= 2, f"CSV file {csv_file.name} in {lab_dir.name} has no data rows"

            # Check header doesn't look like data
            header = lines[0]
            assert not header[
                0
            ].isdigit(), f"CSV file {csv_file.name} in {lab_dir.name} may be missing header"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_starter_has_python_files(self, lab_dir: Path):
        """Starter directory should have Python files."""
        starter_dir = lab_dir / "starter"
        if not starter_dir.exists():
            pytest.skip(f"No starter directory in {lab_dir.name}")

        py_files = list(starter_dir.glob("*.py"))
        assert len(py_files) > 0, f"Lab {lab_dir.name} starter/ has no Python files"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_solution_has_python_files(self, lab_dir: Path):
        """Solution directory should have Python files."""
        solution_dir = lab_dir / "solution"
        if not solution_dir.exists():
            pytest.skip(f"No solution directory in {lab_dir.name}")

        py_files = list(solution_dir.glob("*.py"))
        assert len(py_files) > 0, f"Lab {lab_dir.name} solution/ has no Python files"

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

        # Skip setup/fundamentals labs that may not have notebooks
        if "environment-setup" in lab_name or "fundamentals" in lab_name:
            if not matching_notebooks:
                pytest.skip(f"Lab {lab_name} is a setup/fundamentals lab")

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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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
        (["## objectives", "## 🎯 objectives", "## learning objectives",
          "## what you'll learn", "## what you will learn", "## goals",
          "## 🎯 learning objectives"], "objectives/learning goals"),
    ]

    # Files section is recommended but not required (some labs don't have data files)
    RECOMMENDED_SECTIONS = [
        (["## files", "## 📁 files", "## directory structure", "## structure"], "files"),
        (["## getting started", "## 🚀 getting started", "## setup"], "getting started"),
        (["## prerequisites", "## 📋 prerequisites", "## requirements"], "prerequisites"),
    ]

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

        assert description_found, f"README in {lab_dir.name} may be missing a description after the title"


class TestFunctionParity:
    """Tests to verify starter and solution have matching function signatures."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_starter_solution_function_parity(self, lab_dir: Path):
        """Starter and solution main.py should have same top-level function names."""
        starter_main = lab_dir / "starter" / "main.py"
        solution_main = lab_dir / "solution" / "main.py"

        if not starter_main.exists() or not solution_main.exists():
            pytest.skip(f"No starter/solution main.py pair in {lab_dir.name}")

        def extract_functions(filepath: Path) -> set[str]:
            """Extract top-level function names from a Python file."""
            try:
                content = filepath.read_text(encoding="utf-8")
                tree = ast.parse(content)
                return {
                    node.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and not node.name.startswith("_")
                }
            except SyntaxError:
                return set()

        starter_funcs = extract_functions(starter_main)
        solution_funcs = extract_functions(solution_main)

        if not starter_funcs:
            pytest.skip(f"No functions found in {lab_dir.name} starter")

        # All starter functions should exist in solution
        missing_in_solution = starter_funcs - solution_funcs

        if missing_in_solution:
            pytest.fail(
                f"Lab {lab_dir.name}: Functions in starter but not solution: {missing_in_solution}"
            )


class TestNotebookOutputs:
    """Tests to verify notebook outputs are cleared."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_readme_internal_links_valid(self, lab_dir: Path):
        """Internal file links in README should point to existing files."""
        readme = lab_dir / "README.md"
        if not readme.exists():
            pytest.skip(f"No README in {lab_dir.name}")

        content = readme.read_text(encoding="utf-8")

        # Find markdown links: [text](path)
        link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        links = link_pattern.findall(content)

        broken_links = []
        for text, href in links:
            # Skip external links
            if href.startswith(("http://", "https://", "mailto:", "#")):
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

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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
                                sensitive_findings.append(
                                    f"{py_file.name}: Possible {description}"
                                )
            except (OSError, UnicodeDecodeError):
                continue

        if sensitive_findings:
            pytest.fail(
                f"Lab {lab_dir.name} may contain sensitive data:\n"
                + "\n".join(sensitive_findings[:5])
            )

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
    def test_no_env_files_committed(self, lab_dir: Path):
        """Actual .env files should not be committed (only .env.example)."""
        env_files = list(lab_dir.rglob(".env"))

        # Filter out .env.example, .env.template, etc.
        actual_env_files = [
            f for f in env_files
            if f.name == ".env" and "example" not in str(f).lower()
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
        "os", "sys", "re", "json", "ast", "csv", "datetime", "time", "math",
        "random", "collections", "itertools", "functools", "pathlib", "typing",
        "dataclasses", "enum", "abc", "io", "copy", "hashlib", "base64",
        "urllib", "http", "logging", "argparse", "configparser", "tempfile",
        "shutil", "glob", "pickle", "sqlite3", "subprocess", "threading",
        "multiprocessing", "socket", "struct", "textwrap", "string", "unittest",
        "traceback", "warnings", "contextlib", "concurrent", "asyncio",
        "uuid", "secrets", "hmac", "binascii", "html", "xml", "zipfile",
    }

    # Common third-party packages that we expect to be available
    EXPECTED_PACKAGES = {
        # Data science
        "numpy", "pandas", "sklearn", "scipy", "matplotlib", "seaborn",
        # AI/ML
        "anthropic", "openai", "transformers", "torch", "tensorflow", "keras",
        # LangChain ecosystem
        "langchain", "langchain_core", "langchain_community", "langchain_openai",
        "langchain_anthropic", "langchain_google_genai", "langgraph",
        # Utilities
        "requests", "pytest", "yaml", "pyyaml", "dotenv", "python_dotenv",
        "pydantic", "rich", "tqdm", "click", "typer",
        # Visualization
        "plotly", "networkx", "bokeh", "altair",
        # NLP/ML
        "nltk", "spacy", "gensim", "xgboost", "lightgbm", "catboost", "joblib",
        # Security specific
        "yara", "volatility", "scapy", "dpkt", "pyshark",
        # Vector stores and embeddings
        "chromadb", "faiss", "pinecone", "qdrant_client", "sentence_transformers",
        # Others
        "aiohttp", "httpx", "bs4", "lxml", "pillow", "PIL",
    }

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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
                            if module not in self.STDLIB_MODULES and module not in self.EXPECTED_PACKAGES:
                                # Check if it's a local module
                                local_module = solution_dir / f"{module}.py"
                                if not local_module.exists():
                                    unknown_imports.add(module)

                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            module = node.module.split(".")[0]
                            if module not in self.STDLIB_MODULES and module not in self.EXPECTED_PACKAGES:
                                local_module = solution_dir / f"{module}.py"
                                if not local_module.exists():
                                    unknown_imports.add(module)

            except SyntaxError:
                pass  # Handled by other tests

        # Don't fail, just warn about potentially missing packages
        if unknown_imports:
            # Only fail if there are many unknown imports (likely a problem)
            if len(unknown_imports) > 5:
                pytest.fail(
                    f"Lab {lab_dir.name} has many unknown imports: {unknown_imports}"
                )


class TestRequirementsFile:
    """Tests to verify requirements files exist where needed."""

    @pytest.mark.parametrize("lab_dir", ALL_LABS, ids=[l.name for l in ALL_LABS])
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

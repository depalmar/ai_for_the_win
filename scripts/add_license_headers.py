#!/usr/bin/env python3
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
"""
Add license headers to files missing them.

This script adds appropriate license headers to:
- Python files (.py) - MIT License
- Lab README files - CC BY-NC-SA 4.0
- Documentation files - CC BY-NC-SA 4.0
- Jupyter notebooks (.ipynb) - Dual license

Usage:
    python scripts/add_license_headers.py --dry-run  # Preview changes
    python scripts/add_license_headers.py            # Apply changes
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

# License header templates
PYTHON_HEADER = """#!/usr/bin/env python3
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win

"""

PYTHON_HEADER_NO_SHEBANG = """# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win

"""

LAB_README_HEADER = """<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 - See LICENSE file
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

"""

DOC_README_HEADER = """<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

"""

NOTEBOOK_HEADER_CELL = {
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "<!--\n",
        "Copyright (c) 2025-2026 Raymond DePalma\n",
        "Licensed under CC BY-NC-SA 4.0 (content) and MIT (code)\n",
        'Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win\n',
        "-->\n",
        "\n",
        "# Lab Notebook\n",
        "\n",
        "**License**: Educational content (CC BY-NC-SA 4.0) | Code (MIT License)  \n",
        "**Repository**: [AI for the Win](https://github.com/depalmar/ai_for_the_win)",
    ],
}

# Directories to skip
SKIP_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    "node_modules",
    ".pytest_cache",
    "dist",
    "build",
    ".egg-info",
}

# Files to skip
SKIP_FILES = {
    "__init__.py",  # Often empty or minimal
    "setup.py",  # Usually generated
    "conftest.py",  # Pytest config
}


def has_copyright_header(content: str) -> bool:
    """Check if content already has a copyright header."""
    first_500_chars = content[:500].lower()
    return "copyright" in first_500_chars and "raymond depalma" in first_500_chars


def should_skip_path(path: Path) -> bool:
    """Check if path should be skipped."""
    # Skip if in skip directories
    for part in path.parts:
        if part in SKIP_DIRS:
            return True

    # Skip certain files
    if path.name in SKIP_FILES:
        return True

    return False


def add_python_header(file_path: Path, dry_run: bool = False) -> Tuple[bool, str]:
    """Add MIT license header to Python file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        return False, "Failed to read (encoding issue)"
    except Exception as e:
        return False, f"Failed to read: {e}"

    if has_copyright_header(content):
        return False, "Already has header"

    # Check if file starts with shebang
    has_shebang = content.startswith("#!")

    if has_shebang:
        # Replace existing shebang with header that includes new shebang
        lines = content.split("\n", 1)
        if len(lines) > 1:
            new_content = PYTHON_HEADER + lines[1]
        else:
            new_content = PYTHON_HEADER
    else:
        new_content = PYTHON_HEADER_NO_SHEBANG + content

    if not dry_run:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except Exception as e:
            return False, f"Failed to write: {e}"

    return True, "Added MIT header"


def add_markdown_header(
    file_path: Path, is_lab: bool = True, dry_run: bool = False
) -> Tuple[bool, str]:
    """Add CC BY-NC-SA header to Markdown file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        return False, "Failed to read (encoding issue)"
    except Exception as e:
        return False, f"Failed to read: {e}"

    if has_copyright_header(content):
        return False, "Already has header"

    header = LAB_README_HEADER if is_lab else DOC_README_HEADER
    new_content = header + content

    if not dry_run:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except Exception as e:
            return False, f"Failed to write: {e}"

    return True, "Added CC BY-NC-SA header"


def add_notebook_header(file_path: Path, dry_run: bool = False) -> Tuple[bool, str]:
    """Add dual license header to Jupyter notebook."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            notebook = json.load(f)
    except json.JSONDecodeError:
        return False, "Failed to parse (invalid JSON)"
    except Exception as e:
        return False, f"Failed to read: {e}"

    # Check if first cell already has copyright
    if notebook.get("cells") and len(notebook["cells"]) > 0:
        first_cell = notebook["cells"][0]
        if first_cell.get("cell_type") == "markdown":
            source = "".join(first_cell.get("source", [])).lower()
            if "copyright" in source and "raymond depalma" in source:
                return False, "Already has header"

    # Insert header cell at beginning
    notebook["cells"].insert(0, NOTEBOOK_HEADER_CELL)

    if not dry_run:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(notebook, f, indent=2, ensure_ascii=False)
        except Exception as e:
            return False, f"Failed to write: {e}"

    return True, "Added dual license header"


def process_files(dry_run: bool = False, verbose: bool = False) -> Dict[str, List[str]]:
    """Process all relevant files and add headers."""
    results = {"modified": [], "skipped": [], "errors": []}

    root = Path(".")

    # Process Python files
    print("Processing Python files...")
    for py_file in root.rglob("*.py"):
        if should_skip_path(py_file):
            continue

        rel_path = py_file.relative_to(root)
        modified, message = add_python_header(py_file, dry_run)

        if modified:
            results["modified"].append(f"{rel_path}: {message}")
            print(f"  {'[DRY RUN] ' if dry_run else ''}+ {rel_path}")
        elif verbose:
            results["skipped"].append(f"{rel_path}: {message}")
            print(f"  - {rel_path}: {message}")

    # Process lab README files
    print("\nProcessing lab README files...")
    for readme in root.glob("labs/*/README.md"):
        if should_skip_path(readme):
            continue

        rel_path = readme.relative_to(root)
        modified, message = add_markdown_header(readme, is_lab=True, dry_run=dry_run)

        if modified:
            results["modified"].append(f"{rel_path}: {message}")
            print(f"  {'[DRY RUN] ' if dry_run else ''}+ {rel_path}")
        elif verbose:
            results["skipped"].append(f"{rel_path}: {message}")
            print(f"  - {rel_path}: {message}")

    # Process documentation files
    print("\nProcessing documentation files...")
    for doc_file in root.glob("docs/**/*.md"):
        if should_skip_path(doc_file):
            continue

        rel_path = doc_file.relative_to(root)
        modified, message = add_markdown_header(doc_file, is_lab=False, dry_run=dry_run)

        if modified:
            results["modified"].append(f"{rel_path}: {message}")
            print(f"  {'[DRY RUN] ' if dry_run else ''}+ {rel_path}")
        elif verbose:
            results["skipped"].append(f"{rel_path}: {message}")
            print(f"  - {rel_path}: {message}")

    # Process Jupyter notebooks
    print("\nProcessing Jupyter notebooks...")
    for notebook in root.rglob("*.ipynb"):
        if should_skip_path(notebook):
            continue
        if ".ipynb_checkpoints" in str(notebook):
            continue

        rel_path = notebook.relative_to(root)
        modified, message = add_notebook_header(notebook, dry_run=dry_run)

        if modified:
            results["modified"].append(f"{rel_path}: {message}")
            print(f"  {'[DRY RUN] ' if dry_run else ''}+ {rel_path}")
        elif verbose:
            results["skipped"].append(f"{rel_path}: {message}")
            print(f"  - {rel_path}: {message}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Add license headers to files missing them",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without modifying files"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show skipped files in addition to modified ones",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("LICENSE HEADER TOOL")
    print("=" * 70)

    if args.dry_run:
        print("\n[!] DRY RUN MODE - No files will be modified\n")

    results = process_files(dry_run=args.dry_run, verbose=args.verbose)

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Files modified: {len(results['modified'])}")
    print(f"Files skipped:  {len(results['skipped'])}")
    print(f"Errors:         {len(results['errors'])}")

    if results["errors"]:
        print("\nErrors:")
        for error in results["errors"]:
            print(f"  [X] {error}")

    if args.dry_run and results["modified"]:
        print("\n[!] Run without --dry-run to apply changes")

    print("\n[OK] Done!")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Fix incorrect lab number references in Jupyter notebooks.

The curriculum was reorganized from non-sequential lab numbers (29, 31, 35, 36, 42, etc.)
to sequential numbers (10, 11, 12, etc.). This script updates notebook markdown cells.
"""

import json
import sys
from pathlib import Path


def fix_lab_references(notebook_path: Path) -> bool:
    """Fix lab number references in a notebook. Returns True if changes were made."""

    # Context-aware replacements
    replacements = [
        # Unambiguous replacements (with full context to avoid false positives)
        ("Lab 29", "Lab 10"),  # Phishing Classifier
        ("Lab 32", "Lab 12"),  # Anomaly Detection
        ("Lab 33", "Lab 13"),  # ML vs LLM
        ("Lab 34", "Lab 14"),  # First AI Agent
        ("Lab 35", "Lab 15"),  # LLM Log Analysis
        ("Lab 36", "Lab 16"),  # Threat Intel Agent
        ("Lab 39", "Lab 17"),  # Embeddings
        ("Lab 42", "Lab 18"),  # Security RAG
        ("Lab 45", "Lab 19"),  # Binary Basics
        # Context-dependent (need to check surrounding text)
        # Lab 31 could be Lab 02 (Prompt Engineering) or Lab 11 (Malware Clustering)
        # Lab 21 could be Lab 07 (Hello World ML) or Lab 21 (YARA Generator)
        # Lab 22 could be Lab 08 (Working with APIs) or Lab 22 (Vuln Scanner)
    ]

    try:
        with open(notebook_path, "r", encoding="utf-8") as f:
            notebook = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {notebook_path}: {e}")
        return False

    changed = False

    for cell in notebook.get("cells", []):
        if cell.get("cell_type") == "markdown":
            source = cell.get("source", [])
            if isinstance(source, list):
                new_source = []
                for line in source:
                    new_line = line
                    for old, new in replacements:
                        if old in line:
                            # Context check for Lab 31
                            if old == "Lab 31":
                                if "Prompt" in line or "prompt" in line:
                                    new_line = new_line.replace("Lab 31", "Lab 02")
                                    changed = True
                                elif "Malware" in line or "malware" in line or "Clustering" in line:
                                    new_line = new_line.replace("Lab 31", "Lab 11")
                                    changed = True
                            else:
                                new_line = new_line.replace(old, new)
                                if new_line != line:
                                    changed = True
                    new_source.append(new_line)
                cell["source"] = new_source

    if changed:
        try:
            with open(notebook_path, "w", encoding="utf-8") as f:
                json.dump(notebook, f, indent=1, ensure_ascii=False)
                f.write("\n")  # Add final newline
            print(f"Fixed {notebook_path.name}")
            return True
        except OSError as e:
            print(f"Error writing {notebook_path}: {e}")
            return False

    return False


def main():
    notebooks_dir = Path(__file__).parent.parent / "notebooks"

    if not notebooks_dir.exists():
        print(f"Error: {notebooks_dir} does not exist")
        sys.exit(1)

    notebook_files = sorted(notebooks_dir.glob("lab*.ipynb"))

    if not notebook_files:
        print(f"No notebooks found in {notebooks_dir}")
        sys.exit(1)

    print(f"Scanning {len(notebook_files)} notebooks...")
    fixed_count = 0

    for notebook_path in notebook_files:
        if fix_lab_references(notebook_path):
            fixed_count += 1

    print(f"\n{fixed_count} notebook(s) updated")

    if fixed_count > 0:
        print("\nDon't forget to:")
        print("  git add notebooks/*.ipynb")
        print("  git commit -m 'fix: correct lab number references in notebooks'")


if __name__ == "__main__":
    main()

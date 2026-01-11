#!/usr/bin/env python3
"""Fix incorrect lab number references in Jupyter notebooks."""

import json
import re
from pathlib import Path


def fix_lab_references(notebook_path: Path) -> bool:
    """Fix lab number references in a notebook."""

    replacements = {
        r"\bLab 29\b": "Lab 10",
        r"\bLab 32\b": "Lab 12",
        r"\bLab 33\b": "Lab 13",
        r"\bLab 34\b": "Lab 14",
        r"\bLab 35\b": "Lab 15",
        r"\bLab 36\b": "Lab 16",
        r"\bLab 39\b": "Lab 17",
        r"\bLab 42\b": "Lab 18",
    }

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
                    for pattern, replacement in replacements.items():
                        new_line = re.sub(pattern, replacement, new_line)

                    # Context-aware for Lab 31
                    if "Lab 31" in new_line:
                        if re.search(r"Prompt|prompt", new_line):
                            new_line = re.sub(r"\bLab 31\b", "Lab 02", new_line)
                        elif re.search(r"Malware|malware|Clustering", new_line):
                            new_line = re.sub(r"\bLab 31\b", "Lab 11", new_line)

                    if new_line != line:
                        changed = True
                    new_source.append(new_line)
                cell["source"] = new_source

    if changed:
        try:
            with open(notebook_path, "w", encoding="utf-8") as f:
                json.dump(notebook, f, indent=1, ensure_ascii=False)
                f.write("\n")
            print(f"Fixed {notebook_path.name}")
            return True
        except OSError as e:
            print(f"Error writing {notebook_path}: {e}")
            return False

    return False


def main():
    notebooks_dir = Path(__file__).parent.parent / "notebooks"
    notebook_files = sorted(notebooks_dir.glob("lab*.ipynb"))
    print(f"Scanning {len(notebook_files)} notebooks...")
    fixed_count = sum(1 for nb in notebook_files if fix_lab_references(nb))
    print(f"\n{fixed_count} notebook(s) updated")


if __name__ == "__main__":
    main()

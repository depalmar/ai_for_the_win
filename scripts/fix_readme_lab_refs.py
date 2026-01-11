#!/usr/bin/env python3
"""Fix legacy lab number references in README files."""

import re
from pathlib import Path


def fix_readme_references(readme_path: Path) -> bool:
    """Fix lab number references in a README."""

    # Extract this README's own lab number to avoid self-references
    parent_dir = readme_path.parent.name
    match = re.match(r"lab(\d+)-", parent_dir)
    own_lab_num = match.group(1) if match else None

    replacements = {
        r"\bLab 29\b": "Lab 10",
        r"\bLab 32\b": "Lab 12",
        r"\bLab 33\b": "Lab 13",
        r"\bLab 34\b": "Lab 14",
        r"\bLab 35\b": "Lab 15",
        r"\bLab 36\b": "Lab 16",
    }

    try:
        content = readme_path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"Error reading {readme_path}: {e}")
        return False

    original_content = content

    for pattern, replacement in replacements.items():
        # Don't replace if this README IS the lab being referenced
        lab_num = pattern.split()[1].rstrip("\\b")
        if own_lab_num == lab_num:
            continue

        content = re.sub(pattern, replacement, content)

    if content != original_content:
        try:
            readme_path.write_text(content, encoding="utf-8")
            print(f"Fixed {readme_path.relative_to(Path.cwd())}")
            return True
        except OSError as e:
            print(f"Error writing {readme_path}: {e}")
            return False

    return False


def main():
    root = Path(__file__).parent.parent
    readme_files = list((root / "labs").glob("lab*/README.md"))

    print(f"Scanning {len(readme_files)} README files...")
    fixed_count = sum(1 for f in readme_files if fix_readme_references(f))
    print(f"\n{fixed_count} file(s) updated")


if __name__ == "__main__":
    main()

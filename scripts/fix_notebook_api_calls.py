#!/usr/bin/env python3
"""Fix remaining self.client.messages.create and client.messages.create calls."""

import json
import re
from pathlib import Path

NOTEBOOKS_DIR = Path(__file__).parent.parent / "notebooks"


def source_to_str(source):
    if isinstance(source, list):
        return "".join(source)
    return source


def str_to_source(text):
    if not text:
        return []
    return text.splitlines(keepends=True)


def fix_api_calls(src: str) -> str:
    """Replace hardcoded client.messages.create() calls with query_llm()."""

    # Pattern 1: self.client.messages.create (class methods)
    # Replace:
    #   response = self.client.messages.create(
    #       model="claude-...",
    #       max_tokens=N,
    #       messages=[{"role": "user", "content": prompt}],
    #   )
    #   return response.content[0].text
    # With: return query_llm(prompt, max_tokens=N)

    src = re.sub(
        r'response = self\.client\.messages\.create\(\s*\n'
        r'\s+model="[^"]*",\s*\n'
        r'\s+max_tokens=(\d+),\s*\n'
        r'\s+messages=\[{"role": "user", "content": prompt}\],\s*\n'
        r'\s+\)\s*\n'
        r'(\s+)return response\.content\[0\]\.text',
        r'\2return query_llm(prompt, max_tokens=\1)',
        src
    )

    # Pattern 1b: with system prompt in separate messages list
    src = re.sub(
        r'response = self\.client\.messages\.create\(\s*\n'
        r'\s+model="[^"]*",\s*\n'
        r'\s+max_tokens=(\d+),\s*\n'
        r'\s+system=([^,\n]+),\s*\n'
        r'\s+messages=\[{"role": "user", "content": prompt}\],\s*\n'
        r'\s+\)\s*\n'
        r'(\s+)return response\.content\[0\]\.text',
        r'\3return query_llm(prompt, system_prompt=\2, max_tokens=\1)',
        src
    )

    # Pattern 1c: json.loads(response.content[0].text) variant
    src = re.sub(
        r'response = self\.client\.messages\.create\(\s*\n'
        r'\s+model="[^"]*",\s*\n'
        r'\s+max_tokens=(\d+),\s*\n'
        r'\s+messages=\[{"role": "user", "content": prompt}\],\s*\n'
        r'\s+\)\s*\n'
        r'(\s+)return json\.loads\(response\.content\[0\]\.text\)',
        r'\2return json.loads(query_llm(prompt, max_tokens=\1))',
        src
    )

    # Pattern 2: direct client.messages.create (standalone functions)
    # Replace:
    #   response = client.messages.create(
    #       model="claude-...",
    #       max_tokens=N,
    #       messages=[{"role": "user", "content": prompt}],
    #   )
    #   return response.content[0].text
    # With: return query_llm(prompt, system_prompt="...", max_tokens=N)

    src = re.sub(
        r'    response = client\.messages\.create\(\s*\n'
        r'        model="[^"]*",\s*\n'
        r'        max_tokens=(\d+),\s*\n'
        r'        messages=\[{"role": "user", "content": prompt}\],\s*\n'
        r'    \)\s*\n'
        r'(\n)?'
        r'    return response\.content\[0\]\.text',
        r'    return query_llm(prompt, system_prompt="You are a security analyst.", max_tokens=\1)',
        src
    )

    # Broader pattern for direct calls with varying indentation
    src = re.sub(
        r'(\s+)response = client\.messages\.create\(\s*\n'
        r'(\s+)model="[^"]*",\s*\n'
        r'\s+max_tokens=(\d+),\s*\n'
        r'\s+messages=\[{"role": "user", "content": prompt}\],?\s*\n'
        r'\s+\)\s*\n'
        r'(\n)?'
        r'\1return response\.content\[0\]\.text',
        r'\1return query_llm(prompt, system_prompt="You are a security analyst.", max_tokens=\3)',
        src
    )

    # Clean up leftover client = Anthropic() lines (outside query_llm)
    src = re.sub(r'^\s*client = Anthropic\(\)\s*\n', '', src, flags=re.MULTILINE)

    return src


def process_notebook(nb_path: Path) -> bool:
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    modified = False
    for cell in nb["cells"]:
        if cell.get("cell_type") != "code":
            continue
        src = source_to_str(cell.get("source", ""))

        # Skip the query_llm definition cell itself
        if "def query_llm(" in src:
            continue

        new_src = fix_api_calls(src)
        if new_src != src:
            cell["source"] = str_to_source(new_src)
            modified = True

    if modified:
        with open(nb_path, "w", encoding="utf-8") as f:
            json.dump(nb, f, indent=1, ensure_ascii=False)
        print(f"  [FIXED]: {nb_path.name}")
    else:
        print(f"  [skip]: {nb_path.name}")

    return modified


def main():
    targets = [
        "lab18_security_rag.ipynb",
        "lab21_yara_generator.ipynb",
        "lab22_vuln_scanner_ai.ipynb",
        "lab23_detection_pipeline.ipynb",
        "lab29_ir_copilot.ipynb",
        "lab34_c2_traffic.ipynb",
        "lab36_threat_actor_profiling.ipynb",
        "lab45_cloud_security.ipynb",
    ]

    fixed = 0
    for nb_name in targets:
        nb_path = NOTEBOOKS_DIR / nb_name
        if process_notebook(nb_path):
            fixed += 1

    print(f"\nDone. Fixed {fixed}/{len(targets)} notebooks.")


if __name__ == "__main__":
    main()

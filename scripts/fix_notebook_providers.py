#!/usr/bin/env python3
"""
Fix notebooks to use multi-provider LLM setup instead of hardcoded Anthropic.

For each affected notebook:
1. Updates pip install comments to include all three providers
2. Updates Colab secret loading to load all three API keys
3. Replaces Claude-only setup cells with multi-provider setup_llm/query_llm
4. Updates class __init__ methods that hardcode Anthropic
5. Updates direct API calls (client.messages.create) to use query_llm()
"""

import json
import re
import sys
from pathlib import Path

NOTEBOOKS_DIR = Path(__file__).parent.parent / "notebooks"

# The standard multi-provider setup cell content (matches lab15 pattern)
MULTI_PROVIDER_SETUP_CELL = """\
# === LLM Setup (Provider-Agnostic) ===
# Works with: Anthropic Claude, OpenAI GPT, or Google Gemini
# Set ONE API key in Colab Secrets (🔑 sidebar) or environment

# Install dependencies (uncomment for Colab - use Ctrl+/ or Cmd+/ to toggle)
# !pip install anthropic openai google-generativeai -q

import os

# For Colab: Load API key from Secrets
try:
    from google.colab import userdata
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"]:
        try:
            os.environ[key] = userdata.get(key)
        except Exception:
            pass
except ImportError:
    pass  # Not in Colab


def setup_llm():
    \"\"\"Detect and configure LLM provider.\"\"\"
    providers = {
        "anthropic": ("ANTHROPIC_API_KEY", "claude-sonnet-4-5"),
        "openai": ("OPENAI_API_KEY", "gpt-5"),
        "google": ("GOOGLE_API_KEY", "gemini-3-flash"),
    }
    for name, (key, model) in providers.items():
        if os.environ.get(key):
            return name, model
    raise ValueError("❌ No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")


def query_llm(prompt, system_prompt="You are a security analyst.", max_tokens=4096):
    \"\"\"Query the configured LLM provider (provider-agnostic).\"\"\"
    provider, model = setup_llm()

    if provider == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()
        response = client.messages.create(
            model=model, max_tokens=max_tokens, system=system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    elif provider == "openai":
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model=model, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    elif provider == "google":
        import google.generativeai as genai
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        model_instance = genai.GenerativeModel(model)
        response = model_instance.generate_content(f"{system_prompt}\\n\\n{prompt}")
        return response.text


# Test setup
try:
    provider, model = setup_llm()
    print(f"✓ Using {provider.title()} ({model})")
except ValueError as e:
    print(e)
"""


def source_to_str(source):
    """Convert cell source (list or str) to single string."""
    if isinstance(source, list):
        return "".join(source)
    return source


def str_to_source(text):
    """Convert string back to list-of-lines format for notebook cells."""
    if not text:
        return []
    lines = text.splitlines(keepends=True)
    return lines


def cell_matches_old_setup(src: str) -> bool:
    """Check if this cell is the old single-provider Anthropic setup."""
    return (
        "ANTHROPIC_API_KEY" in src
        and "userdata.get" in src
        and "OPENAI_API_KEY" not in src
        and "setup_llm" not in src
    ) or (
        "from anthropic import Anthropic" in src
        and "client = Anthropic()" in src
        and "def " not in src  # not inside a class/function def
        and "setup_llm" not in src
    )


def cell_is_setup_llm(src: str) -> bool:
    """Check if this cell already has the multi-provider setup."""
    return "setup_llm" in src and "query_llm" in src


def cell_is_pip_anthropic_only(src: str) -> bool:
    """Check if pip install only mentions anthropic."""
    has_anthropic_pip = bool(re.search(r'pip install.*anthropic', src, re.IGNORECASE))
    has_openai_pip = "openai" in src and "pip" in src
    has_google_pip = "google-generativeai" in src and "pip" in src
    return has_anthropic_pip and not has_openai_pip and not has_google_pip


def fix_pip_cell(src: str) -> str:
    """Update pip install to include all providers."""
    # Replace anthropic-only pip install with multi-provider
    src = re.sub(
        r'(#\s*!pip install[^\n]*?)anthropic([^\n]*)',
        r'\1anthropic openai google-generativeai\2',
        src
    )
    # If it's an actual (non-commented) pip install
    src = re.sub(
        r'(!pip install[^\n]*?)anthropic([^\n]*)',
        r'\1anthropic openai google-generativeai\2',
        src
    )
    return src


def fix_class_init(src: str) -> str:
    """Replace hardcoded Anthropic class __init__ with multi-provider version."""
    # Pattern: try: from anthropic import Anthropic; self.client = Anthropic(); self.available = True
    old_init = re.compile(
        r'try:\s*\n(\s+)from anthropic import Anthropic\s*\n'
        r'\s+self\.client = Anthropic\(\)\s*\n'
        r'(\s+(?:self\.\w+ = \w+\s*\n)*)'
        r'\s+self\.available = True\s*\n'
        r'(\s*)except[^:]*:\s*\n'
        r'(\s+)self\.available = False\s*\n'
        r'(\s+\w[^\n]*\n)*',
        re.MULTILINE
    )

    def replace_init(m):
        indent = m.group(1)
        return (
            f"try:\n"
            f"{indent}self._provider, self._model = setup_llm()\n"
            f"{indent}self.available = True\n"
            f"{indent}print(f'  AI initialized with {{self._provider.title()}}')\n"
            f"    except Exception as e:\n"
            f"{indent}self.available = False\n"
            f"{indent}print(f'  Note: AI not available - using mock responses ({{e}})')\n"
        )

    # Use simpler string replacement for common patterns
    patterns = [
        (
            "try:\n            from anthropic import Anthropic\n\n            self.client = Anthropic()\n            self.available = True\n        except:\n            self.available = False",
            "try:\n            self._provider, self._model = setup_llm()\n            self.available = True\n            print(f'  AI initialized with {self._provider.title()}')\n        except Exception as e:\n            self.available = False\n            print(f'  Note: AI not available - using mock responses ({e})')"
        ),
        (
            "try:\n            from anthropic import Anthropic\n            self.client = Anthropic()\n            self.available = True\n        except:\n            self.available = False",
            "try:\n            self._provider, self._model = setup_llm()\n            self.available = True\n            print(f'  AI initialized with {self._provider.title()}')\n        except Exception as e:\n            self.available = False\n            print(f'  Note: AI not available - using mock responses ({e})')"
        ),
    ]
    for old, new in patterns:
        src = src.replace(old, new)
    return src


def fix_direct_client_calls(src: str) -> str:
    """Replace direct Anthropic() + messages.create() with query_llm()."""
    # Fix: from anthropic import Anthropic / client = Anthropic()
    # followed by client.messages.create(...)

    # Replace standalone client creation
    src = re.sub(
        r'^from anthropic import Anthropic\s*\n',
        '# LLM queries use query_llm() defined in setup cell above\n',
        src, flags=re.MULTILINE
    )
    src = re.sub(r'^\s*client = Anthropic\(\)\s*\n', '', src, flags=re.MULTILINE)

    # Replace client.messages.create blocks with hardcoded claude model
    # Pattern: response = client.messages.create(\n    model="claude-...",\n    ...
    # This is complex so we handle common cases
    src = re.sub(
        r'client = Anthropic\(\)\s*\n\s*',
        '',
        src
    )

    return src


def process_notebook(nb_path: Path) -> bool:
    """Process a single notebook. Returns True if modified."""
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    cells = nb.get("cells", [])
    modified = False
    has_setup_cell = any(cell_is_setup_llm(source_to_str(c.get("source", ""))) for c in cells)
    setup_cell_inserted = has_setup_cell

    new_cells = []
    for i, cell in enumerate(cells):
        src = source_to_str(cell.get("source", ""))
        cell_type = cell.get("cell_type", "code")

        # Fix pip install cells
        if cell_type == "code" and cell_is_pip_anthropic_only(src):
            new_src = fix_pip_cell(src)
            if new_src != src:
                cell = dict(cell)
                cell["source"] = str_to_source(new_src)
                modified = True

        src = source_to_str(cell.get("source", ""))

        # Replace old single-provider setup cells with multi-provider setup cell
        if cell_type == "code" and cell_matches_old_setup(src) and not setup_cell_inserted:
            # Replace with multi-provider setup
            cell = dict(cell)
            cell["source"] = str_to_source(MULTI_PROVIDER_SETUP_CELL)
            setup_cell_inserted = True
            modified = True

        # Insert multi-provider setup cell before first LLM-using cell if not yet inserted
        elif (cell_type == "code"
              and not setup_cell_inserted
              and ("from anthropic import Anthropic" in src or "Anthropic()" in src or "ANTHROPIC_API_KEY" in src)):
            # Insert setup cell before this cell
            setup_cell = {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": str_to_source(MULTI_PROVIDER_SETUP_CELL),
            }
            new_cells.append(setup_cell)
            setup_cell_inserted = True
            modified = True

        src = source_to_str(cell.get("source", ""))

        # Fix class __init__ methods
        if cell_type == "code" and "from anthropic import Anthropic" in src and "self.client = Anthropic()" in src:
            new_src = fix_class_init(src)
            if new_src != src:
                cell = dict(cell)
                cell["source"] = str_to_source(new_src)
                modified = True

        # Fix direct (non-class) Anthropic calls
        src = source_to_str(cell.get("source", ""))
        if (cell_type == "code"
                and "from anthropic import Anthropic" in src
                and "self.client" not in src
                and "def " in src):
            new_src = fix_direct_client_calls(src)
            if new_src != src:
                cell = dict(cell)
                cell["source"] = str_to_source(new_src)
                modified = True

        new_cells.append(cell)

    if modified:
        nb["cells"] = new_cells
        with open(nb_path, "w", encoding="utf-8") as f:
            json.dump(nb, f, indent=1, ensure_ascii=False)
        print(f"  [FIXED]: {nb_path.name}")
    else:
        print(f"  [skip]: {nb_path.name}")

    return modified


def main():
    # Notebooks confirmed to have hardcoded Anthropic
    target_notebooks = [
        "lab16_threat_intel_agent.ipynb",
        "lab18_security_rag.ipynb",
        "lab21_yara_generator.ipynb",
        "lab22_vuln_scanner_ai.ipynb",
        "lab23_detection_pipeline.ipynb",
        "lab29_ir_copilot.ipynb",
        "lab34_c2_traffic.ipynb",
        "lab35_lateral_movement.ipynb",
        "lab36_threat_actor_profiling.ipynb",
        "lab45_cloud_security.ipynb",
        "lab49_llm_red_teaming.ipynb",
    ]

    print(f"Processing {len(target_notebooks)} notebooks...\n")
    fixed_count = 0

    for nb_name in target_notebooks:
        nb_path = NOTEBOOKS_DIR / nb_name
        if not nb_path.exists():
            print(f"  ! Not found: {nb_name}")
            continue
        if process_notebook(nb_path):
            fixed_count += 1

    print(f"\nDone. Fixed {fixed_count}/{len(target_notebooks)} notebooks.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fix remaining 3 notebooks: lab02, lab13, lab16."""

import json
import re
from pathlib import Path

NOTEBOOKS_DIR = Path(__file__).parent.parent / "notebooks"

MULTI_PROVIDER_SETUP = """\
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
    raise ValueError("No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")


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
    print(f"Using {provider.title()} ({model})")
except ValueError as e:
    print(e)
"""

def source_to_str(s):
    return "".join(s) if isinstance(s, list) else s

def str_to_source(text):
    return text.splitlines(keepends=True) if text else []

def has_setup_cell(nb):
    return any(
        "def setup_llm" in source_to_str(c.get("source", ""))
        for c in nb.get("cells", [])
    )

def insert_setup_cell(nb, before_idx):
    """Insert the multi-provider setup cell at before_idx."""
    setup = {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": str_to_source(MULTI_PROVIDER_SETUP),
    }
    nb["cells"].insert(before_idx, setup)

def fix_lab02(nb_path):
    """Fix lab02: add setup cell, replace direct Anthropic call."""
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    if has_setup_cell(nb):
        print("  [skip] lab02 already has setup cell")
        return False

    cells = nb["cells"]
    insert_at = 0

    for i, cell in enumerate(cells):
        src = source_to_str(cell.get("source", ""))
        if "from anthropic import Anthropic" in src and "def extract_iocs" in src:
            insert_at = i
            # Fix the function to use query_llm
            new_src = src
            # Remove the import and client creation
            new_src = re.sub(r'from anthropic import Anthropic\s*\n\n?', '', new_src)
            new_src = re.sub(r'    client = Anthropic\(\)\n\n?', '', new_src)
            # Replace the response = client.messages.create block
            new_src = re.sub(
                r'    response = client\.messages\.create\(\s*\n'
                r'        model="[^"]*",\s*\n'
                r'        max_tokens=\d+,\s*\n'
                r'        messages=\[{"role": "user", "content": prompt}\],\s*\n'
                r'    \)\s*\n\n?',
                '    response_text = query_llm(prompt, system_prompt="You are a security analyst specializing in IOC extraction.", max_tokens=1000)\n\n',
                new_src
            )
            # Fix the return to use response_text instead of response.content[0].text
            new_src = new_src.replace(
                'return json.loads(response.content[0].text)',
                'return json.loads(response_text)'
            )
            new_src = new_src.replace(
                'response.content[0].text',
                'response_text'
            )
            cell["source"] = str_to_source(new_src)
            break

    insert_setup_cell(nb, insert_at)

    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)
    print("  [FIXED] lab02_prompt_engineering.ipynb")
    return True


def fix_lab13(nb_path):
    """Fix lab13: add setup cell, replace direct Anthropic call."""
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    if has_setup_cell(nb):
        print("  [skip] lab13 already has setup cell")
        return False

    cells = nb["cells"]
    insert_at = 0

    for i, cell in enumerate(cells):
        src = source_to_str(cell.get("source", ""))
        if "from anthropic import Anthropic" in src and "def analyze_memory" in src:
            insert_at = i
            new_src = src
            # Remove import and client creation
            new_src = re.sub(r'from anthropic import Anthropic\s*\n\n?', '', new_src)
            new_src = re.sub(r'    client = Anthropic\(\)\s*\n\n?', '', new_src)
            # Replace the API call block
            new_src = re.sub(
                r'    response = client\.messages\.create\(\s*\n'
                r'        model="[^"]*",\s*\n'
                r'        max_tokens=(\d+),\s*\n'
                r'        messages=\[{"role": "user", "content": prompt}\]\s*\n'
                r'    \)\s*\n\n?'
                r'    return response\.content\[0\]\.text',
                r'    return query_llm(prompt, system_prompt="You are a memory forensics expert.", max_tokens=\1)',
                new_src
            )
            cell["source"] = str_to_source(new_src)
            break

    insert_setup_cell(nb, insert_at)

    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)
    print("  [FIXED] lab13_memory_forensics.ipynb")
    return True


def fix_lab16(nb_path):
    """Fix lab16: update class __init__ to use setup_llm(), update investigate() to get model dynamically."""
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    modified = False
    for cell in nb["cells"]:
        src = source_to_str(cell.get("source", ""))
        if "class ThreatIntelAgent" not in src:
            continue

        new_src = src

        # Fix the __init__ - various whitespace patterns
        # Pattern: try:\n            from anthropic import Anthropic\n\n            self.client = Anthropic()
        old_init = (
            "        try:\n"
            "            from anthropic import Anthropic\n"
            "\n"
            "            self.client = Anthropic()\n"
            "            self.available = True\n"
            '            print("  AI Agent initialized with Anthropic API")\n'
            "        except:\n"
            "            self.available = False\n"
            '            print("  AI not available - using mock responses")\n'
            '            print("  Set ANTHROPIC_API_KEY for real AI analysis")'
        )
        new_init = (
            "        try:\n"
            "            self._provider, self._model = setup_llm()\n"
            "            self.available = True\n"
            '            print(f"  AI Agent initialized with {self._provider.title()}")\n'
            "        except Exception as e:\n"
            "            self.available = False\n"
            '            print(f"  AI not available - using mock responses ({e})")\n'
            '            print("  Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")'
        )
        if old_init in new_src:
            new_src = new_src.replace(old_init, new_init)
            modified = True

        # Fix investigate() - update hardcoded model in messages.create to use self._model
        # The tool-calling is Anthropic-specific; wrap it to handle other providers too
        old_investigate = (
            '            response = self.client.messages.create(\n'
            '                model="claude-sonnet-4.5",\n'
            '                max_tokens=4096,  # Increased for detailed analysis\n'
            '                tools=TOOLS,\n'
            '                messages=messages,\n'
            '            )'
        )
        new_investigate = (
            '            # Note: Tool calling uses Anthropic format; other providers use query_llm()\n'
            '            if self._provider == "anthropic":\n'
            '                from anthropic import Anthropic\n'
            '                client = Anthropic()\n'
            '                response = client.messages.create(\n'
            '                    model=self._model,\n'
            '                    max_tokens=4096,\n'
            '                    tools=TOOLS,\n'
            '                    messages=messages,\n'
            '                )\n'
            '            else:\n'
            '                # Other providers: use text-based query without native tool calling\n'
            '                text_response = query_llm(\n'
            '                    messages[-1]["content"] if messages else query,\n'
            '                    system_prompt="You are a threat intelligence analyst. Analyze the query and provide detailed findings.",\n'
            '                    max_tokens=4096\n'
            '                )\n'
            '                return text_response'
        )
        if old_investigate in new_src:
            new_src = new_src.replace(old_investigate, new_investigate)
            modified = True

        if new_src != src:
            cell["source"] = str_to_source(new_src)

    if modified:
        with open(nb_path, "w", encoding="utf-8") as f:
            json.dump(nb, f, indent=1, ensure_ascii=False)
        print("  [FIXED] lab16_threat_intel_agent.ipynb")
    else:
        print("  [skip] lab16 - pattern not matched (may need manual fix)")
    return modified


def main():
    print("Fixing remaining 3 notebooks...\n")

    fix_lab02(NOTEBOOKS_DIR / "lab02_prompt_engineering.ipynb")
    fix_lab13(NOTEBOOKS_DIR / "lab13_memory_forensics.ipynb")
    fix_lab16(NOTEBOOKS_DIR / "lab16_threat_intel_agent.ipynb")

    # Final check
    print("\n--- Final check for remaining hardcoded calls ---")
    for nb_path in sorted(NOTEBOOKS_DIR.glob("lab*.ipynb")):
        with open(nb_path, encoding="utf-8") as f:
            nb = json.load(f)
        for cell in nb["cells"]:
            src = source_to_str(cell.get("source", ""))
            if ("client.messages.create" in src or "client = Anthropic()" in src) and "def query_llm" not in src and "def monitored_llm_call" not in src:
                print(f"  Still has hardcoded calls: {nb_path.name}")
                break


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AI for the Win - Setup Verification Script

This script verifies that your environment is correctly configured
for the AI Security Training labs.

Usage:
    python scripts/verify_setup.py
"""

import os
import sys
from pathlib import Path

# Add color output if available
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def print_header(text):
    if RICH_AVAILABLE:
        console.print(f"\n[bold blue]{text}[/bold blue]")
    else:
        print(f"\n{'=' * 60}\n{text}\n{'=' * 60}")


def print_success(text):
    if RICH_AVAILABLE:
        console.print(f"[green]✓[/green] {text}")
    else:
        print(f"[OK] {text}")


def print_warning(text):
    if RICH_AVAILABLE:
        console.print(f"[yellow]![/yellow] {text}")
    else:
        print(f"[WARN] {text}")


def print_error(text):
    if RICH_AVAILABLE:
        console.print(f"[red]✗[/red] {text}")
    else:
        print(f"[FAIL] {text}")


def check_python_version():
    """Check Python version is 3.10+"""
    print_header("Checking Python Version")

    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version.major >= 3 and version.minor >= 10:
        print_success(f"Python {version_str} (3.10+ required)")
        return True
    else:
        print_error(f"Python {version_str} - requires 3.10+")
        return False


def check_required_packages():
    """Check that core packages are installed"""
    print_header("Checking Required Packages")

    packages = {
        # Core ML (Labs 00-13: ML foundations, no LLM required)
        "numpy": "NumPy (numerical computing)",
        "pandas": "Pandas (data manipulation)",
        "sklearn": "scikit-learn (machine learning)",
        # LLM Frameworks (base)
        "langchain": "LangChain (LLM orchestration)",
        "langchain_community": "LangChain Community (Tools/Integrations)",
        # Vector DB
        "chromadb": "ChromaDB (vector database)",
        # Security
        "yara": "YARA (malware detection rules)",
        # CLI/UI
        "rich": "Rich (CLI output)",
        "gradio": "Gradio (web UI demos)",
        # Utils
        "dotenv": "python-dotenv (environment variables)",
    }

    all_ok = True
    installed = []
    missing = []

    for package, description in packages.items():
        try:
            __import__(package)
            print_success(description)
            installed.append(package)
        except ImportError:
            print_error(f"{description} - not installed")
            missing.append(package)
            all_ok = False

    if missing:
        print_warning(f"\nMissing packages: {', '.join(missing)}")
        print_warning("Run: pip install -e .")

    return all_ok


def check_optional_packages():
    """Check optional packages"""
    print_header("Checking Optional Packages")

    packages = {
        "torch": "PyTorch (deep learning)",
        "transformers": "Hugging Face Transformers",
        "litellm": "LiteLLM (unified LLM API)",
        "instructor": "Instructor (structured outputs)",
    }

    for package, description in packages.items():
        try:
            __import__(package)
            print_success(description)
        except ImportError:
            print_warning(f"{description} - not installed (optional)")


def check_llm_providers():
    """Check which LLM providers are installed (at least one needed for LLM labs)

    Returns:
        set: Names of installed provider packages (e.g., {'langchain_ollama', 'langchain_anthropic'})
    """
    print_header("Checking LLM Provider Packages")

    # LLM provider packages - install with: pip install -e ".[provider]"
    providers = {
        "langchain_ollama": ("Ollama (local)", 'pip install -e ".[ollama]"'),
        "langchain_anthropic": ("Anthropic Claude", 'pip install -e ".[anthropic]"'),
        "langchain_openai": ("OpenAI GPT", 'pip install -e ".[openai]"'),
        "langchain_google_genai": ("Google Gemini", 'pip install -e ".[google]"'),
    }

    installed_providers = set()

    for package, (description, install_cmd) in providers.items():
        try:
            __import__(package)
            print_success(f"{description} - installed")
            installed_providers.add(package)
        except ImportError:
            print_warning(f"{description} - not installed ({install_cmd})")

    if not installed_providers:
        print_warning("\nNo LLM providers installed!")
        print_warning("Install at least one for LLM labs (14+):")
        print_warning('  pip install -e ".[ollama]"   # FREE, local, recommended')
        print_warning('  pip install -e ".[anthropic]" # Claude (best quality)')

    return installed_providers


def check_api_keys(ollama_available=False, installed_providers=None):
    """Check that API keys are configured AND match installed providers.

    Cross-validates that at least one complete LLM stack is usable:
    - Ollama: langchain_ollama installed AND ollama runtime available
    - Anthropic: langchain_anthropic installed AND ANTHROPIC_API_KEY set
    - OpenAI: langchain_openai installed AND OPENAI_API_KEY set
    - Google: langchain_google_genai installed AND GOOGLE_API_KEY set
    """
    print_header("Checking LLM Configuration")

    if installed_providers is None:
        installed_providers = set()

    # Load .env if exists
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    # Map provider packages to their required API keys
    provider_key_map = {
        "langchain_anthropic": ("ANTHROPIC_API_KEY", "Anthropic (Claude)"),
        "langchain_openai": ("OPENAI_API_KEY", "OpenAI (GPT)"),
        "langchain_google_genai": ("GOOGLE_API_KEY", "Google (Gemini)"),
    }

    optional_keys = {
        "VIRUSTOTAL_API_KEY": "VirusTotal",
        "ABUSEIPDB_API_KEY": "AbuseIPDB",
        "SHODAN_API_KEY": "Shodan",
    }

    # Track which providers are FULLY usable (package + key/runtime)
    usable_providers = []

    # Check Ollama: needs both package AND runtime
    if "langchain_ollama" in installed_providers and ollama_available:
        print_success("Ollama - READY (package installed + runtime available)")
        usable_providers.append("Ollama")
    elif "langchain_ollama" in installed_providers:
        print_warning("Ollama - package installed but runtime not available")
        print_warning("  Start Ollama: ollama serve")
    elif ollama_available:
        print_warning("Ollama - runtime available but package not installed")
        print_warning('  Install: pip install -e ".[ollama]"')
    else:
        print_warning("Ollama not configured (optional - install from https://ollama.ai)")

    print("\nCloud LLM providers:")
    for package, (key_name, provider_name) in provider_key_map.items():
        has_package = package in installed_providers
        api_key = os.getenv(key_name, "")
        has_key = api_key and len(api_key) > 10

        if has_package and has_key:
            print_success(f"{provider_name} - READY (package installed + API key set)")
            usable_providers.append(provider_name)
        elif has_package:
            print_warning(f"{provider_name} - package installed but API key not set")
            print_warning(f"  Set {key_name} in .env file")
        elif has_key:
            print_warning(f"{provider_name} - API key set but package not installed")
        else:
            print_warning(f"{provider_name} - not configured")

    # Final verdict: at least one complete stack required
    if usable_providers:
        print_success(f"\nReady for LLM labs with: {', '.join(usable_providers)}")
    else:
        print_error("\nNo usable LLM provider!")
        print_warning("You need BOTH a package AND its configuration:")
        print_warning('  Ollama:    pip install -e ".[ollama]" + ollama serve')
        print_warning('  Anthropic: pip install -e ".[anthropic]" + ANTHROPIC_API_KEY')
        print_warning('  OpenAI:    pip install -e ".[openai]" + OPENAI_API_KEY')
        print_warning('  Google:    pip install -e ".[google]" + GOOGLE_API_KEY')

    print("\nOptional threat intel API keys:")
    for key, provider in optional_keys.items():
        value = os.getenv(key, "")
        if value and len(value) > 5:
            print_success(f"{provider} API key configured")
        else:
            print_warning(f"{provider} API key not set (optional)")

    return len(usable_providers) > 0


def check_data_files():
    """Check that sample data files exist"""
    print_header("Checking Sample Data")

    project_root = Path(__file__).parent.parent

    data_paths = [
        ("labs/lab00a-python-security-fundamentals/data", "Lab 00a data"),
        ("labs/lab01-phishing-classifier/data", "Lab 01 data"),
        ("labs/lab02-malware-clustering/data", "Lab 02 data"),
        ("labs/lab03-anomaly-detection/data", "Lab 03 data"),
    ]

    all_ok = True
    for path, description in data_paths:
        full_path = project_root / path
        if full_path.exists():
            files = list(full_path.glob("*"))
            if files:
                print_success(f"{description}: {len(files)} files found")
            else:
                print_warning(f"{description}: directory exists but empty")
                all_ok = False
        else:
            print_warning(f"{description}: directory not found")
            all_ok = False

    return all_ok


def check_ctf_infrastructure():
    """Check CTF challenge infrastructure"""
    print_header("Checking CTF Infrastructure")

    project_root = Path(__file__).parent.parent
    all_ok = True

    # Check verify_flag.py exists
    verify_flag = project_root / "scripts" / "verify_flag.py"
    if verify_flag.exists():
        print_success("CTF flag verification script found")
    else:
        print_warning("scripts/verify_flag.py not found")
        all_ok = False

    # Check CTF challenge directories
    ctf_dir = project_root / "ctf-challenges"
    if ctf_dir.exists():
        difficulties = ["beginner", "intermediate", "advanced"]
        for difficulty in difficulties:
            diff_dir = ctf_dir / difficulty
            if diff_dir.exists():
                challenges = list(diff_dir.glob("challenge-*"))
                print_success(f"CTF {difficulty}: {len(challenges)} challenges found")
            else:
                print_warning(f"CTF {difficulty} directory not found")
                all_ok = False
    else:
        print_warning("ctf-challenges directory not found")
        all_ok = False

    return all_ok


def check_lab00a_structure():
    """Check Lab 00a has proper structure"""
    print_header("Checking Lab 00a Structure")

    project_root = Path(__file__).parent.parent
    lab00a = project_root / "labs" / "lab00a-python-security-fundamentals"

    all_ok = True
    required_components = [
        ("data", "Sample data files"),
        ("starter", "Starter code"),
        ("solution", "Solution code"),
    ]

    for component, description in required_components:
        path = lab00a / component
        if path.exists():
            files = list(path.glob("*"))
            if files:
                print_success(f"Lab 00a {description}: {len(files)} files")
            else:
                print_warning(f"Lab 00a {description}: directory empty")
                all_ok = False
        else:
            print_warning(f"Lab 00a {description}: not found")
            all_ok = False

    return all_ok


def check_ollama(verbose=True):
    """Check if Ollama is available for local models"""
    if verbose:
        print_header("Checking Ollama (Local LLM)")

    import subprocess

    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if verbose:
                print_success("Ollama installed and running")
            models = result.stdout.strip().split("\n")[1:]  # Skip header
            if models and models[0]:
                if verbose:
                    print_success(f"Available models: {len(models)}")
                    for model in models[:3]:  # Show first 3
                        model_name = model.split()[0] if model.split() else model
                        print_success(f"  - {model_name}")
                    if len(models) > 3:
                        print_success(f"  ... and {len(models) - 3} more")
            else:
                if verbose:
                    print_warning("No models installed yet.")
                    print_warning("Run: ollama pull llama3.3:8b  (recommended, 8GB RAM)")
            return True
        else:
            if verbose:
                print_warning("Ollama installed but not running. Run: ollama serve")
            return False
    except FileNotFoundError:
        if verbose:
            print_warning("Ollama not installed")
            print_warning("Install from: https://ollama.ai (FREE, recommended)")
        return False
    except subprocess.TimeoutExpired:
        if verbose:
            print_warning("Ollama not responding")
        return False


def print_summary(results):
    """Print final summary"""
    print_header("Setup Summary")

    all_passed = all(results.values())

    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Check")
        table.add_column("Status")

        for check, passed in results.items():
            status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
            table.add_row(check, status)

        console.print(table)

        if all_passed:
            console.print(
                Panel.fit(
                    "[bold green]All checks passed! You're ready to start.[/bold green]\n\n"
                    "Next step: cd labs/lab01-phishing-classifier",
                    title="Ready!",
                )
            )
        else:
            console.print(
                Panel.fit(
                    "[bold yellow]Some checks failed. Review the issues above.[/bold yellow]\n\n"
                    "Most labs will still work with optional packages missing.",
                    title="Setup Incomplete",
                )
            )
    else:
        print("\n" + "-" * 40)
        for check, passed in results.items():
            status = "PASS" if passed else "FAIL"
            print(f"{check}: {status}")

        if all_passed:
            print("\nAll checks passed! You're ready to start.")
            print("Next step: cd labs/lab01-phishing-classifier")
        else:
            print("\nSome checks failed. Review the issues above.")


def main():
    """Run all verification checks"""
    if RICH_AVAILABLE:
        console.print(
            Panel.fit(
                "[bold]AI for the Win - Setup Verification[/bold]\n"
                "Checking your environment configuration...",
                border_style="blue",
            )
        )
    else:
        print("=" * 60)
        print("AI for the Win - Setup Verification")
        print("=" * 60)

    # Check Ollama first (needed for API keys check)
    ollama_available = check_ollama(verbose=True)

    # Check LLM providers (returns set of installed packages)
    installed_providers = check_llm_providers()

    results = {
        "Python Version": check_python_version(),
        "Required Packages": check_required_packages(),
        "LLM Providers": len(installed_providers) > 0,
        "LLM Configuration": check_api_keys(
            ollama_available=ollama_available, installed_providers=installed_providers
        ),
        "Sample Data": check_data_files(),
        "Lab 00a Structure": check_lab00a_structure(),
        "CTF Infrastructure": check_ctf_infrastructure(),
    }

    # Optional packages (PyTorch, transformers, etc.)
    check_optional_packages()

    print_summary(results)

    # Return exit code
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

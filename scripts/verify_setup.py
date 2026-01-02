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
        # Core ML
        "numpy": "NumPy (numerical computing)",
        "pandas": "Pandas (data manipulation)",
        "sklearn": "scikit-learn (machine learning)",
        # LLM Frameworks
        "langchain": "LangChain (LLM orchestration)",
        "langchain_anthropic": "LangChain Anthropic (Claude)",
        "langchain_openai": "LangChain OpenAI (GPT)",
        "langchain_google_genai": "LangChain Google (Gemini)",
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
        print_warning("Run: pip install -r requirements.txt")

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


def check_api_keys():
    """Check that API keys are configured"""
    print_header("Checking API Keys")

    # Load .env if exists
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    required_keys = {
        "ANTHROPIC_API_KEY": "Anthropic (Claude)",
        "OPENAI_API_KEY": "OpenAI (GPT)",
        "GOOGLE_API_KEY": "Google (Gemini)",
    }

    optional_keys = {
        "VIRUSTOTAL_API_KEY": "VirusTotal",
        "ABUSEIPDB_API_KEY": "AbuseIPDB",
        "SHODAN_API_KEY": "Shodan",
    }

    has_llm_key = False

    for key, provider in required_keys.items():
        value = os.getenv(key, "")
        if value and len(value) > 10:
            print_success(f"{provider} API key configured")
            has_llm_key = True
        else:
            print_warning(f"{provider} API key not set")

    if not has_llm_key:
        print_error("\nNo LLM API key found! At least one is required for LLM labs.")
        print_warning("Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY in .env")

    print("\nOptional API keys:")
    for key, provider in optional_keys.items():
        value = os.getenv(key, "")
        if value and len(value) > 5:
            print_success(f"{provider} API key configured")
        else:
            print_warning(f"{provider} API key not set (optional)")

    return has_llm_key


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


def check_ollama():
    """Check if Ollama is available for local models"""
    print_header("Checking Local Model Support")

    import subprocess

    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print_success("Ollama installed and running")
            models = result.stdout.strip().split("\n")[1:]  # Skip header
            if models and models[0]:
                print_success(f"Available models: {len(models)}")
            else:
                print_warning("No models installed. Run: ollama pull llama3.1")
            return True
        else:
            print_warning("Ollama installed but not running. Run: ollama serve")
            return False
    except FileNotFoundError:
        print_warning("Ollama not installed (optional - for local models)")
        print_warning("Install from: https://ollama.com")
        return False
    except subprocess.TimeoutExpired:
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

    results = {
        "Python Version": check_python_version(),
        "Required Packages": check_required_packages(),
        "API Keys": check_api_keys(),
        "Sample Data": check_data_files(),
        "Lab 00a Structure": check_lab00a_structure(),
        "CTF Infrastructure": check_ctf_infrastructure(),
    }

    # Optional checks
    check_optional_packages()
    check_ollama()

    print_summary(results)

    # Return exit code
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

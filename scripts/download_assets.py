#!/usr/bin/env python3
"""
AI for the Win - Asset Download Script

Pre-downloads all required external assets (NLTK data, spaCy models, etc.)
for offline/firewalled environments.

Usage:
    python scripts/download_assets.py           # Download all assets
    python scripts/download_assets.py --nltk   # NLTK data only
    python scripts/download_assets.py --spacy  # spaCy models only
    python scripts/download_assets.py --check  # Check what's installed
"""

import argparse
import sys
from pathlib import Path

# Add color output if available
try:
    from rich.console import Console
    from rich.panel import Panel

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
        print(f"[ERROR] {text}")


def print_info(text):
    if RICH_AVAILABLE:
        console.print(f"[cyan]→[/cyan] {text}")
    else:
        print(f"[INFO] {text}")


def download_nltk_data():
    """Download required NLTK data packages."""
    print_header("Downloading NLTK Data")

    try:
        import nltk
    except ImportError:
        print_error("NLTK not installed. Run: pip install nltk")
        return False

    # Required NLTK packages for the labs
    packages = [
        ("punkt", "Sentence tokenizer"),
        ("punkt_tab", "Sentence tokenizer (tabular)"),
        ("stopwords", "Stop words corpus"),
        ("wordnet", "WordNet lexical database"),
        ("averaged_perceptron_tagger", "Part-of-speech tagger"),
        ("averaged_perceptron_tagger_eng", "English POS tagger"),
    ]

    all_ok = True
    for package, description in packages:
        try:
            # Check if already downloaded
            try:
                nltk.data.find(f"tokenizers/{package}")
                print_success(f"{description} ({package}) - already installed")
                continue
            except LookupError:
                pass

            try:
                nltk.data.find(f"corpora/{package}")
                print_success(f"{description} ({package}) - already installed")
                continue
            except LookupError:
                pass

            try:
                nltk.data.find(f"taggers/{package}")
                print_success(f"{description} ({package}) - already installed")
                continue
            except LookupError:
                pass

            # Download the package
            print_info(f"Downloading {package}...")
            nltk.download(package, quiet=True)
            print_success(f"{description} ({package})")

        except Exception as e:
            print_error(f"{description} ({package}): {e}")
            all_ok = False

    return all_ok


def download_spacy_models():
    """Download required spaCy models."""
    print_header("Downloading spaCy Models")

    try:
        import spacy
    except ImportError:
        print_warning("spaCy not installed. Run: pip install spacy")
        return True  # Optional, so don't fail

    import subprocess

    models = [
        ("en_core_web_sm", "English small model (~12MB)"),
    ]

    all_ok = True
    for model, description in models:
        try:
            # Check if already installed
            try:
                spacy.load(model)
                print_success(f"{description} - already installed")
                continue
            except OSError:
                pass

            # Download the model
            print_info(f"Downloading {model}...")
            result = subprocess.run(
                [sys.executable, "-m", "spacy", "download", model],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print_success(description)
            else:
                print_error(f"{description}: {result.stderr[:100]}")
                all_ok = False

        except Exception as e:
            print_error(f"{description}: {e}")
            all_ok = False

    return all_ok


def check_assets():
    """Check which assets are installed."""
    print_header("Checking Installed Assets")

    # Check NLTK
    print("\nNLTK Data:")
    try:
        import nltk

        nltk_packages = ["punkt", "stopwords", "wordnet"]
        for package in nltk_packages:
            try:
                nltk.data.find(f"tokenizers/{package}")
                print_success(f"  {package}")
            except LookupError:
                try:
                    nltk.data.find(f"corpora/{package}")
                    print_success(f"  {package}")
                except LookupError:
                    print_warning(f"  {package} - not installed")
    except ImportError:
        print_warning("  NLTK not installed")

    # Check spaCy
    print("\nspaCy Models:")
    try:
        import spacy

        models = ["en_core_web_sm"]
        for model in models:
            try:
                spacy.load(model)
                print_success(f"  {model}")
            except OSError:
                print_warning(f"  {model} - not installed")
    except ImportError:
        print_warning("  spaCy not installed")

    # Check sentence-transformers cache
    print("\nSentence Transformers:")
    try:
        from sentence_transformers import SentenceTransformer

        cache_dir = Path.home() / ".cache" / "huggingface" / "hub"
        if cache_dir.exists():
            models = list(cache_dir.glob("models--*"))
            if models:
                print_success(f"  Cache directory: {len(models)} models cached")
            else:
                print_warning("  Cache directory empty")
        else:
            print_warning("  No models cached")
    except ImportError:
        print_warning("  sentence-transformers not installed")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Download external assets for AI for the Win labs")
    parser.add_argument("--nltk", action="store_true", help="Download NLTK data only")
    parser.add_argument("--spacy", action="store_true", help="Download spaCy models only")
    parser.add_argument("--check", action="store_true", help="Check installed assets")
    args = parser.parse_args()

    if RICH_AVAILABLE:
        console.print(
            Panel.fit(
                "[bold]AI for the Win - Asset Downloader[/bold]\n"
                "Downloading required data for offline use...",
                border_style="blue",
            )
        )
    else:
        print("=" * 60)
        print("AI for the Win - Asset Downloader")
        print("=" * 60)

    if args.check:
        check_assets()
        return 0

    results = []

    if args.nltk or (not args.nltk and not args.spacy):
        results.append(("NLTK Data", download_nltk_data()))

    if args.spacy or (not args.nltk and not args.spacy):
        results.append(("spaCy Models", download_spacy_models()))

    # Summary
    print_header("Download Summary")
    all_ok = True
    for name, success in results:
        if success:
            print_success(name)
        else:
            print_error(name)
            all_ok = False

    if all_ok:
        print("\n✓ All assets downloaded successfully!")
        print("  You can now work offline for labs that use these resources.")
    else:
        print("\n! Some downloads failed. Check your network connection.")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

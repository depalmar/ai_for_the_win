#!/usr/bin/env python3
"""
Accessibility Audit Script for Gradio Demo UI.

Provides:
1. Manual checklist for accessibility review
2. Automated axe-core audit (requires selenium + axe-selenium-python)

Usage:
    python scripts/accessibility_audit.py [--url URL] [--automated]
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


def print_manual_checklist() -> None:
    """Print manual accessibility checklist for Gradio demos."""
    checklist = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    ACCESSIBILITY CHECKLIST FOR GRADIO DEMO                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  KEYBOARD NAVIGATION                                                          ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  [ ] All interactive elements reachable with Tab key                          ║
║  [ ] Focus indicator visible on all focusable elements                        ║
║  [ ] Tab order follows logical reading order                                  ║
║  [ ] No keyboard traps (can Tab out of all components)                        ║
║  [ ] Escape key closes modals/dropdowns                                       ║
║                                                                               ║
║  SCREEN READER SUPPORT                                                        ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  [ ] All images have alt text                                                 ║
║  [ ] Form inputs have associated labels                                       ║
║  [ ] Buttons have descriptive text (not just icons)                           ║
║  [ ] Tables have proper headers                                               ║
║  [ ] Dynamic content changes announced                                        ║
║                                                                               ║
║  COLOR & CONTRAST                                                             ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  [ ] Text contrast ratio >= 4.5:1 (normal text)                               ║
║  [ ] Text contrast ratio >= 3:1 (large text, 18pt+)                           ║
║  [ ] Information not conveyed by color alone                                  ║
║  [ ] Focus indicators have sufficient contrast                                ║
║                                                                               ║
║  CONTENT & STRUCTURE                                                          ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  [ ] Page has descriptive title                                               ║
║  [ ] Headings used in logical hierarchy (h1 -> h2 -> h3)                      ║
║  [ ] Links have descriptive text (not "click here")                           ║
║  [ ] Error messages are clear and specific                                    ║
║  [ ] Instructions don't rely solely on sensory characteristics                ║
║                                                                               ║
║  RESPONSIVE & ZOOM                                                            ║
║  ─────────────────────────────────────────────────────────────────────────── ║
║  [ ] Content readable at 200% zoom                                            ║
║  [ ] No horizontal scrolling at 320px width                                   ║
║  [ ] Touch targets >= 44x44 pixels                                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

TESTING TOOLS:
  - Browser DevTools > Lighthouse > Accessibility
  - WAVE browser extension (wave.webaim.org)
  - axe DevTools browser extension
  - NVDA or VoiceOver screen reader testing

WCAG 2.1 LEVEL AA TARGET:
  - Perceivable: Text alternatives, time-based media, adaptable, distinguishable
  - Operable: Keyboard accessible, enough time, no seizures, navigable
  - Understandable: Readable, predictable, input assistance
  - Robust: Compatible with assistive technologies
"""
    print(checklist)


def run_axe_audit(url: str) -> Dict[str, Any]:
    """
    Run automated axe-core accessibility audit.

    Requires: pip install selenium axe-selenium-python webdriver-manager

    Args:
        url: URL to audit (e.g., http://localhost:7860)

    Returns:
        Audit results dictionary
    """
    try:
        from axe_selenium_python import Axe
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError:
        print("ERROR: Required packages not installed.")
        print("Run: pip install selenium axe-selenium-python webdriver-manager")
        sys.exit(1)

    # Setup headless Chrome
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    print(f"Starting accessibility audit of {url}...")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    try:
        driver.get(url)
        # Wait for Gradio to load
        driver.implicitly_wait(10)

        # Run axe audit
        axe = Axe(driver)
        axe.inject()
        results = axe.run()

        return results

    finally:
        driver.quit()


def format_axe_results(results: Dict[str, Any]) -> str:
    """Format axe results for console output."""
    output = []
    output.append("\n" + "=" * 70)
    output.append("AXE-CORE ACCESSIBILITY AUDIT RESULTS")
    output.append("=" * 70)

    violations = results.get("violations", [])
    passes = results.get("passes", [])
    incomplete = results.get("incomplete", [])

    output.append(f"\n📊 Summary:")
    output.append(f"   ❌ Violations: {len(violations)}")
    output.append(f"   ✅ Passes: {len(passes)}")
    output.append(f"   ⚠️  Incomplete (needs review): {len(incomplete)}")

    if violations:
        output.append("\n" + "-" * 70)
        output.append("❌ VIOLATIONS (must fix)")
        output.append("-" * 70)

        for v in violations:
            impact = v.get("impact", "unknown").upper()
            output.append(f"\n[{impact}] {v.get('id')}: {v.get('description')}")
            output.append(f"   Help: {v.get('helpUrl')}")
            output.append(f"   Affected elements: {len(v.get('nodes', []))}")
            for node in v.get("nodes", [])[:3]:  # Show first 3
                output.append(f"   - {node.get('html', '')[:80]}...")

    if incomplete:
        output.append("\n" + "-" * 70)
        output.append("⚠️  NEEDS MANUAL REVIEW")
        output.append("-" * 70)

        for item in incomplete[:5]:  # Show first 5
            output.append(f"\n• {item.get('id')}: {item.get('description')}")

    output.append("\n" + "=" * 70)

    return "\n".join(output)


def save_results(results: Dict[str, Any], filepath: str) -> None:
    """Save full results to JSON file."""
    results["audit_timestamp"] = datetime.now().isoformat()
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Accessibility audit for Gradio demo UI"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:7860",
        help="URL to audit (default: http://localhost:7860)"
    )
    parser.add_argument(
        "--automated",
        action="store_true",
        help="Run automated axe-core audit (requires selenium)"
    )
    parser.add_argument(
        "--output",
        help="Save full results to JSON file"
    )

    args = parser.parse_args()

    # Always show manual checklist
    print_manual_checklist()

    if args.automated:
        print("\nRunning automated audit...")
        results = run_axe_audit(args.url)
        print(format_axe_results(results))

        if args.output:
            save_results(results, args.output)

        # Exit with error code if violations found
        violations = results.get("violations", [])
        critical = [v for v in violations if v.get("impact") in ["critical", "serious"]]
        if critical:
            print(f"\n⚠️  {len(critical)} critical/serious violations found!")
            sys.exit(1)
    else:
        print("\nTip: Run with --automated flag for axe-core scan")
        print("Example: python scripts/accessibility_audit.py --automated --url http://localhost:7860")


if __name__ == "__main__":
    main()

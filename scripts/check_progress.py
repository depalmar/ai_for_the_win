#!/usr/bin/env python3
"""
AI for the Win - Progress Tracker

Track your progress through the labs and CTF challenges.

Usage:
    python scripts/check_progress.py
    python scripts/check_progress.py --verbose
    python scripts/check_progress.py --lab 01
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Try to import rich for pretty output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.table import Table

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# =============================================================================
# Lab and Challenge Definitions
# =============================================================================

INTRO_LABS = [
    ("00a", "Python for Security Fundamentals", ["starter/main.py", "solution/main.py"]),
    ("00b", "ML Concepts Primer", []),  # No code, conceptual
    ("00c", "Intro to Prompt Engineering", []),  # No code, uses web UIs
    ("00d", "Security Data 101", []),  # No code, conceptual
]

ML_LABS = [
    ("01", "Phishing Classifier", ["starter/main.py", "solution/main.py"]),
    ("02", "Malware Clustering", ["starter/main.py", "solution/main.py"]),
    ("03", "Anomaly Detection", ["starter/main.py", "solution/main.py"]),
]

LLM_LABS = [
    ("04", "LLM Prompts for Security", ["starter/main.py", "solution/main.py"]),
    ("05", "Threat Intel Agent", ["starter/main.py", "solution/main.py"]),
    ("06", "Security RAG Pipeline", ["starter/main.py", "solution/main.py"]),
    ("07", "YARA Rule Generator", ["starter/main.py", "solution/main.py"]),
]

ADVANCED_LABS = [
    ("08", "Security Copilot", ["starter/main.py", "solution/main.py"]),
    ("09", "Alert Triage Pipeline", ["starter/main.py", "solution/main.py"]),
    ("10", "Incident Response Agent", ["starter/main.py", "solution/main.py"]),
]

EXPERT_LABS = [
    ("11", "Ransomware Detection", ["starter/behavior_detector.py", "starter/ransom_note_analyzer.py"]),
    ("12", "Ransomware Simulation", ["starter/scenario_generator.py", "starter/safe_simulator.py"]),
    ("13", "Memory Forensics AI", ["starter/main.py"]),
    ("14", "Log Analysis Pipeline", ["starter/main.py"]),
    ("15", "Threat Hunting Agent", ["starter/main.py"]),
    ("16", "Malware Analysis AI", ["starter/main.py"]),
    ("17", "Vulnerability Scanner", ["starter/main.py"]),
    ("18", "Red Team Assistant", ["starter/main.py"]),
    ("19", "Blue Team Dashboard", ["starter/main.py"]),
    ("20", "C2 Detection ML", ["starter/main.py"]),
]

CTF_CHALLENGES = {
    "beginner": [
        ("01", "Stolen Credentials", 100),
        ("02", "Phishing Recon", 100),
        ("03", "IOC Extraction", 100),
        ("04", "ML Model Abuse", 100),
        ("05", "Prompt Injection", 100),
    ],
    "intermediate": [
        ("01", "RAG Poisoning", 250),
        ("02", "Memory Forensics", 250),
        ("03", "Malware Classification", 250),
        ("04", "Agent Exploitation", 250),
        ("05", "Ransomware Analysis", 250),
    ],
    "advanced": [
        ("01", "APT Detection", 500),
        ("02", "Model Poisoning", 500),
        ("03", "Cloud Incident", 500),
        ("04", "Zero Day Hunt", 500),
        ("05", "Full Compromise", 500),
    ],
}


# =============================================================================
# Progress Tracking
# =============================================================================

def get_project_root() -> Path:
    """Get the project root directory."""
    script_path = Path(__file__).resolve()
    return script_path.parent.parent


def check_lab_progress(lab_id: str, lab_name: str, files: List[str]) -> Dict:
    """
    Check progress for a specific lab.

    Returns:
        Dict with status info
    """
    project_root = get_project_root()

    # Find lab directory
    lab_patterns = [
        f"lab{lab_id}-*",
        f"lab{lab_id.zfill(2)}-*",
    ]

    lab_dir = None
    for pattern in lab_patterns:
        matches = list(project_root.glob(f"labs/{pattern}"))
        if matches:
            lab_dir = matches[0]
            break

    if not lab_dir:
        return {
            "lab_id": lab_id,
            "name": lab_name,
            "status": "not_found",
            "has_starter": False,
            "has_solution": False,
            "has_data": False,
            "has_tests": False,
            "tests_passing": None,
        }

    # Check components
    has_starter = (lab_dir / "starter").exists()
    has_solution = (lab_dir / "solution").exists()
    has_data = (lab_dir / "data").exists()
    has_tests = (lab_dir / "tests").exists() or list(lab_dir.glob("test_*.py"))

    # Check if starter files have been modified (student progress)
    starter_modified = False
    if has_starter:
        for starter_file in (lab_dir / "starter").glob("*.py"):
            # Check if file has content beyond the template
            content = starter_file.read_text()
            if "pass" not in content or "# TODO" not in content:
                # File has been implemented
                starter_modified = True
                break

    status = "not_started"
    if starter_modified:
        status = "in_progress"
    if has_solution and has_starter:
        # Check if solution matches starter (completed)
        # For simplicity, just check if starter has implementations
        status = "in_progress" if starter_modified else "not_started"

    return {
        "lab_id": lab_id,
        "name": lab_name,
        "status": status,
        "has_starter": has_starter,
        "has_solution": has_solution,
        "has_data": has_data,
        "has_tests": has_tests,
        "lab_dir": str(lab_dir),
    }


def check_ctf_progress() -> Dict:
    """
    Check CTF challenge progress.

    Reads from ~/.ai_for_the_win/ctf_progress.json if exists.
    """
    progress_file = Path.home() / ".ai_for_the_win" / "ctf_progress.json"

    if progress_file.exists():
        try:
            with open(progress_file) as f:
                return json.load(f)
        except Exception:
            pass

    return {"completed": [], "points": 0}


def save_ctf_progress(progress: Dict) -> None:
    """Save CTF progress to file."""
    progress_dir = Path.home() / ".ai_for_the_win"
    progress_dir.mkdir(exist_ok=True)

    progress_file = progress_dir / "ctf_progress.json"
    with open(progress_file, "w") as f:
        json.dump(progress, f, indent=2)


def check_all_progress() -> Dict:
    """Check progress across all labs and challenges."""
    progress = {
        "intro_labs": [],
        "ml_labs": [],
        "llm_labs": [],
        "advanced_labs": [],
        "expert_labs": [],
        "ctf": check_ctf_progress(),
    }

    for lab_id, name, files in INTRO_LABS:
        progress["intro_labs"].append(check_lab_progress(lab_id, name, files))

    for lab_id, name, files in ML_LABS:
        progress["ml_labs"].append(check_lab_progress(lab_id, name, files))

    for lab_id, name, files in LLM_LABS:
        progress["llm_labs"].append(check_lab_progress(lab_id, name, files))

    for lab_id, name, files in ADVANCED_LABS:
        progress["advanced_labs"].append(check_lab_progress(lab_id, name, files))

    for lab_id, name, files in EXPERT_LABS:
        progress["expert_labs"].append(check_lab_progress(lab_id, name, files))

    return progress


# =============================================================================
# Display Functions
# =============================================================================

def print_header(text: str) -> None:
    """Print a section header."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold blue]{text}[/bold blue]")
    else:
        print(f"\n{'=' * 60}\n{text}\n{'=' * 60}")


def print_lab_status(lab: Dict) -> None:
    """Print status for a single lab."""
    status_icons = {
        "not_started": "[gray][ ][/gray]" if RICH_AVAILABLE else "[ ]",
        "in_progress": "[yellow][~][/yellow]" if RICH_AVAILABLE else "[~]",
        "completed": "[green][x][/green]" if RICH_AVAILABLE else "[x]",
        "not_found": "[red][?][/red]" if RICH_AVAILABLE else "[?]",
    }

    icon = status_icons.get(lab["status"], "[ ]")

    components = []
    if lab.get("has_starter"):
        components.append("starter")
    if lab.get("has_solution"):
        components.append("solution")
    if lab.get("has_data"):
        components.append("data")
    if lab.get("has_tests"):
        components.append("tests")

    component_str = f"({', '.join(components)})" if components else ""

    if RICH_AVAILABLE:
        console.print(f"  {icon} Lab {lab['lab_id']}: {lab['name']} {component_str}")
    else:
        print(f"  {icon} Lab {lab['lab_id']}: {lab['name']} {component_str}")


def print_progress_bar(completed: int, total: int, label: str) -> None:
    """Print a progress bar."""
    percentage = (completed / total * 100) if total > 0 else 0

    if RICH_AVAILABLE:
        bar_width = 30
        filled = int(bar_width * completed / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_width - filled)
        console.print(f"  {label}: [{bar}] {completed}/{total} ({percentage:.0f}%)")
    else:
        bar_width = 20
        filled = int(bar_width * completed / total) if total > 0 else 0
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"  {label}: [{bar}] {completed}/{total} ({percentage:.0f}%)")


def print_ctf_status(ctf_progress: Dict) -> None:
    """Print CTF challenge status."""
    print_header("CTF Challenges")

    completed = set(ctf_progress.get("completed", []))
    points = ctf_progress.get("points", 0)

    max_points = sum(
        sum(pts for _, _, pts in challenges)
        for challenges in CTF_CHALLENGES.values()
    )

    if RICH_AVAILABLE:
        console.print(f"  Points: [bold green]{points}[/bold green] / {max_points}")
    else:
        print(f"  Points: {points} / {max_points}")

    for difficulty, challenges in CTF_CHALLENGES.items():
        if RICH_AVAILABLE:
            console.print(f"\n  [bold]{difficulty.title()}[/bold] ({sum(p for _, _, p in challenges)} pts available)")
        else:
            print(f"\n  {difficulty.title()} ({sum(p for _, _, p in challenges)} pts available)")

        for cid, name, pts in challenges:
            challenge_id = f"{difficulty}-{cid}"
            is_complete = challenge_id in completed

            if RICH_AVAILABLE:
                icon = "[green][x][/green]" if is_complete else "[gray][ ][/gray]"
                pts_str = f"[green]+{pts}[/green]" if is_complete else f"[gray]{pts} pts[/gray]"
                console.print(f"    {icon} {name} {pts_str}")
            else:
                icon = "[x]" if is_complete else "[ ]"
                print(f"    {icon} {name} ({pts} pts)")


def print_summary(progress: Dict) -> None:
    """Print overall progress summary."""
    print_header("Progress Summary")

    # Count labs
    all_labs = (
        progress["intro_labs"] +
        progress["ml_labs"] +
        progress["llm_labs"] +
        progress["advanced_labs"] +
        progress["expert_labs"]
    )

    total_labs = len(all_labs)
    completed_labs = sum(1 for lab in all_labs if lab["status"] == "completed")
    in_progress_labs = sum(1 for lab in all_labs if lab["status"] == "in_progress")

    print_progress_bar(completed_labs, total_labs, "Labs Completed")
    print_progress_bar(in_progress_labs, total_labs, "Labs In Progress")

    # CTF
    ctf = progress["ctf"]
    total_challenges = sum(len(c) for c in CTF_CHALLENGES.values())
    completed_challenges = len(ctf.get("completed", []))
    print_progress_bar(completed_challenges, total_challenges, "CTF Challenges")

    # Recommendations
    if RICH_AVAILABLE:
        console.print("\n[bold]Recommended Next Steps:[/bold]")
    else:
        print("\nRecommended Next Steps:")

    # Find next lab to work on
    for lab in all_labs:
        if lab["status"] == "not_started" and lab.get("has_starter"):
            if RICH_AVAILABLE:
                console.print(f"  → Start Lab {lab['lab_id']}: {lab['name']}")
            else:
                print(f"  -> Start Lab {lab['lab_id']}: {lab['name']}")
            break

    # CTF suggestion
    if completed_challenges < total_challenges:
        ctf_completed = set(ctf.get("completed", []))
        for difficulty in ["beginner", "intermediate", "advanced"]:
            for cid, name, pts in CTF_CHALLENGES[difficulty]:
                if f"{difficulty}-{cid}" not in ctf_completed:
                    if RICH_AVAILABLE:
                        console.print(f"  → Try CTF: {name} ({difficulty}, {pts} pts)")
                    else:
                        print(f"  -> Try CTF: {name} ({difficulty}, {pts} pts)")
                    break
            else:
                continue
            break


def print_verbose_progress(progress: Dict) -> None:
    """Print detailed progress for all sections."""
    sections = [
        ("Intro Labs (00a-00d)", progress["intro_labs"]),
        ("ML Foundations (01-03)", progress["ml_labs"]),
        ("LLM Basics (04-07)", progress["llm_labs"]),
        ("Advanced (08-10)", progress["advanced_labs"]),
        ("Expert (11-20)", progress["expert_labs"]),
    ]

    for section_name, labs in sections:
        print_header(section_name)
        for lab in labs:
            print_lab_status(lab)

    print_ctf_status(progress["ctf"])
    print_summary(progress)


def print_compact_progress(progress: Dict) -> None:
    """Print compact progress view."""
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold]AI for the Win - Progress Tracker[/bold]",
            border_style="blue"
        ))
    else:
        print("\n" + "=" * 50)
        print("AI for the Win - Progress Tracker")
        print("=" * 50)

    print_summary(progress)


# =============================================================================
# Main
# =============================================================================

def main():
    """Run the progress tracker."""
    parser = argparse.ArgumentParser(
        description="Track your AI for the Win progress"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed progress for all labs"
    )
    parser.add_argument(
        "--lab",
        type=str,
        help="Show status for a specific lab (e.g., --lab 01)"
    )
    parser.add_argument(
        "--ctf",
        action="store_true",
        help="Show CTF challenge progress"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output progress as JSON"
    )

    args = parser.parse_args()

    # Check all progress
    progress = check_all_progress()

    if args.json:
        print(json.dumps(progress, indent=2, default=str))
        return

    if args.lab:
        # Find specific lab
        all_labs = (
            progress["intro_labs"] +
            progress["ml_labs"] +
            progress["llm_labs"] +
            progress["advanced_labs"] +
            progress["expert_labs"]
        )

        lab = next(
            (l for l in all_labs if l["lab_id"] == args.lab or l["lab_id"] == args.lab.zfill(2)),
            None
        )

        if lab:
            print_header(f"Lab {lab['lab_id']}: {lab['name']}")
            print_lab_status(lab)
            if lab.get("lab_dir"):
                print(f"\n  Directory: {lab['lab_dir']}")
        else:
            print(f"Lab {args.lab} not found")
        return

    if args.ctf:
        print_ctf_status(progress["ctf"])
        return

    if args.verbose:
        print_verbose_progress(progress)
    else:
        print_compact_progress(progress)


if __name__ == "__main__":
    main()

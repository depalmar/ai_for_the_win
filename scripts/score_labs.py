#!/usr/bin/env python3
"""
AI for the Win - Lab Scoring System

Automatically score lab implementations against test criteria.

Usage:
    python scripts/score_labs.py                    # Score all labs
    python scripts/score_labs.py --lab 11          # Score specific lab
    python scripts/score_labs.py --verbose         # Detailed output
"""

import argparse
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Try to import rich for pretty output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class TestCase:
    """A single test case for scoring."""

    name: str
    description: str
    points: int
    test_fn: Callable[..., bool]
    partial_credit: bool = False


@dataclass
class ScoringResult:
    """Result of scoring a lab."""

    lab_id: str
    lab_name: str
    total_points: int
    earned_points: int
    tests_passed: int
    tests_total: int
    details: List[Dict] = field(default_factory=list)


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).resolve().parent.parent


def load_module(module_path: Path) -> Optional[Any]:
    """Dynamically load a Python module from path."""
    if not module_path.exists():
        return None

    try:
        spec = importlib.util.spec_from_file_location(
            module_path.stem, module_path
        )
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    except Exception as e:
        print(f"Error loading {module_path}: {e}")

    return None


# =============================================================================
# Lab 11 Scoring: Ransomware Detection
# =============================================================================

def score_lab11() -> ScoringResult:
    """Score Lab 11: Ransomware Detection."""
    project_root = get_project_root()
    lab_dir = project_root / "labs" / "lab11-ransomware-detection"
    starter_dir = lab_dir / "starter"

    tests = []
    details = []

    # Test 1: Entropy calculation (20 pts)
    def test_entropy():
        behavior = load_module(starter_dir / "behavior_detector.py")
        if not behavior:
            return False
        detector = behavior.RansomwareBehaviorDetector()
        if not hasattr(detector, "calculate_entropy"):
            return False
        # Test with known data
        zeros = bytes([0] * 100)
        random_data = bytes(range(256))
        try:
            low = detector.calculate_entropy(zeros)
            high = detector.calculate_entropy(random_data)
            return low is not None and high is not None and low < high
        except Exception:
            return False

    tests.append(TestCase(
        name="Entropy Calculation",
        description="calculate_entropy() correctly computes Shannon entropy",
        points=20,
        test_fn=test_entropy
    ))

    # Test 2: Event analysis (25 pts)
    def test_analyze_events():
        behavior = load_module(starter_dir / "behavior_detector.py")
        if not behavior:
            return False
        detector = behavior.RansomwareBehaviorDetector()
        if not hasattr(detector, "analyze_events"):
            return False
        events = [
            behavior.FileEvent(
                timestamp=1000.0,
                process_name="test.exe",
                operation="WRITE",
                file_path="/test/file.encrypted",
                file_extension=".encrypted",
                entropy=7.9,
                size_bytes=1000
            )
        ]
        try:
            result = detector.analyze_events(events)
            return result is not None and isinstance(result, dict)
        except Exception:
            return False

    tests.append(TestCase(
        name="Event Analysis",
        description="analyze_events() returns detection results",
        points=25,
        test_fn=test_analyze_events
    ))

    # Test 3: Shadow deletion detection (15 pts)
    def test_shadow_detection():
        behavior = load_module(starter_dir / "behavior_detector.py")
        if not behavior:
            return False
        detector = behavior.RansomwareBehaviorDetector()
        events = [
            behavior.FileEvent(
                timestamp=1000.0,
                process_name="vssadmin",
                operation="CREATE",
                file_path="/tmp/out",
                file_extension=".tmp",
                entropy=2.0,
                size_bytes=100
            )
        ]
        try:
            result = detector.detect_shadow_deletion(events)
            return result is True
        except Exception:
            return False

    tests.append(TestCase(
        name="Shadow Deletion Detection",
        description="detect_shadow_deletion() identifies VSS deletion",
        points=15,
        test_fn=test_shadow_detection
    ))

    # Test 4: Ransom note IOC extraction (20 pts)
    def test_ioc_extraction():
        analyzer = load_module(starter_dir / "ransom_note_analyzer.py")
        if not analyzer:
            return False
        note_analyzer = analyzer.RansomNoteAnalyzer()
        sample = "Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or visit test.onion"
        try:
            iocs = note_analyzer.extract_iocs(sample)
            return (
                iocs is not None and
                isinstance(iocs, dict) and
                len(iocs.get("bitcoin_addresses", [])) > 0
            )
        except Exception:
            return False

    tests.append(TestCase(
        name="IOC Extraction",
        description="extract_iocs() finds Bitcoin addresses and onion URLs",
        points=20,
        test_fn=test_ioc_extraction
    ))

    # Test 5: Response playbook generation (20 pts)
    def test_playbook():
        responder = load_module(starter_dir / "ransomware_responder.py")
        if not responder:
            return False
        resp = responder.RansomwareResponder()
        context = responder.IncidentContext(
            affected_hosts=["host1"],
            affected_shares=[],
            ransomware_family="lockbit",
            encryption_progress=50.0,
            lateral_movement_detected=True,
            exfiltration_detected=False,
            first_seen="2024-01-01T00:00:00Z"
        )
        try:
            playbook = resp.generate_playbook(context)
            return playbook is not None and len(playbook) > 0
        except Exception:
            return False

    tests.append(TestCase(
        name="Response Playbook",
        description="generate_playbook() creates incident response steps",
        points=20,
        test_fn=test_playbook
    ))

    # Run all tests
    total_points = sum(t.points for t in tests)
    earned_points = 0
    passed = 0

    for test in tests:
        try:
            result = test.test_fn()
            if result:
                earned_points += test.points
                passed += 1
            details.append({
                "name": test.name,
                "description": test.description,
                "points": test.points,
                "earned": test.points if result else 0,
                "passed": result
            })
        except Exception as e:
            details.append({
                "name": test.name,
                "description": test.description,
                "points": test.points,
                "earned": 0,
                "passed": False,
                "error": str(e)
            })

    return ScoringResult(
        lab_id="11",
        lab_name="Ransomware Detection",
        total_points=total_points,
        earned_points=earned_points,
        tests_passed=passed,
        tests_total=len(tests),
        details=details
    )


# =============================================================================
# Lab 12 Scoring: Ransomware Simulation
# =============================================================================

def score_lab12() -> ScoringResult:
    """Score Lab 12: Ransomware Simulation."""
    project_root = get_project_root()
    lab_dir = project_root / "labs" / "lab12-ransomware-simulation"
    starter_dir = lab_dir / "starter"

    tests = []
    details = []

    # Test 1: Safety validation (30 pts) - CRITICAL
    def test_safety_validation():
        simulator = load_module(starter_dir / "safe_simulator.py")
        if not simulator:
            return False
        # Try to create simulator with invalid path - should raise
        from tempfile import gettempdir
        try:
            config = simulator.SimulationConfig(
                target_directory="/etc/passwd",  # Should be blocked!
            )
            sim = simulator.SafeRansomwareSimulator(config)
            return False  # Should have raised!
        except simulator.SafetyViolationError:
            return True  # Correctly blocked
        except Exception:
            return False

    tests.append(TestCase(
        name="Safety Path Validation",
        description="SafeRansomwareSimulator blocks non-allowed paths",
        points=30,
        test_fn=test_safety_validation
    ))

    # Test 2: Scenario generation (20 pts)
    def test_scenario_generation():
        generator = load_module(starter_dir / "scenario_generator.py")
        if not generator:
            return False
        gen = generator.ScenarioGenerator()
        try:
            scenario = gen.generate_scenario(
                family=generator.RansomwareFamily.LOCKBIT,
                complexity=generator.Complexity.MEDIUM
            )
            return scenario is not None
        except Exception:
            return False

    tests.append(TestCase(
        name="Scenario Generation",
        description="generate_scenario() creates attack scenarios",
        points=20,
        test_fn=test_scenario_generation
    ))

    # Test 3: Detection tests (20 pts)
    def test_detection_tests():
        generator = load_module(starter_dir / "scenario_generator.py")
        if not generator:
            return False
        gen = generator.ScenarioGenerator()
        try:
            scenario = gen.generate_scenario(
                family=generator.RansomwareFamily.LOCKBIT
            )
            if not scenario:
                return False
            tests = gen.generate_detection_tests(scenario)
            return tests is not None and isinstance(tests, list)
        except Exception:
            return False

    tests.append(TestCase(
        name="Detection Test Generation",
        description="generate_detection_tests() creates test cases",
        points=20,
        test_fn=test_detection_tests
    ))

    # Test 4: Audit logging (15 pts)
    def test_audit_logging():
        simulator = load_module(starter_dir / "safe_simulator.py")
        if not simulator:
            return False
        import tempfile
        test_dir = tempfile.mkdtemp(prefix="ransomware_test_")
        try:
            config = simulator.SimulationConfig(target_directory=test_dir)
            sim = simulator.SafeRansomwareSimulator(config)
            log = sim.get_audit_log()
            return len(log) > 0  # Should have config validation log
        except Exception:
            return False
        finally:
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)

    tests.append(TestCase(
        name="Audit Logging",
        description="All simulation actions are logged",
        points=15,
        test_fn=test_audit_logging
    ))

    # Test 5: Gap analysis (15 pts)
    def test_gap_analysis():
        validator = load_module(starter_dir / "detection_validator.py")
        if not validator:
            return False
        v = validator.DetectionValidator()
        try:
            gaps = v.generate_gap_analysis()
            return gaps is not None and isinstance(gaps, list)
        except Exception:
            return False

    tests.append(TestCase(
        name="Gap Analysis",
        description="generate_gap_analysis() identifies detection gaps",
        points=15,
        test_fn=test_gap_analysis
    ))

    # Run all tests
    total_points = sum(t.points for t in tests)
    earned_points = 0
    passed = 0

    for test in tests:
        try:
            result = test.test_fn()
            if result:
                earned_points += test.points
                passed += 1
            details.append({
                "name": test.name,
                "description": test.description,
                "points": test.points,
                "earned": test.points if result else 0,
                "passed": result
            })
        except Exception as e:
            details.append({
                "name": test.name,
                "description": test.description,
                "points": test.points,
                "earned": 0,
                "passed": False,
                "error": str(e)
            })

    return ScoringResult(
        lab_id="12",
        lab_name="Ransomware Simulation",
        total_points=total_points,
        earned_points=earned_points,
        tests_passed=passed,
        tests_total=len(tests),
        details=details
    )


# =============================================================================
# Placeholder Scoring for Labs 13-20
# =============================================================================

def create_placeholder_scorer(lab_id: str, lab_name: str) -> Callable[[], ScoringResult]:
    """Create a placeholder scorer for labs not yet implemented."""
    def scorer() -> ScoringResult:
        return ScoringResult(
            lab_id=lab_id,
            lab_name=lab_name,
            total_points=100,
            earned_points=0,
            tests_passed=0,
            tests_total=5,
            details=[{
                "name": "Lab Not Implemented",
                "description": f"Lab {lab_id} scoring tests pending implementation",
                "points": 100,
                "earned": 0,
                "passed": False
            }]
        )
    return scorer


# Lab scorers registry
LAB_SCORERS = {
    "11": score_lab11,
    "12": score_lab12,
    "13": create_placeholder_scorer("13", "Memory Forensics AI"),
    "14": create_placeholder_scorer("14", "Log Analysis Pipeline"),
    "15": create_placeholder_scorer("15", "Threat Hunting Agent"),
    "16": create_placeholder_scorer("16", "Malware Analysis AI"),
    "17": create_placeholder_scorer("17", "Vulnerability Scanner"),
    "18": create_placeholder_scorer("18", "Red Team Assistant"),
    "19": create_placeholder_scorer("19", "Blue Team Dashboard"),
    "20": create_placeholder_scorer("20", "C2 Detection ML"),
}


# =============================================================================
# Display Functions
# =============================================================================

def print_result(result: ScoringResult, verbose: bool = False) -> None:
    """Print scoring result."""
    percentage = (result.earned_points / result.total_points * 100) if result.total_points > 0 else 0

    if RICH_AVAILABLE:
        # Grade color
        if percentage >= 90:
            grade_color = "green"
            grade = "A"
        elif percentage >= 80:
            grade_color = "blue"
            grade = "B"
        elif percentage >= 70:
            grade_color = "yellow"
            grade = "C"
        elif percentage >= 60:
            grade_color = "orange1"
            grade = "D"
        else:
            grade_color = "red"
            grade = "F"

        console.print(f"\n[bold]Lab {result.lab_id}: {result.lab_name}[/bold]")
        console.print(
            f"  Score: [{grade_color}]{result.earned_points}/{result.total_points}[/{grade_color}] "
            f"({percentage:.0f}%) - Grade: [{grade_color}]{grade}[/{grade_color}]"
        )
        console.print(f"  Tests: {result.tests_passed}/{result.tests_total} passed")

        if verbose and result.details:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Test")
            table.add_column("Points")
            table.add_column("Status")

            for detail in result.details:
                status = "[green]PASS[/green]" if detail["passed"] else "[red]FAIL[/red]"
                pts = f"{detail['earned']}/{detail['points']}"
                table.add_row(detail["name"], pts, status)

            console.print(table)
    else:
        print(f"\nLab {result.lab_id}: {result.lab_name}")
        print(f"  Score: {result.earned_points}/{result.total_points} ({percentage:.0f}%)")
        print(f"  Tests: {result.tests_passed}/{result.tests_total} passed")

        if verbose and result.details:
            for detail in result.details:
                status = "PASS" if detail["passed"] else "FAIL"
                print(f"    [{status}] {detail['name']} ({detail['earned']}/{detail['points']})")


def print_summary(results: List[ScoringResult]) -> None:
    """Print summary of all results."""
    total_earned = sum(r.earned_points for r in results)
    total_possible = sum(r.total_points for r in results)
    total_passed = sum(r.tests_passed for r in results)
    total_tests = sum(r.tests_total for r in results)

    if RICH_AVAILABLE:
        console.print("\n" + "=" * 60)
        console.print("[bold]Overall Summary[/bold]")
        console.print(f"  Total Score: {total_earned}/{total_possible}")
        console.print(f"  Tests Passed: {total_passed}/{total_tests}")
    else:
        print("\n" + "=" * 60)
        print("Overall Summary")
        print(f"  Total Score: {total_earned}/{total_possible}")
        print(f"  Tests Passed: {total_passed}/{total_tests}")


def main():
    """Run the scoring system."""
    parser = argparse.ArgumentParser(description="Score AI for the Win labs")
    parser.add_argument(
        "--lab",
        type=str,
        help="Score specific lab (e.g., --lab 11)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed test results"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )

    args = parser.parse_args()

    if args.lab:
        lab_id = args.lab.zfill(2) if len(args.lab) == 1 else args.lab
        if lab_id not in LAB_SCORERS:
            print(f"No scorer available for Lab {lab_id}")
            print(f"Available labs: {', '.join(sorted(LAB_SCORERS.keys()))}")
            sys.exit(1)

        result = LAB_SCORERS[lab_id]()
        results = [result]
    else:
        # Score all available labs
        results = []
        for lab_id in sorted(LAB_SCORERS.keys()):
            result = LAB_SCORERS[lab_id]()
            results.append(result)

    if args.json:
        output = [{
            "lab_id": r.lab_id,
            "lab_name": r.lab_name,
            "total_points": r.total_points,
            "earned_points": r.earned_points,
            "tests_passed": r.tests_passed,
            "tests_total": r.tests_total,
            "details": r.details
        } for r in results]
        print(json.dumps(output, indent=2))
    else:
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                "[bold]AI for the Win - Lab Scoring System[/bold]",
                border_style="blue"
            ))

        for result in results:
            print_result(result, verbose=args.verbose)

        if len(results) > 1:
            print_summary(results)


if __name__ == "__main__":
    main()

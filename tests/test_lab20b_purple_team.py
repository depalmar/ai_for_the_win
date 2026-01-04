"""Tests for Lab 20b: AI-Assisted Purple Team."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab20b-purple-team-ai" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        AttackPhase,
        AttackScenario,
        AttackSimulator,
        AttackTechnique,
        DetectionGapAnalyzer,
        PurpleTeamReporter,
    )


def test_attack_simulator_initialization():
    """Test attack simulator initializes with techniques."""
    from main import AttackSimulator

    simulator = AttackSimulator()

    assert len(simulator.technique_library) > 0
    assert "T1059.001" in simulator.technique_library  # PowerShell


def test_generate_scenario():
    """Test attack scenario generation."""
    from main import AttackSimulator

    simulator = AttackSimulator()

    scenario = simulator.generate_scenario(
        threat_actor="APT29",
        objective="Credential theft",
        techniques=["T1059.001", "T1003.001"],
    )

    assert scenario.name == "APT29 Simulation"
    assert len(scenario.techniques) == 2
    assert len(scenario.expected_detections) > 0


def test_gap_analyzer():
    """Test detection gap analysis."""
    from main import DetectionGapAnalyzer, DetectionRule

    analyzer = DetectionGapAnalyzer()

    rules = [
        DetectionRule("R001", "PowerShell Detection", ["T1059.001"]),
    ]

    analysis = analyzer.analyze_coverage(rules)

    assert analysis.coverage_percentage > 0
    assert analysis.total_techniques > 0


def test_gap_analyzer_identifies_gaps():
    """Test that analyzer identifies gaps correctly."""
    from main import DetectionGapAnalyzer, DetectionRule

    analyzer = DetectionGapAnalyzer()

    # Only covering one technique
    rules = [
        DetectionRule("R001", "PowerShell Detection", ["T1059.001"]),
    ]

    analysis = analyzer.analyze_coverage(rules)

    # Should identify gaps for techniques not covered
    assert len(analysis.critical_gaps) > 0


def test_purple_team_reporter():
    """Test purple team report generation."""
    from main import FindingSeverity, PurpleTeamFinding, PurpleTeamReporter

    reporter = PurpleTeamReporter()

    findings = [
        PurpleTeamFinding(
            id="F001",
            title="PowerShell Bypass",
            severity=FindingSeverity.HIGH,
            technique_id="T1059.001",
            detection_result="detected",
            recommendations=[],
        ),
        PurpleTeamFinding(
            id="F002",
            title="LSASS Access",
            severity=FindingSeverity.CRITICAL,
            technique_id="T1003.001",
            detection_result="not_detected",
            recommendations=["Add Sysmon monitoring"],
        ),
    ]

    report = reporter.generate_report("Q1 2026 Exercise", findings)

    assert report["detection_rate"] == 50.0
    assert "critical_gaps" in report
    assert len(report["critical_gaps"]) == 1  # One not detected


def test_attack_phase_enum():
    """Test AttackPhase enumeration."""
    from main import AttackPhase

    assert AttackPhase.EXECUTION.value == "execution"
    assert AttackPhase.CREDENTIAL_ACCESS.value == "credential_access"


def test_finding_severity_enum():
    """Test FindingSeverity enumeration."""
    from main import FindingSeverity

    assert FindingSeverity.CRITICAL.value == "critical"
    assert FindingSeverity.HIGH.value == "high"

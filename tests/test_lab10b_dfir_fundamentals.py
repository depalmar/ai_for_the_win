"""Tests for Lab 10b: DFIR Fundamentals."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab10b-dfir-fundamentals" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        SAMPLE_PROCESSES,
        Finding,
        Severity,
        analyze_files,
        analyze_network,
        analyze_processes,
        generate_report,
        map_to_attack,
    )


def test_severity_enum():
    """Test severity levels are defined."""
    from main import Severity

    assert Severity.CRITICAL.value.startswith("🔴")
    assert Severity.HIGH.value.startswith("🟠")
    assert Severity.MEDIUM.value.startswith("🟡")
    assert Severity.LOW.value.startswith("🟢")


def test_finding_dataclass():
    """Test Finding dataclass works."""
    from main import Finding, Severity

    finding = Finding(
        severity=Severity.CRITICAL,
        category="process",
        description="Test finding",
        evidence="Some evidence",
    )

    assert finding.severity == Severity.CRITICAL
    assert finding.category == "process"


def test_process_analysis_detects_office_shell():
    """Test that Office spawning shell is detected."""
    from main import analyze_processes

    processes = [
        {
            "pid": 100,
            "name": "powershell.exe",
            "parent": "WINWORD.EXE",
            "path": "C:\\Windows\\System32\\powershell.exe",
            "cmdline": "powershell.exe",
        }
    ]

    findings = analyze_processes(processes)
    assert len(findings) > 0
    assert any(
        "office" in f.description.lower() or "spawn" in f.description.lower() for f in findings
    )


def test_process_analysis_detects_masquerading():
    """Test that masquerading is detected."""
    from main import analyze_processes

    processes = [
        {
            "pid": 100,
            "name": "svchost.exe",
            "parent": "cmd.exe",
            "path": "C:\\Users\\Public\\svchost.exe",
            "cmdline": "svchost.exe",
        }
    ]

    findings = analyze_processes(processes)
    assert len(findings) > 0
    assert any("masquerad" in f.description.lower() for f in findings)


def test_file_analysis_detects_temp_exe():
    """Test that executables in temp are detected."""
    from main import analyze_files

    files = [{"path": "C:\\Windows\\Temp\\malware.exe", "size": 100000, "created": "2024-01-15"}]

    findings = analyze_files(files)
    assert len(findings) > 0


def test_network_analysis_detects_suspicious_port():
    """Test that suspicious ports are detected."""
    from main import analyze_network

    connections = [
        {"pid": 100, "local": "192.168.1.1:49000", "remote": "1.2.3.4:4444", "state": "ESTABLISHED"}
    ]

    findings = analyze_network(connections)
    assert len(findings) > 0
    assert any("4444" in f.description or "suspicious" in f.description.lower() for f in findings)


def test_attack_mapping():
    """Test ATT&CK technique mapping."""
    from main import Finding, Severity, map_to_attack

    finding = Finding(
        severity=Severity.CRITICAL,
        category="process",
        description="Encoded PowerShell command detected",
        evidence="powershell -enc ABC",
    )

    mapped = map_to_attack(finding)
    assert mapped.technique_id == "T1059.001"


def test_report_generation():
    """Test report generation."""
    from main import Finding, Severity, generate_report

    findings = [
        Finding(Severity.CRITICAL, "process", "Test finding 1"),
        Finding(Severity.HIGH, "network", "Test finding 2"),
    ]

    report = generate_report(findings)

    assert "DFIR" in report or "Report" in report
    assert "CRITICAL" in report
    assert "process" in report.lower() or "PROCESS" in report

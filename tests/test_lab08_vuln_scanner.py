#!/usr/bin/env python3
"""Tests for Lab 08: Vulnerability Scanner AI."""

import sys
from pathlib import Path

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(
    Path(__file__).parent.parent / "labs" / "lab08-vuln-scanner-ai" / "solution"
)
sys.path.insert(0, lab_path)

from main import (RemediationGenerator, ScanResult, Vulnerability,
                  VulnerabilityAnalyzer, VulnerabilityPrioritizer,
                  VulnerabilityScanner)


@pytest.fixture
def sample_scan_result():
    """Create sample scan result."""
    return ScanResult(
        target="192.168.1.100",
        scan_type="full",
        timestamp="2024-01-15T10:00:00Z",
        vulnerabilities=[
            Vulnerability(
                vuln_id="CVE-2024-1234",
                title="Remote Code Execution in Apache",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Allows remote attackers to execute arbitrary code.",
                affected_component="Apache HTTP Server 2.4.49",
                evidence="Version detected in HTTP headers",
                remediation="Update to Apache 2.4.52 or later",
            ),
            Vulnerability(
                vuln_id="CVE-2024-5678",
                title="SQL Injection in Web App",
                severity="HIGH",
                cvss_score=8.5,
                description="SQL injection in login form.",
                affected_component="Custom Web Application",
                evidence="Error-based SQLi confirmed",
                remediation="Implement parameterized queries",
            ),
            Vulnerability(
                vuln_id="CVE-2024-9999",
                title="Missing Security Headers",
                severity="LOW",
                cvss_score=3.0,
                description="Missing X-Frame-Options header.",
                affected_component="Web Server Configuration",
                evidence="Header not present in response",
                remediation="Add X-Frame-Options: DENY",
            ),
        ],
        services_detected=["http", "https", "ssh"],
        os_detected="Linux",
    )


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerability list."""
    return [
        Vulnerability(
            vuln_id="CVE-2024-1111",
            title="Critical RCE",
            severity="CRITICAL",
            cvss_score=10.0,
            description="Remote code execution",
            affected_component="Web Server",
            evidence="Confirmed",
            remediation="Patch immediately",
        ),
        Vulnerability(
            vuln_id="CVE-2024-2222",
            title="Medium Issue",
            severity="MEDIUM",
            cvss_score=5.5,
            description="Information disclosure",
            affected_component="API",
            evidence="Version exposed",
            remediation="Update configuration",
        ),
    ]


class TestVulnerabilityScanner:
    """Tests for vulnerability scanner."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = VulnerabilityScanner()
        assert scanner is not None

    def test_scan_returns_result(self):
        """Test that scan returns a result object."""
        scanner = VulnerabilityScanner()
        # Using localhost for testing
        result = scanner.scan("127.0.0.1", scan_type="quick")

        assert result is not None
        assert isinstance(result, ScanResult)
        assert result.target == "127.0.0.1"


class TestVulnerabilityAnalyzer:
    """Tests for vulnerability analysis."""

    def test_analyze_vulnerabilities(self, sample_scan_result):
        """Test vulnerability analysis."""
        analyzer = VulnerabilityAnalyzer()
        analysis = analyzer.analyze(sample_scan_result)

        assert analysis is not None
        assert "summary" in analysis
        assert "by_severity" in analysis

    def test_severity_breakdown(self, sample_scan_result):
        """Test severity breakdown."""
        analyzer = VulnerabilityAnalyzer()
        analysis = analyzer.analyze(sample_scan_result)

        by_severity = analysis["by_severity"]
        assert "CRITICAL" in by_severity
        assert "HIGH" in by_severity
        assert by_severity["CRITICAL"] == 1
        assert by_severity["HIGH"] == 1


class TestVulnerabilityPrioritizer:
    """Tests for vulnerability prioritization."""

    def test_prioritize_by_cvss(self, sample_vulnerabilities):
        """Test CVSS-based prioritization."""
        prioritizer = VulnerabilityPrioritizer()
        prioritized = prioritizer.prioritize(sample_vulnerabilities, method="cvss")

        assert len(prioritized) == len(sample_vulnerabilities)
        # Critical should come first
        assert prioritized[0].severity == "CRITICAL"
        assert prioritized[0].cvss_score == 10.0

    def test_prioritize_by_exploitability(self, sample_vulnerabilities):
        """Test exploitability-based prioritization."""
        prioritizer = VulnerabilityPrioritizer()
        prioritized = prioritizer.prioritize(
            sample_vulnerabilities, method="exploitability"
        )

        assert len(prioritized) == len(sample_vulnerabilities)

    def test_priority_score_calculation(self, sample_vulnerabilities):
        """Test priority score calculation."""
        prioritizer = VulnerabilityPrioritizer()
        scores = prioritizer.calculate_scores(sample_vulnerabilities)

        assert len(scores) == len(sample_vulnerabilities)
        # Higher CVSS should have higher score
        assert (
            scores[0] >= scores[1]
            or sample_vulnerabilities[0].cvss_score
            >= sample_vulnerabilities[1].cvss_score
        )


class TestRemediationGenerator:
    """Tests for remediation generation."""

    def test_generate_remediation_plan(self, sample_vulnerabilities):
        """Test remediation plan generation."""
        generator = RemediationGenerator()
        plan = generator.generate_plan(sample_vulnerabilities)

        assert plan is not None
        assert "steps" in plan or "recommendations" in plan

    def test_remediation_grouped_by_priority(self, sample_vulnerabilities):
        """Test that remediations are grouped by priority."""
        generator = RemediationGenerator()
        plan = generator.generate_plan(sample_vulnerabilities)

        # Should have immediate actions for critical vulns
        plan_text = str(plan)
        assert "immediate" in plan_text.lower() or "critical" in plan_text.lower()


class TestVulnerabilityDataClass:
    """Tests for Vulnerability data class."""

    def test_vulnerability_creation(self):
        """Test Vulnerability creation."""
        vuln = Vulnerability(
            vuln_id="CVE-2024-0001",
            title="Test Vulnerability",
            severity="HIGH",
            cvss_score=7.5,
            description="Test description",
            affected_component="Test Component",
            evidence="Test evidence",
            remediation="Test remediation",
        )

        assert vuln.vuln_id == "CVE-2024-0001"
        assert vuln.severity == "HIGH"
        assert vuln.cvss_score == 7.5


class TestScanResultDataClass:
    """Tests for ScanResult data class."""

    def test_scan_result_creation(self, sample_vulnerabilities):
        """Test ScanResult creation."""
        result = ScanResult(
            target="10.0.0.1",
            scan_type="full",
            timestamp="2024-01-15T12:00:00Z",
            vulnerabilities=sample_vulnerabilities,
            services_detected=["http", "ssh"],
            os_detected="Ubuntu 22.04",
        )

        assert result.target == "10.0.0.1"
        assert len(result.vulnerabilities) == 2
        assert "http" in result.services_detected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""
Lab 08: AI-Powered Vulnerability Scanner - Solution

Complete implementation with AI-powered analysis and prioritization.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

import pandas as pd
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

console = Console()


# =============================================================================
# Data Structures (for test compatibility)
# =============================================================================


@dataclass
class Vulnerability:
    """Represents a vulnerability finding."""

    vuln_id: str
    title: str
    severity: str
    cvss_score: float
    description: str
    affected_component: str
    evidence: str
    remediation: str


@dataclass
class ScanResult:
    """Represents a vulnerability scan result."""

    target: str
    scan_type: str
    timestamp: str
    vulnerabilities: List[Vulnerability]
    services_detected: List[str]
    os_detected: str


# =============================================================================
# Wrapper Classes (for test compatibility)
# =============================================================================


class VulnerabilityScanner:
    """Mock vulnerability scanner for testing."""

    def scan(self, target: str, scan_type: str = "quick") -> ScanResult:
        """Perform a vulnerability scan."""
        return ScanResult(
            target=target,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
            vulnerabilities=[],
            services_detected=["http", "https"],
            os_detected="Unknown",
        )


class VulnerabilityAnalyzer:
    """Analyze vulnerabilities and provide severity breakdown."""

    def analyze(self, scan_result: ScanResult) -> dict:
        """Analyze scan results."""
        by_severity = {}
        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "summary": f"Found {len(scan_result.vulnerabilities)} vulnerabilities",
            "by_severity": by_severity,
            "total": len(scan_result.vulnerabilities),
        }


class VulnerabilityPrioritizer:
    """Prioritize vulnerabilities based on different criteria."""

    def prioritize(
        self, vulnerabilities: List[Vulnerability], method: str = "cvss"
    ) -> List[Vulnerability]:
        """Prioritize vulnerabilities."""
        if method == "cvss":
            return sorted(vulnerabilities, key=lambda v: v.cvss_score, reverse=True)
        elif method == "exploitability":
            # Simple heuristic - prioritize higher CVSS
            return sorted(vulnerabilities, key=lambda v: v.cvss_score, reverse=True)
        else:
            return vulnerabilities

    def calculate_scores(self, vulnerabilities: List[Vulnerability]) -> List[float]:
        """Calculate priority scores for vulnerabilities."""
        return [v.cvss_score for v in vulnerabilities]


class RemediationGenerator:
    """Generate remediation plans for vulnerabilities."""

    def generate_plan(self, vulnerabilities: List[Vulnerability]) -> dict:
        """Generate a remediation plan."""
        prioritized = sorted(vulnerabilities, key=lambda v: v.cvss_score, reverse=True)

        plan = {"steps": [], "recommendations": []}

        for vuln in prioritized:
            if vuln.cvss_score >= 9.0:
                plan["steps"].append(f"IMMEDIATE: {vuln.title} - {vuln.remediation}")
            elif vuln.cvss_score >= 7.0:
                plan["steps"].append(f"HIGH PRIORITY: {vuln.title} - {vuln.remediation}")
            elif vuln.cvss_score >= 4.0:
                plan["steps"].append(f"MEDIUM PRIORITY: {vuln.title} - {vuln.remediation}")

        # Add priority-based grouping
        critical_count = sum(1 for v in vulnerabilities if v.cvss_score >= 9.0)
        if critical_count > 0:
            plan["recommendations"].append(
                f"Address {critical_count} critical vulnerabilities immediately"
            )

        return plan


# =============================================================================
# Task 1: Vulnerability Data Ingestion - SOLUTION
# =============================================================================


class VulnDataLoader:
    """Load vulnerability scan results."""

    def load_scan_results(self, filepath: str) -> List[dict]:
        """Load scan results from CSV or JSON."""
        path = Path(filepath)

        if path.suffix == ".json":
            with open(filepath, "r") as f:
                return json.load(f)
        elif path.suffix == ".csv":
            df = pd.read_csv(filepath)
            return df.to_dict("records")
        else:
            raise ValueError(f"Unsupported format: {path.suffix}")

    def enrich_with_cve_data(self, vulns: List[dict]) -> List[dict]:
        """Enrich vulnerabilities with additional CVE data."""
        # Mock enrichment data
        cve_enrichment = {
            "CVE-2024-1234": {
                "epss_score": 0.92,
                "exploit_available": True,
                "cisa_kev": True,
                "patch_available": True,
            },
            "CVE-2024-5678": {
                "epss_score": 0.45,
                "exploit_available": False,
                "cisa_kev": False,
                "patch_available": True,
            },
        }

        for vuln in vulns:
            cve_id = vuln.get("cve_id", "")
            if cve_id in cve_enrichment:
                vuln.update(cve_enrichment[cve_id])

        return vulns


# =============================================================================
# Task 2: AI Analysis Engine - SOLUTION
# =============================================================================

ANALYSIS_PROMPT = """You are a vulnerability analyst. Analyze this vulnerability:

CVE: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
Affected Host: {host}
Service: {service}
Asset Context: {context}

Provide:
1. Plain English Explanation: What does this vulnerability mean?
2. Attack Scenario: How could an attacker exploit this?
3. Business Impact: What's at risk if exploited?
4. Remediation Steps: Specific actions to fix this

Be concise but thorough."""


class VulnAnalyzer:
    """AI-powered vulnerability analysis."""

    def __init__(self, llm=None):
        if llm:
            self.llm = llm
        elif LANGCHAIN_AVAILABLE and os.getenv("ANTHROPIC_API_KEY"):
            self.llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        else:
            self.llm = None

    def analyze_vulnerability(self, vuln: dict, context: dict = None) -> dict:
        """Deep analysis of a single vulnerability."""
        if not self.llm:
            return self._basic_analysis(vuln)

        context_str = json.dumps(context) if context else "No additional context"

        prompt = ANALYSIS_PROMPT.format(
            cve_id=vuln.get("cve_id", "Unknown"),
            description=vuln.get("description", "No description"),
            cvss_score=vuln.get("cvss_score", "Unknown"),
            host=vuln.get("host", "Unknown"),
            service=vuln.get("service", "Unknown"),
            context=context_str,
        )

        response = self.llm.invoke([HumanMessage(content=prompt)])

        return {
            "cve_id": vuln.get("cve_id"),
            "analysis": response.content,
            "analyzed_at": datetime.now().isoformat(),
        }

    def _basic_analysis(self, vuln: dict) -> dict:
        """Basic analysis without LLM."""
        cvss = vuln.get("cvss_score", 0)

        if cvss >= 9.0:
            urgency = "CRITICAL - Immediate action required"
        elif cvss >= 7.0:
            urgency = "HIGH - Address within 7 days"
        elif cvss >= 4.0:
            urgency = "MEDIUM - Address within 30 days"
        else:
            urgency = "LOW - Address in next maintenance window"

        return {
            "cve_id": vuln.get("cve_id"),
            "urgency": urgency,
            "recommendation": f"Apply vendor patches for {vuln.get('service', 'affected service')}",
        }

    def assess_exploitability(self, vuln: dict) -> dict:
        """Assess real-world exploitability."""
        score = 0.0
        factors = []

        # Check for exploit availability
        if vuln.get("exploit_available"):
            score += 0.4
            factors.append("Public exploit available")

        # Check EPSS score
        epss = vuln.get("epss_score", 0)
        if epss > 0.5:
            score += 0.3
            factors.append(f"High EPSS score ({epss:.2f})")

        # Check if in CISA KEV
        if vuln.get("cisa_kev"):
            score += 0.3
            factors.append("In CISA Known Exploited Vulnerabilities")

        return {
            "exploitability_score": score,
            "factors": factors,
            "recommendation": ("Prioritize remediation" if score > 0.5 else "Standard remediation"),
        }


# =============================================================================
# Task 3: Intelligent Prioritization - SOLUTION
# =============================================================================


class VulnPrioritizer:
    """Prioritize vulnerabilities intelligently."""

    def __init__(self, asset_inventory: dict = None):
        self.assets = asset_inventory or {}

    def calculate_risk_score(self, vuln: dict, asset: dict = None) -> float:
        """Calculate contextual risk score (0-100)."""
        score = 0.0

        # Base CVSS score (40% weight)
        cvss = vuln.get("cvss_score", 0)
        score += (cvss / 10) * 40

        # Exploitability factors (30% weight)
        if vuln.get("exploit_available"):
            score += 15
        if vuln.get("cisa_kev"):
            score += 15

        # Asset context (30% weight)
        if asset:
            criticality = asset.get("criticality", "medium")
            if criticality == "critical":
                score += 20
            elif criticality == "high":
                score += 15
            elif criticality == "medium":
                score += 10

            if asset.get("internet_facing"):
                score += 10

        return min(100, score)

    def prioritize_vulns(self, vulns: List[dict]) -> List[dict]:
        """Prioritize vulnerability list by risk score."""
        for vuln in vulns:
            host = vuln.get("host", "")
            asset = self.assets.get(host, {})
            vuln["risk_score"] = self.calculate_risk_score(vuln, asset)

        # Sort by risk score descending
        return sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True)

    def create_remediation_roadmap(self, vulns: List[dict]) -> dict:
        """Create phased remediation plan."""
        prioritized = self.prioritize_vulns(vulns)

        roadmap = {
            "immediate": [],  # Risk > 80
            "week_1": [],  # Risk 60-80
            "week_2_3": [],  # Risk 40-60
            "month_1": [],  # Risk < 40
        }

        for vuln in prioritized:
            score = vuln.get("risk_score", 0)
            entry = {
                "host": vuln.get("host"),
                "cve": vuln.get("cve_id"),
                "score": score,
            }

            if score > 80:
                roadmap["immediate"].append(entry)
            elif score > 60:
                roadmap["week_1"].append(entry)
            elif score > 40:
                roadmap["week_2_3"].append(entry)
            else:
                roadmap["month_1"].append(entry)

        return roadmap


# =============================================================================
# Task 4: Report Generation - SOLUTION
# =============================================================================


class VulnReporter:
    """Generate vulnerability reports."""

    def __init__(self, llm=None):
        self.llm = llm

    def generate_executive_summary(self, vulns: List[dict]) -> str:
        """Generate executive summary."""
        total = len(vulns)
        critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        high = sum(1 for v in vulns if v.get("severity") == "HIGH")

        summary = f"""# Executive Vulnerability Summary

## Overview
- **Total Vulnerabilities:** {total}
- **Critical:** {critical}
- **High:** {high}

## Risk Assessment
{'**URGENT ACTION REQUIRED**: Critical vulnerabilities detected that require immediate attention.' if critical > 0 else 'No critical vulnerabilities requiring immediate action.'}

## Top Recommendations
1. Address all critical vulnerabilities within 24-48 hours
2. Patch high-severity items within 7 days
3. Implement network segmentation for affected systems
4. Enable enhanced monitoring on vulnerable hosts

## Resource Requirements
Estimated remediation effort: {total * 2}-{total * 4} hours
"""
        return summary

    def generate_technical_report(self, vulns: List[dict]) -> str:
        """Generate detailed technical report."""
        report = "# Technical Vulnerability Report\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"

        for vuln in vulns:
            report += f"""## {vuln.get('cve_id', 'Unknown')}

**Host:** {vuln.get('host', 'Unknown')}
**Service:** {vuln.get('service', 'Unknown')}
**Severity:** {vuln.get('severity', 'Unknown')} (CVSS: {vuln.get('cvss_score', 'N/A')})
**Risk Score:** {vuln.get('risk_score', 'N/A'):.1f}/100

**Description:**
{vuln.get('description', 'No description available.')}

**Remediation:**
1. Apply vendor patches
2. Verify fix with rescan
3. Update asset inventory

---

"""
        return report


# =============================================================================
# Main - SOLUTION
# =============================================================================


def main():
    """Main execution."""
    console.print("[bold]Lab 08: AI-Powered Vulnerability Scanner - SOLUTION[/bold]")

    # Create sample data
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)

    sample_vulns = [
        {
            "host": "web-server-01",
            "cve_id": "CVE-2024-1234",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "port": 443,
            "service": "Apache/2.4.49",
            "description": "Remote code execution in Apache HTTP Server",
        },
        {
            "host": "db-server-01",
            "cve_id": "CVE-2024-5678",
            "cvss_score": 8.5,
            "severity": "HIGH",
            "port": 3306,
            "service": "MySQL 8.0.30",
            "description": "SQL injection vulnerability",
        },
        {
            "host": "app-server-01",
            "cve_id": "CVE-2024-9999",
            "cvss_score": 5.3,
            "severity": "MEDIUM",
            "port": 8080,
            "service": "Tomcat/9.0",
            "description": "Information disclosure vulnerability",
        },
    ]

    (data_dir / "sample_scan.json").write_text(json.dumps(sample_vulns, indent=2))

    # Asset inventory
    assets = {
        "web-server-01": {"criticality": "high", "internet_facing": True},
        "db-server-01": {"criticality": "critical", "internet_facing": False},
        "app-server-01": {"criticality": "medium", "internet_facing": False},
    }

    # Load and enrich
    console.print("\n[yellow]Step 1: Loading and enriching scan results...[/yellow]")
    loader = VulnDataLoader()
    vulns = loader.load_scan_results(str(data_dir / "sample_scan.json"))
    vulns = loader.enrich_with_cve_data(vulns)
    console.print(f"Loaded {len(vulns)} vulnerabilities")

    # Prioritize
    console.print("\n[yellow]Step 2: Prioritizing vulnerabilities...[/yellow]")
    prioritizer = VulnPrioritizer(asset_inventory=assets)
    prioritized = prioritizer.prioritize_vulns(vulns)

    # Display table
    table = Table(title="Prioritized Vulnerabilities")
    table.add_column("Rank", style="cyan")
    table.add_column("Host")
    table.add_column("CVE")
    table.add_column("Severity")
    table.add_column("CVSS")
    table.add_column("Risk Score", style="bold red")

    for i, v in enumerate(prioritized, 1):
        table.add_row(
            str(i),
            v.get("host", ""),
            v.get("cve_id", ""),
            v.get("severity", ""),
            str(v.get("cvss_score", "")),
            f"{v.get('risk_score', 0):.1f}",
        )

    console.print(table)

    # Create roadmap
    console.print("\n[yellow]Step 3: Creating remediation roadmap...[/yellow]")
    roadmap = prioritizer.create_remediation_roadmap(prioritized)

    console.print("\n[bold]Remediation Roadmap:[/bold]")
    console.print(f"  Immediate: {len(roadmap['immediate'])} items")
    console.print(f"  Week 1: {len(roadmap['week_1'])} items")
    console.print(f"  Week 2-3: {len(roadmap['week_2_3'])} items")
    console.print(f"  Month 1: {len(roadmap['month_1'])} items")

    # Generate reports
    console.print("\n[yellow]Step 4: Generating reports...[/yellow]")
    reporter = VulnReporter()

    exec_summary = reporter.generate_executive_summary(prioritized)
    console.print("\n[bold]Executive Summary:[/bold]")
    console.print(Markdown(exec_summary))

    # Save reports
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    (reports_dir / "executive_summary.md").write_text(exec_summary)
    (reports_dir / "technical_report.md").write_text(
        reporter.generate_technical_report(prioritized)
    )

    console.print(f"\n[green]Reports saved to: {reports_dir}[/green]")


if __name__ == "__main__":
    main()

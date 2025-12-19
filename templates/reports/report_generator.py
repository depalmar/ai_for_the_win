#!/usr/bin/env python3
"""
Security Report Generator

Generate professional PDF, HTML, and Markdown reports for:
- Incident Response
- Threat Intelligence
- Vulnerability Assessment
- Detection Analysis
- Ransomware Incidents
"""

import os
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
from enum import Enum

# Optional imports for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, ListFlowable, ListItem
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Optional imports for charts
try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class ReportFormat(Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReportSection:
    """A section in the report."""
    title: str
    content: str
    level: int = 2
    subsections: List['ReportSection'] = field(default_factory=list)


@dataclass
class TableData:
    """Table data for reports."""
    headers: List[str]
    rows: List[List[str]]
    title: Optional[str] = None


@dataclass
class ChartData:
    """Chart data for reports."""
    chart_type: str  # pie, bar, line, heatmap
    title: str
    data: Dict[str, Any]
    filename: Optional[str] = None


@dataclass
class Finding:
    """A security finding."""
    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str
    mitre_technique: Optional[str] = None
    cve_id: Optional[str] = None


@dataclass
class ReportMetadata:
    """Report metadata."""
    title: str
    author: str = "Security Team"
    date: datetime = field(default_factory=datetime.now)
    classification: str = "CONFIDENTIAL"
    version: str = "1.0"
    organization: str = ""


# =============================================================================
# Base Report Generator
# =============================================================================

class BaseReportGenerator(ABC):
    """Abstract base class for report generators."""

    def __init__(self, metadata: ReportMetadata):
        self.metadata = metadata
        self.sections: List[ReportSection] = []
        self.tables: List[TableData] = []
        self.charts: List[ChartData] = []
        self.findings: List[Finding] = []

    def add_section(self, section: ReportSection):
        """Add a section to the report."""
        self.sections.append(section)

    def add_table(self, table: TableData):
        """Add a table to the report."""
        self.tables.append(table)

    def add_chart(self, chart: ChartData):
        """Add a chart to the report."""
        self.charts.append(chart)

    def add_finding(self, finding: Finding):
        """Add a security finding."""
        self.findings.append(finding)

    @abstractmethod
    def generate(self, output_path: str) -> str:
        """Generate the report."""
        pass


# =============================================================================
# Markdown Report Generator
# =============================================================================

class MarkdownReportGenerator(BaseReportGenerator):
    """Generate Markdown reports."""

    def generate(self, output_path: str) -> str:
        """Generate Markdown report."""
        lines = []

        # Title and metadata
        lines.append(f"# {self.metadata.title}")
        lines.append("")
        lines.append(f"**Author:** {self.metadata.author}")
        lines.append(f"**Date:** {self.metadata.date.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"**Classification:** {self.metadata.classification}")
        lines.append(f"**Version:** {self.metadata.version}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary if findings exist
        if self.findings:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(self._generate_executive_summary())
            lines.append("")

        # Findings summary table
        if self.findings:
            lines.append("## Findings Overview")
            lines.append("")
            lines.append("| # | Severity | Title | MITRE |")
            lines.append("|---|----------|-------|-------|")
            for i, f in enumerate(self.findings, 1):
                severity_icon = self._severity_icon(f.severity)
                mitre = f.mitre_technique or "N/A"
                lines.append(f"| {i} | {severity_icon} {f.severity.value.upper()} | {f.title} | {mitre} |")
            lines.append("")

        # Sections
        for section in self.sections:
            lines.extend(self._render_section(section))

        # Tables
        for table in self.tables:
            lines.extend(self._render_table(table))

        # Detailed Findings
        if self.findings:
            lines.append("## Detailed Findings")
            lines.append("")
            for i, finding in enumerate(self.findings, 1):
                lines.extend(self._render_finding(i, finding))

        # Write to file
        content = "\n".join(lines)
        with open(output_path, 'w') as f:
            f.write(content)

        return output_path

    def _generate_executive_summary(self) -> str:
        """Generate executive summary from findings."""
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)

        return f"""This assessment identified **{len(self.findings)} findings**:
- 🔴 Critical: {critical}
- 🟠 High: {high}
- 🟡 Medium: {medium}
- 🟢 Low: {low}

{"**Immediate action required** due to critical findings." if critical > 0 else "No critical findings identified."}"""

    def _severity_icon(self, severity: Severity) -> str:
        """Get severity icon."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵"
        }
        return icons.get(severity, "⚪")

    def _render_section(self, section: ReportSection) -> List[str]:
        """Render a section to Markdown."""
        lines = []
        prefix = "#" * section.level
        lines.append(f"{prefix} {section.title}")
        lines.append("")
        lines.append(section.content)
        lines.append("")

        for subsection in section.subsections:
            lines.extend(self._render_section(subsection))

        return lines

    def _render_table(self, table: TableData) -> List[str]:
        """Render a table to Markdown."""
        lines = []
        if table.title:
            lines.append(f"### {table.title}")
            lines.append("")

        # Header
        lines.append("| " + " | ".join(table.headers) + " |")
        lines.append("|" + "|".join(["---"] * len(table.headers)) + "|")

        # Rows
        for row in table.rows:
            lines.append("| " + " | ".join(str(cell) for cell in row) + " |")

        lines.append("")
        return lines

    def _render_finding(self, num: int, finding: Finding) -> List[str]:
        """Render a finding to Markdown."""
        lines = []
        icon = self._severity_icon(finding.severity)

        lines.append(f"### Finding {num}: {finding.title}")
        lines.append("")
        lines.append(f"**Severity:** {icon} {finding.severity.value.upper()}")
        if finding.mitre_technique:
            lines.append(f"**MITRE ATT&CK:** {finding.mitre_technique}")
        if finding.cve_id:
            lines.append(f"**CVE:** {finding.cve_id}")
        lines.append("")
        lines.append("**Description:**")
        lines.append(finding.description)
        lines.append("")
        lines.append("**Evidence:**")
        lines.append(f"```\n{finding.evidence}\n```")
        lines.append("")
        lines.append("**Recommendation:**")
        lines.append(finding.recommendation)
        lines.append("")
        lines.append("---")
        lines.append("")

        return lines


# =============================================================================
# HTML Report Generator
# =============================================================================

class HTMLReportGenerator(BaseReportGenerator):
    """Generate HTML reports with styling."""

    CSS_STYLES = """
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .metadata span { margin-right: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; }
        tr:hover { background: #f5f5f5; }
        .finding { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin: 20px 0; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #e67e22; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .info { border-left: 5px solid #3498db; }
        .severity-badge { display: inline-block; padding: 3px 10px; border-radius: 3px; color: white; font-size: 12px; }
        .severity-critical { background: #e74c3c; }
        .severity-high { background: #e67e22; }
        .severity-medium { background: #f1c40f; color: #333; }
        .severity-low { background: #27ae60; }
        .severity-info { background: #3498db; }
        code { background: #2c3e50; color: #ecf0f1; padding: 15px; display: block; border-radius: 5px; overflow-x: auto; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; }
        .summary-item { flex: 1; padding: 20px; border-radius: 5px; text-align: center; }
        .summary-critical { background: #fadbd8; }
        .summary-high { background: #fdebd0; }
        .summary-medium { background: #fcf3cf; }
        .summary-low { background: #d5f5e3; }
        .chart-container { margin: 20px 0; text-align: center; }
    </style>
    """

    def generate(self, output_path: str) -> str:
        """Generate HTML report."""
        html = []

        # Header
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("<meta charset='UTF-8'>")
        html.append(f"<title>{self.metadata.title}</title>")
        html.append(self.CSS_STYLES)
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='container'>")

        # Title and metadata
        html.append(f"<h1>{self.metadata.title}</h1>")
        html.append("<div class='metadata'>")
        html.append(f"<span><strong>Author:</strong> {self.metadata.author}</span>")
        html.append(f"<span><strong>Date:</strong> {self.metadata.date.strftime('%Y-%m-%d %H:%M')}</span>")
        html.append(f"<span><strong>Classification:</strong> {self.metadata.classification}</span>")
        html.append("</div>")

        # Executive Summary
        if self.findings:
            html.append("<h2>Executive Summary</h2>")
            html.append(self._generate_summary_boxes())

        # Sections
        for section in self.sections:
            html.append(self._render_section_html(section))

        # Tables
        for table in self.tables:
            html.append(self._render_table_html(table))

        # Findings
        if self.findings:
            html.append("<h2>Detailed Findings</h2>")
            for i, finding in enumerate(self.findings, 1):
                html.append(self._render_finding_html(i, finding))

        # Footer
        html.append("</div>")
        html.append("</body>")
        html.append("</html>")

        content = "\n".join(html)
        with open(output_path, 'w') as f:
            f.write(content)

        return output_path

    def _generate_summary_boxes(self) -> str:
        """Generate summary boxes HTML."""
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)

        return f"""
        <div class='summary-box'>
            <div class='summary-item summary-critical'><h3>{critical}</h3><p>Critical</p></div>
            <div class='summary-item summary-high'><h3>{high}</h3><p>High</p></div>
            <div class='summary-item summary-medium'><h3>{medium}</h3><p>Medium</p></div>
            <div class='summary-item summary-low'><h3>{low}</h3><p>Low</p></div>
        </div>
        """

    def _render_section_html(self, section: ReportSection) -> str:
        """Render section to HTML."""
        tag = f"h{section.level}"
        html = f"<{tag}>{section.title}</{tag}>"
        html += f"<p>{section.content}</p>"
        for sub in section.subsections:
            html += self._render_section_html(sub)
        return html

    def _render_table_html(self, table: TableData) -> str:
        """Render table to HTML."""
        html = ""
        if table.title:
            html += f"<h3>{table.title}</h3>"
        html += "<table><thead><tr>"
        for header in table.headers:
            html += f"<th>{header}</th>"
        html += "</tr></thead><tbody>"
        for row in table.rows:
            html += "<tr>"
            for cell in row:
                html += f"<td>{cell}</td>"
            html += "</tr>"
        html += "</tbody></table>"
        return html

    def _render_finding_html(self, num: int, finding: Finding) -> str:
        """Render finding to HTML."""
        severity_class = finding.severity.value
        return f"""
        <div class='finding {severity_class}'>
            <h3>Finding {num}: {finding.title}</h3>
            <span class='severity-badge severity-{severity_class}'>{finding.severity.value.upper()}</span>
            {f"<span style='margin-left:10px'><strong>MITRE:</strong> {finding.mitre_technique}</span>" if finding.mitre_technique else ""}
            <p><strong>Description:</strong> {finding.description}</p>
            <p><strong>Evidence:</strong></p>
            <code>{finding.evidence}</code>
            <p><strong>Recommendation:</strong> {finding.recommendation}</p>
        </div>
        """


# =============================================================================
# Report Templates
# =============================================================================

class IncidentReportTemplate:
    """Template for incident response reports."""

    @staticmethod
    def create(
        incident_id: str,
        incident_type: str,
        summary: str,
        timeline: List[Dict],
        affected_systems: List[str],
        iocs: List[Dict],
        actions_taken: List[str],
        recommendations: List[str],
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> BaseReportGenerator:
        """Create an incident report."""
        metadata = ReportMetadata(
            title=f"Incident Report: {incident_id}",
            classification="CONFIDENTIAL"
        )

        if format == ReportFormat.HTML:
            report = HTMLReportGenerator(metadata)
        else:
            report = MarkdownReportGenerator(metadata)

        # Add sections
        report.add_section(ReportSection(
            title="Incident Summary",
            content=f"**Incident Type:** {incident_type}\n\n{summary}"
        ))

        # Timeline table
        if timeline:
            report.add_table(TableData(
                title="Incident Timeline",
                headers=["Time", "Event", "Source"],
                rows=[[t.get("time", ""), t.get("event", ""), t.get("source", "")] for t in timeline]
            ))

        # Affected systems
        report.add_section(ReportSection(
            title="Affected Systems",
            content="\n".join(f"- {s}" for s in affected_systems)
        ))

        # IOCs table
        if iocs:
            report.add_table(TableData(
                title="Indicators of Compromise",
                headers=["Type", "Value", "Description"],
                rows=[[i.get("type", ""), i.get("value", ""), i.get("description", "")] for i in iocs]
            ))

        # Actions taken
        report.add_section(ReportSection(
            title="Actions Taken",
            content="\n".join(f"{i}. {a}" for i, a in enumerate(actions_taken, 1))
        ))

        # Recommendations
        report.add_section(ReportSection(
            title="Recommendations",
            content="\n".join(f"- {r}" for r in recommendations)
        ))

        return report


class RansomwareReportTemplate:
    """Template for ransomware incident reports."""

    @staticmethod
    def create(
        incident_id: str,
        ransomware_family: str,
        affected_hosts: List[str],
        encrypted_files: int,
        ransom_amount: str,
        bitcoin_addresses: List[str],
        timeline: List[Dict],
        containment_actions: List[str],
        recovery_status: str,
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> BaseReportGenerator:
        """Create a ransomware incident report."""
        metadata = ReportMetadata(
            title=f"Ransomware Incident Report: {incident_id}",
            classification="CONFIDENTIAL - INCIDENT RESPONSE"
        )

        if format == ReportFormat.HTML:
            report = HTMLReportGenerator(metadata)
        else:
            report = MarkdownReportGenerator(metadata)

        # Executive Summary
        report.add_section(ReportSection(
            title="Executive Summary",
            content=f"""A ransomware incident involving **{ransomware_family}** was detected.

**Key Facts:**
- Affected Hosts: {len(affected_hosts)}
- Encrypted Files: {encrypted_files:,}
- Ransom Demand: {ransom_amount}
- Recovery Status: {recovery_status}"""
        ))

        # Add critical finding
        report.add_finding(Finding(
            title=f"{ransomware_family} Ransomware Detected",
            severity=Severity.CRITICAL,
            description=f"Active ransomware encryption detected across {len(affected_hosts)} systems.",
            evidence=f"Encrypted files: {encrypted_files:,}\nBitcoin addresses: {', '.join(bitcoin_addresses[:2])}",
            recommendation="Immediately isolate affected systems and initiate incident response procedures.",
            mitre_technique="T1486 - Data Encrypted for Impact"
        ))

        # Affected hosts
        report.add_table(TableData(
            title="Affected Systems",
            headers=["Hostname", "Status"],
            rows=[[h, "Encrypted"] for h in affected_hosts]
        ))

        # Timeline
        if timeline:
            report.add_table(TableData(
                title="Attack Timeline",
                headers=["Time", "Event", "Details"],
                rows=[[t.get("time", ""), t.get("event", ""), t.get("details", "")] for t in timeline]
            ))

        # IOCs
        report.add_table(TableData(
            title="Indicators of Compromise",
            headers=["Type", "Value"],
            rows=[["Bitcoin Address", addr] for addr in bitcoin_addresses]
        ))

        # Containment actions
        report.add_section(ReportSection(
            title="Containment Actions",
            content="\n".join(f"- [x] {a}" for a in containment_actions)
        ))

        return report


# =============================================================================
# Demo
# =============================================================================

def main():
    """Demo the report generator."""
    print("=" * 60)
    print("Security Report Generator Demo")
    print("=" * 60)

    # Create a sample incident report
    report = IncidentReportTemplate.create(
        incident_id="INC-2024-001",
        incident_type="Ransomware",
        summary="A LockBit ransomware attack was detected affecting multiple systems.",
        timeline=[
            {"time": "2024-01-15 09:15", "event": "Phishing email received", "source": "Email Gateway"},
            {"time": "2024-01-15 09:17", "event": "Malware executed", "source": "EDR"},
            {"time": "2024-01-15 10:30", "event": "Lateral movement detected", "source": "SIEM"},
            {"time": "2024-01-15 15:00", "event": "Encryption started", "source": "EDR"},
        ],
        affected_systems=["WS-001", "WS-002", "SRV-FILE-01"],
        iocs=[
            {"type": "Hash", "value": "abc123...", "description": "LockBit payload"},
            {"type": "IP", "value": "192.168.1.100", "description": "C2 server"},
        ],
        actions_taken=[
            "Isolated affected systems from network",
            "Disabled compromised accounts",
            "Collected forensic evidence",
        ],
        recommendations=[
            "Implement network segmentation",
            "Deploy EDR to all endpoints",
            "Conduct security awareness training",
        ],
        format=ReportFormat.MARKDOWN
    )

    # Add a finding
    report.add_finding(Finding(
        title="Phishing Email Bypassed Security Controls",
        severity=Severity.HIGH,
        description="A malicious email with ransomware payload bypassed email security.",
        evidence="Email headers showing bypass of SPF/DKIM checks",
        recommendation="Review and strengthen email security policies.",
        mitre_technique="T1566.001 - Phishing: Spearphishing Attachment"
    ))

    # Generate reports
    output_dir = Path("/tmp/security_reports")
    output_dir.mkdir(exist_ok=True)

    md_path = report.generate(str(output_dir / "incident_report.md"))
    print(f"\n[+] Generated Markdown report: {md_path}")

    # Generate HTML version
    html_report = IncidentReportTemplate.create(
        incident_id="INC-2024-001",
        incident_type="Ransomware",
        summary="A LockBit ransomware attack was detected.",
        timeline=[],
        affected_systems=["WS-001", "WS-002"],
        iocs=[],
        actions_taken=["Isolated systems"],
        recommendations=["Improve security"],
        format=ReportFormat.HTML
    )
    html_path = html_report.generate(str(output_dir / "incident_report.html"))
    print(f"[+] Generated HTML report: {html_path}")

    print("\n[+] Report generation complete!")


if __name__ == "__main__":
    main()

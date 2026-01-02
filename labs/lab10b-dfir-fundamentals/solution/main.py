"""
Lab 10b: DFIR Fundamentals (Solution)

A complete artifact analysis toolkit for incident response.
"""

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"


@dataclass
class Finding:
    """Represents a security finding."""

    severity: Severity
    category: str
    description: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    evidence: Optional[str] = None


# Sample data (same as starter)
SAMPLE_PROCESSES = [
    {
        "pid": 4100,
        "name": "WINWORD.EXE",
        "parent": "explorer.exe",
        "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "cmdline": "WINWORD.EXE /n Invoice.docm",
    },
    {
        "pid": 4200,
        "name": "powershell.exe",
        "parent": "WINWORD.EXE",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -enc JABjAGwAaQBlAG4=",
    },
    {
        "pid": 4350,
        "name": "rundll32.exe",
        "parent": "powershell.exe",
        "path": "C:\\Windows\\System32\\rundll32.exe",
        "cmdline": "rundll32.exe",
    },
    {
        "pid": 5600,
        "name": "svchost.exe",
        "parent": "rundll32.exe",
        "path": "C:\\Users\\Public\\svchost.exe",
        "cmdline": "svchost.exe -k netsvcs",
    },
    {
        "pid": 7000,
        "name": "locker.exe",
        "parent": "rundll32.exe",
        "path": "C:\\Windows\\Temp\\locker.exe",
        "cmdline": "locker.exe -encrypt C:\\",
    },
    {
        "pid": 7100,
        "name": "vssadmin.exe",
        "parent": "locker.exe",
        "path": "C:\\Windows\\System32\\vssadmin.exe",
        "cmdline": "vssadmin delete shadows /all /quiet",
    },
    {
        "pid": 800,
        "name": "svchost.exe",
        "parent": "services.exe",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "cmdline": "svchost.exe -k DcomLaunch",
    },
    {
        "pid": 2100,
        "name": "explorer.exe",
        "parent": "userinit.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmdline": "explorer.exe",
    },
]

SAMPLE_FILES = [
    {"path": "C:\\Windows\\Temp\\locker.exe", "size": 245760, "created": "2024-01-15 09:15"},
    {"path": "C:\\Users\\Public\\svchost.exe", "size": 102400, "created": "2024-01-15 09:20"},
    {"path": "C:\\Users\\jsmith\\Desktop\\README.txt", "size": 2048, "created": "2024-01-15 11:00"},
    {
        "path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice.docm",
        "size": 51200,
        "created": "2024-01-15 09:00",
    },
]

SAMPLE_CONNECTIONS = [
    {
        "pid": 4350,
        "local": "192.168.1.50:49667",
        "remote": "185.143.223.47:443",
        "state": "ESTABLISHED",
    },
    {
        "pid": 4350,
        "local": "192.168.1.50:49668",
        "remote": "185.143.223.47:8080",
        "state": "ESTABLISHED",
    },
    {
        "pid": 5600,
        "local": "192.168.1.50:49700",
        "remote": "45.33.32.156:4444",
        "state": "ESTABLISHED",
    },
    {"pid": 800, "local": "192.168.1.50:135", "remote": "0.0.0.0:0", "state": "LISTENING"},
]

ATTACK_TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1059.001": "Command and Scripting: PowerShell",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1055": "Process Injection",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1041": "Exfiltration Over C2 Channel",
    "T1204.002": "User Execution: Malicious File",
}


def analyze_processes(processes: List[Dict]) -> List[Finding]:
    """Analyze process data for suspicious indicators."""
    findings = []

    suspicious_parents = {
        "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"],
        "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    }

    system_binaries = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe"]

    for proc in processes:
        name = proc["name"].lower()
        parent = proc["parent"].lower()
        path = proc["path"].lower()
        cmdline = proc["cmdline"]

        # Check suspicious parent-child
        if name in suspicious_parents:
            if parent in suspicious_parents[name]:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="process",
                        description=f"Office spawning shell: {proc['parent']} → {proc['name']}",
                        evidence=f"PID {proc['pid']}: {cmdline}",
                    )
                )

        # Check masquerading
        if name in system_binaries:
            if "system32" not in path and "syswow64" not in path:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="process",
                        description=f"Masquerading: {name} running from wrong path",
                        evidence=f"Path: {proc['path']}",
                    )
                )

        # Check encoded PowerShell
        if "powershell" in name:
            if "-enc" in cmdline.lower() or "-encoded" in cmdline.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="process",
                        description="Encoded PowerShell command detected",
                        evidence=f"Command: {cmdline[:50]}...",
                    )
                )

        # Check rundll32 without args
        if "rundll32" in name:
            if cmdline.strip().lower() == "rundll32.exe":
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="process",
                        description="rundll32.exe without arguments (possible injection)",
                        evidence=f"PID: {proc['pid']}",
                    )
                )

        # Check for shadow copy deletion
        if "vssadmin" in name and "delete" in cmdline.lower():
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="process",
                    description="Shadow copy deletion (ransomware indicator)",
                    evidence=f"Command: {cmdline}",
                )
            )

        # Check for encryption activity
        if "encrypt" in cmdline.lower() or "locker" in name:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="process",
                    description="Encryption activity detected (ransomware indicator)",
                    evidence=f"Command: {cmdline}",
                )
            )

    return findings


def analyze_files(files: List[Dict]) -> List[Finding]:
    """Analyze file artifacts for suspicious indicators."""
    findings = []

    suspicious_locations = [
        "\\temp\\",
        "\\users\\public\\",
        "\\appdata\\local\\temp\\",
        "\\programdata\\",
    ]

    suspicious_extensions = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"]

    for file in files:
        path_lower = file["path"].lower()

        # Check for executables in suspicious locations
        for location in suspicious_locations:
            if location in path_lower:
                for ext in suspicious_extensions:
                    if path_lower.endswith(ext):
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                category="file",
                                description=f"Executable in suspicious location",
                                evidence=f"Path: {file['path']}",
                            )
                        )
                        break

        # Check for specific malicious indicators
        if "locker" in path_lower or "ransom" in path_lower:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="file",
                    description="Potential ransomware file detected",
                    evidence=f"Path: {file['path']}",
                )
            )

    return findings


def analyze_network(connections: List[Dict]) -> List[Finding]:
    """Analyze network connections for suspicious indicators."""
    findings = []

    suspicious_ports = [4444, 5555, 6666, 8080, 8443, 1337, 31337, 9001]
    known_c2 = ["185.143.223.47", "45.33.32.156"]

    for conn in connections:
        if conn["state"] != "ESTABLISHED":
            continue

        remote_parts = conn["remote"].split(":")
        remote_ip = remote_parts[0]
        remote_port = int(remote_parts[1])

        # Check suspicious ports
        if remote_port in suspicious_ports:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="network",
                    description=f"Connection to suspicious port {remote_port}",
                    evidence=f"PID {conn['pid']}: {conn['local']} → {conn['remote']}",
                )
            )

        # Check known C2
        if remote_ip in known_c2:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="network",
                    description=f"Connection to known C2 infrastructure",
                    evidence=f"IP: {remote_ip}, PID: {conn['pid']}",
                )
            )

    return findings


def map_to_attack(finding: Finding) -> Finding:
    """Map a finding to MITRE ATT&CK technique."""
    patterns = {
        "T1566.001": ["office", "spawn", "macro", "attachment", "winword", "excel"],
        "T1059.001": ["powershell", "-enc", "encoded"],
        "T1036.005": ["masquerad", "wrong path", "impersonat"],
        "T1055": ["injection", "hollow"],
        "T1490": ["shadow", "vssadmin", "recovery"],
        "T1486": ["encrypt", "ransom", "locker"],
        "T1071.001": ["c2", "beacon", "established"],
        "T1204.002": ["executable", "suspicious location"],
    }

    desc_lower = finding.description.lower()
    evidence_lower = (finding.evidence or "").lower()
    combined = desc_lower + " " + evidence_lower

    for technique, keywords in patterns.items():
        if any(kw in combined for kw in keywords):
            finding.technique_id = technique
            finding.technique_name = ATTACK_TECHNIQUES.get(technique, "Unknown")
            break

    return finding


def generate_report(findings: List[Finding]) -> str:
    """Generate a formatted incident report."""
    report = []
    report.append("🔍 DFIR Artifact Analysis Report")
    report.append("=" * 60)
    report.append("")

    # Group by category
    by_category = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    # Sort each category by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

    for category in ["process", "file", "network", "registry"]:
        if category not in by_category:
            continue

        cat_findings = sorted(by_category[category], key=lambda x: severity_order[x.severity])

        report.append(f"{'━' * 60}")
        report.append(f"📁 {category.upper()} ANALYSIS")
        report.append(f"{'━' * 60}")

        for f in cat_findings:
            report.append(f"")
            report.append(f"  {f.severity.value}: {f.description}")
            if f.evidence:
                report.append(f"     Evidence: {f.evidence}")
            if f.technique_id:
                report.append(f"     Technique: {f.technique_id} ({f.technique_name})")

        report.append("")

    # ATT&CK Summary
    techniques = set()
    for f in findings:
        if f.technique_id:
            techniques.add((f.technique_id, f.technique_name))

    if techniques:
        report.append(f"{'━' * 60}")
        report.append("🎯 MITRE ATT&CK COVERAGE")
        report.append(f"{'━' * 60}")
        for tid, tname in sorted(techniques):
            report.append(f"  • {tid}: {tname}")
        report.append("")

    # Severity summary
    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f.severity] += 1

    report.append(f"{'━' * 60}")
    report.append("📊 SEVERITY SUMMARY")
    report.append(f"{'━' * 60}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if severity_counts[sev] > 0:
            report.append(f"  {sev.value}: {severity_counts[sev]} findings")
    report.append("")

    # Recommendations
    report.append(f"{'━' * 60}")
    report.append("📋 RECOMMENDED ACTIONS")
    report.append(f"{'━' * 60}")

    if severity_counts[Severity.CRITICAL] > 0:
        report.append("  1. IMMEDIATE: Isolate affected systems")
        report.append("  2. Block identified C2 IPs at firewall")
        report.append("  3. Capture memory dumps before remediation")
        report.append("  4. Reset credentials for all affected accounts")
        report.append("  5. Hunt for IOCs across all endpoints")
    else:
        report.append("  1. Monitor systems for additional activity")
        report.append("  2. Review and tune detection rules")
        report.append("  3. Document findings for threat intel")

    return "\n".join(report)


def main():
    print("🔍 DFIR Fundamentals - Artifact Analysis")
    print("=" * 60)

    all_findings = []

    # Analyze processes
    print("\n[1] Analyzing processes...")
    process_findings = analyze_processes(SAMPLE_PROCESSES)
    all_findings.extend(process_findings)
    print(f"    Found {len(process_findings)} process anomalies")

    # Analyze files
    print("\n[2] Analyzing files...")
    file_findings = analyze_files(SAMPLE_FILES)
    all_findings.extend(file_findings)
    print(f"    Found {len(file_findings)} file anomalies")

    # Analyze network
    print("\n[3] Analyzing network...")
    network_findings = analyze_network(SAMPLE_CONNECTIONS)
    all_findings.extend(network_findings)
    print(f"    Found {len(network_findings)} network anomalies")

    # Map to ATT&CK
    print("\n[4] Mapping to MITRE ATT&CK...")
    for finding in all_findings:
        map_to_attack(finding)
    mapped = sum(1 for f in all_findings if f.technique_id)
    print(f"    Mapped {mapped}/{len(all_findings)} findings to ATT&CK")

    # Generate report
    print("\n[5] Generating report...")
    report = generate_report(all_findings)

    print("\n" + "=" * 60)
    print(report)

    print(f"\n✅ Analysis complete! {len(all_findings)} findings identified.")
    print("   Ready for Labs 11-16 advanced DFIR topics!")


if __name__ == "__main__":
    main()

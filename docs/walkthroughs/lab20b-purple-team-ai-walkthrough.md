# Lab 20b: AI-Assisted Purple Team - Solution Walkthrough

## Overview

Build an AI-powered purple team framework that bridges red and blue team operations through automated attack simulation, detection gap analysis, and comprehensive reporting.

**Time:** 2-2.5 hours
**Difficulty:** Expert (Bridge Lab)

---

## Task 1: AI-Powered Attack Simulation

### Building a Safe Attack Scenario Generator

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


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
    EXFILTRATION = "exfiltration"


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


@dataclass
class AttackScenario:
    """A complete attack scenario for purple team exercise."""
    
    name: str
    description: str
    threat_actor: str
    objective: str
    techniques: List[AttackTechnique]
    expected_detections: List[str]


class AttackSimulator:
    """
    Generate and execute attack simulations for purple team exercises.
    
    Creates SAFE, SIMULATED attack patterns that:
    - Generate detectable artifacts
    - Map to ATT&CK techniques
    - Validate detection coverage
    """
    
    def __init__(self):
        self.technique_library = self._load_technique_library()
    
    def _load_technique_library(self) -> Dict[str, AttackTechnique]:
        """Load library of safe attack simulations."""
        return {
            "T1059.001": AttackTechnique(
                technique_id="T1059.001",
                name="PowerShell",
                phase=AttackPhase.EXECUTION,
                description="Command and script execution via PowerShell",
                simulation_command='powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host \'Test\'"',
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
                simulation_command="# SIMULATION ONLY - Use Atomic Red Team",
                expected_artifacts=[
                    "Process accessing lsass.exe",
                    "Windows Event ID 4656 (Handle to LSASS)",
                    "Sysmon Event ID 10 (Process Access)",
                ],
                detection_opportunities=[
                    "Non-system process accessing LSASS",
                    "Known tools (mimikatz, procdump) execution",
                ],
            ),
            "T1021.002": AttackTechnique(
                technique_id="T1021.002",
                name="SMB/Windows Admin Shares",
                phase=AttackPhase.LATERAL_MOVEMENT,
                description="Lateral movement via SMB and admin shares",
                simulation_command="# net use \\\\target\\C$ - SIMULATION ONLY",
                expected_artifacts=[
                    "Windows Event ID 5140 (Network Share Access)",
                    "Windows Event ID 4624 (Logon Type 3)",
                ],
                detection_opportunities=[
                    "Access to C$, ADMIN$ shares",
                    "Unusual SMB traffic patterns",
                ],
            ),
            "T1567.002": AttackTechnique(
                technique_id="T1567.002",
                name="Exfiltration to Cloud Storage",
                phase=AttackPhase.EXFILTRATION,
                description="Data exfiltration to cloud storage services",
                simulation_command="# SIMULATION: curl https://api.dropbox.com/test",
                expected_artifacts=[
                    "HTTPS traffic to cloud storage APIs",
                    "Large outbound data transfers",
                ],
                detection_opportunities=[
                    "Unusual cloud storage API calls",
                    "Large uploads during off-hours",
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
            description=f"Purple team exercise simulating {threat_actor} tactics",
            threat_actor=threat_actor,
            objective=objective,
            techniques=scenario_techniques,
            expected_detections=list(set(expected_detections)),
        )


# Usage
simulator = AttackSimulator()
scenario = simulator.generate_scenario(
    threat_actor="APT29",
    objective="Data exfiltration via cloud storage",
    techniques=["T1059.001", "T1003.001", "T1021.002", "T1567.002"]
)

print(f"Scenario: {scenario.name}")
print(f"Objective: {scenario.objective}")
print(f"\nTechniques ({len(scenario.techniques)}):")
for tech in scenario.techniques:
    print(f"  {tech.technique_id}: {tech.name} ({tech.phase.value})")
print(f"\nExpected Detections:")
for detection in scenario.expected_detections[:5]:
    print(f"  • {detection}")
```

---

## Task 2: Detection Gap Analysis

### AI-Powered Coverage Assessment

```python
from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum


class CoverageLevel(Enum):
    NONE = "none"
    PARTIAL = "partial"
    GOOD = "good"
    EXCELLENT = "excellent"


@dataclass
class DetectionRule:
    """A detection rule with ATT&CK mapping."""
    
    rule_id: str
    name: str
    techniques: List[str]  # ATT&CK technique IDs
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


class DetectionGapAnalyzer:
    """
    Analyze detection coverage against MITRE ATT&CK.
    
    Uses AI to:
    - Map existing rules to techniques
    - Identify coverage gaps
    - Prioritize improvements
    """
    
    def __init__(self):
        self.attack_matrix = self._load_attack_matrix()
    
    def _load_attack_matrix(self) -> Dict[str, Dict]:
        """Load ATT&CK matrix (simplified for exercise)."""
        return {
            "initial_access": {
                "T1566.001": {"name": "Spearphishing Attachment", "priority": "high"},
                "T1566.002": {"name": "Spearphishing Link", "priority": "high"},
                "T1190": {"name": "Exploit Public-Facing Application", "priority": "high"},
            },
            "execution": {
                "T1059.001": {"name": "PowerShell", "priority": "critical"},
                "T1059.003": {"name": "Windows Command Shell", "priority": "high"},
                "T1047": {"name": "WMI", "priority": "medium"},
            },
            "credential_access": {
                "T1003.001": {"name": "LSASS Memory", "priority": "critical"},
                "T1558.003": {"name": "Kerberoasting", "priority": "high"},
                "T1110": {"name": "Brute Force", "priority": "medium"},
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
    
    def analyze_coverage(self, detection_rules: List[DetectionRule]) -> GapAnalysis:
        """Analyze detection coverage against ATT&CK matrix."""
        # Get all covered techniques
        covered_techniques = set()
        for rule in detection_rules:
            if rule.enabled:
                covered_techniques.update(rule.techniques)
        
        # Calculate coverage per tactic
        tactic_coverage = {}
        total_techniques = 0
        critical_gaps = []
        
        for tactic, techniques in self.attack_matrix.items():
            total_techniques += len(techniques)
            covered_in_tactic = sum(1 for t in techniques if t in covered_techniques)
            coverage = covered_in_tactic / len(techniques) if techniques else 0
            tactic_coverage[tactic] = coverage
            
            # Find critical gaps
            for tech_id, tech_info in techniques.items():
                if tech_id not in covered_techniques:
                    if tech_info["priority"] in ["critical", "high"]:
                        critical_gaps.append(f"{tech_id}: {tech_info['name']}")
        
        overall_coverage = len(covered_techniques) / total_techniques if total_techniques else 0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(critical_gaps, tactic_coverage)
        
        return GapAnalysis(
            total_techniques=total_techniques,
            covered_techniques=len(covered_techniques),
            coverage_percentage=overall_coverage * 100,
            critical_gaps=critical_gaps[:10],
            priority_recommendations=recommendations,
            tactic_coverage=tactic_coverage,
        )
    
    def _generate_recommendations(
        self,
        gaps: List[str],
        tactic_coverage: Dict[str, float],
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Find lowest coverage tactics
        sorted_tactics = sorted(tactic_coverage.items(), key=lambda x: x[1])
        
        for tactic, coverage in sorted_tactics[:3]:
            if coverage < 0.7:
                recommendations.append(
                    f"Improve {tactic.replace('_', ' ')} coverage (currently {coverage:.0%})"
                )
        
        if gaps:
            recommendations.append(f"Address {len(gaps)} high-priority detection gaps")
        
        recommendations.append("Deploy Atomic Red Team for validation")
        
        return recommendations


# Sample detection rules
sample_rules = [
    DetectionRule("R001", "PowerShell Suspicious Activity", ["T1059.001"]),
    DetectionRule("R002", "LSASS Memory Access", ["T1003.001"]),
    DetectionRule("R003", "Spearphishing Attachment", ["T1566.001"]),
]

analyzer = DetectionGapAnalyzer()
analysis = analyzer.analyze_coverage(sample_rules)

print(f"Detection Coverage Analysis")
print(f"=" * 50)
print(f"Total Techniques: {analysis.total_techniques}")
print(f"Covered: {analysis.covered_techniques}")
print(f"Coverage: {analysis.coverage_percentage:.1f}%")
print(f"\nCritical Gaps:")
for gap in analysis.critical_gaps[:5]:
    print(f"  🔴 {gap}")
print(f"\nRecommendations:")
for rec in analysis.priority_recommendations:
    print(f"  • {rec}")
```

---

## Task 3: Purple Team Report Generator

### Creating Comprehensive Exercise Reports

```python
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime
from enum import Enum


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PurpleTeamFinding:
    """A finding from a purple team exercise."""
    
    id: str
    title: str
    severity: FindingSeverity
    technique_id: str
    technique_name: str
    detection_result: str  # detected, partially_detected, not_detected
    recommendations: List[str]


@dataclass
class PurpleTeamReport:
    """Complete purple team exercise report."""
    
    title: str
    exercise_date: str
    executive_summary: str
    scope: str
    findings: List[PurpleTeamFinding]
    overall_score: float  # 0-100
    detection_rate: float
    critical_gaps: List[str]
    recommendations: List[str]


class PurpleTeamReporter:
    """Generate comprehensive purple team reports."""
    
    def generate_report(
        self,
        exercise_name: str,
        threat_scenario: str,
        findings: List[PurpleTeamFinding],
        scope: str,
    ) -> PurpleTeamReport:
        """Generate a complete purple team report."""
        # Calculate metrics
        total_tests = len(findings)
        detected = sum(1 for f in findings if f.detection_result == "detected")
        detection_rate = (detected / total_tests * 100) if total_tests else 0
        
        # Identify critical gaps
        critical_gaps = [
            f.title for f in findings
            if f.detection_result == "not_detected"
            and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]
        
        # Calculate overall score
        overall_score = self._calculate_score(findings)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(
            exercise_name, detection_rate, critical_gaps, overall_score
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        return PurpleTeamReport(
            title=f"Purple Team Report: {exercise_name}",
            exercise_date=datetime.now().strftime("%Y-%m-%d"),
            executive_summary=exec_summary,
            scope=scope,
            findings=sorted(findings, key=lambda f: f.severity.value),
            overall_score=overall_score,
            detection_rate=detection_rate,
            critical_gaps=critical_gaps,
            recommendations=recommendations,
        )
    
    def _calculate_score(self, findings: List[PurpleTeamFinding]) -> float:
        """Calculate overall security score."""
        if not findings:
            return 0.0
        
        weights = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        
        total_weight = sum(weights[f.severity] for f in findings)
        detected_weight = sum(
            weights[f.severity] for f in findings
            if f.detection_result == "detected"
        )
        partial_weight = sum(
            weights[f.severity] * 0.5 for f in findings
            if f.detection_result == "partially_detected"
        )
        
        return ((detected_weight + partial_weight) / total_weight * 100) if total_weight else 0
    
    def _generate_executive_summary(
        self,
        exercise_name: str,
        detection_rate: float,
        critical_gaps: List[str],
        score: float,
    ) -> str:
        """Generate executive summary."""
        if score >= 80:
            assessment = "STRONG"
            outlook = "minimal critical gaps identified"
        elif score >= 60:
            assessment = "MODERATE"
            outlook = "several improvement opportunities identified"
        else:
            assessment = "NEEDS IMPROVEMENT"
            outlook = "significant detection gaps require attention"
        
        return f"""
Purple Team Exercise: {exercise_name}

Overall Assessment: {assessment} ({score:.0f}/100)

The purple team exercise achieved a {detection_rate:.0f}% detection rate.
{len(critical_gaps)} critical or high-severity gaps were identified.

Key Finding: {outlook}.
{"Top Priority: " + critical_gaps[0] if critical_gaps else "No critical gaps."}
""".strip()
    
    def _generate_recommendations(self, findings: List[PurpleTeamFinding]) -> List[str]:
        """Generate prioritized recommendations."""
        not_detected = [f for f in findings if f.detection_result == "not_detected"]
        
        recommendations = []
        if not_detected:
            critical_count = sum(
                1 for f in not_detected
                if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
            )
            if critical_count:
                recommendations.append(
                    f"CRITICAL: Implement detections for {critical_count} high-priority techniques"
                )
        
        recommendations.extend([
            "Enable additional logging (PowerShell Script Block, Process Creation)",
            "Deploy Sysmon for enhanced endpoint visibility",
            "Schedule quarterly purple team exercises",
        ])
        
        return recommendations


# Sample findings
sample_findings = [
    PurpleTeamFinding(
        id="F001",
        title="PowerShell Execution Bypass",
        severity=FindingSeverity.HIGH,
        technique_id="T1059.001",
        technique_name="PowerShell",
        detection_result="detected",
        recommendations=["Rule triggered correctly"],
    ),
    PurpleTeamFinding(
        id="F002",
        title="LSASS Memory Access",
        severity=FindingSeverity.CRITICAL,
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        detection_result="not_detected",
        recommendations=["Implement Sysmon Event ID 10 monitoring"],
    ),
    PurpleTeamFinding(
        id="F003",
        title="Lateral Movement via SMB",
        severity=FindingSeverity.HIGH,
        technique_id="T1021.002",
        technique_name="SMB/Windows Admin Shares",
        detection_result="partially_detected",
        recommendations=["Tune rule to reduce false negatives"],
    ),
]

reporter = PurpleTeamReporter()
report = reporter.generate_report(
    exercise_name="Q1 2026 Purple Team Exercise",
    threat_scenario="APT29 Simulation",
    findings=sample_findings,
    scope="Corporate network endpoints"
)

print(report.executive_summary)
print(f"\nDetection Rate: {report.detection_rate:.0f}%")
print(f"Overall Score: {report.overall_score:.0f}/100")
print(f"\nCritical Gaps:")
for gap in report.critical_gaps:
    print(f"  🔴 {gap}")
print(f"\nRecommendations:")
for rec in report.recommendations:
    print(f"  • {rec}")
```

---

## Task 4: Continuous Validation Pipeline

### Automating Purple Team Operations

```python
"""
Continuous validation pipeline for ongoing security testing.

Key components:
- Scheduled attack simulations
- Automated detection validation
- Trend tracking over time
"""

from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime


@dataclass
class ValidationResult:
    """Result of a single validation run."""
    
    timestamp: str
    techniques_tested: int
    techniques_detected: int
    detection_rate: float
    new_gaps: List[str]
    resolved_gaps: List[str]


class ContinuousValidator:
    """Automated continuous validation pipeline."""
    
    def __init__(self):
        self.history: List[ValidationResult] = []
        self.known_gaps: set = set()
    
    def run_validation(
        self,
        techniques: List[str],
        detection_results: Dict[str, bool],
    ) -> ValidationResult:
        """Run a validation cycle and track trends."""
        detected = sum(1 for t in techniques if detection_results.get(t, False))
        detection_rate = (detected / len(techniques) * 100) if techniques else 0
        
        # Find new gaps
        current_gaps = {t for t in techniques if not detection_results.get(t, False)}
        new_gaps = list(current_gaps - self.known_gaps)
        resolved_gaps = list(self.known_gaps - current_gaps)
        
        self.known_gaps = current_gaps
        
        result = ValidationResult(
            timestamp=datetime.now().isoformat(),
            techniques_tested=len(techniques),
            techniques_detected=detected,
            detection_rate=detection_rate,
            new_gaps=new_gaps,
            resolved_gaps=resolved_gaps,
        )
        
        self.history.append(result)
        return result
    
    def get_trend_report(self) -> str:
        """Generate trend report from validation history."""
        if len(self.history) < 2:
            return "Insufficient data for trend analysis"
        
        recent = self.history[-1]
        previous = self.history[-2]
        
        rate_change = recent.detection_rate - previous.detection_rate
        trend = "📈 Improving" if rate_change > 0 else "📉 Declining" if rate_change < 0 else "➡️ Stable"
        
        return f"""
Continuous Validation Trend Report
==================================
Current Detection Rate: {recent.detection_rate:.1f}%
Previous Detection Rate: {previous.detection_rate:.1f}%
Trend: {trend} ({rate_change:+.1f}%)

New Gaps This Cycle: {len(recent.new_gaps)}
Resolved Gaps: {len(recent.resolved_gaps)}
Total Validation Runs: {len(self.history)}
""".strip()


# Demo the continuous validator
validator = ContinuousValidator()

# First validation run
result1 = validator.run_validation(
    techniques=["T1059.001", "T1003.001", "T1021.002", "T1567.002"],
    detection_results={
        "T1059.001": True,
        "T1003.001": False,
        "T1021.002": True,
        "T1567.002": False,
    }
)

# Second validation run (improved)
result2 = validator.run_validation(
    techniques=["T1059.001", "T1003.001", "T1021.002", "T1567.002"],
    detection_results={
        "T1059.001": True,
        "T1003.001": True,  # Now detected!
        "T1021.002": True,
        "T1567.002": False,
    }
)

print(validator.get_trend_report())
```

---

## Key Takeaways

1. **Purple Team Methodology**
   - Combines offensive and defensive expertise
   - Focuses on validating detection capabilities
   - Creates continuous improvement feedback loop

2. **AI Integration Benefits**
   - Scale attack simulations without additional resources
   - Identify gaps across entire ATT&CK matrix
   - Generate and tune detection rules automatically

3. **Detection Coverage**
   - Map all detections to ATT&CK techniques
   - Prioritize gaps by technique criticality
   - Track coverage trends over time

4. **Continuous Validation**
   - Automate regular testing cycles
   - Track improvements and regressions
   - Build institutional knowledge

---

## Resources

| Tool | Purpose | Link |
|------|---------|------|
| **Atomic Red Team** | Safe attack simulation | [github.com/redcanaryco](https://github.com/redcanaryco/atomic-red-team) |
| **MITRE Caldera** | Adversary emulation | [github.com/mitre/caldera](https://github.com/mitre/caldera) |
| **ATT&CK Navigator** | Coverage visualization | [attack.mitre.org](https://attack.mitre.org) |

---

## Next Steps

- **Lab 07b**: Sigma Fundamentals - Detection rule creation
- **Lab 09**: Detection Pipeline - Building detection systems
- **Lab 17**: Adversarial ML - Understanding ML evasion

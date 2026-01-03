# Lab 20b: AI-Assisted Purple Team Exercises

## Bridging Red and Blue with AI-Powered Collaboration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AI-POWERED PURPLE TEAM FRAMEWORK                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RED TEAM (ATTACK)              AI BRIDGE               BLUE TEAM (DEFEND) │
│   ┌─────────────┐            ┌───────────────┐          ┌─────────────┐    │
│   │ Attack      │            │ • Gap Analysis│          │ Detection   │    │
│   │ Simulation  │──────────▶│ • Coverage    │◀─────────│ Engineering │    │
│   │             │            │   Mapping     │          │             │    │
│   └─────────────┘            │ • Auto-Tune   │          └─────────────┘    │
│                              │   Detections  │                              │
│   ┌─────────────┐            │ • Report      │          ┌─────────────┐    │
│   │ TTP         │            │   Generation  │          │ Alert       │    │
│   │ Execution   │──────────▶│               │◀─────────│ Validation  │    │
│   │             │            └───────────────┘          │             │    │
│   └─────────────┘                   │                   └─────────────┘    │
│                                     │                                       │
│                                     ▼                                       │
│                           ┌───────────────────┐                             │
│                           │ CONTINUOUS        │                             │
│                           │ IMPROVEMENT LOOP  │                             │
│                           │ • New detections  │                             │
│                           │ • Updated TTPs    │                             │
│                           │ • Better coverage │                             │
│                           └───────────────────┘                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. **Understand purple team methodology** - How red and blue teams collaborate
2. **Build AI-assisted attack simulations** - Generate realistic attack scenarios
3. **Create detection gap analysis** - Use AI to identify coverage gaps
4. **Automate detection tuning** - AI-assisted Sigma/YARA rule refinement
5. **Generate purple team reports** - Automated findings and recommendations

---

## ⏱️ Estimated Time

2-2.5 hours (with AI assistance)

---

## 📋 Prerequisites

- Completed Lab 07b (Sigma Fundamentals)
- Completed Lab 09 (Detection Pipeline)
- Understanding of MITRE ATT&CK framework
- Basic knowledge of red team operations

---

## 📖 Background

### What is Purple Teaming?

Purple teaming is the collaborative practice of combining offensive (red team) and defensive (blue team) security operations to improve overall security posture.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    PURPLE TEAM MATURITY MODEL                               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LEVEL 1: AD-HOC         LEVEL 2: DEFINED        LEVEL 3: AI-AUGMENTED     │
│  ─────────────────       ─────────────────       ─────────────────────     │
│  • Occasional red        • Regular exercises     • Continuous testing      │
│    team engagements      • Documented TTPs       • AI attack simulation    │
│  • Manual gap analysis   • Coverage tracking     • Automated gap analysis  │
│  • Reactive fixes        • Proactive tuning      • Self-tuning detections  │
│  • Siloed teams          • Collaboration         • Unified platform        │
│                                                                             │
│  MATURITY: ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━▶    │
│                                                                             │
│  AI INTEGRATION BENEFITS:                                                   │
│  • Scale attack simulations without additional red team resources           │
│  • Identify detection gaps across entire ATT&CK matrix                     │
│  • Generate and tune detection rules automatically                          │
│  • Create consistent, reproducible exercises                                │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Purple Team Exercise Types

| Exercise Type | Red Team Role | Blue Team Role | AI Assistance |
|---------------|---------------|----------------|---------------|
| **Detection Validation** | Execute specific TTPs | Verify alerts trigger | Generate TTPs, analyze logs |
| **Gap Analysis** | Test coverage gaps | Document missing detections | Map coverage, prioritize gaps |
| **Hunt Validation** | Leave artifacts | Find artifacts without alerts | Generate hunting queries |
| **Response Testing** | Full attack chain | IR process validation | Timeline analysis, reporting |
| **Detection Tuning** | Vary techniques | Reduce false positives | Suggest rule improvements |

### MITRE ATT&CK Coverage Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DETECTION COVERAGE HEATMAP                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   TACTIC          │ TECHNIQUES │ DETECTED │ COVERAGE │ PRIORITY            │
│   ─────────────────────────────────────────────────────────────────         │
│   Initial Access  │     12     │     8    │   67%   │ ⚠️ Medium            │
│   Execution       │     14     │    11    │   79%   │ ✅ Good              │
│   Persistence     │     22     │    15    │   68%   │ ⚠️ Medium            │
│   Priv Escalation │     14     │     9    │   64%   │ 🔴 High              │
│   Defense Evasion │     43     │    22    │   51%   │ 🔴 Critical          │
│   Credential Access│    17     │    12    │   71%   │ ⚠️ Medium            │
│   Discovery       │     32     │    18    │   56%   │ ⚠️ Medium            │
│   Lateral Movement│     11     │     7    │   64%   │ 🔴 High              │
│   Collection      │     19     │    10    │   53%   │ ⚠️ Medium            │
│   C2              │     18     │    14    │   78%   │ ✅ Good              │
│   Exfiltration    │     12     │     6    │   50%   │ 🔴 High              │
│   Impact          │     14     │    10    │   71%   │ ⚠️ Medium            │
│                                                                             │
│   AI RECOMMENDATIONS:                                                       │
│   1. Focus on Defense Evasion (T1036, T1055, T1070)                        │
│   2. Improve Exfiltration detection (T1041, T1567)                         │
│   3. Add Lateral Movement coverage (T1021, T1550)                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Lab Exercises

### Exercise 1: AI-Powered Attack Simulation

Generate realistic attack scenarios for purple team exercises.

```python
"""
Exercise 1: Build an AI attack scenario generator

Create attack simulations that:
- Map to specific MITRE ATT&CK techniques
- Generate realistic artifacts
- Provide expected detection opportunities
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json


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


@dataclass
class AttackTechnique:
    """A single ATT&CK technique for simulation."""
    
    technique_id: str  # e.g., "T1059.001"
    name: str
    phase: AttackPhase
    description: str
    simulation_command: str  # Safe simulation command
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


class AttackSimulator:
    """
    Generate and execute attack simulations for purple team exercises.
    
    This simulator creates SAFE, SIMULATED attack patterns that:
    - Generate detectable artifacts
    - Map to ATT&CK techniques
    - Can validate detection coverage
    """
    
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
                simulation_command='powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host \'Purple Team Test\'"',
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
                simulation_command="# SIMULATION ONLY - Use Atomic Red Team for safe testing",
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
                simulation_command="# SIMULATION ONLY - Use Atomic Red Team for safe testing",
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
                simulation_command="# net use \\\\target\\C$ - SIMULATION ONLY",
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
                simulation_command="# SIMULATION: curl https://api.dropbox.com/test",
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
        }
    
    def generate_scenario(
        self,
        threat_actor: str,
        objective: str,
        techniques: List[str],
    ) -> AttackScenario:
        """
        Generate a complete attack scenario.
        
        Args:
            threat_actor: Name/type of threat actor to simulate
            objective: What the attacker is trying to achieve
            techniques: List of ATT&CK technique IDs to include
            
        Returns:
            AttackScenario ready for execution
        """
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
    
    def get_atomic_red_team_tests(self, technique_id: str) -> List[Dict]:
        """
        Get Atomic Red Team tests for a technique.
        
        Returns safe, documented tests from the Atomic Red Team framework.
        """
        # Reference to Atomic Red Team
        atomic_reference = {
            "T1059.001": {
                "name": "PowerShell Execution",
                "repo": "https://github.com/redcanaryco/atomic-red-team",
                "path": "atomics/T1059.001/T1059.001.md",
                "safe_tests": [
                    "Mimikatz Detection Test (safe)",
                    "PowerShell Download Cradle",
                    "Encoded Command Execution",
                ],
            },
            "T1003.001": {
                "name": "LSASS Memory Dump",
                "repo": "https://github.com/redcanaryco/atomic-red-team",
                "path": "atomics/T1003.001/T1003.001.md",
                "safe_tests": [
                    "Windows Credential Editor (detectable)",
                    "Dump LSASS with comsvcs.dll",
                    "ProcDump LSASS Dump",
                ],
            },
        }
        
        return atomic_reference.get(technique_id, {})


# TODO: Implement the simulator
# simulator = AttackSimulator()
# scenario = simulator.generate_scenario(
#     threat_actor="APT29",
#     objective="Data exfiltration",
#     techniques=["T1059.001", "T1003.001", "T1567.002"]
# )
```

### Exercise 2: Detection Gap Analysis

Use AI to identify gaps in detection coverage.

```python
"""
Exercise 2: AI-powered detection gap analysis

Map existing detections to ATT&CK and identify gaps.
"""

from dataclasses import dataclass
from typing import List, Dict, Set, Optional
from enum import Enum


class CoverageLevel(Enum):
    """Detection coverage levels."""
    
    NONE = "none"
    PARTIAL = "partial"
    GOOD = "good"
    EXCELLENT = "excellent"


@dataclass
class DetectionRule:
    """A detection rule with ATT&CK mapping."""
    
    rule_id: str
    name: str
    description: str
    techniques: List[str]  # ATT&CK technique IDs
    log_sources: List[str]
    false_positive_rate: str  # low, medium, high
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
    - Suggest new detections
    """
    
    def __init__(self, llm=None):
        self.llm = llm
        self.attack_matrix = self._load_attack_matrix()
    
    def _load_attack_matrix(self) -> Dict[str, Dict]:
        """Load ATT&CK matrix (simplified)."""
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
                "T1546.001": {"name": "Change Default File Association", "priority": "low"},
            },
            "privilege_escalation": {
                "T1055": {"name": "Process Injection", "priority": "critical"},
                "T1134": {"name": "Access Token Manipulation", "priority": "high"},
                "T1068": {"name": "Exploitation for Privilege Escalation", "priority": "high"},
            },
            "defense_evasion": {
                "T1070.001": {"name": "Clear Windows Event Logs", "priority": "critical"},
                "T1036": {"name": "Masquerading", "priority": "high"},
                "T1055": {"name": "Process Injection", "priority": "critical"},
                "T1027": {"name": "Obfuscated Files", "priority": "medium"},
            },
            "credential_access": {
                "T1003.001": {"name": "LSASS Memory", "priority": "critical"},
                "T1003.002": {"name": "Security Account Manager", "priority": "high"},
                "T1558.003": {"name": "Kerberoasting", "priority": "high"},
                "T1110": {"name": "Brute Force", "priority": "medium"},
            },
            "lateral_movement": {
                "T1021.001": {"name": "Remote Desktop Protocol", "priority": "high"},
                "T1021.002": {"name": "SMB/Windows Admin Shares", "priority": "high"},
                "T1021.006": {"name": "Windows Remote Management", "priority": "medium"},
                "T1550.002": {"name": "Pass the Hash", "priority": "critical"},
            },
            "exfiltration": {
                "T1041": {"name": "Exfiltration Over C2 Channel", "priority": "high"},
                "T1567.002": {"name": "Exfiltration to Cloud Storage", "priority": "high"},
                "T1048": {"name": "Exfiltration Over Alternative Protocol", "priority": "medium"},
            },
        }
    
    def analyze_coverage(
        self,
        detection_rules: List[DetectionRule],
    ) -> GapAnalysis:
        """
        Analyze detection coverage against ATT&CK matrix.
        
        Args:
            detection_rules: List of existing detection rules
            
        Returns:
            GapAnalysis with coverage metrics and recommendations
        """
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
            covered_in_tactic = sum(
                1 for t in techniques if t in covered_techniques
            )
            coverage = covered_in_tactic / len(techniques) if techniques else 0
            tactic_coverage[tactic] = coverage
            
            # Find critical gaps
            for tech_id, tech_info in techniques.items():
                if tech_id not in covered_techniques:
                    if tech_info["priority"] in ["critical", "high"]:
                        critical_gaps.append(
                            f"{tech_id}: {tech_info['name']} ({tech_info['priority']})"
                        )
        
        # Generate priority recommendations
        recommendations = self._generate_recommendations(
            critical_gaps, tactic_coverage
        )
        
        overall_coverage = len(covered_techniques) / total_techniques if total_techniques else 0
        
        return GapAnalysis(
            total_techniques=total_techniques,
            covered_techniques=len(covered_techniques),
            coverage_percentage=overall_coverage * 100,
            critical_gaps=critical_gaps[:10],  # Top 10
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
        
        # Add specific technique recommendations
        if gaps:
            recommendations.append(f"Address {len(gaps)} high-priority detection gaps")
            recommendations.append(f"Priority: {gaps[0].split(':')[1].strip()}")
        
        recommendations.append("Consider deploying Atomic Red Team for validation")
        
        return recommendations
    
    def suggest_detection_rule(
        self,
        technique_id: str,
    ) -> Dict:
        """
        Use AI to suggest a detection rule for a technique.
        
        Returns a Sigma rule template for the specified technique.
        """
        sigma_templates = {
            "T1059.001": {
                "title": "Suspicious PowerShell Execution",
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
                    }
                },
                "level": "medium",
            },
            "T1003.001": {
                "title": "LSASS Memory Access",
                "logsource": {"product": "windows", "category": "process_access"},
                "detection": {
                    "selection": {
                        "TargetImage|endswith": "\\lsass.exe",
                        "GrantedAccess|contains": ["0x1010", "0x1410"],
                    },
                    "filter": {
                        "SourceImage|endswith": [
                            "\\wmiprvse.exe",
                            "\\svchost.exe",
                        ]
                    }
                },
                "level": "high",
            },
        }
        
        return sigma_templates.get(technique_id, {
            "title": f"Detection for {technique_id}",
            "note": "Use AI to generate custom detection logic",
        })


# TODO: Implement the analyzer
# analyzer = DetectionGapAnalyzer()
# rules = [...]  # Your existing rules
# analysis = analyzer.analyze_coverage(rules)
# print(f"Coverage: {analysis.coverage_percentage:.1f}%")
```

### Exercise 3: Purple Team Report Generator

Generate comprehensive purple team exercise reports.

```python
"""
Exercise 3: AI-powered purple team report generation

Create detailed reports of purple team exercises.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class FindingSeverity(Enum):
    """Severity levels for findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PurpleTeamFinding:
    """A finding from a purple team exercise."""
    
    id: str
    title: str
    severity: FindingSeverity
    technique_id: str
    technique_name: str
    description: str
    attack_executed: str
    detection_result: str  # detected, partially_detected, not_detected
    evidence: List[str]
    recommendations: List[str]


@dataclass
class PurpleTeamReport:
    """Complete purple team exercise report."""
    
    title: str
    exercise_date: str
    executive_summary: str
    scope: str
    threat_scenario: str
    findings: List[PurpleTeamFinding]
    overall_score: float  # 0-100
    detection_rate: float
    critical_gaps: List[str]
    recommendations: List[str]
    appendix: Dict


class PurpleTeamReporter:
    """
    Generate comprehensive purple team reports.
    
    Uses AI to:
    - Summarize exercise results
    - Prioritize findings
    - Generate recommendations
    - Create executive summaries
    """
    
    def __init__(self, llm=None):
        self.llm = llm
    
    def generate_report(
        self,
        exercise_name: str,
        threat_scenario: str,
        findings: List[PurpleTeamFinding],
        scope: str,
    ) -> PurpleTeamReport:
        """
        Generate a complete purple team report.
        
        Args:
            exercise_name: Name of the exercise
            threat_scenario: Description of simulated threat
            findings: List of findings from the exercise
            scope: Scope of the exercise
            
        Returns:
            Complete PurpleTeamReport
        """
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
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Calculate overall score
        overall_score = self._calculate_score(findings)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(
            exercise_name, detection_rate, critical_gaps, overall_score
        )
        
        return PurpleTeamReport(
            title=f"Purple Team Report: {exercise_name}",
            exercise_date=datetime.now().strftime("%Y-%m-%d"),
            executive_summary=exec_summary,
            scope=scope,
            threat_scenario=threat_scenario,
            findings=sorted(findings, key=lambda f: f.severity.value),
            overall_score=overall_score,
            detection_rate=detection_rate,
            critical_gaps=critical_gaps,
            recommendations=recommendations,
            appendix=self._generate_appendix(findings),
        )
    
    def _generate_executive_summary(
        self,
        exercise_name: str,
        detection_rate: float,
        critical_gaps: List[str],
        score: float,
    ) -> str:
        """Generate executive summary."""
        if score >= 80:
            assessment = "strong"
            outlook = "minimal critical gaps identified"
        elif score >= 60:
            assessment = "moderate"
            outlook = "several improvement opportunities identified"
        else:
            assessment = "needs improvement"
            outlook = "significant detection gaps require immediate attention"
        
        summary = f"""
Purple Team Exercise: {exercise_name}

Overall Assessment: {assessment.upper()} ({score:.0f}/100)

The purple team exercise achieved a {detection_rate:.0f}% detection rate across 
all tested techniques. {len(critical_gaps)} critical or high-severity gaps were 
identified that require remediation.

Key Finding: {outlook}.

{"Top Priority: " + critical_gaps[0] if critical_gaps else "No critical gaps identified."}

Immediate actions recommended:
1. Address critical detection gaps
2. Tune existing rules to reduce false negatives
3. Implement recommended detection rules
4. Schedule follow-up validation exercise
"""
        return summary.strip()
    
    def _generate_recommendations(
        self,
        findings: List[PurpleTeamFinding],
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Group by detection result
        not_detected = [f for f in findings if f.detection_result == "not_detected"]
        partial = [f for f in findings if f.detection_result == "partially_detected"]
        
        if not_detected:
            critical_not_detected = [
                f for f in not_detected
                if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
            ]
            if critical_not_detected:
                recommendations.append(
                    f"CRITICAL: Implement detections for {len(critical_not_detected)} "
                    f"high-priority techniques: {', '.join(f.technique_id for f in critical_not_detected[:3])}"
                )
        
        if partial:
            recommendations.append(
                f"Tune {len(partial)} partially-effective detections to improve accuracy"
            )
        
        # Add general recommendations
        recommendations.extend([
            "Enable additional logging (PowerShell Script Block, Process Creation)",
            "Deploy Sysmon for enhanced endpoint visibility",
            "Implement behavioral detection rules in addition to signatures",
            "Schedule quarterly purple team exercises for continuous validation",
        ])
        
        return recommendations
    
    def _calculate_score(self, findings: List[PurpleTeamFinding]) -> float:
        """Calculate overall security score."""
        if not findings:
            return 0.0
        
        # Weight by severity
        weights = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0.5,
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
        
        score = ((detected_weight + partial_weight) / total_weight * 100) if total_weight else 0
        return min(score, 100)
    
    def _generate_appendix(self, findings: List[PurpleTeamFinding]) -> Dict:
        """Generate report appendix with technical details."""
        return {
            "techniques_tested": [f.technique_id for f in findings],
            "mitre_attack_mapping": {
                f.technique_id: f.technique_name for f in findings
            },
            "evidence_collected": [
                {"finding": f.id, "evidence": f.evidence} for f in findings
            ],
            "sigma_rules_recommended": [
                f.technique_id for f in findings
                if f.detection_result == "not_detected"
            ],
        }


# TODO: Create a purple team report
# reporter = PurpleTeamReporter()
# findings = [...]  # Your exercise findings
# report = reporter.generate_report(
#     exercise_name="Q1 2026 Purple Team Exercise",
#     threat_scenario="APT29 Simulation",
#     findings=findings,
#     scope="Corporate network endpoints"
# )
```

---

## 🧪 Challenge Exercises

### Challenge 1: Full Purple Team Platform

Build a complete platform that:
- Generates attack scenarios
- Executes safe simulations
- Validates detections
- Produces reports

### Challenge 2: Continuous Validation Pipeline

Create an automated pipeline that:
- Runs daily detection validation
- Reports new gaps
- Suggests rule improvements
- Tracks coverage over time

### Challenge 3: AI-Assisted Detection Tuning

Build a system that:
- Analyzes false positives
- Suggests rule modifications
- Tests improvements
- Validates accuracy

---

## 📚 Resources

### Frameworks and Tools

| Tool | Purpose | Link |
|------|---------|------|
| **Atomic Red Team** | Safe attack simulation | [github.com/redcanaryco](https://github.com/redcanaryco/atomic-red-team) |
| **MITRE Caldera** | Adversary emulation | [github.com/mitre/caldera](https://github.com/mitre/caldera) |
| **Detection Lab** | Testing environment | [github.com/clong/DetectionLab](https://github.com/clong/DetectionLab) |

### MITRE Resources

| Resource | Description |
|----------|-------------|
| **ATT&CK Matrix** | [attack.mitre.org](https://attack.mitre.org) |
| **ATT&CK Navigator** | Coverage visualization |
| **MITRE Engenuity** | Evaluations and testing |

### SANS Resources

| Resource | Description |
|----------|-------------|
| **SEC599** | Defeating Advanced Adversaries - Purple Team Tactics |
| **Purple Team Poster** | Reference guide |

---

## ✅ Success Criteria

You've successfully completed this lab when you can:

- [ ] Generate realistic attack scenarios mapped to ATT&CK
- [ ] Analyze detection coverage and identify gaps
- [ ] Create comprehensive purple team reports
- [ ] Use Atomic Red Team for safe validation
- [ ] Recommend detection improvements based on analysis

---

## 🔗 Next Steps

- **Lab 07b**: Sigma Fundamentals - Detection rule creation
- **Lab 09**: Detection Pipeline - Building detection systems
- **Lab 17**: Adversarial ML - Understanding ML evasion

# Lab 12: Ransomware Attack Simulation & Purple Team

Build AI-powered tools to simulate ransomware attacks for purple team exercises and defense validation.

## Learning Objectives

1. Understand ransomware attack chains and TTPs
2. Build safe simulation tools for defense testing
3. Use AI to generate realistic attack scenarios
4. Validate detection and response capabilities
5. Create adversary emulation playbooks

## Estimated Time

4-5 hours

## Prerequisites

- Completed Labs 05 (Threat Intel Agent), 11 (Ransomware Detection)
- Understanding of offensive security ethics and authorization
- Familiarity with MITRE ATT&CK framework

## Ethical Framework

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        ETHICAL REQUIREMENTS                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  This lab is for AUTHORIZED TESTING ONLY. Before proceeding:                 ║
║                                                                               ║
║  ✓ Obtain written authorization from system owners                           ║
║  ✓ Define clear scope boundaries                                             ║
║  ✓ Use isolated test environments                                            ║
║  ✓ Never use real encryption keys or destructive payloads                    ║
║  ✓ Document all activities for audit                                         ║
║  ✓ Have rollback/recovery procedures ready                                   ║
║                                                                               ║
║  NEVER deploy these techniques outside authorized environments               ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Background

### Purple Team Ransomware Testing

Purple team exercises combine offensive (red) and defensive (blue) perspectives to validate security controls against ransomware threats.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PURPLE TEAM RANSOMWARE EXERCISE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RED TEAM                    PURPLE                      BLUE TEAM         │
│   (Attack)                    (Collaborate)               (Defend)          │
│   ┌───────────┐              ┌───────────┐              ┌───────────┐      │
│   │ Simulate  │◄────────────►│ Real-time │◄────────────►│ Detect &  │      │
│   │ Ransomware│              │ Feedback  │              │ Respond   │      │
│   │ TTPs      │              │ Loop      │              │           │      │
│   └───────────┘              └───────────┘              └───────────┘      │
│        │                          │                          │             │
│        ▼                          ▼                          ▼             │
│   ┌───────────┐              ┌───────────┐              ┌───────────┐      │
│   │ Document  │              │ Gap       │              │ Tune      │      │
│   │ Findings  │◄────────────►│ Analysis  │◄────────────►│ Controls  │      │
│   │           │              │           │              │           │      │
│   └───────────┘              └───────────┘              └───────────┘      │
│                                                                             │
│   Outcome: Validated detections, improved response, documented gaps         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Ransomware Families for Emulation

| Family | TTPs | Complexity | Good for Testing |
|--------|------|------------|------------------|
| LockBit | T1486, T1490, T1021 | High | Lateral movement detection |
| BlackCat/ALPHV | T1486, T1567, T1048 | High | Exfiltration detection |
| Conti | T1486, T1490, T1059 | Medium | Script-based detection |
| REvil | T1486, T1082, T1083 | Medium | Discovery behavior |
| Ryuk | T1486, T1490, T1047 | Medium | WMI-based detection |

## Tasks

### Task 1: Attack Scenario Generator (60 min)

Use AI to generate realistic ransomware attack scenarios for testing.

```python
# starter/scenario_generator.py
from anthropic import Anthropic
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class RansomwareFamily(Enum):
    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CONTI = "conti"
    REVIL = "revil"
    RYUK = "ryuk"
    CUSTOM = "custom"

@dataclass
class AttackScenario:
    """A ransomware attack scenario for testing."""
    family: RansomwareFamily
    initial_access: str
    execution_chain: List[str]
    persistence_methods: List[str]
    lateral_movement: List[str]
    exfiltration: bool
    encryption_targets: List[str]
    mitre_techniques: List[str]
    detection_opportunities: List[str]
    expected_artifacts: List[str]

class ScenarioGenerator:
    """
    AI-powered ransomware scenario generator.

    TODO: Implement scenario generation:
    1. Based on real ransomware families
    2. Customizable complexity levels
    3. Include detection opportunities
    4. Map to MITRE ATT&CK
    """

    def __init__(self):
        self.client = Anthropic()

    def generate_scenario(
        self,
        family: RansomwareFamily,
        complexity: str = "medium",
        include_exfil: bool = True,
        target_os: str = "windows"
    ) -> AttackScenario:
        """
        Generate a ransomware attack scenario.

        TODO: Use Claude to generate realistic scenarios
        based on threat intelligence about the family.
        """
        pass

    def generate_detection_tests(
        self,
        scenario: AttackScenario
    ) -> List[Dict]:
        """
        Generate specific tests for each detection opportunity.

        TODO: Create testable detection cases
        """
        pass

    def generate_atomic_tests(
        self,
        scenario: AttackScenario
    ) -> List[Dict]:
        """
        Generate Atomic Red Team-style tests.

        TODO: Create safe, atomic tests for each TTP
        """
        pass
```

### Task 2: Safe Simulation Tools (60 min)

Build tools that simulate ransomware behavior safely.

```python
# starter/safe_simulator.py
import os
import hashlib
import tempfile
from dataclasses import dataclass
from typing import List, Callable
from pathlib import Path

@dataclass
class SimulationConfig:
    """Configuration for safe ransomware simulation."""
    target_directory: str  # Must be in allowed paths
    file_extensions: List[str]
    create_ransom_note: bool
    simulate_encryption: bool  # Rename only, no actual encryption
    simulate_shadow_delete: bool  # Log only, no actual deletion
    cleanup_after: bool

class SafeRansomwareSimulator:
    """
    Safe ransomware behavior simulator for purple team.

    SAFETY FEATURES:
    - Only operates in designated test directories
    - No actual encryption (just file renaming)
    - No destructive operations
    - Full audit logging
    - Automatic cleanup

    TODO: Implement safe simulation behaviors
    """

    ALLOWED_PATHS = ["/tmp/ransomware_test", "/opt/purple_team/test"]

    def __init__(self, config: SimulationConfig):
        self.config = config
        self.audit_log = []
        self._validate_config()

    def _validate_config(self):
        """Ensure simulation is in safe directory."""
        # TODO: Validate target_directory is in ALLOWED_PATHS
        pass

    def simulate_file_enumeration(self) -> List[str]:
        """
        Simulate ransomware file discovery.

        TODO: Enumerate files like ransomware would,
        logging all activity for detection testing.
        """
        pass

    def simulate_encryption(self, files: List[str]) -> Dict:
        """
        Simulate encryption by renaming files.

        SAFE: Does not actually encrypt, just renames
        with .encrypted extension for testing.
        """
        pass

    def simulate_shadow_deletion(self) -> Dict:
        """
        Simulate VSS deletion (logging only).

        SAFE: Only logs the commands that would be run,
        does not execute them.
        """
        pass

    def create_ransom_note(self, template: str = "default") -> str:
        """Create a sample ransom note for detection testing."""
        pass

    def generate_telemetry(self) -> List[Dict]:
        """
        Generate telemetry events for SIEM testing.

        TODO: Create realistic event logs that
        detection rules should catch.
        """
        pass

    def cleanup(self):
        """Restore all files to original state."""
        pass
```

### Task 3: Detection Validation Framework (45 min)

Build a framework to validate detection capabilities.

```python
# starter/detection_validator.py
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class DetectionStatus(Enum):
    DETECTED = "detected"
    MISSED = "missed"
    PARTIAL = "partial"
    ERROR = "error"

@dataclass
class DetectionTest:
    """A single detection test case."""
    name: str
    technique_id: str
    description: str
    simulation_steps: List[str]
    expected_detection: str
    detection_source: str  # SIEM, EDR, etc.

@dataclass
class TestResult:
    """Result of a detection test."""
    test: DetectionTest
    status: DetectionStatus
    detection_time: Optional[float]
    alert_generated: bool
    notes: str

class DetectionValidator:
    """
    Validate detection capabilities against ransomware TTPs.

    TODO: Implement validation framework:
    1. Run simulation steps
    2. Check for expected detections
    3. Measure detection time
    4. Generate gap analysis
    """

    def __init__(self, siem_client, edr_client=None):
        self.siem_client = siem_client
        self.edr_client = edr_client
        self.results = []

    def run_test(self, test: DetectionTest) -> TestResult:
        """
        Run a single detection test.

        TODO:
        1. Execute simulation steps
        2. Wait for detection window
        3. Check SIEM/EDR for alerts
        4. Record results
        """
        pass

    def run_test_suite(self, tests: List[DetectionTest]) -> List[TestResult]:
        """Run full test suite."""
        pass

    def generate_gap_analysis(self) -> Dict:
        """
        Analyze detection gaps.

        TODO: Return:
        - Missed techniques
        - Slow detections
        - Coverage percentage
        - Recommended improvements
        """
        pass

    def generate_report(self) -> str:
        """Generate LLM-powered test report."""
        pass
```

### Task 4: Adversary Emulation Playbook (45 min)

Create AI-generated adversary emulation playbooks.

```python
# starter/emulation_playbook.py
from anthropic import Anthropic
from typing import List, Dict

class AdversaryEmulationPlaybook:
    """
    AI-generated ransomware adversary emulation.

    TODO: Create structured playbooks that:
    1. Emulate specific threat actors
    2. Include detection checkpoints
    3. Map to MITRE ATT&CK
    4. Follow safe testing guidelines
    """

    def __init__(self):
        self.client = Anthropic()

    def generate_playbook(
        self,
        threat_actor: str,
        environment: Dict,
        objectives: List[str]
    ) -> Dict:
        """
        Generate adversary emulation playbook.

        TODO: Create step-by-step playbook with:
        - Pre-requisites
        - Execution steps
        - Detection checkpoints
        - Success criteria
        - Cleanup procedures
        """
        pass

    def generate_lockbit_playbook(self, environment: Dict) -> Dict:
        """Generate LockBit-specific emulation."""
        pass

    def generate_blackcat_playbook(self, environment: Dict) -> Dict:
        """Generate BlackCat/ALPHV-specific emulation."""
        pass

    def adapt_for_environment(
        self,
        playbook: Dict,
        environment: Dict
    ) -> Dict:
        """
        Adapt generic playbook for specific environment.

        TODO: Customize based on:
        - OS versions
        - Security tools present
        - Network architecture
        """
        pass
```

### Task 5: Exercise Orchestrator (45 min)

Build a system to orchestrate full purple team exercises.

```python
# starter/exercise_orchestrator.py
from scenario_generator import ScenarioGenerator
from safe_simulator import SafeRansomwareSimulator
from detection_validator import DetectionValidator
from emulation_playbook import AdversaryEmulationPlaybook

class PurpleTeamExercise:
    """
    Orchestrate ransomware purple team exercises.

    TODO: Implement full exercise lifecycle:
    1. Planning phase
    2. Execution phase
    3. Detection validation
    4. Gap analysis
    5. Reporting
    """

    def __init__(self):
        self.scenario_gen = ScenarioGenerator()
        self.validator = DetectionValidator()
        self.playbook_gen = AdversaryEmulationPlaybook()

    def plan_exercise(
        self,
        scope: Dict,
        objectives: List[str],
        ransomware_families: List[str]
    ) -> Dict:
        """
        Plan a purple team exercise.

        TODO: Generate:
        - Timeline
        - Test cases
        - Success criteria
        - Safety checks
        """
        pass

    def execute_phase(
        self,
        phase_name: str,
        steps: List[Dict]
    ) -> Dict:
        """Execute a phase of the exercise."""
        pass

    def validate_detections(self) -> Dict:
        """Validate all expected detections."""
        pass

    def generate_final_report(self) -> str:
        """
        Generate comprehensive exercise report.

        TODO: Include:
        - Executive summary
        - Techniques tested
        - Detection results
        - Gap analysis
        - Recommendations
        """
        pass
```

## Success Criteria

- [ ] Scenario generator creates realistic, MITRE-mapped scenarios
- [ ] Simulator operates safely in designated directories only
- [ ] All simulation activities are fully logged
- [ ] Detection validator accurately measures detection coverage
- [ ] Generated playbooks follow ethical guidelines
- [ ] Exercise orchestrator runs end-to-end successfully

## Sample Data

- `data/threat_intel/` - Threat intelligence on ransomware families
- `data/attack_chains/` - Real-world attack chain documentation
- `data/detection_rules/` - Sample detection rules for validation
- `data/playbook_templates/` - Adversary emulation templates

## Resources

- [MITRE ATT&CK: Ransomware](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [Purple Team Exercise Framework](https://github.com/scythe-io/purple-team-exercise-framework)

## Safety Reminders

1. **Never run on production systems** without explicit authorization
2. **Always use isolated test environments**
3. **Document all activities** for audit purposes
4. **Have recovery procedures** ready before testing
5. **Coordinate with security team** before exercises
6. **Use kill switches** to stop simulation if needed

## Extension Challenges

1. **Automated Purple Team**: Build fully automated exercise pipeline
2. **ML-Based Evasion Testing**: Test detection robustness
3. **Multi-Stage Exercises**: Chain multiple ransomware families
4. **Real-Time Collaboration**: Build blue team visibility dashboard

---

> **Stuck?** See the [Lab 12 Walkthrough](../../docs/walkthroughs/lab12-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 13 - AI-Powered Memory Forensics](../lab13-memory-forensics-ai/)
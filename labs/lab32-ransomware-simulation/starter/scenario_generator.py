#!/usr/bin/env python3
"""
Lab 12: Ransomware Attack Scenario Generator
--------------------------------------------
AI-powered generation of realistic ransomware attack scenarios for purple team exercises.

This module uses Claude to generate attack scenarios based on:
- Real ransomware families (LockBit, BlackCat, Conti, etc.)
- MITRE ATT&CK techniques
- Customizable complexity levels
- Detection opportunity mapping

Author: AI Security Training Labs

ETHICAL REQUIREMENTS:
- Use ONLY in authorized test environments
- Never deploy on production systems without authorization
- Document all activities for audit purposes
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None


class RansomwareFamily(Enum):
    """Known ransomware families for emulation."""

    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CONTI = "conti"
    REVIL = "revil"
    RYUK = "ryuk"
    CUSTOM = "custom"


class Complexity(Enum):
    """Scenario complexity levels."""

    LOW = "low"  # Single technique, basic detection
    MEDIUM = "medium"  # Multiple techniques, some evasion
    HIGH = "high"  # Full attack chain, advanced evasion


@dataclass
class AttackScenario:
    """A ransomware attack scenario for testing."""

    family: RansomwareFamily
    complexity: Complexity
    initial_access: str
    execution_chain: List[str]
    persistence_methods: List[str]
    lateral_movement: List[str]
    exfiltration: bool
    encryption_targets: List[str]
    mitre_techniques: List[str]
    detection_opportunities: List[str]
    expected_artifacts: List[str]
    estimated_duration_minutes: int = 30


@dataclass
class DetectionTest:
    """A specific detection test case."""

    name: str
    technique_id: str
    description: str
    simulation_command: str
    expected_detection: str
    detection_source: str  # SIEM, EDR, etc.


class ScenarioGenerator:
    """
    AI-powered ransomware scenario generator.

    Generates realistic attack scenarios based on:
    - Threat intelligence about ransomware families
    - MITRE ATT&CK framework techniques
    - Environment-specific customization
    - Detection validation requirements
    """

    # MITRE ATT&CK techniques commonly used by ransomware
    RANSOMWARE_TECHNIQUES = {
        "initial_access": ["T1566", "T1190", "T1133"],  # Phishing, Exploit, RDP
        "execution": ["T1059", "T1047", "T1053"],  # Script, WMI, Scheduled Task
        "persistence": ["T1547", "T1053", "T1543"],  # Registry, Task, Service
        "discovery": ["T1082", "T1083", "T1135"],  # System, File, Network Share
        "lateral": ["T1021", "T1570", "T1080"],  # RDP/SMB, Lateral Tool, Taint
        "collection": ["T1560", "T1074"],  # Archive, Data Staged
        "exfiltration": ["T1567", "T1048"],  # Web Service, Exfil Over C2
        "impact": ["T1486", "T1490", "T1489"],  # Encrypt, Shadow Del, Stop Svc
    }

    # Family-specific TTPs
    FAMILY_TTPS = {
        RansomwareFamily.LOCKBIT: {
            "initial_access": "Phishing with macro-enabled documents",
            "lateral": ["PsExec", "WMI", "Group Policy"],
            "signature": "High-speed encryption, double extortion",
            "techniques": ["T1486", "T1490", "T1021.002", "T1059.001"],
        },
        RansomwareFamily.BLACKCAT: {
            "initial_access": "Compromised credentials, vulnerable VPN",
            "lateral": ["RDP", "SMB", "Cobalt Strike"],
            "signature": "Cross-platform (Rust), triple extortion",
            "techniques": ["T1486", "T1567", "T1048", "T1059.001"],
        },
        RansomwareFamily.CONTI: {
            "initial_access": "TrickBot/BazarLoader",
            "lateral": ["Cobalt Strike", "PsExec"],
            "signature": "Manual operation, selective encryption",
            "techniques": ["T1486", "T1490", "T1059.001", "T1047"],
        },
    }

    def __init__(self):
        """Initialize the scenario generator."""
        if Anthropic:
            self.client = Anthropic()
        else:
            self.client = None
            print("Warning: anthropic package not installed. LLM features disabled.")

    def generate_scenario(
        self,
        family: RansomwareFamily,
        complexity: Complexity = Complexity.MEDIUM,
        include_exfil: bool = True,
        target_os: str = "windows",
    ) -> AttackScenario:
        """
        Generate a ransomware attack scenario.

        Creates a detailed attack scenario based on the specified family
        and complexity level, including all phases of the attack chain.

        Args:
            family: Ransomware family to emulate
            complexity: Scenario complexity level
            include_exfil: Whether to include data exfiltration phase
            target_os: Target operating system (windows, linux)

        Returns:
            Complete AttackScenario with all phases

        # TODO: Ask your AI assistant:
        # "Write Python code to generate a ransomware attack scenario.
        # Use FAMILY_TTPS to get family-specific techniques. Build the
        # attack chain from initial access through impact. Include
        # detection opportunities at each phase. Map to MITRE ATT&CK IDs."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_scenario_with_llm(
        self,
        family: RansomwareFamily,
        complexity: Complexity,
        environment: Dict,
    ) -> AttackScenario:
        """
        Use Claude to generate a sophisticated scenario.

        Args:
            family: Ransomware family to emulate
            complexity: Scenario complexity level
            environment: Target environment details

        Returns:
            LLM-generated attack scenario

        # TODO: Ask your AI assistant:
        # "Write Python code to use Claude API for scenario generation.
        # Create a prompt asking Claude to generate a realistic attack
        # scenario for the specified family, considering the target
        # environment. Parse the structured response into AttackScenario."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_detection_tests(self, scenario: AttackScenario) -> List[DetectionTest]:
        """
        Generate specific tests for each detection opportunity.

        Creates testable detection cases that can be used to validate
        security controls against the scenario's techniques.

        Args:
            scenario: Attack scenario to create tests for

        Returns:
            List of DetectionTest objects

        # TODO: Ask your AI assistant:
        # "Write Python code to generate detection tests from a scenario.
        # For each detection_opportunity in the scenario, create a
        # DetectionTest with a safe simulation command, expected
        # detection rule/alert, and the detection source (EDR/SIEM)."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_atomic_tests(self, scenario: AttackScenario) -> List[Dict]:
        """
        Generate Atomic Red Team-style tests.

        Creates atomic (single-technique) tests that can be executed
        independently to validate specific detection capabilities.

        Args:
            scenario: Attack scenario to break into atomic tests

        Returns:
            List of atomic test definitions

        # TODO: Ask your AI assistant:
        # "Write Python code to generate Atomic Red Team-style tests.
        # For each MITRE technique in the scenario, create an atomic
        # test with: technique_id, name, description, executor (cmd/ps),
        # command, cleanup_command, and dependencies."
        #
        # Then review and test the generated code.
        """
        pass

    def customize_for_environment(
        self, scenario: AttackScenario, environment: Dict
    ) -> AttackScenario:
        """
        Customize scenario for specific environment.

        Adapts generic scenario to environment-specific details like
        OS versions, security tools, and network architecture.

        Args:
            scenario: Base attack scenario
            environment: Environment details (OS, security tools, etc.)

        Returns:
            Environment-specific scenario

        # TODO: Ask your AI assistant:
        # "Write Python code to customize an attack scenario for an
        # environment. Modify techniques based on OS version, adjust
        # lateral movement based on network architecture, and consider
        # installed security tools that might detect/block techniques."
        #
        # Then review and test the generated code.
        """
        pass

    def export_to_caldera(self, scenario: AttackScenario) -> Dict:
        """
        Export scenario to CALDERA adversary format.

        Args:
            scenario: Attack scenario to export

        Returns:
            CALDERA-compatible adversary profile

        # TODO: Ask your AI assistant:
        # "Write Python code to export a scenario to CALDERA format.
        # Create an adversary profile with phases mapped to CALDERA
        # abilities. Include technique IDs and execution commands."
        #
        # Then review and test the generated code.
        """
        pass


def main():
    """Demo the scenario generator."""
    generator = ScenarioGenerator()

    # Generate a LockBit scenario
    print("Generating LockBit attack scenario...")
    scenario = generator.generate_scenario(
        family=RansomwareFamily.LOCKBIT,
        complexity=Complexity.MEDIUM,
        include_exfil=True,
        target_os="windows",
    )

    if scenario:
        print(f"\nScenario: {scenario.family.value} ({scenario.complexity.value})")
        print(f"Initial Access: {scenario.initial_access}")
        print(f"MITRE Techniques: {scenario.mitre_techniques}")
        print(f"Detection Opportunities: {scenario.detection_opportunities}")

        # Generate detection tests
        tests = generator.generate_detection_tests(scenario)
        print(f"\nGenerated {len(tests)} detection tests")


if __name__ == "__main__":
    main()

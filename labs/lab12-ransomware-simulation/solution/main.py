#!/usr/bin/env python3
"""
Lab 12: Ransomware Attack Simulation & Purple Team
Complete solution implementation.

ETHICAL NOTICE: This code is for AUTHORIZED TESTING ONLY.
Only use in isolated test environments with proper authorization.

=============================================================================
OVERVIEW
=============================================================================

This lab teaches Purple Team methodologies - the combination of red team
(offensive) and blue team (defensive) skills to improve security posture.
We simulate ransomware behaviors SAFELY to test and validate detections.

KEY CONCEPTS:

1. PURPLE TEAM OPERATIONS
   - Red + Blue working together
   - Controlled adversary emulation
   - Detection validation
   - Gap analysis and improvement

2. SAFE SIMULATION PRINCIPLES
   - NEVER deploy actual ransomware
   - Use safe proxies (file renaming, not encryption)
   - Operate only in designated test environments
   - Full audit logging of all actions
   - Automatic cleanup after exercises

3. RANSOMWARE TTPs (Tactics, Techniques, Procedures)
   - T1486: Data Encrypted for Impact
   - T1490: Inhibit System Recovery (shadow copy deletion)
   - T1082: System Information Discovery
   - T1567: Exfiltration Over Web Service

4. DETECTION VALIDATION
   - Test each TTP against your detection stack
   - Measure detection coverage
   - Identify gaps and prioritize improvements

LEARNING OBJECTIVES:
- Understand purple team methodologies
- Learn safe adversary emulation techniques
- Practice detection validation workflows
- Build gap analysis capabilities

SAFETY FEATURES IN THIS CODE:
- Target directory validation (temp/test dirs only)
- No actual encryption (just file renaming)
- No destructive operations
- Comprehensive audit logging
- Automatic cleanup

RANSOMWARE FAMILIES SIMULATED:
- LockBit: Fast encryption, double extortion
- BlackCat: Rust-based, cross-platform
- Conti: Manual operation phase
- REvil: High-profile enterprise targeting
- Ryuk: Big game hunting

=============================================================================
"""

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# Load environment variables
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# Multi-Provider LLM Support
# =============================================================================
#
# This lab supports multiple LLM providers:
# - Anthropic (Claude): Default, high-quality reasoning
# - OpenAI (GPT-4): Widely available, good performance
# - Gemini (Google): Good for long context, competitive pricing
#
# Set the appropriate environment variable:
# - ANTHROPIC_API_KEY for Claude
# - OPENAI_API_KEY for GPT-4
# - GOOGLE_API_KEY for Gemini
#
# =============================================================================

try:
    from anthropic import Anthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai

    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


def get_llm_client(provider: str = "auto"):
    """
    Get an LLM client based on provider preference.

    Args:
        provider: LLM provider to use. Options:
            - "auto": Try providers in order (anthropic, openai, gemini)
            - "anthropic": Use Claude
            - "openai": Use GPT-4
            - "gemini": Use Gemini

    Returns:
        Tuple of (client, provider_name, model_name)
    """
    providers_to_try = (
        ["anthropic", "openai", "gemini"] if provider == "auto" else [provider]
    )

    for prov in providers_to_try:
        if prov == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key and ANTHROPIC_AVAILABLE:
                return Anthropic(), "anthropic", "claude-sonnet-4-20250514"

        elif prov == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key and OPENAI_AVAILABLE:
                return OpenAI(), "openai", "gpt-4-turbo"

        elif prov == "gemini":
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key and GEMINI_AVAILABLE:
                genai.configure(api_key=api_key)
                return (
                    genai.GenerativeModel("gemini-1.5-pro"),
                    "gemini",
                    "gemini-1.5-pro",
                )

    raise ValueError(
        "No LLM provider available. Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY"
    )


def call_llm(
    client: Any, provider: str, model: str, prompt: str, max_tokens: int = 2048
) -> str:
    """
    Call LLM with provider-specific API.

    Args:
        client: The LLM client
        provider: Provider name (anthropic, openai, gemini)
        model: Model name
        prompt: The prompt to send
        max_tokens: Maximum tokens in response

    Returns:
        The LLM response text
    """
    if provider == "anthropic":
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    elif provider == "openai":
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content

    elif provider == "gemini":
        response = client.generate_content(prompt)
        return response.text

    else:
        raise ValueError(f"Unknown provider: {provider}")


# =============================================================================
# Enums and Data Classes
# =============================================================================
#
# DATA MODELING FOR PURPLE TEAM:
#
# Using Python dataclasses and enums provides:
# 1. Type safety and IDE autocompletion
# 2. Self-documenting code structure
# 3. Consistent data structures across the system
#
# KEY DATA STRUCTURES:
#
# - RansomwareFamily: Known ransomware variants we can emulate
# - DetectionStatus: Track test results (detected/missed/partial)
# - AttackScenario: Complete attack playbook definition
# - SimulationConfig: Safety settings for the simulator
# - DetectionTest: Individual test case definition
# - TestResult: Outcome of running a detection test
#
# =============================================================================


# Ransomware families we can simulate (each has unique TTPs)
class RansomwareFamily(Enum):
    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CONTI = "conti"
    REVIL = "revil"
    RYUK = "ryuk"
    CUSTOM = "custom"


class DetectionStatus(Enum):
    DETECTED = "detected"
    MISSED = "missed"
    PARTIAL = "partial"
    PENDING = "pending"


@dataclass
class AttackScenario:
    """A ransomware attack scenario for testing."""

    family: RansomwareFamily
    name: str
    description: str
    initial_access: str
    execution_chain: List[str]
    persistence_methods: List[str]
    discovery_techniques: List[str]
    lateral_movement: List[str]
    exfiltration: bool
    encryption_targets: List[str]
    mitre_techniques: List[str]
    detection_opportunities: List[str]
    expected_artifacts: List[str]


@dataclass
class SimulationConfig:
    """Configuration for safe ransomware simulation."""

    target_directory: str
    file_extensions: List[str] = field(
        default_factory=lambda: [".txt", ".docx", ".xlsx"]
    )
    create_ransom_note: bool = True
    simulate_encryption: bool = True
    simulate_shadow_delete: bool = True
    cleanup_after: bool = True
    log_all_actions: bool = True


@dataclass
class DetectionTest:
    """A single detection test case."""

    name: str
    technique_id: str
    description: str
    simulation_command: str
    expected_detection: str
    detection_source: str


@dataclass
class TestResult:
    """Result of a detection test."""

    test: DetectionTest
    status: DetectionStatus
    detection_time_ms: Optional[float] = None
    alert_generated: bool = False
    notes: str = ""


# =============================================================================
# Scenario Generator
# =============================================================================


class ScenarioGenerator:
    """AI-powered ransomware scenario generator."""

    FAMILY_PROFILES = {
        RansomwareFamily.LOCKBIT: {
            "description": "Fast-encrypting RaaS with double extortion",
            "initial_access": ["Phishing", "RDP Brute Force", "Exploit Public Apps"],
            "techniques": ["T1486", "T1490", "T1021.001", "T1059.001", "T1082"],
            "lateral": ["PsExec", "WMI", "RDP"],
            "exfiltration": True,
        },
        RansomwareFamily.BLACKCAT: {
            "description": "Rust-based ransomware with cross-platform capability",
            "initial_access": ["Phishing", "Compromised Credentials"],
            "techniques": ["T1486", "T1490", "T1567", "T1048", "T1070"],
            "lateral": ["SMB", "SSH", "Cobalt Strike"],
            "exfiltration": True,
        },
        RansomwareFamily.CONTI: {
            "description": "Prolific RaaS operation with manual operation phase",
            "initial_access": ["TrickBot", "BazarLoader", "Phishing"],
            "techniques": ["T1486", "T1490", "T1059.001", "T1047", "T1018"],
            "lateral": ["Cobalt Strike", "PsExec", "RDP"],
            "exfiltration": True,
        },
        RansomwareFamily.REVIL: {
            "description": "High-profile RaaS targeting enterprises",
            "initial_access": ["Supply Chain", "Exploit", "Phishing"],
            "techniques": ["T1486", "T1490", "T1082", "T1083", "T1489"],
            "lateral": ["PsExec", "WMI"],
            "exfiltration": True,
        },
        RansomwareFamily.RYUK: {
            "description": "Big game hunting ransomware",
            "initial_access": ["Emotet", "TrickBot", "Phishing"],
            "techniques": ["T1486", "T1490", "T1047", "T1059.003", "T1036"],
            "lateral": ["PsExec", "WMI", "SMB"],
            "exfiltration": False,
        },
    }

    def __init__(self, provider: str = "auto"):
        """
        Initialize scenario generator.

        Args:
            provider: LLM provider ("auto", "anthropic", "openai", "gemini")
        """
        self.client, self.provider, self.model = get_llm_client(provider)

    def generate_scenario(
        self,
        family: RansomwareFamily,
        complexity: str = "medium",
        include_exfil: bool = True,
        target_os: str = "windows",
    ) -> AttackScenario:
        """Generate a ransomware attack scenario."""
        profile = self.FAMILY_PROFILES.get(
            family, self.FAMILY_PROFILES[RansomwareFamily.LOCKBIT]
        )

        # Build execution chain based on complexity
        execution_chain = []
        if complexity in ["medium", "high"]:
            execution_chain.extend(
                [
                    "Initial loader drops secondary payload",
                    "Payload establishes C2 communication",
                    "Discovery commands enumerate environment",
                ]
            )
        if complexity == "high":
            execution_chain.extend(
                [
                    "Credential harvesting via Mimikatz/LSASS",
                    "Lateral movement to high-value targets",
                    "Domain admin escalation attempt",
                ]
            )
        execution_chain.append("Ransomware binary execution")

        # Build detection opportunities
        detection_opportunities = [
            f"Initial access via {profile['initial_access'][0]}",
            "Suspicious process spawning patterns",
            "Unusual file system enumeration",
            "Shadow copy deletion commands",
            "Mass file extension changes",
            "Ransom note file creation",
        ]

        if include_exfil:
            detection_opportunities.insert(-2, "Large outbound data transfer")

        return AttackScenario(
            family=family,
            name=f"{family.value.upper()} Simulation",
            description=profile["description"],
            initial_access=profile["initial_access"][0],
            execution_chain=execution_chain,
            persistence_methods=["Registry Run Key", "Scheduled Task"],
            discovery_techniques=[
                "System Info",
                "Network Share Enum",
                "File Discovery",
            ],
            lateral_movement=profile["lateral"],
            exfiltration=include_exfil and profile["exfiltration"],
            encryption_targets=["Documents", "Database Files", "Backups"],
            mitre_techniques=profile["techniques"],
            detection_opportunities=detection_opportunities,
            expected_artifacts=[
                "Ransom note files",
                "Encrypted file extensions",
                "Event log entries",
                "Registry modifications",
            ],
        )

    def generate_detection_tests(self, scenario: AttackScenario) -> List[DetectionTest]:
        """Generate specific tests for each detection opportunity."""
        tests = []

        # T1490 - Inhibit System Recovery
        tests.append(
            DetectionTest(
                name="Shadow Copy Deletion Detection",
                technique_id="T1490",
                description="Detect VSS shadow copy deletion attempts",
                simulation_command="echo 'vssadmin delete shadows /all /quiet'",
                expected_detection="Alert on vssadmin delete shadows command",
                detection_source="EDR/SIEM",
            )
        )

        # T1486 - Data Encrypted for Impact
        tests.append(
            DetectionTest(
                name="Mass File Encryption Detection",
                technique_id="T1486",
                description="Detect rapid file modification with high entropy",
                simulation_command="Rename files with .encrypted extension",
                expected_detection="Alert on mass file extension changes",
                detection_source="EDR",
            )
        )

        # T1082 - System Information Discovery
        tests.append(
            DetectionTest(
                name="System Discovery Detection",
                technique_id="T1082",
                description="Detect system enumeration commands",
                simulation_command="echo 'systeminfo && hostname && whoami'",
                expected_detection="Alert on discovery command sequence",
                detection_source="SIEM",
            )
        )

        if scenario.exfiltration:
            # T1567 - Exfiltration Over Web Service
            tests.append(
                DetectionTest(
                    name="Data Exfiltration Detection",
                    technique_id="T1567",
                    description="Detect large outbound data transfers",
                    simulation_command="Simulate large file upload",
                    expected_detection="Alert on unusual outbound transfer",
                    detection_source="Network/DLP",
                )
            )

        return tests


# =============================================================================
# Safe Simulator
# =============================================================================
#
# SAFE ADVERSARY EMULATION:
#
# The key principle is to simulate BEHAVIORS, not actual malicious code.
# This allows security teams to test detections without risk.
#
# WHAT WE SIMULATE:
#
# 1. FILE ENUMERATION (T1083)
#    - Ransomware scans for files to encrypt
#    - We log what would be targeted
#
# 2. ENCRYPTION (T1486)
#    - Instead of encrypting, we RENAME files with .encrypted extension
#    - This triggers the same file system events
#    - No data is lost or modified
#
# 3. SHADOW COPY DELETION (T1490)
#    - We LOG the commands that would be run
#    - We do NOT actually delete shadow copies
#
# 4. RANSOM NOTE CREATION
#    - Create actual ransom note files (harmless text)
#    - Tests file creation detection rules
#
# SAFETY VALIDATION:
# - _validate_config() ensures we only operate in safe directories
# - Allowed: /tmp, tempfile.gettempdir(), /opt/purple_team
# - Rejected: Any other path (raises ValueError)
#
# AUDIT LOGGING:
# - Every action is logged with timestamp
# - Log can be exported for SIEM testing
# - Full traceability of simulation
#
# =============================================================================


class SafeRansomwareSimulator:
    """
    Safe ransomware behavior simulator for purple team.

    SAFETY FEATURES:
    - Only operates in designated test directories
    - No actual encryption (just file renaming)
    - No destructive operations
    - Full audit logging
    - Automatic cleanup
    """

    def __init__(self, config: SimulationConfig):
        self.config = config
        self.audit_log: List[Dict] = []
        self.created_files: List[str] = []
        self.original_files: Dict[str, str] = {}

        # Validate safe directory
        self._validate_config()

    def _validate_config(self):
        """Ensure simulation is in safe directory."""
        target = Path(self.config.target_directory).resolve()

        # Must be in temp or explicitly marked test directory
        allowed_prefixes = [
            Path(tempfile.gettempdir()),
            Path("/tmp"),
            Path("/opt/purple_team"),
        ]

        is_safe = any(
            str(target).startswith(str(prefix)) for prefix in allowed_prefixes
        )

        if not is_safe:
            raise ValueError(
                f"Target directory must be in temp or designated test area. "
                f"Got: {target}"
            )

        # Create if doesn't exist
        target.mkdir(parents=True, exist_ok=True)

    def _log_action(self, action: str, details: Dict):
        """Log all simulation actions."""
        entry = {"timestamp": datetime.now().isoformat(), "action": action, **details}
        self.audit_log.append(entry)
        if self.config.log_all_actions:
            print(f"[SIM] {action}: {details}")

    def setup_test_files(self, num_files: int = 10) -> List[str]:
        """Create test files for simulation."""
        files = []
        target_dir = Path(self.config.target_directory)

        for i in range(num_files):
            for ext in self.config.file_extensions:
                filename = f"test_file_{i}{ext}"
                filepath = target_dir / filename
                filepath.write_text(f"Test content for {filename}\n" * 100)
                files.append(str(filepath))
                self.created_files.append(str(filepath))

        self._log_action("SETUP", {"files_created": len(files)})
        return files

    def simulate_file_enumeration(self) -> List[str]:
        """Simulate ransomware file discovery."""
        target_dir = Path(self.config.target_directory)
        discovered = []

        for ext in self.config.file_extensions:
            for filepath in target_dir.glob(f"*{ext}"):
                discovered.append(str(filepath))
                self._log_action("ENUMERATE", {"file": str(filepath)})

        return discovered

    def simulate_encryption(self, files: List[str]) -> Dict:
        """
        Simulate encryption by renaming files.

        SAFE: Does not actually encrypt, just renames
        with .encrypted extension for testing.
        """
        if not self.config.simulate_encryption:
            return {"simulated": False, "files_affected": 0}

        affected = 0
        for filepath in files:
            original = Path(filepath)
            if original.exists():
                new_name = str(original) + ".encrypted"
                self.original_files[new_name] = str(original)

                # Rename to simulate encryption
                shutil.move(str(original), new_name)
                affected += 1

                self._log_action(
                    "ENCRYPT_SIM", {"original": str(original), "encrypted": new_name}
                )

        return {"simulated": True, "files_affected": affected}

    def simulate_shadow_deletion(self) -> Dict:
        """
        Simulate VSS deletion (logging only).

        SAFE: Only logs the commands that would be run,
        does not execute them.
        """
        if not self.config.simulate_shadow_delete:
            return {"simulated": False}

        commands = [
            "vssadmin delete shadows /all /quiet",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
        ]

        for cmd in commands:
            self._log_action(
                "SHADOW_DELETE_SIM",
                {
                    "command": cmd,
                    "executed": False,
                    "note": "SIMULATION ONLY - command not executed",
                },
            )

        return {"simulated": True, "commands": commands}

    def create_ransom_note(self, template: str = "default") -> str:
        """Create a sample ransom note for detection testing."""
        if not self.config.create_ransom_note:
            return ""

        note_content = """
=== SIMULATION RANSOM NOTE ===
This is a SIMULATED ransom note for purple team testing.
No actual ransomware was deployed.

This file should trigger detection rules for:
- Ransom note file creation
- Suspicious file naming patterns

Test ID: PURPLE-TEAM-{timestamp}
=== END SIMULATION ===
""".format(
            timestamp=datetime.now().strftime("%Y%m%d-%H%M%S")
        )

        note_paths = [
            Path(self.config.target_directory) / "README_RESTORE_FILES.txt",
            Path(self.config.target_directory) / "HOW_TO_DECRYPT.txt",
        ]

        for note_path in note_paths:
            note_path.write_text(note_content)
            self.created_files.append(str(note_path))
            self._log_action("RANSOM_NOTE", {"path": str(note_path)})

        return str(note_paths[0])

    def generate_telemetry(self) -> List[Dict]:
        """Generate telemetry events for SIEM testing."""
        telemetry = []

        for entry in self.audit_log:
            event = {
                "timestamp": entry["timestamp"],
                "event_type": "file_simulation",
                "action": entry["action"],
                "source": "purple_team_simulator",
                "severity": "info" if entry["action"] == "ENUMERATE" else "high",
                "details": entry,
            }
            telemetry.append(event)

        return telemetry

    def cleanup(self):
        """Restore all files to original state."""
        if not self.config.cleanup_after:
            self._log_action("CLEANUP_SKIPPED", {})
            return

        # Restore renamed files
        for encrypted, original in self.original_files.items():
            if Path(encrypted).exists():
                shutil.move(encrypted, original)
                self._log_action("RESTORE", {"file": original})

        # Remove created test files
        for filepath in self.created_files:
            if Path(filepath).exists():
                Path(filepath).unlink()
                self._log_action("DELETE_TEST_FILE", {"file": filepath})

        self._log_action(
            "CLEANUP_COMPLETE",
            {
                "files_restored": len(self.original_files),
                "files_deleted": len(self.created_files),
            },
        )


# =============================================================================
# Detection Validator
# =============================================================================
#
# DETECTION VALIDATION FRAMEWORK:
#
# After running simulations, we need to validate whether our security
# tools actually detected the activity. This is the core of purple team.
#
# THE VALIDATION WORKFLOW:
#
# 1. EXECUTE: Run a simulation (e.g., simulate encryption)
# 2. WAIT: Allow time for detection systems to process
# 3. QUERY: Check SIEM/EDR for alerts
# 4. RECORD: Document detection status (DETECTED/MISSED/PARTIAL)
# 5. ANALYZE: Calculate coverage and identify gaps
#
# DETECTION STATUSES:
#
# - DETECTED: Alert generated, correct technique identified
# - PARTIAL: Alert generated, but missing context
# - MISSED: No alert generated
# - PENDING: Waiting for validation
#
# GAP ANALYSIS:
# The generate_gap_analysis() method calculates:
# - Detection coverage percentage
# - List of missed techniques
# - Prioritized improvement recommendations
#
# =============================================================================


class DetectionValidator:
    """Validate detection capabilities against ransomware TTPs."""

    def __init__(self):
        self.results: List[TestResult] = []

    def run_test(
        self, test: DetectionTest, simulator: SafeRansomwareSimulator
    ) -> TestResult:
        """Run a single detection test."""
        # In a real implementation, this would:
        # 1. Execute the simulation
        # 2. Wait for detection window
        # 3. Query SIEM/EDR for alerts

        # For demo, we simulate the check
        result = TestResult(
            test=test,
            status=DetectionStatus.PENDING,
            notes="Test executed - check detection systems",
        )

        self.results.append(result)
        return result

    def generate_gap_analysis(self) -> Dict:
        """Analyze detection gaps."""
        total = len(self.results)
        detected = sum(1 for r in self.results if r.status == DetectionStatus.DETECTED)
        missed = sum(1 for r in self.results if r.status == DetectionStatus.MISSED)
        partial = sum(1 for r in self.results if r.status == DetectionStatus.PARTIAL)

        return {
            "total_tests": total,
            "detected": detected,
            "missed": missed,
            "partial": partial,
            "coverage_percentage": (detected / total * 100) if total > 0 else 0,
            "missed_techniques": [
                r.test.technique_id
                for r in self.results
                if r.status == DetectionStatus.MISSED
            ],
        }


# =============================================================================
# Exercise Orchestrator
# =============================================================================
#
# PURPLE TEAM EXERCISE MANAGEMENT:
#
# The orchestrator coordinates all components of a purple team exercise:
# - Scenario generation
# - Simulation execution
# - Detection validation
# - Report generation
#
# EXERCISE PHASES:
#
# 1. PREPARATION (30 min)
#    - Select ransomware family to emulate
#    - Configure simulation parameters
#    - Brief blue team (optional - depends on exercise type)
#
# 2. EXECUTION (60 min)
#    - Run simulations in controlled environment
#    - Generate telemetry for SIEM/EDR
#    - Document all actions
#
# 3. DETECTION VALIDATION (30 min)
#    - Query security tools for alerts
#    - Validate detection accuracy
#    - Record results
#
# 4. GAP ANALYSIS (30 min)
#    - Calculate coverage metrics
#    - Identify missed detections
#    - Prioritize improvements
#
# 5. REPORTING (30 min)
#    - Generate executive summary
#    - Document technical findings
#    - Recommend next steps
#
# AI-POWERED REPORTING:
# We use Claude to generate professional reports from exercise data.
# The LLM synthesizes technical findings into actionable recommendations.
#
# =============================================================================


class PurpleTeamExercise:
    """Orchestrate ransomware purple team exercises."""

    def __init__(self, provider: str = "auto"):
        """
        Initialize purple team exercise orchestrator.

        Args:
            provider: LLM provider ("auto", "anthropic", "openai", "gemini")
        """
        self.scenario_gen = ScenarioGenerator(provider=provider)
        self.validator = DetectionValidator()
        self.client, self.provider, self.model = get_llm_client(provider)

    def plan_exercise(
        self, ransomware_family: RansomwareFamily, complexity: str = "medium"
    ) -> Dict:
        """Plan a purple team exercise."""
        scenario = self.scenario_gen.generate_scenario(
            family=ransomware_family, complexity=complexity
        )

        tests = self.scenario_gen.generate_detection_tests(scenario)

        return {
            "scenario": scenario,
            "tests": tests,
            "phases": [
                {"name": "Preparation", "duration": "30 min"},
                {"name": "Execution", "duration": "60 min"},
                {"name": "Detection Validation", "duration": "30 min"},
                {"name": "Gap Analysis", "duration": "30 min"},
                {"name": "Reporting", "duration": "30 min"},
            ],
        }

    def generate_report(self, exercise_results: Dict) -> str:
        """Generate exercise report using configured LLM provider."""
        prompt = f"""Generate a purple team exercise report based on these results:

EXERCISE SUMMARY:
{json.dumps(exercise_results, indent=2, default=str)}

Create a professional report with:
1. Executive Summary
2. Objectives and Scope
3. Attack Scenario Overview
4. Detection Results
5. Gap Analysis
6. Recommendations
7. Next Steps"""

        return call_llm(self.client, self.provider, self.model, prompt, max_tokens=2048)


# =============================================================================
# Demo
# =============================================================================


def main():
    """Demo the ransomware simulation framework."""
    print("=" * 60)
    print("Lab 12: Ransomware Attack Simulation & Purple Team")
    print("=" * 60)
    print("\n[!] ETHICAL NOTICE: For authorized testing only\n")

    # Create exercise plan
    print("[1] Planning Exercise...")
    exercise = PurpleTeamExercise()
    plan = exercise.plan_exercise(
        ransomware_family=RansomwareFamily.LOCKBIT, complexity="medium"
    )

    print(f"\nScenario: {plan['scenario'].name}")
    print(f"Description: {plan['scenario'].description}")
    print(f"\nMITRE Techniques:")
    for tech in plan["scenario"].mitre_techniques:
        print(f"  - {tech}")

    print(f"\nDetection Tests: {len(plan['tests'])}")
    for test in plan["tests"]:
        print(f"  - [{test.technique_id}] {test.name}")

    # Run safe simulation
    print("\n[2] Running Safe Simulation...")
    with tempfile.TemporaryDirectory() as tmpdir:
        config = SimulationConfig(
            target_directory=tmpdir,
            simulate_encryption=True,
            simulate_shadow_delete=True,
            create_ransom_note=True,
            cleanup_after=True,
        )

        simulator = SafeRansomwareSimulator(config)

        # Setup and run simulation
        files = simulator.setup_test_files(num_files=5)
        print(f"  Created {len(files)} test files")

        discovered = simulator.simulate_file_enumeration()
        print(f"  Enumerated {len(discovered)} files")

        encryption_result = simulator.simulate_encryption(discovered)
        print(f"  Simulated encryption of {encryption_result['files_affected']} files")

        shadow_result = simulator.simulate_shadow_deletion()
        print(f"  Simulated shadow deletion: {shadow_result['simulated']}")

        note_path = simulator.create_ransom_note()
        print(f"  Created ransom note: {note_path}")

        # Generate telemetry
        telemetry = simulator.generate_telemetry()
        print(f"\n[3] Generated {len(telemetry)} telemetry events")

        # Cleanup
        simulator.cleanup()
        print("\n[4] Cleanup complete")

    print("\n[5] Exercise Complete!")
    print("\nNext steps:")
    print("  1. Review detection system alerts")
    print("  2. Document which tests were detected")
    print("  3. Analyze gaps and improve detections")
    print("  4. Re-run exercise to validate improvements")


if __name__ == "__main__":
    main()

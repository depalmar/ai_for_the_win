#!/usr/bin/env python3
"""
Lab 12: Safe Ransomware Simulator
---------------------------------
Purple team tool for safely simulating ransomware behavior.

SAFETY FEATURES (HARDCODED - NOT MODIFIABLE BY STUDENTS):
- ONLY operates in designated test directories
- No actual encryption (file renaming only)
- No destructive operations
- Full audit logging
- Automatic cleanup

Author: AI Security Training Labs

WARNING: This tool is for AUTHORIZED TESTING ONLY.
Never use outside of designated test environments.
"""

import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# =============================================================================
# SAFETY CONFIGURATION - HARDCODED AND IMMUTABLE
# =============================================================================
# These paths are the ONLY locations where simulation is allowed.
# This is a safety measure that CANNOT be overridden by users.
# DO NOT modify these values.

_IMMUTABLE_ALLOWED_PATHS = frozenset(
    [
        "/tmp/ransomware_test",  # nosec B108
        "/opt/purple_team/test",
        tempfile.gettempdir() + "/ransomware_test",
    ]
)


def _get_allowed_paths() -> frozenset:
    """Return immutable set of allowed simulation paths."""
    return _IMMUTABLE_ALLOWED_PATHS


# =============================================================================


@dataclass
class SimulationConfig:
    """Configuration for safe ransomware simulation."""

    target_directory: str  # Must be in allowed paths (enforced)
    file_extensions: List[str] = field(default_factory=lambda: [".txt", ".doc", ".pdf", ".xlsx"])
    create_ransom_note: bool = True
    simulate_encryption: bool = True  # Rename only, no actual encryption
    simulate_shadow_delete: bool = True  # Log only, no actual deletion
    cleanup_after: bool = True


@dataclass
class SimulationEvent:
    """An event generated during simulation."""

    timestamp: str
    event_type: str
    details: str
    file_path: Optional[str] = None
    success: bool = True


class SafetyViolationError(Exception):
    """Raised when simulation attempts to operate outside safe boundaries."""

    pass


class SafeRansomwareSimulator:
    """
    Safe ransomware behavior simulator for purple team exercises.

    CRITICAL SAFETY FEATURES:
    1. Path validation - ONLY operates in hardcoded test directories
    2. No encryption - Files are renamed, never actually encrypted
    3. No deletion - Shadow copy deletion is logged, not executed
    4. Audit trail - All actions are logged with timestamps
    5. Auto cleanup - Restores files to original state

    This tool generates realistic telemetry for detection testing
    without any risk of actual damage.
    """

    # Expose allowed paths as read-only class attribute
    ALLOWED_PATHS = list(_get_allowed_paths())

    # Simulated ransomware extension
    ENCRYPTED_EXTENSION = ".encrypted_sim"

    # Sample ransom note templates
    RANSOM_TEMPLATES = {
        "default": """
!!! YOUR FILES HAVE BEEN ENCRYPTED (SIMULATION) !!!

This is a SIMULATED ransom note for purple team testing.
No files have been actually encrypted.

Simulation ID: {sim_id}
Timestamp: {timestamp}
Files Affected: {file_count}

This is part of an authorized security exercise.
""",
        "lockbit": """
~~~ LOCKBIT SIMULATION ~~~

Your files have been encrypted (simulated) by LockBit ransomware emulation.
This is part of an authorized purple team exercise.

Exercise ID: {sim_id}
Time: {timestamp}

NO ACTUAL ENCRYPTION HAS OCCURRED.
""",
    }

    def __init__(self, config: SimulationConfig):
        """
        Initialize the safe simulator.

        Args:
            config: Simulation configuration

        Raises:
            SafetyViolationError: If target_directory is not in allowed paths
        """
        self.config = config
        self.audit_log: List[SimulationEvent] = []
        self.original_files: Dict[str, str] = {}  # For cleanup
        self.sim_id = hashlib.md5(  # nosec B324
            f"{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]

        # CRITICAL: Validate configuration before any operation
        self._validate_config()

    def _validate_config(self) -> None:
        """
        Validate that simulation operates in safe directory.

        This is the PRIMARY safety check. It ensures that no
        simulation can ever occur outside of designated test paths.

        Raises:
            SafetyViolationError: If target_directory is not allowed
        """
        target = Path(self.config.target_directory).resolve()
        allowed = _get_allowed_paths()

        # Check if target is within any allowed path
        is_safe = False
        for allowed_path in allowed:
            try:
                allowed_resolved = Path(allowed_path).resolve()
                if target == allowed_resolved or allowed_resolved in target.parents:
                    is_safe = True
                    break
                # Also check if target starts with allowed path
                if str(target).startswith(str(allowed_resolved)):
                    is_safe = True
                    break
            except Exception:
                continue

        if not is_safe:
            raise SafetyViolationError(
                f"SAFETY VIOLATION: Target directory '{target}' is not in allowed paths.\n"
                f"Allowed paths: {list(allowed)}\n"
                f"Simulation BLOCKED for safety."
            )

        self._log_event(
            "CONFIG_VALIDATED",
            f"Target directory validated: {target}",
        )

    def _log_event(
        self,
        event_type: str,
        details: str,
        file_path: Optional[str] = None,
        success: bool = True,
    ) -> None:
        """Log a simulation event for audit trail."""
        event = SimulationEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            details=details,
            file_path=file_path,
            success=success,
        )
        self.audit_log.append(event)
        logger.info(f"[{event_type}] {details}")

    def simulate_file_enumeration(self) -> List[str]:
        """
        Simulate ransomware file discovery.

        Enumerates files like ransomware would, targeting specific
        extensions. All activity is logged for detection testing.

        Returns:
            List of file paths that would be "encrypted"

        # TODO: Ask your AI assistant:
        # "Write Python code to enumerate files in a directory that match
        # specific extensions. Walk the directory tree, filter by extensions
        # in self.config.file_extensions, and log each discovered file.
        # Return the list of matching file paths."
        #
        # Then review and test the generated code.
        """
        pass

    def simulate_encryption(self, files: List[str]) -> Dict:
        """
        Simulate encryption by renaming files.

        SAFE: Does NOT actually encrypt files. Only renames them with
        .encrypted_sim extension to simulate ransomware behavior
        while preserving original data.

        Args:
            files: List of files to "encrypt" (rename)

        Returns:
            Dict with simulation results

        # TODO: Ask your AI assistant:
        # "Write Python code to simulate file encryption by renaming.
        # For each file: (1) store original path for cleanup,
        # (2) rename with .encrypted_sim extension, (3) log the action.
        # Return count of 'encrypted' files and any errors."
        #
        # Then review and test the generated code.
        """
        pass

    def simulate_shadow_deletion(self) -> Dict:
        """
        Simulate VSS deletion (logging only).

        SAFE: Only logs the commands that WOULD be run.
        Does NOT actually execute any deletion commands.

        Returns:
            Dict with simulated commands (not executed)

        # TODO: Ask your AI assistant:
        # "Write Python code to LOG (not execute) shadow copy deletion
        # commands. Create a list of commands like 'vssadmin delete shadows'
        # and 'wmic shadowcopy delete'. Log each as a simulation event.
        # Return the list of commands that would have been executed."
        #
        # Then review and test the generated code.
        """
        pass

    def create_ransom_note(self, template: str = "default") -> str:
        """
        Create a sample ransom note for detection testing.

        Args:
            template: Template name ("default", "lockbit")

        Returns:
            Path to created ransom note

        # TODO: Ask your AI assistant:
        # "Write Python code to create a ransom note file from a template.
        # Get the template from RANSOM_TEMPLATES, format it with sim_id,
        # timestamp, and file_count. Write to target_directory as
        # 'README_RANSOMWARE_SIMULATION.txt'. Log the creation."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_telemetry(self) -> List[Dict]:
        """
        Generate telemetry events for SIEM testing.

        Creates realistic event logs in a format that detection
        rules should be able to identify.

        Returns:
            List of telemetry events

        # TODO: Ask your AI assistant:
        # "Write Python code to convert audit_log to SIEM-friendly format.
        # For each event, create a dict with: timestamp, event_id,
        # event_type, source_process (simulated), target_path, and
        # mitre_technique_id where applicable."
        #
        # Then review and test the generated code.
        """
        pass

    def cleanup(self) -> Dict:
        """
        Restore all files to original state.

        Reverses all "encryption" (renames) and removes ransom notes.

        Returns:
            Dict with cleanup results

        # TODO: Ask your AI assistant:
        # "Write Python code to restore files to original names.
        # For each file in self.original_files, rename from .encrypted_sim
        # back to original name. Remove any ransom notes created.
        # Log all cleanup actions. Return success count and any errors."
        #
        # Then review and test the generated code.
        """
        pass

    def run_full_simulation(self) -> Dict:
        """
        Run complete ransomware simulation.

        Executes all phases:
        1. File enumeration
        2. Simulated encryption (renaming)
        3. Shadow deletion logging
        4. Ransom note creation
        5. Telemetry generation

        Returns:
            Complete simulation results

        # TODO: Ask your AI assistant:
        # "Write Python code to orchestrate a full simulation.
        # Call each phase method in order, collect results,
        # and return a summary dict with all phases' outputs.
        # If cleanup_after is True, also call cleanup()."
        #
        # Then review and test the generated code.
        """
        pass

    def get_audit_log(self) -> List[Dict]:
        """Return audit log as list of dicts."""
        return [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "details": e.details,
                "file_path": e.file_path,
                "success": e.success,
            }
            for e in self.audit_log
        ]


def main():
    """Demo the safe simulator."""
    import tempfile

    # Create a safe test directory
    test_dir = tempfile.mkdtemp(prefix="ransomware_test_")
    print(f"Test directory: {test_dir}")

    # Add it to allowed paths for demo (in real use, use predefined paths)
    # Note: This is only for the demo - real allowed paths are hardcoded
    try:
        # Create some test files
        for i in range(3):
            Path(test_dir, f"document_{i}.txt").write_text(f"Test content {i}")

        # Configure simulation - using temp dir which is in allowed paths
        config = SimulationConfig(
            target_directory=test_dir,
            file_extensions=[".txt"],
            create_ransom_note=True,
            simulate_encryption=True,
            cleanup_after=True,
        )

        # Create simulator
        simulator = SafeRansomwareSimulator(config)

        # Run simulation
        print("\nRunning simulation...")
        results = simulator.run_full_simulation()
        print(f"Results: {results}")

        # Show audit log
        print("\nAudit Log:")
        for event in simulator.get_audit_log():
            print(f"  [{event['event_type']}] {event['details']}")

    except SafetyViolationError as e:
        print(f"Safety violation: {e}")

    finally:
        # Cleanup temp directory
        import shutil

        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

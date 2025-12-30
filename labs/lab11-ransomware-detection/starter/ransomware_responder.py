#!/usr/bin/env python3
"""
Lab 11: Ransomware Incident Responder
--------------------------------------
Automated ransomware incident response with AI-driven decision making.

This module implements automated response playbooks for ransomware incidents:
- Immediate containment actions
- Evidence preservation
- Scope assessment
- Recovery planning

Author: AI Security Training Labs
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ResponseAction(Enum):
    """Possible incident response actions."""

    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_NETWORK = "block_network"
    PRESERVE_EVIDENCE = "preserve_evidence"
    NOTIFY_TEAM = "notify_team"
    ESCALATE = "escalate"
    DISABLE_ACCOUNT = "disable_account"
    SNAPSHOT_MEMORY = "snapshot_memory"
    COLLECT_LOGS = "collect_logs"
    BLOCK_C2 = "block_c2"


class Severity(Enum):
    """Incident severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class IncidentContext:
    """Context about the ransomware incident."""

    affected_hosts: List[str]
    affected_shares: List[str]
    ransomware_family: str
    encryption_progress: float  # 0-100%
    lateral_movement_detected: bool
    exfiltration_detected: bool
    first_seen: str  # ISO timestamp
    c2_addresses: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    critical_data_affected: bool = False


@dataclass
class ResponseStep:
    """A single step in the response playbook."""

    action: ResponseAction
    priority: int  # 1 = highest priority
    target: str  # What to act on
    automated: bool  # Can be automated vs requires human
    reason: str
    estimated_impact: str


class RansomwareResponder:
    """
    Automated ransomware incident response.

    Implements response logic for:
    1. Immediate containment (stop the bleeding)
    2. Evidence preservation (forensic readiness)
    3. Scope assessment (how bad is it?)
    4. Recovery planning (how do we fix it?)
    """

    # Priority weights for different factors
    SEVERITY_WEIGHTS = {
        "critical_data": 3.0,
        "lateral_movement": 2.5,
        "exfiltration": 2.5,
        "encryption_rate": 1.5,
        "affected_hosts": 1.0,
    }

    def __init__(self, auto_contain: bool = False):
        """
        Initialize the responder.

        Args:
            auto_contain: If True, automatically execute containment actions.
                         If False, only recommend actions for human approval.
        """
        self.auto_contain = auto_contain
        self.action_log: List[Dict] = []

    def assess_severity(self, context: IncidentContext) -> Severity:
        """
        Assess incident severity based on context.

        Severity Criteria:
        - CRITICAL: Critical data affected, active lateral movement, >50% encrypted
        - HIGH: Multiple hosts, exfiltration detected, >25% encrypted
        - MEDIUM: Single host, no lateral movement, <25% encrypted
        - LOW: Detected before encryption started

        Args:
            context: Incident context information

        Returns:
            Severity level

        # TODO: Ask your AI assistant:
        # "Write Python code to assess ransomware incident severity.
        # Calculate a weighted score based on: critical data affected,
        # lateral movement, exfiltration, encryption progress, and
        # number of affected hosts. Map score to severity level."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_playbook(self, context: IncidentContext) -> List[ResponseStep]:
        """
        Generate response playbook based on incident context.

        Creates a prioritized list of response actions tailored to
        the specific incident characteristics.

        Args:
            context: Incident context information

        Returns:
            Ordered list of ResponseStep objects

        # TODO: Ask your AI assistant:
        # "Write Python code to generate a ransomware response playbook.
        # Include steps for: (1) network isolation if lateral movement,
        # (2) process termination, (3) C2 blocking, (4) evidence collection,
        # (5) user notification, (6) escalation if critical. Prioritize
        # based on severity and encryption progress."
        #
        # Then review and test the generated code.
        """
        pass

    def containment_recommendation(self, context: IncidentContext) -> Dict:
        """
        Generate specific containment recommendations.

        Args:
            context: Incident context information

        Returns:
            Dict with containment recommendations:
            - network_isolation: List of hosts/segments to isolate
            - process_actions: List of processes to terminate
            - account_actions: List of accounts to disable
            - share_actions: List of shares to restrict

        # TODO: Ask your AI assistant:
        # "Write Python code to generate containment recommendations.
        # Based on affected hosts and lateral movement, determine
        # isolation scope. Identify processes to kill, accounts to
        # disable, and network shares to restrict access."
        #
        # Then review and test the generated code.
        """
        pass

    def recovery_plan(self, context: IncidentContext) -> Dict:
        """
        Generate recovery plan.

        Args:
            context: Incident context information

        Returns:
            Dict with recovery planning:
            - backup_status: Assessment of backup availability
            - decryptor_check: Whether decryptor exists for family
            - recovery_priority: Ordered list of systems to recover
            - timeline_estimate: Estimated recovery timeline
            - data_loss_assessment: Potential data loss

        # TODO: Ask your AI assistant:
        # "Write Python code to generate a ransomware recovery plan.
        # Check if decryptors exist for the family (use a lookup dict).
        # Prioritize recovery of critical systems. Estimate timeline
        # based on affected host count and backup availability."
        #
        # Then review and test the generated code.
        """
        pass

    def evidence_collection_plan(self, context: IncidentContext) -> Dict:
        """
        Generate evidence collection plan for forensics.

        Args:
            context: Incident context information

        Returns:
            Dict with evidence collection steps:
            - memory_targets: Hosts to capture memory from
            - disk_targets: Hosts to image
            - log_sources: Logs to preserve
            - network_captures: Traffic to capture

        # TODO: Ask your AI assistant:
        # "Write Python code to plan evidence collection for forensics.
        # Identify which hosts need memory capture (active infections),
        # which need disk imaging, what logs to preserve (Windows Event,
        # firewall, SIEM), and network traffic to capture."
        #
        # Then review and test the generated code.
        """
        pass

    def notification_template(self, context: IncidentContext, severity: Severity) -> str:
        """
        Generate incident notification template.

        Args:
            context: Incident context information
            severity: Assessed severity level

        Returns:
            Formatted notification message

        # TODO: Ask your AI assistant:
        # "Write Python code to generate an incident notification template.
        # Include: severity level, affected systems count, ransomware family,
        # current containment status, immediate actions required, and
        # escalation contacts for critical incidents."
        #
        # Then review and test the generated code.
        """
        pass

    def check_decryptor_availability(self, family: str) -> Optional[str]:
        """
        Check if a free decryptor is available for the ransomware family.

        Args:
            family: Ransomware family name

        Returns:
            URL to decryptor if available, None otherwise

        # TODO: Ask your AI assistant:
        # "Write Python code to check decryptor availability.
        # Create a dict mapping ransomware families to No More Ransom
        # project URLs where decryptors are available. Return the URL
        # if family is in dict, otherwise None."
        #
        # Then review and test the generated code.
        """
        pass

    def execute_playbook(self, playbook: List[ResponseStep], dry_run: bool = True) -> List[Dict]:
        """
        Execute response playbook (or simulate in dry run).

        Args:
            playbook: List of response steps to execute
            dry_run: If True, only log actions without executing

        Returns:
            List of action results

        # TODO: Ask your AI assistant:
        # "Write Python code to execute or simulate a response playbook.
        # For each step, log the action. In dry_run mode, just record
        # what would happen. Otherwise, call appropriate action handlers.
        # Track success/failure for each step."
        #
        # Then review and test the generated code.
        """
        pass


def main():
    """Demo the ransomware responder."""
    # Sample incident context
    context = IncidentContext(
        affected_hosts=["workstation-01", "workstation-02", "file-server-01"],
        affected_shares=["\\\\file-server-01\\shared", "\\\\file-server-01\\finance"],
        ransomware_family="lockbit",
        encryption_progress=35.0,
        lateral_movement_detected=True,
        exfiltration_detected=False,
        first_seen="2024-01-15T10:30:00Z",
        c2_addresses=["192.168.100.50"],
        affected_users=["jsmith", "mjones"],
        critical_data_affected=True,
    )

    responder = RansomwareResponder(auto_contain=False)

    # Assess severity
    severity = responder.assess_severity(context)
    print(f"Incident Severity: {severity.value}")

    # Generate playbook
    playbook = responder.generate_playbook(context)
    print("\nResponse Playbook:")
    for step in playbook:
        print(f"  [{step.priority}] {step.action.value}: {step.target}")
        print(f"      Reason: {step.reason}")

    # Get containment recommendations
    containment = responder.containment_recommendation(context)
    print(f"\nContainment: {containment}")

    # Get recovery plan
    recovery = responder.recovery_plan(context)
    print(f"\nRecovery Plan: {recovery}")


if __name__ == "__main__":
    main()

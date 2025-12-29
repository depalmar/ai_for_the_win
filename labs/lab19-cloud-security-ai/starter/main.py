"""
Lab 19: AI-Powered Cloud Security - Starter Code

Analyze cloud security events from AWS, Azure, and GCP using AI.
Detect threats across multi-cloud environments.

Complete the TODOs to build a cloud security analysis pipeline.
"""

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import numpy as np


# LLM setup - supports multiple providers
def setup_llm(provider: str = "auto"):
    """Initialize LLM client based on available API keys."""
    if provider == "auto":
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("GOOGLE_API_KEY"):
            provider = "google"
        else:
            raise ValueError(
                "No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY"
            )

    if provider == "anthropic":
        from anthropic import Anthropic

        return ("anthropic", Anthropic())
    elif provider == "openai":
        from openai import OpenAI

        return ("openai", OpenAI())
    elif provider == "google":
        import google.generativeai as genai

        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        return ("google", genai.GenerativeModel("gemini-2.5-pro"))
    else:
        raise ValueError(f"Unknown provider: {provider}")


@dataclass
class CloudEvent:
    """Generic cloud security event."""

    event_id: str
    timestamp: str
    cloud_provider: str  # aws, azure, gcp
    event_type: str
    source_ip: str
    user_identity: str
    resource: str
    action: str
    result: str  # success, failure
    region: str
    raw_data: Dict = field(default_factory=dict)


@dataclass
class CloudThreat:
    """Detected cloud security threat."""

    threat_id: str
    timestamp: str
    cloud_provider: str
    threat_type: str
    severity: str
    affected_resources: List[str]
    indicators: List[str]
    mitre_techniques: List[str]
    recommendation: str


@dataclass
class CloudSecurityReport:
    """Cloud security analysis report."""

    report_id: str
    timestamp: str
    clouds_analyzed: List[str]
    total_events: int
    threats_detected: List[CloudThreat]
    risk_score: float
    summary: str


class CloudTrailAnalyzer:
    """Analyze AWS CloudTrail events for security threats."""

    # High-risk AWS actions
    HIGH_RISK_ACTIONS = [
        "CreateUser",
        "CreateAccessKey",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutBucketPolicy",
        "PutBucketAcl",
        "CreateSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "ModifyInstanceAttribute",
        "CreateKeyPair",
        "RunInstances",
        "StopLogging",
        "DeleteTrail",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "AssumeRole",
    ]

    # Reconnaissance actions
    RECON_ACTIONS = [
        "DescribeInstances",
        "ListBuckets",
        "GetBucketAcl",
        "ListUsers",
        "GetUser",
        "ListRoles",
        "ListAccessKeys",
        "DescribeSecurityGroups",
    ]

    def __init__(self):
        self.events = []
        self.user_activity = defaultdict(list)

    def parse_event(self, raw_event: dict) -> CloudEvent:
        """
        Parse raw CloudTrail event into CloudEvent.

        TODO: Implement CloudTrail parsing
        - Extract relevant fields
        - Handle nested userIdentity
        - Parse timestamps

        Args:
            raw_event: Raw CloudTrail JSON event

        Returns:
            CloudEvent object
        """
        # TODO: Implement this method
        pass

    def load_events(self, events: List[dict]):
        """
        Load and parse CloudTrail events.

        TODO: Implement event loading
        - Parse each event
        - Build user activity index

        Args:
            events: List of raw CloudTrail events
        """
        # TODO: Implement this method
        pass

    def detect_privilege_escalation(self) -> List[CloudThreat]:
        """
        Detect privilege escalation attempts.

        TODO: Implement detection
        - Users creating access keys for other users
        - Attaching admin policies
        - Creating new admin users
        - AssumeRole to privileged roles

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def detect_data_exfiltration(self) -> List[CloudThreat]:
        """
        Detect potential data exfiltration.

        TODO: Implement detection
        - S3 bucket policy changes to public
        - Unusual GetObject patterns
        - Cross-account access grants

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def detect_defense_evasion(self) -> List[CloudThreat]:
        """
        Detect defense evasion attempts.

        TODO: Implement detection
        - CloudTrail logging disabled
        - GuardDuty disabled
        - VPC flow logs disabled
        - Config rules deleted

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def detect_reconnaissance(self) -> List[CloudThreat]:
        """
        Detect reconnaissance activity.

        TODO: Implement detection
        - Excessive enumeration calls
        - Unusual API patterns
        - Failed access attempts

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def analyze(self) -> List[CloudThreat]:
        """
        Run all detection methods.

        Returns:
            List of all detected threats
        """
        threats = []
        threats.extend(self.detect_privilege_escalation() or [])
        threats.extend(self.detect_data_exfiltration() or [])
        threats.extend(self.detect_defense_evasion() or [])
        threats.extend(self.detect_reconnaissance() or [])
        return threats


class AzureSentinelAnalyzer:
    """Analyze Azure Sentinel incidents and logs."""

    # High-risk Azure activities
    HIGH_RISK_OPERATIONS = [
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Compute/virtualMachines/write",
        "Microsoft.Storage/storageAccounts/write",
        "Microsoft.KeyVault/vaults/secrets/read",
        "Microsoft.Network/networkSecurityGroups/write",
    ]

    def __init__(self):
        self.incidents = []
        self.activity_logs = []

    def parse_incident(self, raw_incident: dict) -> dict:
        """
        Parse Azure Sentinel incident.

        TODO: Implement incident parsing
        - Extract incident details
        - Parse entities and alerts
        - Map to threat categories

        Args:
            raw_incident: Raw Sentinel incident

        Returns:
            Parsed incident dict
        """
        # TODO: Implement this method
        pass

    def load_incidents(self, incidents: List[dict]):
        """
        Load Azure Sentinel incidents.

        TODO: Implement incident loading

        Args:
            incidents: Raw incidents
        """
        # TODO: Implement this method
        pass

    def load_activity_logs(self, logs: List[dict]):
        """
        Load Azure Activity logs.

        TODO: Implement log loading

        Args:
            logs: Raw activity logs
        """
        # TODO: Implement this method
        pass

    def detect_identity_threats(self) -> List[CloudThreat]:
        """
        Detect identity-based threats.

        TODO: Implement detection
        - Impossible travel
        - Suspicious sign-ins
        - Privilege escalation
        - Service principal abuse

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def detect_resource_threats(self) -> List[CloudThreat]:
        """
        Detect resource-based threats.

        TODO: Implement detection
        - Unusual resource creation
        - Cryptomining indicators
        - Storage exposure
        - Network changes

        Returns:
            List of detected threats
        """
        # TODO: Implement this method
        pass

    def correlate_incidents(self) -> List[CloudThreat]:
        """
        Correlate incidents to identify attack chains.

        TODO: Implement correlation
        - Link related incidents
        - Identify attack progression
        - Calculate composite risk

        Returns:
            Correlated threats
        """
        # TODO: Implement this method
        pass

    def analyze(self) -> List[CloudThreat]:
        """Run all Azure detection methods."""
        threats = []
        threats.extend(self.detect_identity_threats() or [])
        threats.extend(self.detect_resource_threats() or [])
        threats.extend(self.correlate_incidents() or [])
        return threats


class GCPSecurityAnalyzer:
    """Analyze GCP Security Command Center findings."""

    def __init__(self):
        self.findings = []
        self.audit_logs = []

    def parse_finding(self, raw_finding: dict) -> dict:
        """
        Parse GCP Security Command Center finding.

        TODO: Implement finding parsing

        Args:
            raw_finding: Raw SCC finding

        Returns:
            Parsed finding dict
        """
        # TODO: Implement this method
        pass

    def load_findings(self, findings: List[dict]):
        """Load SCC findings."""
        # TODO: Implement this method
        pass

    def analyze(self) -> List[CloudThreat]:
        """Analyze GCP security data."""
        # TODO: Implement this method
        pass


class MultiCloudAnalyzer:
    """Unified multi-cloud security analysis."""

    def __init__(self, llm_provider: str = "auto"):
        """Initialize multi-cloud analyzer."""
        self.aws_analyzer = CloudTrailAnalyzer()
        self.azure_analyzer = AzureSentinelAnalyzer()
        self.gcp_analyzer = GCPSecurityAnalyzer()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        """Lazy initialization of LLM."""
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def load_cloud_data(self, data: dict):
        """
        Load data from all cloud providers.

        TODO: Implement data loading
        - Load AWS CloudTrail events
        - Load Azure incidents and logs
        - Load GCP findings

        Args:
            data: Dict with data from each cloud
        """
        # TODO: Implement this method
        pass

    def correlate_cross_cloud(self, threats: List[CloudThreat]) -> List[CloudThreat]:
        """
        Correlate threats across cloud providers.

        TODO: Implement cross-cloud correlation
        - Match by user identity
        - Match by source IP
        - Match by timeframe
        - Identify multi-cloud attacks

        Args:
            threats: Threats from all clouds

        Returns:
            Correlated threats
        """
        # TODO: Implement this method
        pass

    def calculate_risk_score(self, threats: List[CloudThreat]) -> float:
        """
        Calculate overall risk score.

        TODO: Implement risk scoring
        - Weight by severity
        - Factor in threat count
        - Consider affected resources

        Args:
            threats: All detected threats

        Returns:
            Risk score 0-100
        """
        # TODO: Implement this method
        pass

    def llm_analyze_threats(self, threats: List[CloudThreat]) -> dict:
        """
        Use LLM to analyze and summarize threats.

        TODO: Implement LLM analysis
        - Build context from threats
        - Request analysis and recommendations
        - Parse structured response

        Args:
            threats: Detected threats

        Returns:
            LLM analysis results
        """
        # TODO: Implement this method
        pass

    def analyze_all(self) -> CloudSecurityReport:
        """
        Run complete multi-cloud analysis.

        TODO: Implement full analysis pipeline
        1. Analyze each cloud
        2. Correlate across clouds
        3. Calculate risk score
        4. Generate report

        Returns:
            CloudSecurityReport with all findings
        """
        # TODO: Implement this method
        pass

    def generate_report(self, threats: List[CloudThreat]) -> str:
        """
        Generate human-readable report.

        TODO: Implement report generation

        Args:
            threats: All threats

        Returns:
            Formatted report string
        """
        # TODO: Implement this method
        pass


def create_sample_cloudtrail_events() -> List[dict]:
    """Create sample CloudTrail events for testing."""
    return [
        {
            "eventTime": "2024-01-15T10:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "backdoor-user"},
            "responseElements": {"user": {"userName": "backdoor-user"}},
        },
        {
            "eventTime": "2024-01-15T10:01:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "backdoor-user"},
        },
        {
            "eventTime": "2024-01-15T10:02:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {
                "userName": "backdoor-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    ]


def main():
    """Main entry point for Lab 19."""
    print("=" * 60)
    print("Lab 19: AI-Powered Cloud Security")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    cloud_data = {}
    try:
        with open(os.path.join(data_dir, "cloudtrail_events.json"), "r") as f:
            cloud_data["aws"] = json.load(f)
        print(f"\nLoaded {len(cloud_data['aws'].get('events', []))} AWS events")
    except FileNotFoundError:
        print("CloudTrail data not found. Using demo data.")
        cloud_data["aws"] = {"events": create_sample_cloudtrail_events()}

    try:
        with open(os.path.join(data_dir, "azure_incidents.json"), "r") as f:
            cloud_data["azure"] = json.load(f)
        print(f"Loaded {len(cloud_data['azure'].get('incidents', []))} Azure incidents")
    except FileNotFoundError:
        cloud_data["azure"] = {"incidents": []}

    # Task 1: CloudTrail Analysis
    print("\n--- Task 1: AWS CloudTrail Analysis ---")
    aws_analyzer = CloudTrailAnalyzer()
    aws_analyzer.load_events(cloud_data["aws"].get("events", []))

    if aws_analyzer.events:
        print(f"Loaded {len(aws_analyzer.events)} events")
    else:
        print("TODO: Implement load_events()")

    threats = aws_analyzer.analyze()
    if threats:
        print(f"Detected {len(threats)} threats")
        for t in threats[:3]:
            print(f"  - [{t.severity}] {t.threat_type}")
    else:
        print("TODO: Implement detection methods")

    # Task 2: Azure Analysis
    print("\n--- Task 2: Azure Sentinel Analysis ---")
    azure_analyzer = AzureSentinelAnalyzer()
    azure_analyzer.load_incidents(cloud_data["azure"].get("incidents", []))

    azure_threats = azure_analyzer.analyze()
    if azure_threats:
        print(f"Detected {len(azure_threats)} threats")
    else:
        print("TODO: Implement Azure analysis")

    # Task 3: Multi-Cloud Analysis
    print("\n--- Task 3: Multi-Cloud Analysis ---")
    multi_analyzer = MultiCloudAnalyzer()
    multi_analyzer.load_cloud_data(cloud_data)

    report = multi_analyzer.analyze_all()
    if report:
        print(f"Risk Score: {report.risk_score:.1f}/100")
        print(f"Summary: {report.summary}")
    else:
        print("TODO: Implement analyze_all()")

    # Task 4: LLM Analysis
    print("\n--- Task 4: LLM-Powered Analysis ---")
    api_key = (
        os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    )

    if api_key and threats:
        llm_analysis = multi_analyzer.llm_analyze_threats(threats)
        if llm_analysis:
            print(f"LLM Analysis: {llm_analysis.get('summary', 'N/A')[:200]}...")
        else:
            print("TODO: Implement llm_analyze_threats()")
    else:
        print("Skipped - Set API key for LLM analysis")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 19!")
    print("=" * 60)


if __name__ == "__main__":
    main()

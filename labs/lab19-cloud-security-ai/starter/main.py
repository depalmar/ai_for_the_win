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
        # TODO: Ask your AI assistant:
        # "Write Python code to parse a raw AWS CloudTrail event dictionary into a CloudEvent dataclass.
        # Extract eventTime as timestamp, eventSource and eventName as event_type, sourceIPAddress,
        # userIdentity.userName (handling nested dict), resource from requestParameters,
        # eventName as action, awsRegion as region, and store the full raw_event. Generate a unique event_id."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to load a list of raw CloudTrail event dictionaries.
        # For each event, call self.parse_event() and append to self.events.
        # Also build a user activity index by adding each parsed event to
        # self.user_activity[event.user_identity] for later analysis."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect AWS privilege escalation attempts from self.events.
        # Look for patterns: CreateAccessKey for other users, AttachUserPolicy/AttachRolePolicy
        # with admin policies, CreateUser followed by privilege grants, and AssumeRole to
        # privileged roles. Return a list of CloudThreat objects with threat_type='PrivilegeEscalation',
        # appropriate severity, affected_resources, indicators, and MITRE ATT&CK techniques."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect potential AWS data exfiltration from self.events.
        # Look for: PutBucketPolicy/PutBucketAcl making buckets public, high volume of
        # GetObject calls from unusual IPs, and cross-account access grants in policy changes.
        # Return CloudThreat objects with threat_type='DataExfiltration', severity based on
        # exposure level, and relevant MITRE ATT&CK exfiltration techniques."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect AWS defense evasion attempts from self.events.
        # Look for actions like StopLogging, DeleteTrail, DeleteDetector (GuardDuty),
        # DeleteFlowLogs, and DeleteConfigRule. Return CloudThreat objects with
        # threat_type='DefenseEvasion', high severity, and MITRE ATT&CK defense
        # evasion techniques like T1562 (Impair Defenses)."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect AWS reconnaissance activity from self.events.
        # Check for excessive calls to RECON_ACTIONS (Describe*, List*, Get*) within
        # short time windows, unusual API call patterns per user, and high rates of
        # AccessDenied failures. Return CloudThreat objects with threat_type='Reconnaissance',
        # severity based on volume, and MITRE ATT&CK discovery techniques."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to parse an Azure Sentinel incident dictionary.
        # Extract incident ID, title, severity, status, created/updated times,
        # related alerts, and entities (accounts, hosts, IPs). Map the incident
        # classification to threat categories. Return a structured dict with
        # these parsed fields."
        #
        # Then review and test the generated code.
        pass

    def load_incidents(self, incidents: List[dict]):
        """
        Load Azure Sentinel incidents.

        TODO: Implement incident loading

        Args:
            incidents: Raw incidents
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to load a list of raw Azure Sentinel incidents.
        # For each incident, call self.parse_incident() and append the parsed
        # result to self.incidents list."
        #
        # Then review and test the generated code.
        pass

    def load_activity_logs(self, logs: List[dict]):
        """
        Load Azure Activity logs.

        TODO: Implement log loading

        Args:
            logs: Raw activity logs
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to load a list of raw Azure Activity logs.
        # Parse each log entry and append to self.activity_logs. Extract
        # operation name, resource ID, caller, timestamp, and status."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect Azure identity-based threats from self.incidents
        # and self.activity_logs. Look for: impossible travel (logins from distant
        # locations in short time), suspicious sign-in patterns (unusual times/locations),
        # role assignment escalations, and service principal credential additions.
        # Return CloudThreat objects with cloud_provider='azure' and appropriate MITRE techniques."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect Azure resource-based threats from self.activity_logs.
        # Look for: unusual VM creation (especially GPU instances suggesting cryptomining),
        # storage account public access changes, NSG rule modifications opening sensitive ports,
        # and bulk resource creation. Return CloudThreat objects with cloud_provider='azure'."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to correlate Azure Sentinel incidents from self.incidents.
        # Group incidents by shared entities (users, IPs, resources), identify attack
        # chains based on timestamps and MITRE technique progression, and calculate
        # composite risk scores for correlated incident groups. Return CloudThreat
        # objects representing the correlated attack patterns."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to parse a GCP Security Command Center finding dictionary.
        # Extract finding name, category, severity, state, resource name, event time,
        # and any associated vulnerabilities or misconfigurations. Return a structured
        # dict with these parsed fields."
        #
        # Then review and test the generated code.
        pass

    def load_findings(self, findings: List[dict]):
        """Load SCC findings."""
        # TODO: Ask your AI assistant:
        # "Write Python code to load a list of raw GCP Security Command Center findings.
        # For each finding, call self.parse_finding() and append to self.findings list."
        #
        # Then review and test the generated code.
        pass

    def analyze(self) -> List[CloudThreat]:
        """Analyze GCP security data."""
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze GCP security data from self.findings and self.audit_logs.
        # Convert high-severity SCC findings into CloudThreat objects with cloud_provider='gcp',
        # map finding categories to threat types, and include relevant MITRE ATT&CK techniques.
        # Return a list of CloudThreat objects."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to load multi-cloud security data from a dict.
        # If data contains 'aws', load events via self.aws_analyzer.load_events().
        # If 'azure', load incidents and activity_logs via self.azure_analyzer.
        # If 'gcp', load findings via self.gcp_analyzer. Handle missing keys gracefully."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to correlate threats across AWS, Azure, and GCP.
        # Group threats by: matching user identities/emails, matching source IPs,
        # and events within a configurable time window (e.g., 1 hour). Create new
        # CloudThreat objects for multi-cloud attack patterns with elevated severity
        # and combined indicators from the correlated threats."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate an overall risk score (0-100) from threats.
        # Assign weights to severity levels (critical=40, high=25, medium=10, low=5),
        # sum weighted scores, factor in unique affected resources count, and normalize
        # to 0-100 range. Return 0 if no threats, cap at 100 for extreme cases."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze cloud security threats using an LLM.
        # Call self._init_llm() first. Build a prompt summarizing the threats (types,
        # severities, affected resources, MITRE techniques). Send to the LLM via
        # self.llm (handling anthropic/openai/google providers). Ask for: executive
        # summary, attack chain analysis, prioritized recommendations, and risk assessment.
        # Parse the response into a dict with 'summary', 'recommendations', 'risk_level' keys."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to run a complete multi-cloud security analysis.
        # 1. Call analyze() on aws_analyzer, azure_analyzer, and gcp_analyzer
        # 2. Combine all threats and call correlate_cross_cloud()
        # 3. Calculate risk score via calculate_risk_score()
        # 4. Generate summary via generate_report()
        # 5. Return a CloudSecurityReport with unique report_id, timestamp, list of
        #    clouds analyzed, total events, all threats, risk score, and summary."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to generate a human-readable security report from threats.
        # Include: header with timestamp, executive summary with threat counts by severity,
        # breakdown by cloud provider, detailed threat listings with indicators and
        # recommendations, and MITRE ATT&CK technique summary. Format as a multi-line string."
        #
        # Then review and test the generated code.
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

"""
Lab 19: AI-Powered Cloud Security - Solution

Analyze cloud security events from AWS, Azure, and GCP using AI.
Detect threats across multi-cloud environments.
"""

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import numpy as np


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
            raise ValueError("No API key found.")

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
    cloud_provider: str
    event_type: str
    source_ip: str
    user_identity: str
    resource: str
    action: str
    result: str
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
    affected_resources: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    recommendation: str = ""


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

    RECON_ACTIONS = [
        "DescribeInstances",
        "ListBuckets",
        "GetBucketAcl",
        "ListUsers",
        "GetUser",
        "ListRoles",
        "ListAccessKeys",
        "DescribeSecurityGroups",
        "ListPolicies",
        "GetAccountSummary",
    ]

    def __init__(self):
        self.events: List[CloudEvent] = []
        self.user_activity = defaultdict(list)
        self._threat_counter = 0

    def _generate_threat_id(self) -> str:
        self._threat_counter += 1
        return f"AWS-{self._threat_counter:04d}"

    def parse_event(self, raw_event: dict) -> CloudEvent:
        """Parse raw CloudTrail event into CloudEvent."""
        user_identity = raw_event.get("userIdentity", {})
        user_name = user_identity.get(
            "userName", user_identity.get("principalId", user_identity.get("arn", "unknown"))
        )

        return CloudEvent(
            event_id=raw_event.get("eventID", f"event_{hash(str(raw_event))}"[:16]),
            timestamp=raw_event.get("eventTime", ""),
            cloud_provider="aws",
            event_type=raw_event.get("eventSource", ""),
            source_ip=raw_event.get("sourceIPAddress", ""),
            user_identity=user_name,
            resource=raw_event.get("eventSource", "").split(".")[0],
            action=raw_event.get("eventName", ""),
            result="success" if not raw_event.get("errorCode") else "failure",
            region=raw_event.get("awsRegion", ""),
            raw_data=raw_event,
        )

    def load_events(self, events: List[dict]):
        """Load and parse CloudTrail events."""
        for raw_event in events:
            event = self.parse_event(raw_event)
            self.events.append(event)
            self.user_activity[event.user_identity].append(event)

        print(f"  Loaded {len(self.events)} CloudTrail events")

    def detect_privilege_escalation(self) -> List[CloudThreat]:
        """Detect privilege escalation attempts."""
        threats = []

        priv_esc_actions = [
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "CreateLoginProfile",
        ]

        for user, events in self.user_activity.items():
            priv_events = [e for e in events if e.action in priv_esc_actions]

            if len(priv_events) >= 2:
                # Check for suspicious patterns
                actions = [e.action for e in priv_events]

                # Creating user and attaching admin policy
                if "CreateUser" in actions and any(
                    "Attach" in a and "Policy" in a for a in actions
                ):
                    targets = []
                    for e in priv_events:
                        req_params = e.raw_data.get("requestParameters", {})
                        if "userName" in req_params:
                            targets.append(req_params["userName"])
                        if "policyArn" in req_params:
                            policy = req_params["policyArn"]
                            if "Administrator" in policy or "Admin" in policy:
                                threats.append(
                                    CloudThreat(
                                        threat_id=self._generate_threat_id(),
                                        timestamp=priv_events[0].timestamp,
                                        cloud_provider="aws",
                                        threat_type="Privilege Escalation - Admin Policy Attachment",
                                        severity="critical",
                                        affected_resources=list(set(targets)),
                                        indicators=[
                                            f"User {user} created new user and attached admin policy",
                                            f"Source IP: {priv_events[0].source_ip}",
                                        ],
                                        mitre_techniques=["T1098", "T1136"],
                                        recommendation="Immediately review and revoke suspicious user permissions",
                                    )
                                )

        return threats

    def detect_data_exfiltration(self) -> List[CloudThreat]:
        """Detect potential data exfiltration."""
        threats = []

        for event in self.events:
            # Public bucket policy
            if event.action in ["PutBucketPolicy", "PutBucketAcl"]:
                req_params = event.raw_data.get("requestParameters", {})
                policy_str = str(req_params)

                if "*" in policy_str and "Principal" in policy_str:
                    threats.append(
                        CloudThreat(
                            threat_id=self._generate_threat_id(),
                            timestamp=event.timestamp,
                            cloud_provider="aws",
                            threat_type="Data Exposure - Public Bucket Policy",
                            severity="high",
                            affected_resources=[req_params.get("bucketName", "unknown")],
                            indicators=[
                                f"Bucket policy allows public access",
                                f"Modified by: {event.user_identity}",
                                f"Source IP: {event.source_ip}",
                            ],
                            mitre_techniques=["T1537", "T1530"],
                            recommendation="Review bucket policy and restrict public access",
                        )
                    )

        return threats

    def detect_defense_evasion(self) -> List[CloudThreat]:
        """Detect defense evasion attempts."""
        threats = []

        evasion_actions = [
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail",
            "DeleteFlowLogs",
            "DisableGuardDuty",
        ]

        for event in self.events:
            if event.action in evasion_actions:
                threats.append(
                    CloudThreat(
                        threat_id=self._generate_threat_id(),
                        timestamp=event.timestamp,
                        cloud_provider="aws",
                        threat_type=f"Defense Evasion - {event.action}",
                        severity="critical",
                        affected_resources=[event.resource],
                        indicators=[
                            f"Logging/monitoring modified: {event.action}",
                            f"User: {event.user_identity}",
                            f"Source IP: {event.source_ip}",
                        ],
                        mitre_techniques=["T1562.001", "T1070"],
                        recommendation="Immediately investigate and re-enable security logging",
                    )
                )

        return threats

    def detect_reconnaissance(self) -> List[CloudThreat]:
        """Detect reconnaissance activity."""
        threats = []

        for user, events in self.user_activity.items():
            recon_events = [e for e in events if e.action in self.RECON_ACTIONS]

            # Many enumeration calls in short time
            if len(recon_events) >= 10:
                timestamps = []
                for e in recon_events:
                    try:
                        dt = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                        timestamps.append(dt)
                    except (ValueError, AttributeError):
                        continue

                if len(timestamps) >= 2:
                    timestamps.sort()
                    duration = (timestamps[-1] - timestamps[0]).total_seconds()

                    # More than 10 recon calls in 5 minutes
                    if duration < 300:
                        threats.append(
                            CloudThreat(
                                threat_id=self._generate_threat_id(),
                                timestamp=recon_events[0].timestamp,
                                cloud_provider="aws",
                                threat_type="Reconnaissance - Rapid Enumeration",
                                severity="medium",
                                affected_resources=["multiple"],
                                indicators=[
                                    f"User {user} made {len(recon_events)} enumeration calls",
                                    f"Duration: {duration:.0f} seconds",
                                    f"Actions: {', '.join(set(e.action for e in recon_events[:5]))}",
                                ],
                                mitre_techniques=["T1087", "T1580"],
                                recommendation="Monitor user activity for further suspicious behavior",
                            )
                        )

        return threats

    def analyze(self) -> List[CloudThreat]:
        """Run all detection methods."""
        threats = []
        threats.extend(self.detect_privilege_escalation())
        threats.extend(self.detect_data_exfiltration())
        threats.extend(self.detect_defense_evasion())
        threats.extend(self.detect_reconnaissance())
        return threats


class AzureSentinelAnalyzer:
    """Analyze Azure Sentinel incidents and logs."""

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
        self._threat_counter = 0

    def _generate_threat_id(self) -> str:
        self._threat_counter += 1
        return f"AZR-{self._threat_counter:04d}"

    def parse_incident(self, raw_incident: dict) -> dict:
        """Parse Azure Sentinel incident."""
        return {
            "id": raw_incident.get("name", raw_incident.get("id", "")),
            "title": raw_incident.get("properties", {}).get("title", ""),
            "severity": raw_incident.get("properties", {}).get("severity", "medium"),
            "status": raw_incident.get("properties", {}).get("status", ""),
            "created_time": raw_incident.get("properties", {}).get("createdTimeUtc", ""),
            "alerts": raw_incident.get("properties", {}).get("relatedAlerts", []),
            "entities": raw_incident.get("properties", {}).get("relatedEntities", []),
        }

    def load_incidents(self, incidents: List[dict]):
        """Load Azure Sentinel incidents."""
        for raw in incidents:
            self.incidents.append(self.parse_incident(raw))
        print(f"  Loaded {len(self.incidents)} Azure incidents")

    def load_activity_logs(self, logs: List[dict]):
        """Load Azure Activity logs."""
        self.activity_logs = logs

    def detect_identity_threats(self) -> List[CloudThreat]:
        """Detect identity-based threats."""
        threats = []

        for incident in self.incidents:
            title_lower = incident.get("title", "").lower()

            # Impossible travel
            if "impossible travel" in title_lower:
                threats.append(
                    CloudThreat(
                        threat_id=self._generate_threat_id(),
                        timestamp=incident.get("created_time", ""),
                        cloud_provider="azure",
                        threat_type="Identity - Impossible Travel",
                        severity=incident.get("severity", "medium"),
                        indicators=[f"Sentinel incident: {incident.get('title')}"],
                        mitre_techniques=["T1078"],
                        recommendation="Verify user location and reset credentials if suspicious",
                    )
                )

            # Suspicious sign-in
            if "suspicious" in title_lower and "sign" in title_lower:
                threats.append(
                    CloudThreat(
                        threat_id=self._generate_threat_id(),
                        timestamp=incident.get("created_time", ""),
                        cloud_provider="azure",
                        threat_type="Identity - Suspicious Sign-in",
                        severity=incident.get("severity", "medium"),
                        indicators=[f"Sentinel incident: {incident.get('title')}"],
                        mitre_techniques=["T1078", "T1110"],
                        recommendation="Review sign-in logs and enforce MFA",
                    )
                )

        return threats

    def detect_resource_threats(self) -> List[CloudThreat]:
        """Detect resource-based threats."""
        threats = []

        for incident in self.incidents:
            title_lower = incident.get("title", "").lower()

            if "cryptomining" in title_lower or "crypto" in title_lower:
                threats.append(
                    CloudThreat(
                        threat_id=self._generate_threat_id(),
                        timestamp=incident.get("created_time", ""),
                        cloud_provider="azure",
                        threat_type="Resource Abuse - Cryptomining",
                        severity="high",
                        indicators=[f"Sentinel incident: {incident.get('title')}"],
                        mitre_techniques=["T1496"],
                        recommendation="Terminate affected resources and investigate access",
                    )
                )

        return threats

    def correlate_incidents(self) -> List[CloudThreat]:
        """Correlate incidents to identify attack chains."""
        # Group incidents by time proximity and entities
        return []

    def analyze(self) -> List[CloudThreat]:
        """Run all Azure detection methods."""
        threats = []
        threats.extend(self.detect_identity_threats())
        threats.extend(self.detect_resource_threats())
        threats.extend(self.correlate_incidents())
        return threats


class GCPSecurityAnalyzer:
    """Analyze GCP Security Command Center findings."""

    def __init__(self):
        self.findings = []
        self._threat_counter = 0

    def _generate_threat_id(self) -> str:
        self._threat_counter += 1
        return f"GCP-{self._threat_counter:04d}"

    def load_findings(self, findings: List[dict]):
        """Load SCC findings."""
        self.findings = findings

    def analyze(self) -> List[CloudThreat]:
        """Analyze GCP security data."""
        threats = []

        for finding in self.findings:
            severity = finding.get("severity", "MEDIUM")
            category = finding.get("category", "")

            threats.append(
                CloudThreat(
                    threat_id=self._generate_threat_id(),
                    timestamp=finding.get("createTime", ""),
                    cloud_provider="gcp",
                    threat_type=f"SCC Finding - {category}",
                    severity=severity.lower(),
                    indicators=[finding.get("description", "")],
                    mitre_techniques=finding.get("mitreTechniques", []),
                    recommendation=finding.get("recommendation", "Review finding details"),
                )
            )

        return threats


class MultiCloudAnalyzer:
    """Unified multi-cloud security analysis."""

    def __init__(self, llm_provider: str = "auto"):
        self.aws_analyzer = CloudTrailAnalyzer()
        self.azure_analyzer = AzureSentinelAnalyzer()
        self.gcp_analyzer = GCPSecurityAnalyzer()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def load_cloud_data(self, data: dict):
        """Load data from all cloud providers."""
        if "aws" in data:
            aws_data = data["aws"]
            self.aws_analyzer.load_events(aws_data.get("events", []))

        if "azure" in data:
            azure_data = data["azure"]
            self.azure_analyzer.load_incidents(azure_data.get("incidents", []))
            self.azure_analyzer.load_activity_logs(azure_data.get("activity_logs", []))

        if "gcp" in data:
            gcp_data = data["gcp"]
            self.gcp_analyzer.load_findings(gcp_data.get("findings", []))

    def correlate_cross_cloud(self, threats: List[CloudThreat]) -> List[CloudThreat]:
        """Correlate threats across cloud providers."""
        # Group by source IP and user
        by_ip = defaultdict(list)
        by_user = defaultdict(list)

        for threat in threats:
            for indicator in threat.indicators:
                if "IP:" in indicator or "Source IP" in indicator:
                    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", indicator)
                    if ip_match:
                        by_ip[ip_match.group()].append(threat)

        # Flag cross-cloud activity from same IP
        correlated = []
        for ip, ip_threats in by_ip.items():
            clouds = set(t.cloud_provider for t in ip_threats)
            if len(clouds) > 1:
                correlated.append(
                    CloudThreat(
                        threat_id=f"MULTI-{hash(ip) % 10000:04d}",
                        timestamp=ip_threats[0].timestamp,
                        cloud_provider="multi-cloud",
                        threat_type="Cross-Cloud Attack",
                        severity="critical",
                        indicators=[
                            f"Same IP {ip} observed across {', '.join(clouds)}",
                            f"Related threats: {len(ip_threats)}",
                        ],
                        mitre_techniques=["T1078", "T1580"],
                        recommendation="Coordinate response across all affected cloud environments",
                    )
                )

        return correlated

    def calculate_risk_score(self, threats: List[CloudThreat]) -> float:
        """Calculate overall risk score."""
        if not threats:
            return 0.0

        severity_scores = {"critical": 40, "high": 25, "medium": 10, "low": 5}

        total_score = 0
        for threat in threats:
            base_score = severity_scores.get(threat.severity.lower(), 5)

            # Boost for multi-cloud threats
            if threat.cloud_provider == "multi-cloud":
                base_score *= 1.5

            total_score += base_score

        # Cap at 100
        return min(total_score, 100.0)

    def llm_analyze_threats(self, threats: List[CloudThreat]) -> dict:
        """Use LLM to analyze and summarize threats."""
        self._init_llm()
        if not self.llm:
            return {"error": "LLM not available"}

        provider, client = self.llm

        threat_summary = []
        for t in threats[:10]:
            threat_summary.append(
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "cloud": t.cloud_provider,
                    "indicators": t.indicators[:3],
                }
            )

        prompt = f"""Analyze these cloud security threats and provide recommendations:

Threats Detected:
{json.dumps(threat_summary, indent=2)}

Provide JSON response with:
- summary: Brief overall assessment
- attack_narrative: Possible attack chain explanation
- priority_actions: Top 3 immediate actions
- long_term_recommendations: Strategic improvements"""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                result_text = response.content[0].text
            elif provider == "openai":
                response = client.chat.completions.create(
                    model="gpt-5",
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                )
                result_text = response.choices[0].message.content
            elif provider == "google":
                response = client.generate_content(prompt)
                result_text = response.text

            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]

            return json.loads(result_text)
        except Exception as e:
            return {"error": str(e), "summary": "Analysis failed"}

    def analyze_all(self) -> CloudSecurityReport:
        """Run complete multi-cloud analysis."""
        all_threats = []

        # Analyze each cloud
        aws_threats = self.aws_analyzer.analyze()
        azure_threats = self.azure_analyzer.analyze()
        gcp_threats = self.gcp_analyzer.analyze()

        all_threats.extend(aws_threats)
        all_threats.extend(azure_threats)
        all_threats.extend(gcp_threats)

        # Cross-cloud correlation
        correlated = self.correlate_cross_cloud(all_threats)
        all_threats.extend(correlated)

        # Calculate risk
        risk_score = self.calculate_risk_score(all_threats)

        # Generate summary
        clouds = []
        if aws_threats:
            clouds.append("AWS")
        if azure_threats:
            clouds.append("Azure")
        if gcp_threats:
            clouds.append("GCP")

        summary_parts = []
        if all_threats:
            by_severity = defaultdict(int)
            for t in all_threats:
                by_severity[t.severity] += 1

            summary_parts.append(f"Detected {len(all_threats)} threats")
            if by_severity.get("critical"):
                summary_parts.append(f"{by_severity['critical']} critical")
            if by_severity.get("high"):
                summary_parts.append(f"{by_severity['high']} high")
        else:
            summary_parts.append("No threats detected")

        total_events = len(self.aws_analyzer.events)

        return CloudSecurityReport(
            report_id=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            clouds_analyzed=clouds,
            total_events=total_events,
            threats_detected=all_threats,
            risk_score=risk_score,
            summary=". ".join(summary_parts),
        )

    def generate_report(self, threats: List[CloudThreat]) -> str:
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 60)
        lines.append("MULTI-CLOUD SECURITY REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total Threats: {len(threats)}")
        lines.append("")

        # Group by cloud
        by_cloud = defaultdict(list)
        for t in threats:
            by_cloud[t.cloud_provider].append(t)

        for cloud, cloud_threats in by_cloud.items():
            lines.append(f"--- {cloud.upper()} ({len(cloud_threats)} threats) ---")
            for t in cloud_threats[:5]:
                lines.append(f"  [{t.severity.upper()}] {t.threat_type}")
                for ind in t.indicators[:2]:
                    lines.append(f"    - {ind}")
            lines.append("")

        return "\n".join(lines)


def create_sample_cloudtrail_events() -> List[dict]:
    """Create sample CloudTrail events."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    return [
        {
            "eventTime": base_time.isoformat() + "Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "backdoor-user"},
        },
        {
            "eventTime": (base_time + timedelta(minutes=1)).isoformat() + "Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
            "requestParameters": {"userName": "backdoor-user"},
        },
        {
            "eventTime": (base_time + timedelta(minutes=2)).isoformat() + "Z",
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
        {
            "eventTime": (base_time + timedelta(minutes=5)).isoformat() + "Z",
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "userIdentity": {"type": "IAMUser", "userName": "backdoor-user"},
            "sourceIPAddress": "185.234.72.19",
            "awsRegion": "us-east-1",
        },
    ]


def main():
    """Main entry point for Lab 19."""
    print("=" * 60)
    print("Lab 19: AI-Powered Cloud Security - Solution")
    print("=" * 60)

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
    except FileNotFoundError:
        cloud_data["azure"] = {"incidents": []}

    # Run multi-cloud analysis
    print("\n--- Running Multi-Cloud Analysis ---")
    analyzer = MultiCloudAnalyzer()
    analyzer.load_cloud_data(cloud_data)

    report = analyzer.analyze_all()

    # Display results
    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    print(f"Clouds Analyzed: {', '.join(report.clouds_analyzed)}")
    print(f"Total Events: {report.total_events}")
    print(f"Threats Detected: {len(report.threats_detected)}")
    print(f"Risk Score: {report.risk_score:.1f}/100")
    print(f"Summary: {report.summary}")

    if report.threats_detected:
        print("\n--- Detected Threats ---")
        for threat in report.threats_detected[:5]:
            print(f"\n[{threat.severity.upper()}] {threat.threat_type}")
            print(f"  Cloud: {threat.cloud_provider}")
            print(f"  MITRE: {', '.join(threat.mitre_techniques)}")
            for indicator in threat.indicators[:2]:
                print(f"  - {indicator}")

    # Generate full report
    full_report = analyzer.generate_report(report.threats_detected)
    print("\n" + full_report)


if __name__ == "__main__":
    main()

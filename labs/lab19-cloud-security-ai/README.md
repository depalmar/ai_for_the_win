# Lab 19: Cloud Security with AI

## AI-Powered Security for AWS, Azure, and GCP

```
+-----------------------------------------------------------------------------+
|                    AI + CLOUD SECURITY ARCHITECTURE                          |
+-----------------------------------------------------------------------------+
|                                                                             |
|   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    |
|   │     AWS     │    │    Azure    │    │     GCP     │                    |
|   │ CloudTrail  │    │  Sentinel   │    │   SCC       │                    |
|   │ GuardDuty   │    │  Defender   │    │   Chronicle │                    |
|   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                    |
|          |                  |                  |                            |
|          +------------------+------------------+                            |
|                             |                                               |
|                    ┌────────▼────────┐                                     |
|                    │   AI Analysis   │                                     |
|                    │   Engine        │                                     |
|                    └────────┬────────┘                                     |
|                             |                                               |
|          +------------------+------------------+                            |
|          |                  |                  |                            |
|   ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐                    |
|   │  Threat     │    │  Misconfig  │    │  Compliance │                    |
|   │  Detection  │    │  Detection  │    │  Monitoring │                    |
|   └─────────────┘    └─────────────┘    └─────────────┘                    |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## 📊 Overview

| Aspect | Details |
|--------|---------|
| **Time** | 2-2.5 hours (with AI assistance) |
| **Difficulty** | Advanced |
| **Prerequisites** | Labs 04-05, Cloud fundamentals |
| **Skills** | Multi-cloud security, AI analysis, IaC security |

### New to Cloud Security?

If you're not familiar with AWS/Azure/GCP, IAM, or CloudTrail, complete [Lab 19a: Cloud Security Fundamentals](../lab19a-cloud-security-fundamentals/) first. It covers:
- Cloud service models (IaaS, PaaS, SaaS)
- IAM concepts across all three major clouds
- Key security logging services (CloudTrail, Activity Log, Audit Logs)
- Common cloud attack patterns

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

1. **Analyze CloudTrail logs** with AI for threat detection
2. **Detect misconfigurations** across AWS, Azure, GCP
3. **Automate compliance checks** using AI
4. **Build multi-cloud security** monitoring
5. **Implement AI-powered** cloud threat hunting

---

## Part 1: AWS Security with AI

### 1.1 CloudTrail Analysis

```python
"""
AI-powered AWS CloudTrail analysis
"""
import boto3
import json
from datetime import datetime, timedelta
from anthropic import Anthropic

class CloudTrailAnalyzer:
    """Analyze AWS CloudTrail events with AI"""

    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail')
        self.llm = Anthropic()

        # High-risk event patterns
        self.high_risk_events = [
            "ConsoleLogin",
            "CreateUser",
            "AttachUserPolicy",
            "CreateAccessKey",
            "PutBucketPolicy",
            "AuthorizeSecurityGroupIngress",
            "CreateKeyPair",
            "RunInstances",
            "StopLogging"
        ]

    def get_recent_events(self, hours: int = 24,
                         event_names: list = None) -> list:
        """Get CloudTrail events from the last N hours"""

        start_time = datetime.utcnow() - timedelta(hours=hours)

        lookup_attributes = []
        if event_names:
            for event in event_names:
                lookup_attributes.append({
                    'AttributeKey': 'EventName',
                    'AttributeValue': event
                })

        events = []
        paginator = self.cloudtrail.get_paginator('lookup_events')

        for page in paginator.paginate(
            StartTime=start_time,
            LookupAttributes=lookup_attributes[:1] if lookup_attributes else []
        ):
            events.extend(page.get('Events', []))

        return events

    def analyze_event(self, event: dict) -> dict:
        """Analyze a single CloudTrail event with AI"""

        event_data = json.loads(event.get('CloudTrailEvent', '{}'))

        prompt = f"""Analyze this AWS CloudTrail event for security implications.

Event:
```json
{json.dumps(event_data, indent=2, default=str)[:3000]}
```

Provide:
1. Risk level (Critical/High/Medium/Low/Info)
2. Is this normal administrative activity or potentially malicious?
3. What security concerns does this raise?
4. Recommended investigation steps
5. Related AWS security best practices

Respond in JSON format:
{{
    "risk_level": "string",
    "is_suspicious": true/false,
    "reasoning": "string",
    "security_concerns": ["list"],
    "investigation_steps": ["list"],
    "best_practices": ["list"],
    "mitre_techniques": ["T1234"]
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def detect_threats(self, hours: int = 24) -> list:
        """Detect potential threats in recent CloudTrail events"""

        # Get high-risk events
        events = self.get_recent_events(hours, self.high_risk_events)

        threats = []
        for event in events:
            analysis = self.analyze_event(event)

            if analysis.get("is_suspicious") or analysis.get("risk_level") in ["Critical", "High"]:
                threats.append({
                    "event": event,
                    "analysis": analysis
                })

        return threats

    def hunt_for_persistence(self) -> list:
        """Hunt for persistence mechanisms in AWS"""

        persistence_events = [
            "CreateUser",
            "CreateAccessKey",
            "CreateRole",
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "CreateLoginProfile",
            "UpdateLoginProfile"
        ]

        events = self.get_recent_events(hours=168, event_names=persistence_events)

        prompt = f"""Analyze these AWS events for potential persistence mechanisms.

Events:
```json
{json.dumps(events[:20], indent=2, default=str)}
```

Identify:
1. Any suspicious account creation patterns
2. Privilege escalation attempts
3. Backdoor access key creation
4. Unusual timing or source IPs
5. Signs of compromised credentials

Respond in JSON format with findings."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}
```

### 1.2 GuardDuty Integration

```python
"""
Integrate AWS GuardDuty with AI analysis
"""

class GuardDutyAnalyzer:
    """Enhance GuardDuty findings with AI"""

    def __init__(self):
        self.guardduty = boto3.client('guardduty')
        self.llm = Anthropic()

    def get_findings(self, detector_id: str,
                    severity: str = "HIGH") -> list:
        """Get GuardDuty findings"""

        finding_criteria = {
            'Criterion': {
                'severity': {
                    'Gte': 7 if severity == "HIGH" else 4
                }
            }
        }

        response = self.guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria=finding_criteria,
            MaxResults=50
        )

        finding_ids = response.get('FindingIds', [])

        if finding_ids:
            findings = self.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            return findings.get('Findings', [])

        return []

    def analyze_finding(self, finding: dict) -> dict:
        """Analyze GuardDuty finding with AI"""

        prompt = f"""Analyze this AWS GuardDuty security finding.

Finding:
```json
{json.dumps(finding, indent=2, default=str)}
```

Provide:
1. Threat assessment and severity validation
2. Potential attack scenario
3. Affected resources and blast radius
4. Immediate containment actions
5. Long-term remediation steps
6. Related findings to investigate

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}
```

---

## Part 2: Azure Security with AI

### 2.1 Azure Sentinel Integration

```python
"""
AI-powered Azure Sentinel analysis
"""
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

class AzureSentinelAnalyzer:
    """Analyze Azure Sentinel incidents with AI"""

    def __init__(self, workspace_id: str):
        self.credential = DefaultAzureCredential()
        self.logs_client = LogsQueryClient(self.credential)
        self.workspace_id = workspace_id
        self.llm = Anthropic()

    def query_security_events(self, query: str,
                             timespan: timedelta = timedelta(days=1)) -> list:
        """Query Azure Log Analytics"""

        response = self.logs_client.query_workspace(
            workspace_id=self.workspace_id,
            query=query,
            timespan=timespan
        )

        results = []
        for table in response.tables:
            for row in table.rows:
                results.append(dict(zip(table.columns, row)))

        return results

    def get_security_incidents(self, hours: int = 24) -> list:
        """Get recent security incidents"""

        query = f"""
        SecurityIncident
        | where TimeGenerated > ago({hours}h)
        | order by TimeGenerated desc
        | take 50
        """

        return self.query_security_events(query)

    def get_signin_anomalies(self) -> list:
        """Detect sign-in anomalies"""

        query = """
        SigninLogs
        | where TimeGenerated > ago(24h)
        | where ResultType != 0
        | summarize FailedAttempts = count() by
            UserPrincipalName, IPAddress, Location
        | where FailedAttempts > 5
        | order by FailedAttempts desc
        """

        return self.query_security_events(query)

    def analyze_incident(self, incident: dict) -> dict:
        """Analyze Sentinel incident with AI"""

        prompt = f"""Analyze this Azure Sentinel security incident.

Incident:
```json
{json.dumps(incident, indent=2, default=str)}
```

Provide:
1. Threat assessment
2. Attack chain analysis
3. Affected Azure resources
4. Recommended response playbook
5. KQL queries for further investigation
6. Azure-specific remediation steps

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def generate_hunting_query(self, description: str) -> str:
        """Generate KQL hunting query from description"""

        prompt = f"""Generate a KQL (Kusto Query Language) query for Azure Sentinel:

"{description}"

KQL syntax examples:
- SecurityEvent | where EventID == 4625
- SigninLogs | where ResultType != 0
- AzureActivity | where OperationName contains "Delete"

Return only the KQL query."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text.strip()
```

---

## Part 3: GCP Security with AI

### 3.1 Security Command Center Integration

```python
"""
AI-powered GCP Security Command Center analysis
"""
from google.cloud import securitycenter_v1
from google.cloud import logging_v2

class GCPSecurityAnalyzer:
    """Analyze GCP security findings with AI"""

    def __init__(self, organization_id: str):
        self.scc_client = securitycenter_v1.SecurityCenterClient()
        self.logging_client = logging_v2.Client()
        self.organization_id = organization_id
        self.llm = Anthropic()

    def get_security_findings(self, severity: str = "HIGH") -> list:
        """Get Security Command Center findings"""

        parent = f"organizations/{self.organization_id}/sources/-"

        severity_filter = f'severity="{severity}"'

        findings = []
        for finding in self.scc_client.list_findings(
            request={"parent": parent, "filter": severity_filter}
        ):
            findings.append({
                "name": finding.finding.name,
                "category": finding.finding.category,
                "severity": finding.finding.severity.name,
                "state": finding.finding.state.name,
                "resource": finding.finding.resource_name,
                "description": finding.finding.description
            })

        return findings

    def analyze_finding(self, finding: dict) -> dict:
        """Analyze SCC finding with AI"""

        prompt = f"""Analyze this GCP Security Command Center finding.

Finding:
```json
{json.dumps(finding, indent=2)}
```

Provide:
1. Risk assessment
2. GCP-specific attack vectors
3. Affected resources and services
4. Remediation using gcloud commands
5. Preventive IAM policies
6. Monitoring recommendations

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def get_audit_logs(self, hours: int = 24) -> list:
        """Get GCP audit logs"""

        filter_str = f"""
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        timestamp >= "{(datetime.utcnow() - timedelta(hours=hours)).isoformat()}Z"
        """

        entries = []
        for entry in self.logging_client.list_entries(filter_=filter_str):
            entries.append(entry.to_api_repr())

        return entries
```

---

## Part 4: Multi-Cloud Security

### 4.1 Unified Security Analysis

```python
"""
Multi-cloud security analysis with AI
"""

class MultiCloudSecurityAnalyzer:
    """Unified security analysis across AWS, Azure, GCP"""

    def __init__(self):
        self.llm = Anthropic()
        self.analyzers = {}

    def add_aws(self, aws_analyzer):
        self.analyzers['aws'] = aws_analyzer

    def add_azure(self, azure_analyzer):
        self.analyzers['azure'] = azure_analyzer

    def add_gcp(self, gcp_analyzer):
        self.analyzers['gcp'] = gcp_analyzer

    def get_all_findings(self) -> dict:
        """Gather findings from all cloud providers"""

        findings = {}

        if 'aws' in self.analyzers:
            findings['aws'] = {
                'guardduty': self.analyzers['aws'].get_findings(),
                'cloudtrail_threats': self.analyzers['aws'].detect_threats()
            }

        if 'azure' in self.analyzers:
            findings['azure'] = {
                'incidents': self.analyzers['azure'].get_security_incidents(),
                'signin_anomalies': self.analyzers['azure'].get_signin_anomalies()
            }

        if 'gcp' in self.analyzers:
            findings['gcp'] = {
                'scc_findings': self.analyzers['gcp'].get_security_findings()
            }

        return findings

    def correlate_findings(self, findings: dict) -> dict:
        """Correlate findings across clouds"""

        prompt = f"""Analyze security findings from multiple cloud providers and identify correlations.

Findings:
```json
{json.dumps(findings, indent=2, default=str)[:6000]}
```

Identify:
1. Cross-cloud attack patterns
2. Shared IOCs (IPs, users, resources)
3. Attack progression across clouds
4. Unified threat assessment
5. Prioritized response actions
6. Multi-cloud remediation strategy

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def generate_security_report(self) -> str:
        """Generate unified security report"""

        findings = self.get_all_findings()
        correlation = self.correlate_findings(findings)

        prompt = f"""Generate an executive security report for multi-cloud environment.

Findings Summary:
```json
{json.dumps(correlation, indent=2, default=str)}
```

Format as markdown with:
1. Executive Summary
2. Critical Findings by Cloud
3. Cross-Cloud Threats
4. Risk Matrix
5. Recommended Actions
6. Compliance Status"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text
```

---

## Part 5: Cloud Misconfiguration Detection

### 5.1 AI-Powered Config Analysis

```python
"""
Detect cloud misconfigurations with AI
"""

class CloudConfigAnalyzer:
    """Detect misconfigurations across clouds"""

    COMMON_MISCONFIGS = {
        "aws": [
            "S3 bucket public access",
            "Security group 0.0.0.0/0 ingress",
            "IAM users without MFA",
            "Unencrypted EBS volumes",
            "Root account access keys"
        ],
        "azure": [
            "Storage account public access",
            "NSG any-any rules",
            "Users without MFA",
            "Unencrypted managed disks",
            "Service principals with excessive permissions"
        ],
        "gcp": [
            "Cloud Storage allUsers access",
            "Firewall rules 0.0.0.0/0",
            "Service accounts with primitive roles",
            "Unencrypted disks",
            "Public IP on sensitive VMs"
        ]
    }

    def __init__(self):
        self.llm = Anthropic()

    def analyze_terraform(self, tf_content: str) -> dict:
        """Analyze Terraform for security issues"""

        prompt = f"""Analyze this Terraform configuration for security misconfigurations.

Terraform:
```hcl
{tf_content[:5000]}
```

Check for:
1. Overly permissive IAM/RBAC
2. Public network exposure
3. Missing encryption
4. Hardcoded secrets
5. Missing logging/monitoring
6. Non-compliant configurations

Respond in JSON format:
{{
    "issues": [
        {{
            "severity": "critical/high/medium/low",
            "resource": "resource.name",
            "issue": "description",
            "remediation": "fix",
            "compliance": ["CIS", "SOC2"]
        }}
    ],
    "score": 0-100,
    "summary": "string"
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def analyze_cloudformation(self, cf_template: str) -> dict:
        """Analyze CloudFormation template for security issues"""
        # Similar implementation for CloudFormation
        pass

    def analyze_arm_template(self, arm_template: str) -> dict:
        """Analyze ARM template for security issues"""
        # Similar implementation for ARM templates
        pass
```

---

## Exercises

### Exercise 1: CloudTrail Threat Detection
Set up real-time CloudTrail analysis for your AWS account.

### Exercise 2: Multi-Cloud Dashboard
Build a unified dashboard showing findings from all three clouds.

### Exercise 3: IaC Security Scanner
Create a CI/CD pipeline that scans Terraform for security issues.

### Exercise 4: Compliance Automation
Automate CIS benchmark checks across all cloud providers.

---

## Resources

- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [Azure Sentinel](https://azure.microsoft.com/en-us/services/microsoft-sentinel/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)

---

> **Stuck?** See the [Lab 19 Walkthrough](../../docs/walkthroughs/lab19-cloud-security-ai-walkthrough.md) for step-by-step guidance.

**Congratulations!** You've completed all the AI Security labs.

**Next**: [Capstone Projects](../../capstone-projects/) - Apply your skills to comprehensive security projects.
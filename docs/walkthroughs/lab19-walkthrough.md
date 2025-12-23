# Lab 19: Cloud Security with AI - Solution Walkthrough

## Overview

Build AI-powered cloud security monitoring for AWS, Azure, and GCP using CloudTrail analysis, Sentinel integration, and multi-cloud threat detection.

**Time:** 4-5 hours
**Difficulty:** Expert

---

## Task 1: AWS CloudTrail Analysis

### AI-Powered CloudTrail Log Analysis

```python
import boto3
import json
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
import anthropic

@dataclass
class CloudTrailEvent:
    event_time: datetime
    event_name: str
    event_source: str
    user_identity: dict
    source_ip: str
    user_agent: str
    request_parameters: dict
    response_elements: dict
    error_code: Optional[str] = None

class AWSCloudTrailAnalyzer:
    def __init__(self, region: str = 'us-east-1'):
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.client = anthropic.Anthropic()

        # High-risk events to monitor
        self.high_risk_events = {
            'ConsoleLogin': 'authentication',
            'CreateUser': 'privilege_escalation',
            'AttachUserPolicy': 'privilege_escalation',
            'CreateAccessKey': 'persistence',
            'StopLogging': 'defense_evasion',
            'DeleteTrail': 'defense_evasion',
            'AuthorizeSecurityGroupIngress': 'network_modification',
            'CreateKeyPair': 'credential_access',
            'RunInstances': 'resource_creation',
            'AssumeRole': 'lateral_movement'
        }

    def fetch_events(self, hours: int = 24,
                    event_names: list[str] = None) -> list[CloudTrailEvent]:
        """Fetch CloudTrail events."""

        start_time = datetime.utcnow() - timedelta(hours=hours)
        end_time = datetime.utcnow()

        lookup_attributes = []
        if event_names:
            # Can only filter by one attribute at a time
            lookup_attributes = [
                {'AttributeKey': 'EventName', 'AttributeValue': event_names[0]}
            ]

        events = []
        paginator = self.cloudtrail.get_paginator('lookup_events')

        for page in paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            LookupAttributes=lookup_attributes if lookup_attributes else []
        ):
            for event in page['Events']:
                cloud_event = json.loads(event['CloudTrailEvent'])

                events.append(CloudTrailEvent(
                    event_time=event['EventTime'],
                    event_name=event['EventName'],
                    event_source=cloud_event.get('eventSource', ''),
                    user_identity=cloud_event.get('userIdentity', {}),
                    source_ip=cloud_event.get('sourceIPAddress', ''),
                    user_agent=cloud_event.get('userAgent', ''),
                    request_parameters=cloud_event.get('requestParameters', {}),
                    response_elements=cloud_event.get('responseElements', {}),
                    error_code=cloud_event.get('errorCode')
                ))

        return events

    def detect_anomalies(self, events: list[CloudTrailEvent]) -> list[dict]:
        """Detect anomalous CloudTrail events."""

        anomalies = []

        for event in events:
            risk_factors = []
            risk_score = 0

            # Check if high-risk event
            if event.event_name in self.high_risk_events:
                risk_factors.append(f"High-risk event: {self.high_risk_events[event.event_name]}")
                risk_score += 30

            # Check for root account usage
            if event.user_identity.get('type') == 'Root':
                risk_factors.append("Root account usage")
                risk_score += 40

            # Check for console login without MFA
            if event.event_name == 'ConsoleLogin':
                mfa_used = event.response_elements.get('ConsoleLogin', {}).get('MFAUsed')
                if mfa_used == 'No':
                    risk_factors.append("Console login without MFA")
                    risk_score += 30

            # Check for unusual source IP
            if event.source_ip and not event.source_ip.startswith(('10.', '172.', '192.168.')):
                if 'amazonaws.com' not in event.source_ip:
                    risk_factors.append(f"External IP: {event.source_ip}")
                    risk_score += 10

            # Check for failed events
            if event.error_code:
                risk_factors.append(f"Error: {event.error_code}")
                risk_score += 10

            # Check for off-hours activity (UTC)
            hour = event.event_time.hour
            if hour < 6 or hour > 22:
                risk_factors.append("Off-hours activity")
                risk_score += 15

            if risk_score >= 30:
                anomalies.append({
                    'event_time': event.event_time.isoformat(),
                    'event_name': event.event_name,
                    'user': event.user_identity.get('userName', event.user_identity.get('arn', 'Unknown')),
                    'source_ip': event.source_ip,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors
                })

        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)

    def analyze_with_ai(self, events: list[CloudTrailEvent]) -> str:
        """AI-powered analysis of CloudTrail events."""

        # Summarize events
        event_summary = []
        for event in events[:50]:  # Limit for context
            event_summary.append({
                'time': event.event_time.isoformat(),
                'event': event.event_name,
                'source': event.event_source,
                'user': event.user_identity.get('userName', 'Unknown'),
                'ip': event.source_ip,
                'error': event.error_code
            })

        prompt = f"""Analyze these AWS CloudTrail events for security threats:

```json
{json.dumps(event_summary, indent=2)}
```

Provide:
1. **Threat Assessment** - Any active threats or compromises?
2. **Suspicious Patterns** - Unusual activity patterns
3. **User Behavior Analysis** - Any users showing risky behavior
4. **MITRE ATT&CK Mapping** - Relevant techniques
5. **Recommendations** - Immediate actions needed

Focus on AWS-specific threats like:
- Credential compromise
- Privilege escalation
- Data exfiltration
- Resource hijacking
- Defense evasion"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# AWS CloudTrail analysis
# aws_analyzer = AWSCloudTrailAnalyzer()
# events = aws_analyzer.fetch_events(hours=24)
# anomalies = aws_analyzer.detect_anomalies(events)
# analysis = aws_analyzer.analyze_with_ai(events)
```

---

## Task 2: Azure Sentinel Integration

### AI-Enhanced Azure Security

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

class AzureSentinelAnalyzer:
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.credential = DefaultAzureCredential()
        self.logs_client = LogsQueryClient(self.credential)
        self.client = anthropic.Anthropic()

    def query_security_events(self, query: str, hours: int = 24) -> list[dict]:
        """Execute KQL query against Log Analytics."""

        try:
            response = self.logs_client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(hours=hours)
            )

            results = []
            for table in response.tables:
                for row in table.rows:
                    result = {}
                    for i, column in enumerate(table.columns):
                        result[column.name] = row[i]
                    results.append(result)

            return results

        except Exception as e:
            print(f"Query error: {e}")
            return []

    def get_security_alerts(self, hours: int = 24) -> list[dict]:
        """Get Azure Security Center alerts."""

        query = """
        SecurityAlert
        | where TimeGenerated > ago({hours}h)
        | project TimeGenerated, AlertName, AlertSeverity, Description,
                  RemediationSteps, Entities, ExtendedProperties
        | order by TimeGenerated desc
        """.format(hours=hours)

        return self.query_security_events(query, hours)

    def get_signin_anomalies(self, hours: int = 24) -> list[dict]:
        """Get Azure AD sign-in anomalies."""

        query = """
        SigninLogs
        | where TimeGenerated > ago({hours}h)
        | where RiskLevelDuringSignIn != "none" or RiskState != "none"
        | project TimeGenerated, UserPrincipalName, IPAddress, Location,
                  RiskLevelDuringSignIn, RiskState, RiskEventTypes,
                  DeviceDetail, Status
        | order by TimeGenerated desc
        """.format(hours=hours)

        return self.query_security_events(query, hours)

    def detect_impossible_travel(self, hours: int = 24) -> list[dict]:
        """Detect impossible travel scenarios."""

        query = """
        SigninLogs
        | where TimeGenerated > ago({hours}h)
        | where ResultType == 0  // Successful logins
        | project TimeGenerated, UserPrincipalName, IPAddress,
                  Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
        | order by UserPrincipalName, TimeGenerated
        | serialize
        | extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated),
                 PrevUser = prev(UserPrincipalName)
        | where UserPrincipalName == PrevUser and Location != PrevLocation
        | extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
        | where TimeDiffMinutes < 60 and TimeDiffMinutes > 0
        | project TimeGenerated, UserPrincipalName, FromLocation = PrevLocation,
                  ToLocation = Location, TimeDiffMinutes
        """.format(hours=hours)

        return self.query_security_events(query, hours)

    def analyze_with_ai(self, alerts: list[dict],
                       signin_anomalies: list[dict]) -> str:
        """AI analysis of Azure security data."""

        prompt = f"""Analyze these Azure security findings:

## Security Alerts
{json.dumps(alerts[:20], indent=2, default=str)}

## Sign-in Anomalies
{json.dumps(signin_anomalies[:20], indent=2, default=str)}

Provide:
1. **Critical Findings** - What needs immediate attention?
2. **Compromised Accounts** - Any accounts likely compromised?
3. **Attack Patterns** - Any coordinated attack activity?
4. **Azure-Specific Risks** - Risks to Azure resources
5. **Remediation Steps** - Specific actions for Azure environment

Consider Azure-specific threats:
- Azure AD compromise
- Service principal abuse
- Key vault access
- Storage account exposure"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Azure Sentinel analysis
# azure_analyzer = AzureSentinelAnalyzer("your-workspace-id")
# alerts = azure_analyzer.get_security_alerts()
# signin_anomalies = azure_analyzer.get_signin_anomalies()
# analysis = azure_analyzer.analyze_with_ai(alerts, signin_anomalies)
```

---

## Task 3: GCP Security Command Center

### AI-Powered GCP Security

```python
from google.cloud import securitycenter_v1
from google.cloud import logging_v2

class GCPSecurityAnalyzer:
    def __init__(self, organization_id: str):
        self.organization_id = organization_id
        self.scc_client = securitycenter_v1.SecurityCenterClient()
        self.logging_client = logging_v2.Client()
        self.ai_client = anthropic.Anthropic()

    def get_findings(self, hours: int = 24) -> list[dict]:
        """Get Security Command Center findings."""

        parent = f"organizations/{self.organization_id}/sources/-"

        # Filter for recent findings
        filter_str = f'state="ACTIVE" AND createTime > "{hours}h"'

        findings = []
        request = securitycenter_v1.ListFindingsRequest(
            parent=parent,
            filter=filter_str
        )

        for finding in self.scc_client.list_findings(request=request):
            findings.append({
                'name': finding.finding.name,
                'category': finding.finding.category,
                'severity': finding.finding.severity.name,
                'state': finding.finding.state.name,
                'resource_name': finding.finding.resource_name,
                'description': finding.finding.description,
                'create_time': finding.finding.create_time.isoformat()
            })

        return findings

    def get_audit_logs(self, project_id: str, hours: int = 24) -> list[dict]:
        """Get GCP audit logs."""

        filter_str = f'''
        logName:"cloudaudit.googleapis.com"
        AND timestamp >= "{hours}h"
        AND (
            protoPayload.methodName:"SetIamPolicy"
            OR protoPayload.methodName:"CreateServiceAccount"
            OR protoPayload.methodName:"CreateServiceAccountKey"
            OR protoPayload.methodName:"compute.firewalls.insert"
            OR protoPayload.methodName:"storage.buckets.setIamPolicy"
        )
        '''

        logs = []
        for entry in self.logging_client.list_entries(
            filter_=filter_str,
            page_size=100
        ):
            logs.append({
                'timestamp': entry.timestamp.isoformat(),
                'severity': entry.severity,
                'method': entry.payload.get('methodName', ''),
                'principal': entry.payload.get('authenticationInfo', {}).get('principalEmail', ''),
                'resource': entry.resource.labels,
                'request': entry.payload.get('request', {})
            })

        return logs

    def detect_public_exposure(self) -> list[dict]:
        """Detect publicly exposed resources."""

        findings = []

        # Check for public storage buckets
        parent = f"organizations/{self.organization_id}/sources/-"
        filter_str = 'category="PUBLIC_BUCKET_ACL" AND state="ACTIVE"'

        request = securitycenter_v1.ListFindingsRequest(
            parent=parent,
            filter=filter_str
        )

        for finding in self.scc_client.list_findings(request=request):
            findings.append({
                'type': 'public_bucket',
                'resource': finding.finding.resource_name,
                'severity': finding.finding.severity.name
            })

        return findings

    def analyze_with_ai(self, findings: list[dict],
                       audit_logs: list[dict]) -> str:
        """AI analysis of GCP security data."""

        prompt = f"""Analyze these GCP security findings:

## Security Command Center Findings
{json.dumps(findings[:20], indent=2, default=str)}

## High-Risk Audit Log Events
{json.dumps(audit_logs[:20], indent=2, default=str)}

Provide:
1. **Critical Findings** - Resources at risk
2. **IAM Analysis** - Permission issues and risks
3. **Public Exposure** - Any publicly accessible resources
4. **Compliance Issues** - Policy violations
5. **Remediation Steps** - GCP-specific fixes

Consider GCP-specific threats:
- Service account key exposure
- Over-permissioned IAM roles
- Public Cloud Storage buckets
- Firewall misconfigurations
- Compute Engine vulnerabilities"""

        response = self.ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# GCP Security analysis
# gcp_analyzer = GCPSecurityAnalyzer("your-org-id")
# findings = gcp_analyzer.get_findings()
# audit_logs = gcp_analyzer.get_audit_logs("your-project")
# analysis = gcp_analyzer.analyze_with_ai(findings, audit_logs)
```

---

## Task 4: Multi-Cloud Correlation

### Correlating Threats Across Clouds

```python
class MultiCloudSecurityAnalyzer:
    def __init__(self):
        self.ai_client = anthropic.Anthropic()
        self.correlations = []

    def normalize_events(self, aws_events: list, azure_events: list,
                        gcp_events: list) -> list[dict]:
        """Normalize events from different clouds."""

        normalized = []

        # Normalize AWS events
        for event in aws_events:
            normalized.append({
                'cloud': 'AWS',
                'timestamp': event.get('event_time', ''),
                'event_type': event.get('event_name', ''),
                'user': event.get('user', ''),
                'source_ip': event.get('source_ip', ''),
                'resource': event.get('resource', ''),
                'risk_score': event.get('risk_score', 0)
            })

        # Normalize Azure events
        for event in azure_events:
            normalized.append({
                'cloud': 'Azure',
                'timestamp': event.get('TimeGenerated', ''),
                'event_type': event.get('AlertName', event.get('OperationName', '')),
                'user': event.get('UserPrincipalName', ''),
                'source_ip': event.get('IPAddress', ''),
                'resource': event.get('Resource', ''),
                'risk_score': self._severity_to_score(event.get('AlertSeverity', ''))
            })

        # Normalize GCP events
        for event in gcp_events:
            normalized.append({
                'cloud': 'GCP',
                'timestamp': event.get('timestamp', event.get('create_time', '')),
                'event_type': event.get('category', event.get('method', '')),
                'user': event.get('principal', ''),
                'source_ip': event.get('source_ip', ''),
                'resource': event.get('resource_name', ''),
                'risk_score': self._severity_to_score(event.get('severity', ''))
            })

        return sorted(normalized, key=lambda x: x['timestamp'], reverse=True)

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score."""
        severity_map = {
            'CRITICAL': 100,
            'HIGH': 75,
            'MEDIUM': 50,
            'LOW': 25,
            'INFO': 10
        }
        return severity_map.get(severity.upper(), 0)

    def detect_cross_cloud_attacks(self, normalized_events: list[dict]) -> list[dict]:
        """Detect attacks spanning multiple clouds."""

        # Group events by user/IP
        by_user = {}
        by_ip = {}

        for event in normalized_events:
            user = event['user']
            ip = event['source_ip']

            if user and user != 'Unknown':
                if user not in by_user:
                    by_user[user] = []
                by_user[user].append(event)

            if ip:
                if ip not in by_ip:
                    by_ip[ip] = []
                by_ip[ip].append(event)

        # Find users/IPs active in multiple clouds
        cross_cloud_findings = []

        for user, events in by_user.items():
            clouds = set(e['cloud'] for e in events)
            if len(clouds) > 1:
                cross_cloud_findings.append({
                    'type': 'cross_cloud_user',
                    'user': user,
                    'clouds': list(clouds),
                    'event_count': len(events),
                    'risk_level': 'HIGH' if len(clouds) == 3 else 'MEDIUM'
                })

        for ip, events in by_ip.items():
            clouds = set(e['cloud'] for e in events)
            if len(clouds) > 1:
                cross_cloud_findings.append({
                    'type': 'cross_cloud_ip',
                    'ip': ip,
                    'clouds': list(clouds),
                    'event_count': len(events),
                    'risk_level': 'HIGH'
                })

        return cross_cloud_findings

    def analyze_multi_cloud(self, normalized_events: list[dict],
                           cross_cloud_findings: list[dict]) -> str:
        """AI analysis of multi-cloud security posture."""

        # Summary statistics
        cloud_summary = {}
        for event in normalized_events:
            cloud = event['cloud']
            if cloud not in cloud_summary:
                cloud_summary[cloud] = {'count': 0, 'high_risk': 0}
            cloud_summary[cloud]['count'] += 1
            if event['risk_score'] >= 70:
                cloud_summary[cloud]['high_risk'] += 1

        prompt = f"""Analyze this multi-cloud security data:

## Cloud Summary
{json.dumps(cloud_summary, indent=2)}

## Cross-Cloud Findings
{json.dumps(cross_cloud_findings, indent=2)}

## Recent High-Risk Events (sample)
{json.dumps([e for e in normalized_events if e['risk_score'] >= 50][:20], indent=2)}

Provide:
1. **Multi-Cloud Threat Assessment** - Are there coordinated attacks?
2. **Cross-Cloud Attack Paths** - How might attackers pivot between clouds?
3. **Identity Risks** - Users/service accounts at risk across clouds
4. **Data Exfiltration Risk** - Potential data movement between clouds
5. **Unified Recommendations** - Actions for multi-cloud security

Consider:
- Federated identity risks
- Cross-cloud lateral movement
- Data synchronization vulnerabilities
- Shared credentials/secrets"""

        response = self.ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Multi-cloud analysis
multi_cloud = MultiCloudSecurityAnalyzer()

# Sample data (in production, fetch from each cloud)
aws_events = [{'event_name': 'ConsoleLogin', 'user': 'admin@corp.com', 'source_ip': '1.2.3.4', 'risk_score': 50}]
azure_events = [{'AlertName': 'Risky sign-in', 'UserPrincipalName': 'admin@corp.com', 'IPAddress': '1.2.3.4'}]
gcp_events = [{'category': 'IAM_ANOMALOUS', 'principal': 'admin@corp.com', 'severity': 'HIGH'}]

normalized = multi_cloud.normalize_events(aws_events, azure_events, gcp_events)
cross_cloud = multi_cloud.detect_cross_cloud_attacks(normalized)
analysis = multi_cloud.analyze_multi_cloud(normalized, cross_cloud)

print(analysis)
```

---

## Task 5: Complete Cloud Security Pipeline

### Integrated Multi-Cloud Security System

```python
class CloudSecurityPipeline:
    def __init__(self):
        self.multi_cloud = MultiCloudSecurityAnalyzer()
        # Initialize cloud-specific analyzers as needed
        # self.aws = AWSCloudTrailAnalyzer()
        # self.azure = AzureSentinelAnalyzer(workspace_id)
        # self.gcp = GCPSecurityAnalyzer(org_id)

    def run_full_analysis(self) -> dict:
        """Run complete multi-cloud security analysis."""

        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'clouds_analyzed': [],
            'findings': {},
            'cross_cloud': {},
            'risk_summary': {}
        }

        # Collect from each cloud
        aws_events = []  # self.aws.fetch_events() if available
        azure_events = []  # self.azure.get_security_alerts() if available
        gcp_events = []  # self.gcp.get_findings() if available

        # Normalize and correlate
        normalized = self.multi_cloud.normalize_events(
            aws_events, azure_events, gcp_events
        )

        cross_cloud = self.multi_cloud.detect_cross_cloud_attacks(normalized)

        results['findings']['normalized_events'] = len(normalized)
        results['cross_cloud']['findings'] = cross_cloud

        # Calculate risk summary
        high_risk = sum(1 for e in normalized if e['risk_score'] >= 70)
        results['risk_summary'] = {
            'total_events': len(normalized),
            'high_risk_events': high_risk,
            'cross_cloud_concerns': len(cross_cloud),
            'overall_risk': 'CRITICAL' if high_risk > 10 or len(cross_cloud) > 3 else
                           'HIGH' if high_risk > 5 else 'MEDIUM'
        }

        return results

    def generate_executive_report(self, results: dict) -> str:
        """Generate executive summary report."""

        prompt = f"""Generate an executive summary for this multi-cloud security assessment:

## Assessment Results
{json.dumps(results, indent=2)}

Create a 1-page executive brief with:
1. **Security Posture Summary** - Overall health across clouds
2. **Key Risks** - Top 3 risks requiring attention
3. **Compliance Status** - Any compliance concerns
4. **Resource Impact** - Cost/performance implications
5. **Strategic Recommendations** - Long-term improvements

Use business language appropriate for C-level executives."""

        response = self.multi_cloud.ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Run pipeline
pipeline = CloudSecurityPipeline()
results = pipeline.run_full_analysis()
report = pipeline.generate_executive_report(results)

print("Executive Report:")
print(report)
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| API rate limits | Implement backoff, cache results |
| Missing permissions | Verify IAM roles in each cloud |
| Data volume | Use sampling, time-based filtering |
| Credential management | Use cloud-native auth (roles, workload identity) |
| Cross-cloud identity | Implement identity federation |

---

## Next Steps

- Add real-time streaming analysis
- Implement automated remediation
- Build unified security dashboard
- Add compliance checking (CIS benchmarks)
- Create multi-cloud SIEM integration

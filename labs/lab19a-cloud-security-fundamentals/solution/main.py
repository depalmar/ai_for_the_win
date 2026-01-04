"""
Lab 19a: Cloud Security Fundamentals - Solution
==============================================

Complete solution for cloud security log analysis exercises.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# =============================================================================
# TEST-COMPATIBLE CLASSES
# =============================================================================


@dataclass
class CloudTrailEvent:
    """Parsed CloudTrail event."""

    event_time: str
    event_name: str
    event_source: str
    user_identity: str
    user_type: str
    source_ip: str
    region: str = ""
    error_code: str = ""


@dataclass
class IAMFinding:
    """IAM policy finding."""

    severity: str
    description: str
    resource: str = ""


class CloudTrailParser:
    """Parse and analyze CloudTrail events."""

    def __init__(self):
        self.high_risk_events = {
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail",
            "PutBucketPolicy",
            "PutBucketAcl",
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "AttachRolePolicy",
        }

    def parse_event(self, raw_event: Dict) -> CloudTrailEvent:
        """Parse a raw CloudTrail event into structured format."""
        user_identity = raw_event.get("userIdentity", {})

        return CloudTrailEvent(
            event_time=raw_event.get("eventTime", ""),
            event_name=raw_event.get("eventName", ""),
            event_source=raw_event.get("eventSource", ""),
            user_identity=user_identity.get(
                "userName", user_identity.get("principalId", "unknown")
            ),
            user_type=user_identity.get("type", "Unknown"),
            source_ip=raw_event.get("sourceIPAddress", ""),
            region=raw_event.get("awsRegion", ""),
            error_code=raw_event.get("errorCode", ""),
        )

    def is_high_risk(self, event: CloudTrailEvent) -> bool:
        """Check if event is high risk."""
        return event.event_name in self.high_risk_events


class IAMAnalyzer:
    """Analyze IAM policies for security issues."""

    def check_overly_permissive(self, policy: Dict) -> List[IAMFinding]:
        """Check for overly permissive policy statements."""
        findings = []

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            action = statement.get("Action", "")
            resource = statement.get("Resource", "")

            # Check for admin access
            if action == "*" and resource == "*":
                findings.append(
                    IAMFinding(
                        severity="CRITICAL",
                        description="Policy grants full admin access (Action: *, Resource: *)",
                        resource=str(resource),
                    )
                )
            elif action == "*":
                findings.append(
                    IAMFinding(
                        severity="HIGH",
                        description="Policy grants all actions",
                        resource=str(resource),
                    )
                )
            elif resource == "*":
                findings.append(
                    IAMFinding(
                        severity="MEDIUM",
                        description="Policy applies to all resources",
                        resource=str(resource),
                    )
                )

        return findings


class CloudThreatDetector:
    """Detect and classify cloud security threats."""

    def __init__(self):
        self.event_tactics = {
            # Defense Evasion
            "StopLogging": "DEFENSE_EVASION",
            "DeleteTrail": "DEFENSE_EVASION",
            "UpdateTrail": "DEFENSE_EVASION",
            # Persistence
            "CreateUser": "PERSISTENCE",
            "CreateAccessKey": "PERSISTENCE",
            "CreateLoginProfile": "PERSISTENCE",
            # Privilege Escalation
            "AttachUserPolicy": "PRIVILEGE_ESCALATION",
            "AttachRolePolicy": "PRIVILEGE_ESCALATION",
            "PutUserPolicy": "PRIVILEGE_ESCALATION",
            # Exfiltration
            "PutBucketPolicy": "EXFILTRATION",
            "PutBucketAcl": "EXFILTRATION",
        }

        self.event_severity = {
            "StopLogging": "CRITICAL",
            "DeleteTrail": "CRITICAL",
            "PutBucketPolicy": "CRITICAL",
            "PutBucketAcl": "CRITICAL",
            "CreateAccessKey": "HIGH",
            "CreateUser": "HIGH",
            "AttachUserPolicy": "HIGH",
            "AttachRolePolicy": "HIGH",
            "UpdateTrail": "MEDIUM",
        }

    def classify_event(self, event_name: str) -> str:
        """Classify an event by MITRE ATT&CK tactic."""
        return self.event_tactics.get(event_name, "UNKNOWN")

    def get_severity(self, event_name: str) -> str:
        """Get severity level for an event."""
        return self.event_severity.get(event_name, "LOW")


# =============================================================================
# EXERCISE 1: Parse CloudTrail Events
# =============================================================================


def parse_cloudtrail_event(event: Dict) -> Dict:
    """Extract key fields from an AWS CloudTrail event."""

    # Extract user identity (handle different types)
    user_identity = event.get("userIdentity", {})
    identity_type = user_identity.get("type", "Unknown")

    if identity_type == "Root":
        user = "ROOT"
    elif identity_type == "IAMUser":
        user = user_identity.get("userName", "unknown")
    elif identity_type == "AssumedRole":
        # Extract role name from ARN
        arn = user_identity.get("arn", "")
        user = arn.split("/")[-1] if "/" in arn else arn
    else:
        user = user_identity.get("principalId", "unknown")

    # Extract resource from request parameters
    request_params = event.get("requestParameters", {})
    resource = (
        request_params.get("bucketName")
        or request_params.get("userName")
        or request_params.get("roleName")
        or request_params.get("instanceId")
        or "N/A"
    )

    return {
        "timestamp": event.get("eventTime"),
        "user": user,
        "user_type": identity_type,
        "action": event.get("eventName"),
        "resource": resource,
        "source_ip": event.get("sourceIPAddress"),
        "region": event.get("awsRegion"),
        "error": event.get("errorCode"),
        "error_message": event.get("errorMessage"),
    }


# Suspicious events categorized by severity
CRITICAL_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",  # Audit tampering
    "PutBucketPolicy",
    "PutBucketAcl",  # Storage exposure
}

HIGH_RISK_EVENTS = {
    "CreateUser",
    "CreateLoginProfile",  # New identities
    "CreateAccessKey",  # New credentials
    "AttachUserPolicy",
    "AttachRolePolicy",  # Permission grants
    "PutUserPolicy",
    "PutRolePolicy",
    "AuthorizeSecurityGroupIngress",  # Network opening
    "CreateRole",  # New role creation
}


def is_suspicious_cloudtrail_event(event: Dict) -> Tuple[bool, str]:
    """Determine if a CloudTrail event is suspicious."""

    event_name = event.get("eventName", "")
    user_identity = event.get("userIdentity", {})

    # Critical: Root account usage
    if user_identity.get("type") == "Root":
        return True, f"CRITICAL: Root account used for {event_name}"

    # Critical: Audit tampering
    if event_name in CRITICAL_EVENTS:
        return True, f"CRITICAL: Audit/security configuration change: {event_name}"

    # High: IAM changes
    if event_name in HIGH_RISK_EVENTS:
        request_params = event.get("requestParameters", {})

        # Extra suspicious if granting admin
        policy_arn = request_params.get("policyArn", "")
        if "AdministratorAccess" in policy_arn:
            return True, f"CRITICAL: Admin policy attached via {event_name}"

        return True, f"HIGH: Sensitive action: {event_name}"

    # Medium: Failed access attempts (potential recon)
    if event.get("errorCode") in ["AccessDenied", "UnauthorizedAccess"]:
        return True, f"MEDIUM: Access denied for {event_name} - potential recon"

    return False, "Normal activity"


# =============================================================================
# EXERCISE 2: Cross-Cloud Event Mapping
# =============================================================================

CROSS_CLOUD_EVENTS = {
    "user_creation": {
        "aws": ["CreateUser", "CreateLoginProfile"],
        "azure": ["Microsoft.Authorization/users/write", "Add user"],
        "gcp": ["google.admin.AdminService.createUser", "CreateUser"],
    },
    "permission_change": {
        "aws": ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"],
        "azure": ["Microsoft.Authorization/roleAssignments/write"],
        "gcp": ["SetIamPolicy", "google.iam.admin.v1.SetIamPolicy"],
    },
    "credential_creation": {
        "aws": ["CreateAccessKey"],
        "azure": ["Microsoft.KeyVault/vaults/secrets/write", "Add service principal credential"],
        "gcp": ["google.iam.admin.v1.CreateServiceAccountKey"],
    },
    "storage_exposure": {
        "aws": ["PutBucketPolicy", "PutBucketAcl", "PutObjectAcl"],
        "azure": ["Microsoft.Storage/storageAccounts/write"],
        "gcp": ["storage.buckets.setIamPolicy", "storage.objects.setIamPolicy"],
    },
    "audit_tampering": {
        "aws": ["StopLogging", "DeleteTrail", "UpdateTrail"],
        "azure": ["Microsoft.Insights/diagnosticSettings/delete"],
        "gcp": ["google.logging.v2.ConfigServiceV2.DeleteSink"],
    },
    "network_change": {
        "aws": [
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "CreateSecurityGroup",
        ],
        "azure": ["Microsoft.Network/networkSecurityGroups/write"],
        "gcp": ["compute.firewalls.create", "compute.firewalls.update"],
    },
    "instance_creation": {
        "aws": ["RunInstances"],
        "azure": ["Microsoft.Compute/virtualMachines/write"],
        "gcp": ["compute.instances.insert"],
    },
}


def categorize_cloud_event(event_name: str, cloud_provider: str) -> str:
    """Categorize a cloud event into a standard category."""
    for category, mappings in CROSS_CLOUD_EVENTS.items():
        if event_name in mappings.get(cloud_provider, []):
            return category
    return "unknown"


def normalize_cloud_event(event: Dict, cloud_provider: str) -> Dict:
    """Normalize events from different clouds into a common format."""

    if cloud_provider == "aws":
        user_identity = event.get("userIdentity", {})
        user = user_identity.get("userName") or user_identity.get("principalId", "unknown")

        return {
            "timestamp": event.get("eventTime"),
            "provider": "aws",
            "user": user,
            "action": event.get("eventName"),
            "category": categorize_cloud_event(event.get("eventName", ""), "aws"),
            "resource": event.get("requestParameters", {}).get("bucketName")
            or event.get("requestParameters", {}).get("userName")
            or "N/A",
            "source_ip": event.get("sourceIPAddress"),
            "result": "failure" if event.get("errorCode") else "success",
            "raw": event,
        }

    elif cloud_provider == "azure":
        identity = event.get("identity", {})
        claims = identity.get("claims", {}) if isinstance(identity, dict) else {}

        return {
            "timestamp": event.get("time"),
            "provider": "azure",
            "user": claims.get("name") or event.get("caller", "unknown"),
            "action": event.get("operationName"),
            "category": categorize_cloud_event(event.get("operationName", ""), "azure"),
            "resource": event.get("resourceId", "N/A"),
            "source_ip": event.get("callerIpAddress"),
            "result": "success" if event.get("resultType") == "Success" else "failure",
            "raw": event,
        }

    elif cloud_provider == "gcp":
        proto = event.get("protoPayload", {})
        auth_info = proto.get("authenticationInfo", {})

        return {
            "timestamp": event.get("timestamp"),
            "provider": "gcp",
            "user": auth_info.get("principalEmail", "unknown"),
            "action": proto.get("methodName"),
            "category": categorize_cloud_event(proto.get("methodName", ""), "gcp"),
            "resource": proto.get("resourceName", "N/A"),
            "source_ip": proto.get("requestMetadata", {}).get("callerIp"),
            "result": "success" if event.get("severity") != "ERROR" else "failure",
            "raw": event,
        }

    return {"error": f"Unknown cloud provider: {cloud_provider}"}


# =============================================================================
# EXERCISE 3: Detect Attack Patterns
# =============================================================================


def detect_privilege_escalation(events: List[Dict]) -> List[Dict]:
    """Detect potential privilege escalation from a series of events."""

    detections = []

    # Group events by user
    user_events = {}
    for event in events:
        user = event.get("user", "unknown")
        if user not in user_events:
            user_events[user] = []
        user_events[user].append(event)

    # Analyze each user's activity
    for user, user_event_list in user_events.items():
        recon_events = []
        escalation_events = []

        for event in user_event_list:
            action = event.get("action", "")
            category = event.get("category", "")

            # Track reconnaissance
            if action in ["ListUsers", "ListRoles", "GetUser", "GetRole", "ListPolicies"]:
                recon_events.append(event)

            # Track permission changes
            if category == "permission_change":
                escalation_events.append(event)

            # Track credential creation
            if category == "credential_creation":
                escalation_events.append(event)

        # Suspicious pattern: recon followed by escalation
        if recon_events and escalation_events:
            detections.append(
                {
                    "type": "privilege_escalation",
                    "user": user,
                    "severity": "HIGH",
                    "description": f"User performed recon ({len(recon_events)} events) followed by privilege changes ({len(escalation_events)} events)",
                    "recon_events": [e.get("action") for e in recon_events],
                    "escalation_events": [e.get("action") for e in escalation_events],
                }
            )

        # Suspicious: Multiple permission grants in short time
        if len(escalation_events) >= 3:
            detections.append(
                {
                    "type": "bulk_permission_change",
                    "user": user,
                    "severity": "MEDIUM",
                    "description": f"Multiple permission changes by single user ({len(escalation_events)} events)",
                    "events": [e.get("action") for e in escalation_events],
                }
            )

    return detections


def detect_data_exfiltration_risk(events: List[Dict]) -> List[Dict]:
    """Detect potential data exfiltration preparation."""

    detections = []

    for event in events:
        action = event.get("action", "")
        category = event.get("category", "")

        # Storage exposure
        if category == "storage_exposure":
            detections.append(
                {
                    "type": "storage_exposure",
                    "severity": "CRITICAL",
                    "user": event.get("user"),
                    "action": action,
                    "resource": event.get("resource"),
                    "description": "Storage permissions changed - potential public exposure",
                }
            )

        # Bulk data access (simplified - real detection would track volume)
        if action in ["GetObject", "DownloadBlob", "storage.objects.get"]:
            # In real world, you'd track volume/frequency
            pass

        # Snapshot sharing
        if action in ["ModifySnapshotAttribute", "ShareSnapshot"]:
            detections.append(
                {
                    "type": "snapshot_sharing",
                    "severity": "HIGH",
                    "user": event.get("user"),
                    "action": action,
                    "description": "Snapshot shared - potential data exfiltration",
                }
            )

    return detections


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Lab 19a: Cloud Security Fundamentals - SOLUTION")
    print("=" * 60)

    # Test CloudTrail parsing
    sample_cloudtrail = {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventName": "AttachUserPolicy",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "suspicious-user",
            "arn": "arn:aws:iam::123456789012:user/suspicious-user",
        },
        "sourceIPAddress": "203.0.113.50",
        "awsRegion": "us-east-1",
        "requestParameters": {
            "userName": "suspicious-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    }

    print("\n📋 Exercise 1: Parse CloudTrail Event")
    print("-" * 40)
    parsed = parse_cloudtrail_event(sample_cloudtrail)
    print(f"Parsed event: {json.dumps(parsed, indent=2)}")

    print("\n🔍 Exercise 1b: Suspicious Event Check")
    print("-" * 40)
    is_sus, reason = is_suspicious_cloudtrail_event(sample_cloudtrail)
    print(f"Suspicious: {is_sus}")
    print(f"Reason: {reason}")

    print("\n🌐 Exercise 2: Cross-Cloud Event Mapping")
    print("-" * 40)
    test_events = [
        ("CreateAccessKey", "aws"),
        ("SetIamPolicy", "gcp"),
        ("Microsoft.Authorization/roleAssignments/write", "azure"),
        ("StopLogging", "aws"),
        ("AuthorizeSecurityGroupIngress", "aws"),
    ]
    for event_name, cloud in test_events:
        category = categorize_cloud_event(event_name, cloud)
        print(f"  {cloud:6s}: {event_name:45s} → {category}")

    print("\n🔎 Exercise 3: Attack Pattern Detection")
    print("-" * 40)

    # Simulate a privilege escalation attack sequence
    attack_sequence = [
        normalize_cloud_event(
            {
                "eventTime": "2024-01-15T10:00:00Z",
                "eventName": "ListUsers",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "1.2.3.4",
            },
            "aws",
        ),
        normalize_cloud_event(
            {
                "eventTime": "2024-01-15T10:01:00Z",
                "eventName": "ListRoles",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "1.2.3.4",
            },
            "aws",
        ),
        normalize_cloud_event(
            {
                "eventTime": "2024-01-15T10:02:00Z",
                "eventName": "AttachUserPolicy",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "1.2.3.4",
                "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            },
            "aws",
        ),
        normalize_cloud_event(
            {
                "eventTime": "2024-01-15T10:03:00Z",
                "eventName": "CreateAccessKey",
                "userIdentity": {"userName": "attacker"},
                "sourceIPAddress": "1.2.3.4",
            },
            "aws",
        ),
    ]

    priv_esc = detect_privilege_escalation(attack_sequence)
    for detection in priv_esc:
        print(f"\n  [{detection['severity']}] {detection['type']}")
        print(f"  User: {detection['user']}")
        print(f"  Description: {detection['description']}")

    print("\n" + "=" * 60)
    print("✅ Solution complete! Compare with your implementation.")
    print("=" * 60)

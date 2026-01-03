"""
Lab 19a: Cloud Security Fundamentals - Solution
==============================================

Complete solution for cloud security log analysis exercises.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple

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

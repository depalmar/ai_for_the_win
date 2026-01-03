"""
Lab 19a: Cloud Security Fundamentals - Starter
=============================================

Learn to analyze cloud security logs before Lab 19.

Learning Objectives:
- Parse CloudTrail, Azure Activity Log, and GCP Audit Log formats
- Identify suspicious cloud events
- Map events across cloud providers
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

# =============================================================================
# EXERCISE 1: Parse CloudTrail Events
# =============================================================================


def parse_cloudtrail_event(event: Dict) -> Dict:
    """
    Extract key fields from an AWS CloudTrail event.

    Args:
        event: Raw CloudTrail event dictionary

    Returns:
        Normalized event with: timestamp, user, action, resource, source_ip, region

    TODO:
    1. Extract eventTime (convert to standard format)
    2. Extract user identity (handle different identity types)
    3. Extract eventName (the action)
    4. Extract affected resource
    5. Extract sourceIPAddress
    6. Extract awsRegion
    """
    # YOUR CODE HERE
    pass


def is_suspicious_cloudtrail_event(event: Dict) -> tuple[bool, str]:
    """
    Determine if a CloudTrail event is suspicious.

    Args:
        event: Parsed CloudTrail event

    Returns:
        Tuple of (is_suspicious: bool, reason: str)

    TODO:
    Check for these suspicious patterns:
    1. Root account usage
    2. IAM policy changes (AttachUserPolicy, AttachRolePolicy, etc.)
    3. Security group changes (AuthorizeSecurityGroupIngress)
    4. Audit log tampering (StopLogging, DeleteTrail)
    5. Public bucket policies (PutBucketPolicy with public access)
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# EXERCISE 2: Cross-Cloud Event Mapping
# =============================================================================

# Event category mapping across clouds
CROSS_CLOUD_EVENTS = {
    "user_creation": {
        "aws": ["CreateUser", "CreateLoginProfile"],
        "azure": ["Microsoft.Authorization/users/write"],
        "gcp": ["google.admin.AdminService.createUser"],
    },
    "permission_change": {
        "aws": ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"],
        "azure": ["Microsoft.Authorization/roleAssignments/write"],
        "gcp": ["SetIamPolicy", "google.iam.admin.v1.SetIamPolicy"],
    },
    "credential_creation": {
        "aws": ["CreateAccessKey"],
        "azure": ["Microsoft.KeyVault/vaults/secrets/write"],
        "gcp": ["google.iam.admin.v1.CreateServiceAccountKey"],
    },
    # TODO: Add more mappings for:
    # - storage_exposure
    # - audit_tampering
    # - network_change
}


def categorize_cloud_event(event_name: str, cloud_provider: str) -> str:
    """
    Categorize a cloud event into a standard category.

    Args:
        event_name: The specific event name (e.g., "CreateAccessKey")
        cloud_provider: One of "aws", "azure", "gcp"

    Returns:
        Category string (e.g., "credential_creation") or "unknown"

    TODO:
    1. Look up event_name in CROSS_CLOUD_EVENTS
    2. Return the matching category
    3. Return "unknown" if not found
    """
    # YOUR CODE HERE
    pass


def normalize_cloud_event(event: Dict, cloud_provider: str) -> Dict:
    """
    Normalize events from different clouds into a common format.

    Args:
        event: Raw event from AWS/Azure/GCP
        cloud_provider: Source cloud

    Returns:
        Normalized event dict with common fields:
        {
            "timestamp": ISO8601 string,
            "provider": "aws"|"azure"|"gcp",
            "user": username or identity,
            "action": the event/operation name,
            "category": categorized action,
            "resource": affected resource,
            "source_ip": IP address,
            "result": "success"|"failure",
            "raw": original event
        }

    TODO:
    Handle the different field names/structures for each cloud:
    - AWS: eventTime, userIdentity, eventName, sourceIPAddress
    - Azure: time, identity, operationName, callerIpAddress
    - GCP: timestamp, protoPayload.authenticationInfo, protoPayload.methodName
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# EXERCISE 3: Detect Attack Patterns
# =============================================================================


def detect_privilege_escalation(events: List[Dict]) -> List[Dict]:
    """
    Detect potential privilege escalation from a series of events.

    Pattern: User performs recon, then grants themselves more permissions

    Args:
        events: List of normalized cloud events (sorted by timestamp)

    Returns:
        List of detected escalation attempts with details

    TODO:
    Look for patterns like:
    1. ListUsers/ListRoles followed by AttachUserPolicy/AttachRolePolicy
    2. Same user creating new credentials shortly after gaining access
    3. Permission changes to overly broad policies
    """
    # YOUR CODE HERE
    pass


def detect_data_exfiltration_risk(events: List[Dict]) -> List[Dict]:
    """
    Detect potential data exfiltration preparation.

    Pattern: Storage exposure or large data access

    Args:
        events: List of normalized cloud events

    Returns:
        List of potential exfiltration risks

    TODO:
    Look for:
    1. Public bucket/storage policies
    2. Large number of GetObject/read operations
    3. New network egress rules
    4. Snapshot sharing to external accounts
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# MAIN: Test Your Implementation
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Lab 19a: Cloud Security Fundamentals")
    print("=" * 60)

    # Sample CloudTrail event
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
    if parsed:
        print(f"Parsed event: {json.dumps(parsed, indent=2)}")
    else:
        print("TODO: Implement parse_cloudtrail_event()")

    print("\n🔍 Exercise 1b: Check if Suspicious")
    print("-" * 40)
    result = is_suspicious_cloudtrail_event(sample_cloudtrail)
    if result:
        is_sus, reason = result
        print(f"Suspicious: {is_sus}")
        print(f"Reason: {reason}")
    else:
        print("TODO: Implement is_suspicious_cloudtrail_event()")

    print("\n🌐 Exercise 2: Cross-Cloud Event Mapping")
    print("-" * 40)
    test_events = [
        ("CreateAccessKey", "aws"),
        ("SetIamPolicy", "gcp"),
        ("Microsoft.Authorization/roleAssignments/write", "azure"),
    ]
    for event_name, cloud in test_events:
        category = categorize_cloud_event(event_name, cloud)
        if category:
            print(f"{cloud}: {event_name} → {category}")
        else:
            print(f"TODO: Implement categorize_cloud_event()")
            break

    print("\n" + "=" * 60)
    print("Complete the TODOs, then run the solution to compare!")
    print("=" * 60)

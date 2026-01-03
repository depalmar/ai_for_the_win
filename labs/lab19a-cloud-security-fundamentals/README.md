# Lab 19a: Cloud Security Fundamentals

**Difficulty:** 🟡 Intermediate | **Time:** 60-90 min | **Prerequisites:** Lab 04, basic networking

Understanding cloud infrastructure and security before diving into AI-powered cloud detection.

---

## 🎯 Learning Objectives

By the end of this lab, you will:

1. Understand core cloud concepts (IaaS, PaaS, SaaS)
2. Navigate AWS, Azure, and GCP security logging
3. Understand IAM (Identity and Access Management) across clouds
4. Know key security services and their purposes
5. Be prepared for Lab 19 (Cloud Security AI)

---

## ⏱️ Estimated Time

60-90 minutes (conceptual + hands-on exploration)

---

## 📋 Prerequisites

- Completed Lab 04 (LLM Log Analysis)
- Basic understanding of networking (IP, ports, HTTP)
- No cloud accounts required (we use sample data)

---

## Why This Matters

Modern security increasingly involves cloud infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CLOUD SECURITY REALITY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   On-Premises (Traditional)           Cloud (Modern)                        │
│   ─────────────────────────           ──────────────                        │
│   • You control everything            • Shared responsibility               │
│   • Physical security = yours         • Provider handles physical           │
│   • Limited attack surface            • Exposed APIs everywhere             │
│   • Slow to scale                     • Infinite scale, infinite risk       │
│                                                                             │
│   Cloud-native attacks:                                                     │
│   • Misconfigured S3 buckets          • Exposed credentials in repos       │
│   • Overprivileged IAM roles          • Insecure serverless functions      │
│   • Cross-account access abuse        • Container escape                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 1: Cloud Service Models

### IaaS vs PaaS vs SaaS

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CLOUD SERVICE MODELS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   On-Premises        IaaS              PaaS              SaaS               │
│   ───────────        ────              ────              ────               │
│                                                                             │
│   Applications      Applications      Applications      ████████████       │
│   Data              Data              Data              ████████████       │
│   Runtime           Runtime           ████████████      ████████████       │
│   Middleware        Middleware        ████████████      ████████████       │
│   OS                OS                ████████████      ████████████       │
│   Virtualization    ████████████      ████████████      ████████████       │
│   Servers           ████████████      ████████████      ████████████       │
│   Storage           ████████████      ████████████      ████████████       │
│   Networking        ████████████      ████████████      ████████████       │
│                                                                             │
│   You Manage        ████████████ = Provider Manages                         │
│                                                                             │
│   Example:          EC2, Azure VM     Lambda, App       Microsoft 365       │
│                     GCE               Engine, Azure     Salesforce          │
│                                       Functions                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Implications by Model

| Model | You're Responsible For | Provider Handles |
|-------|------------------------|------------------|
| **IaaS** | OS patches, app security, data encryption, IAM | Physical security, hypervisor, network infrastructure |
| **PaaS** | Application code, data, IAM | OS, runtime, scaling, patching |
| **SaaS** | User access, data classification | Everything else |

---

## Part 2: The Big Three Cloud Providers

### AWS (Amazon Web Services)

**Market Leader** - Most mature, most services, most complex.

| Service | Category | Security Purpose |
|---------|----------|------------------|
| **IAM** | Identity | User/role management, policies |
| **CloudTrail** | Logging | API call audit logs |
| **GuardDuty** | Detection | ML-based threat detection |
| **Security Hub** | SIEM-lite | Aggregated security findings |
| **VPC** | Network | Virtual network isolation |
| **S3** | Storage | Object storage (common misconfiguration target!) |
| **KMS** | Encryption | Key management |
| **WAF** | Perimeter | Web application firewall |

**Key Log Source**: CloudTrail

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "userName": "admin",
        "arn": "arn:aws:iam::123456789012:user/admin"
    },
    "eventTime": "2024-01-15T10:30:00Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "PutBucketPolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.50",
    "requestParameters": {
        "bucketName": "sensitive-data-bucket",
        "policy": "..."
    }
}
```

### Azure (Microsoft)

**Enterprise Favorite** - Deep Microsoft integration, strong hybrid cloud.

| Service | Category | Security Purpose |
|---------|----------|------------------|
| **Entra ID** (Azure AD) | Identity | Users, groups, SSO |
| **Activity Log** | Logging | Control plane audit |
| **Sentinel** | SIEM | Full security analytics |
| **Defender for Cloud** | Detection | CSPM + threat detection |
| **Virtual Network** | Network | Network isolation |
| **Key Vault** | Secrets | Credential management |
| **NSG** | Network | Network security groups |

**Key Log Source**: Activity Log / Sign-in Logs

```json
{
    "time": "2024-01-15T10:30:00Z",
    "resourceId": "/subscriptions/.../resourceGroups/prod/providers/...",
    "operationName": "Microsoft.Authorization/roleAssignments/write",
    "category": "Administrative",
    "resultType": "Success",
    "callerIpAddress": "203.0.113.50",
    "identity": {
        "claim": {
            "name": "admin@company.com"
        }
    }
}
```

### GCP (Google Cloud Platform)

**Developer Friendly** - Strong in AI/ML, Kubernetes, data analytics.

| Service | Category | Security Purpose |
|---------|----------|------------------|
| **IAM** | Identity | Fine-grained permissions |
| **Cloud Audit Logs** | Logging | Comprehensive audit trail |
| **Security Command Center** | Detection | Threat and vuln detection |
| **Chronicle** | SIEM | Google's security analytics |
| **VPC** | Network | Virtual networks |
| **Cloud KMS** | Encryption | Key management |

**Key Log Source**: Cloud Audit Logs

```json
{
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {
            "principalEmail": "admin@company.com"
        },
        "methodName": "storage.buckets.setIamPolicy",
        "resourceName": "projects/_/buckets/sensitive-data",
        "serviceData": {
            "policyDelta": {...}
        }
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "severity": "NOTICE"
}
```

---

## Part 3: IAM - The Foundation of Cloud Security

### Why IAM is Critical

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IAM = KEYS TO THE KINGDOM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   If an attacker compromises:                                               │
│                                                                             │
│   Regular User        Admin User           Service Account                  │
│   ────────────        ──────────           ───────────────                  │
│   • Read some data    • Do ANYTHING        • Automated actions              │
│   • Limited blast     • Create backdoor    • Often overprivileged           │
│     radius              accounts           • Keys never rotated             │
│                       • Delete everything  • Used by attackers for          │
│                       • Exfil all data       persistence                    │
│                                                                             │
│   80% of cloud breaches involve IAM misconfiguration                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### IAM Concepts Across Clouds

| Concept | AWS | Azure | GCP |
|---------|-----|-------|-----|
| **User** | IAM User | User (Entra ID) | User (Cloud Identity) |
| **Group** | IAM Group | Group | Group |
| **Role** | IAM Role | Azure Role | IAM Role |
| **Service Identity** | IAM Role (for services) | Managed Identity | Service Account |
| **Policy** | IAM Policy (JSON) | Azure Role Definition | IAM Policy |
| **Permission** | Action on Resource | Operation on Scope | Permission on Resource |

### IAM Best Practices

```
PRINCIPLE OF LEAST PRIVILEGE

❌ Bad:  "Give admin access so it works"
✅ Good: "Give exactly what's needed, nothing more"

❌ Bad:  {
           "Effect": "Allow",
           "Action": "*",
           "Resource": "*"
         }

✅ Good: {
           "Effect": "Allow", 
           "Action": "s3:GetObject",
           "Resource": "arn:aws:s3:::app-data/*"
         }
```

### Common IAM Attacks

| Attack | Description | Detection |
|--------|-------------|-----------|
| **Privilege Escalation** | User grants themselves more permissions | Monitor IAM policy changes |
| **Credential Theft** | Steal access keys, tokens | Unusual API calls, new geolocations |
| **Service Account Abuse** | Compromise automation credentials | Unusual service account activity |
| **Cross-Account Access** | Abuse trust relationships | Cross-account AssumeRole calls |

---

## Part 4: Cloud Logging and Detection

### What to Monitor

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CLOUD DETECTION PRIORITIES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CRITICAL (Always Alert)                                                   │
│   ─────────────────────────                                                 │
│   • Root/admin account usage                                                │
│   • IAM policy changes (especially to admin roles)                          │
│   • Security group/firewall rule changes                                    │
│   • Encryption key deletion or disabling                                    │
│   • Public exposure of storage (S3/Blob/GCS)                               │
│   • New user/role creation                                                  │
│                                                                             │
│   HIGH (Investigate Quickly)                                                │
│   ─────────────────────────────                                            │
│   • Failed authentications (brute force)                                    │
│   • Access from unusual locations/IPs                                       │
│   • Large data transfers                                                    │
│   • Service account key creation                                            │
│   • Cross-account access patterns                                           │
│                                                                             │
│   MEDIUM (Review Regularly)                                                 │
│   ─────────────────────────────                                            │
│   • Resource creation in unusual regions                                    │
│   • Configuration changes                                                   │
│   • New network routes                                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Events to Detect

#### AWS CloudTrail Events

| Event Name | Risk | Why |
|------------|------|-----|
| `ConsoleLogin` | High | Someone accessed web console |
| `CreateUser` | High | New IAM user created |
| `AttachUserPolicy` | Critical | Permissions granted |
| `PutBucketPolicy` | Critical | S3 permissions changed |
| `StopLogging` | Critical | Someone turning off audit trail! |
| `CreateAccessKey` | High | New programmatic credentials |
| `AssumeRole` | Medium | Cross-account or service access |

#### Azure Activity Log Events

| Operation | Risk | Why |
|-----------|------|-----|
| `Microsoft.Authorization/roleAssignments/write` | Critical | Role granted |
| `Microsoft.Compute/virtualMachines/delete` | High | VM deleted |
| `Microsoft.Storage/storageAccounts/listKeys` | High | Storage key accessed |
| `Microsoft.KeyVault/vaults/secrets/read` | High | Secret accessed |

#### GCP Audit Log Events

| Method | Risk | Why |
|--------|------|-----|
| `SetIamPolicy` | Critical | Permissions changed |
| `storage.buckets.create` | Medium | New storage created |
| `compute.firewalls.delete` | High | Firewall rule removed |
| `iam.serviceAccountKeys.create` | High | New service account key |

---

## Part 5: Hands-On - Analyzing Cloud Logs

### Exercise 1: Parse CloudTrail Logs

```python
"""
Analyze AWS CloudTrail logs for suspicious activity.
"""
import json
from datetime import datetime, timedelta
from typing import List, Dict

def load_cloudtrail_events(log_data: str) -> List[Dict]:
    """Parse CloudTrail log file."""
    data = json.loads(log_data)
    return data.get("Records", [])

def detect_suspicious_events(events: List[Dict]) -> List[Dict]:
    """Find potentially malicious CloudTrail events."""
    
    # High-risk event names to flag
    critical_events = {
        "ConsoleLogin",           # Console access
        "CreateUser",             # New user
        "CreateAccessKey",        # New credentials
        "AttachUserPolicy",       # Permission grant
        "AttachRolePolicy",       # Permission grant
        "PutBucketPolicy",        # S3 policy change
        "PutBucketAcl",           # S3 ACL change
        "StopLogging",            # Disabling audit!
        "DeleteTrail",            # Deleting audit!
        "AuthorizeSecurityGroupIngress",  # Firewall opening
    }
    
    suspicious = []
    for event in events:
        event_name = event.get("eventName", "")
        
        # Flag critical events
        if event_name in critical_events:
            suspicious.append({
                "event": event_name,
                "time": event.get("eventTime"),
                "user": event.get("userIdentity", {}).get("userName", "unknown"),
                "source_ip": event.get("sourceIPAddress"),
                "region": event.get("awsRegion"),
                "risk": "CRITICAL" if event_name in ["StopLogging", "DeleteTrail"] else "HIGH"
            })
        
        # Flag root account usage
        if event.get("userIdentity", {}).get("type") == "Root":
            suspicious.append({
                "event": event_name,
                "time": event.get("eventTime"),
                "user": "ROOT",
                "source_ip": event.get("sourceIPAddress"),
                "region": event.get("awsRegion"),
                "risk": "CRITICAL",
                "note": "Root account used - should almost never happen"
            })
        
        # Flag failed events (potential brute force)
        if event.get("errorCode") in ["AccessDenied", "UnauthorizedAccess"]:
            suspicious.append({
                "event": event_name,
                "time": event.get("eventTime"),
                "user": event.get("userIdentity", {}).get("userName", "unknown"),
                "source_ip": event.get("sourceIPAddress"),
                "risk": "MEDIUM",
                "note": f"Access denied: {event.get('errorMessage', '')}"
            })
    
    return suspicious

# Example usage
sample_cloudtrail = """
{
    "Records": [
        {
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "CreateUser",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "sourceIPAddress": "203.0.113.50",
            "awsRegion": "us-east-1"
        },
        {
            "eventTime": "2024-01-15T10:31:00Z",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "sourceIPAddress": "203.0.113.50",
            "awsRegion": "us-east-1"
        }
    ]
}
"""

events = load_cloudtrail_events(sample_cloudtrail)
findings = detect_suspicious_events(events)
for f in findings:
    print(f"[{f['risk']}] {f['event']} by {f['user']} from {f['source_ip']}")
```

### Exercise 2: Cross-Cloud Event Mapping

```python
"""
Map similar events across AWS, Azure, and GCP.
"""

CROSS_CLOUD_MAPPING = {
    "user_creation": {
        "aws": ["CreateUser", "CreateLoginProfile"],
        "azure": ["Microsoft.Authorization/users/write"],
        "gcp": ["google.admin.AdminService.createUser"]
    },
    "permission_change": {
        "aws": ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"],
        "azure": ["Microsoft.Authorization/roleAssignments/write"],
        "gcp": ["SetIamPolicy"]
    },
    "storage_exposure": {
        "aws": ["PutBucketPolicy", "PutBucketAcl", "PutObjectAcl"],
        "azure": ["Microsoft.Storage/storageAccounts/write"],
        "gcp": ["storage.buckets.setIamPolicy"]
    },
    "audit_tampering": {
        "aws": ["StopLogging", "DeleteTrail", "UpdateTrail"],
        "azure": ["Microsoft.Insights/diagnosticSettings/delete"],
        "gcp": ["google.logging.v2.ConfigServiceV2.DeleteSink"]
    },
    "credential_creation": {
        "aws": ["CreateAccessKey"],
        "azure": ["Microsoft.KeyVault/vaults/secrets/write"],
        "gcp": ["google.iam.admin.v1.CreateServiceAccountKey"]
    }
}

def categorize_event(event_name: str, cloud: str) -> str:
    """Categorize a cloud event into a standard category."""
    for category, mappings in CROSS_CLOUD_MAPPING.items():
        if event_name in mappings.get(cloud, []):
            return category
    return "other"

# Example
print(categorize_event("CreateAccessKey", "aws"))  # "credential_creation"
print(categorize_event("SetIamPolicy", "gcp"))     # "permission_change"
```

---

## Part 6: Common Cloud Attack Patterns

### Attack 1: Credential Theft → Privilege Escalation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               CREDENTIAL THEFT ATTACK CHAIN                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Initial Access           2. Reconnaissance       3. Privilege Esc      │
│   ─────────────────           ─────────────────       ─────────────────     │
│   Stolen AWS keys             List users, roles       Attach admin policy   │
│   from GitHub repo            Check permissions       to compromised user   │
│        │                           │                        │               │
│        ▼                           ▼                        ▼               │
│   CreateAccessKey             GetUser, ListRoles      AttachUserPolicy      │
│   ConsoleLogin                GetPolicy               CreateRole            │
│                                                                             │
│   4. Persistence              5. Impact                                     │
│   ─────────────────           ─────────────────                            │
│   Create new user             Exfiltrate data                              │
│   Create backdoor role        Delete resources                             │
│        │                      Crypto mining                                │
│        ▼                           │                                       │
│   CreateUser                       ▼                                       │
│   CreateLoginProfile          GetObject (mass)                             │
│                               RunInstances (mining)                        │
│                                                                             │
│   DETECTION: Monitor IAM changes, unusual API patterns, new credentials    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Attack 2: S3 Bucket Misconfiguration

```
PUBLIC BUCKET EXPOSURE

Common Misconfigurations:
• Bucket policy allows s3:GetObject to "*" (everyone)
• ACL set to "public-read"
• Block Public Access disabled

Detection Signals:
• PutBucketPolicy with Principal: "*"
• PutBucketAcl with public grants
• GetObject from unknown IPs
• Large data transfer spikes
```

### Attack 3: Service Account Abuse

```
SERVICE ACCOUNT COMPROMISE

Why Service Accounts are Targets:
• Often have broad permissions
• Keys rarely rotated
• Less monitoring than user accounts
• Perfect for persistence

Detection Signals:
• Service account used from unusual IPs
• Service account accessing unexpected resources
• New service account keys created
• Cross-account AssumeRole from service accounts
```

---

## Key Takeaways

1. **Shared Responsibility** - You're still responsible for configuration and data security
2. **IAM is Everything** - Most cloud breaches involve identity/permission issues
3. **Logs are Your Friend** - CloudTrail, Activity Log, Audit Logs are essential
4. **Cross-Cloud Patterns** - Similar attacks, different event names
5. **Detection Focus** - Monitor IAM changes, unusual access, data exfiltration

---

## Quick Reference: Cloud Security Cheat Sheet

### AWS Security Commands
```bash
# Check who you are
aws sts get-caller-identity

# List users
aws iam list-users

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME

# View recent CloudTrail events
aws cloudtrail lookup-events --max-results 10
```

### Azure CLI Commands
```bash
# Check current user
az account show

# List role assignments
az role assignment list

# View activity log
az monitor activity-log list --max-events 10
```

### GCP Commands
```bash
# Check current identity
gcloud auth list

# List IAM policies
gcloud projects get-iam-policy PROJECT_ID

# View audit logs (requires log viewer role)
gcloud logging read "logName:cloudaudit.googleapis.com"
```

---

## Resources

### Official Documentation
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

### SANS Resources
- [SANS Cloud Security Poster](https://www.sans.org/posters/) - Multi-cloud reference
- [SANS SEC510](https://www.sans.org/cyber-security-courses/cloud-security-architecture-and-operations/) - Cloud Security Architecture

### Tools
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) - Cloud security scanning

---

## What's Next?

You're now ready for Lab 19 (Cloud Security AI), which will teach you to:
- Build AI-powered cloud threat detection
- Analyze CloudTrail/Activity Logs with LLMs
- Create multi-cloud security monitoring
- Automate cloud compliance checks

**Next Lab**: [Lab 19 - Cloud Security with AI](../lab19-cloud-security-ai/)

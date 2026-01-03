# Lab 19a Walkthrough: Cloud Security Fundamentals

Step-by-step guide to understanding cloud security concepts before Lab 19.

---

## Overview

This bridge lab prepares you for Lab 19 (Cloud Security AI) by covering foundational cloud security concepts across AWS, Azure, and GCP.

**Time**: ~60-90 minutes  
**Prerequisites**: Labs 04 (LLM Log Analysis), basic networking  
**API Keys**: None required

---

## Part 1: Understanding Cloud Models

### Key Takeaways

1. **IaaS** (Infrastructure as a Service): You manage OS, apps, data
   - Examples: EC2, Azure VMs, Google Compute Engine
   
2. **PaaS** (Platform as a Service): Provider manages runtime/OS
   - Examples: Lambda, Azure Functions, Cloud Functions
   
3. **SaaS** (Software as a Service): Provider manages everything
   - Examples: Microsoft 365, Salesforce

### Security Implications

- **Shared Responsibility**: Cloud provider handles physical security, you handle configuration
- **More exposed**: APIs are internet-accessible by default
- **IAM is critical**: Most cloud breaches involve misconfigured permissions

---

## Part 2: The Big Three Clouds

### Comparison Table

| Concept | AWS | Azure | GCP |
|---------|-----|-------|-----|
| **Identity** | IAM | Entra ID | IAM |
| **Audit Logs** | CloudTrail | Activity Log | Audit Logs |
| **Threat Detection** | GuardDuty | Defender | SCC |
| **Network** | VPC | Virtual Network | VPC |

### What to Monitor

**High Priority Events:**
- Root/admin account usage
- IAM policy changes
- Storage exposure (public buckets)
- Audit log tampering

---

## Part 3: Exercises Walkthrough

### Exercise 1: Parse CloudTrail Events

The goal is to extract meaningful fields from AWS CloudTrail logs.

**Key Fields to Extract:**
- `eventTime` → timestamp
- `userIdentity.userName` → who did it
- `eventName` → what action
- `sourceIPAddress` → from where
- `awsRegion` → which region

**Solution Approach:**
```python
def parse_cloudtrail_event(event):
    user_identity = event.get("userIdentity", {})
    
    # Handle different identity types
    if user_identity.get("type") == "Root":
        user = "ROOT"
    else:
        user = user_identity.get("userName", "unknown")
    
    return {
        "timestamp": event.get("eventTime"),
        "user": user,
        "action": event.get("eventName"),
        "source_ip": event.get("sourceIPAddress"),
        "region": event.get("awsRegion")
    }
```

### Exercise 2: Cross-Cloud Event Mapping

Map similar events across clouds:

| Category | AWS | Azure | GCP |
|----------|-----|-------|-----|
| User created | CreateUser | users/write | createUser |
| Permission change | AttachUserPolicy | roleAssignments/write | SetIamPolicy |
| Credential created | CreateAccessKey | secrets/write | CreateServiceAccountKey |

**Why This Matters**: Multi-cloud environments need unified detection. Same attack, different log formats.

### Exercise 3: Detect Attack Patterns

**Privilege Escalation Pattern:**
1. Recon: `ListUsers`, `ListRoles` → Attacker enumerates accounts
2. Escalation: `AttachUserPolicy` → Attacker grants themselves admin
3. Persistence: `CreateAccessKey` → Attacker creates backdoor credentials

**Detection Logic:**
- Group events by user
- Look for recon followed by permission changes
- Flag users with multiple sensitive actions

---

## Common Mistakes

1. **Ignoring Root Account Usage** - Root should almost never be used
2. **Not Checking Source IP** - Unusual IPs indicate compromise
3. **Missing Cross-Account Access** - `AssumeRole` to external accounts is risky
4. **Overlooking Failed Events** - Access denied errors signal recon attempts

---

## Key Concepts to Remember

| Concept | Why It Matters |
|---------|---------------|
| **Principle of Least Privilege** | Only grant minimum needed permissions |
| **CloudTrail** | Your audit trail - never disable it |
| **IAM Policies** | JSON documents defining permissions |
| **Service Accounts** | Machine identities - often overprivileged |
| **VPC** | Network isolation - first line of defense |

---

## Ready for Lab 19?

After completing this lab, you should understand:

- ✅ Cloud service models and shared responsibility
- ✅ Key security services across AWS/Azure/GCP
- ✅ IAM concepts and common attacks
- ✅ Critical events to monitor in cloud logs
- ✅ How to detect privilege escalation patterns

**Next**: [Lab 19 - Cloud Security AI](../../labs/lab19-cloud-security-ai/) uses LLMs to analyze cloud logs at scale.

---

## Resources

- [Lab 19a README](../../labs/lab19a-cloud-security-fundamentals/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

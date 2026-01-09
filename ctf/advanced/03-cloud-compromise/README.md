# Cloud Compromise

**Difficulty:** Advanced
**Points:** 500
**Prerequisite:** Lab 45 (Cloud Security AI)
**Time Estimate:** 90-120 minutes

## Challenge Description

A multi-cloud organization detected suspicious activity across their AWS, Azure, and GCP environments. The attacker appears to be moving laterally between clouds using compromised service accounts.

Analyze the cloud logs, trace the attack path, and identify the data the attacker exfiltrated. The flag is hidden in the exfiltrated data.

## Files Provided

- `data/aws_cloudtrail.json` - AWS CloudTrail logs
- `data/azure_activity.json` - Azure Activity logs
- `data/gcp_audit.json` - GCP Audit logs
- `data/iam_policies.json` - IAM configurations across clouds
- `data/resource_inventory.json` - Cloud resource inventory

## Objectives

1. Identify the initial compromise vector
2. Trace lateral movement across clouds
3. Map the privilege escalation path
4. Identify exfiltrated data and extract the flag

## Hints

<details>
<summary>Hint 1 (Cost: 50 points)</summary>

The initial access was through a misconfigured AWS Lambda function with overly permissive IAM role. Look for AssumeRole events.
</details>

<details>
<summary>Hint 2 (Cost: 100 points)</summary>

The attacker pivoted to Azure using federation trust. Search for unusual SAML token issuance events.
</details>

<details>
<summary>Hint 3 (Cost: 150 points)</summary>

The exfiltrated data went through GCP Cloud Functions to an external endpoint. The flag is base64-encoded in the request body logged in the audit trail.
</details>

## Scoring

- Full solution without hints: 500 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Multi-cloud attack analysis
- IAM privilege escalation detection
- Cross-cloud lateral movement
- Cloud audit log correlation

## Tools You Might Use

- jq for JSON parsing
- Python for log analysis
- Cloud-specific CLI tools
- Timeline visualization

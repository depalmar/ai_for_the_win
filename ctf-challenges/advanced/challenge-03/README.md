# Challenge 03: Cloud Compromise

**Category:** Cloud Security
**Points:** 500
**Difficulty:** Advanced

## Description

A sophisticated attacker has compromised your multi-cloud environment spanning AWS and Azure. They've moved laterally across cloud boundaries and established persistence in multiple locations.

Your mission: Trace the attack path across clouds, identify all compromised resources, and find the flag hidden in the attacker's trail.

## Objective

1. Analyze CloudTrail and Azure Activity logs
2. Trace the lateral movement path
3. Identify all compromised resources
4. Find the flag in the attacker's persistence mechanism

## Files

- `aws_cloudtrail.json` - AWS CloudTrail events
- `azure_activity.json` - Azure Activity Log events
- `iam_analysis.json` - Compromised identity analysis
- `resource_inventory.json` - Cloud resource inventory

## Attack Path Elements

- Initial access via compromised credentials
- Privilege escalation in AWS
- Cross-cloud movement to Azure
- Data access and exfiltration
- Persistence establishment

## Rules

- Correlate events across both clouds
- The flag format is `FLAG{...}`
- AI can help trace the attack path

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

The attacker created a backdoor user in Azure - check the user creation events.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

The backdoor user's display name contains encoded data.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

Base64 decode the display name "RkxBR3tDTE9VRF9IT1BQRVJ9" to get the flag: FLAG{CLOUD_HOPPER}

</details>

## Skills Tested

- Multi-cloud security
- Log correlation
- Attack path analysis
- Identity security

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-03 "FLAG{your_answer}"
```

Hunt across clouds! ☁️

# CTF Beginner 01: Log Detective

**Difficulty:** Easy
**Points:** 100
**Prerequisite:** Lab 35 (LLM Log Analysis)
**API Key:** Optional (can be solved manually)

## Challenge Description

A suspicious alert triggered at 3:47 AM - outbound traffic to an unusual destination during off-hours. The automated detection system flagged it, but the initial triage was inconclusive. The security team has exported the relevant logs for deeper analysis.

Your mission: Dig through the logs, identify the attacker's footprints, and recover the hidden flag that proves the compromise.

## Files Provided

- `logs/auth.log` - Authentication logs from the target server
- `logs/system.log` - System events
- `logs/network.log` - Network connection logs

## Objective

Find the flag hidden within the provided log files.

## Hints

<details>
<summary>Hint 1 (Cost: 10 points)</summary>

Focus on the 3:00-4:00 AM time window in the network logs. Something doesn't match the normal traffic pattern.
</details>

<details>
<summary>Hint 2 (Cost: 25 points)</summary>

The attacker tried to hide their tracks using encoding. Check for base64.
</details>

<details>
<summary>Hint 3 (Cost: 50 points)</summary>

Look at the user-agent string in the network logs. It contains encoded data.
</details>

## Submit Your Flag

Once you find the flag, validate it matches the format: `FLAG{...}`

## Learning Objectives

By completing this challenge, you will practice:
- Log analysis techniques
- Pattern recognition in security data
- Base64 decoding
- Correlating data across multiple log sources

# Challenge 05: Full IR Scenario

**Category:** DFIR
**Points:** 500
**Difficulty:** Advanced

## Description

This is the final challenge - a complete incident response scenario that tests all your AI-powered security skills. A major breach has occurred, and you need to piece together the full attack narrative from multiple artifact sources.

Your mission: Conduct a complete investigation using all available artifacts, build the attack timeline, identify all compromise indicators, and find the flag that proves your mastery.

## Objective

1. Analyze all provided artifacts comprehensively
2. Build a complete attack timeline
3. Identify initial access, persistence, lateral movement, and objectives
4. Find the flag hidden across multiple artifacts

## Files

- `incident_summary.json` - High-level incident overview
- `endpoint_artifacts/` - Artifacts from compromised endpoints
  - `registry.json` - Registry changes
  - `scheduled_tasks.json` - Scheduled task analysis
  - `prefetch.json` - Program execution evidence
- `network_artifacts/` - Network-based evidence
  - `firewall_logs.json` - Firewall log entries
  - `proxy_logs.json` - Web proxy logs
  - `dns_logs.json` - DNS query logs
- `threat_intel.json` - IOC matches from threat intel

## Challenge Structure

This challenge requires correlating evidence across:
- Endpoint forensics
- Network forensics
- Threat intelligence
- Timeline analysis

The flag is split across multiple artifacts - you need ALL pieces.

## Rules

- Use AI to correlate findings across all sources
- The flag format is `FLAG{...}`
- Each artifact source contains one part of the flag

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

The flag is split into 4 parts, one in each major artifact category.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

Look for "flag_part" fields in each JSON file. Combine them in order.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

Flag parts: MAS + TER_ + IR_ + PR0 = FLAG{MASTER_IR_PR0}

</details>

## Skills Tested

- Complete incident response
- Multi-source correlation
- Timeline reconstruction
- AI-assisted analysis
- Evidence synthesis

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-05 "FLAG{your_answer}"
```

Prove your mastery! 🏆

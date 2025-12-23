# Challenge 01: APT Attribution

**Category:** Threat Intelligence
**Points:** 500
**Difficulty:** Advanced

## Description

A sophisticated threat actor has been operating in your network. Your threat intelligence team has collected artifacts from multiple intrusions. Your mission is to profile the threat actor and determine their identity.

## Scenario

Over the past month, three separate incidents have been detected:
1. Initial access via spear-phishing
2. Lateral movement using custom tools
3. Data exfiltration through encrypted channels

You have:
- Malware samples (metadata only)
- Network indicators
- MITRE ATT&CK technique observations
- Partial threat actor profiles

## Objective

1. Analyze the TTPs across all incidents
2. Correlate with known threat actor behaviors
3. Determine the likely threat actor group
4. Find the flag hidden in the attribution evidence

## Files

- `incident_1/` - First incident artifacts
- `incident_2/` - Second incident artifacts
- `incident_3/` - Third incident artifacts
- `threat_actors.json` - Known APT group profiles
- `mitre_mapping.json` - Observed techniques

## Analysis Requirements

Your AI-powered analysis should consider:
- TTP overlap with known groups
- Infrastructure patterns
- Malware code similarities
- Targeting and victimology
- Operational timing patterns

## Rules

- Use AI for correlation and analysis
- The flag format is `FLAG{...}`
- Attribution requires evidence from all three incidents
- Document your analytical methodology

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

The threat actor's name relates to a specific geographic region and weather phenomenon.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

Look for the unique tool name that appears across all incidents - it's the actor's signature.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

The flag is formed by: APT group number + first letter of signature tool + year first seen.

</details>

## Skills Tested

- Advanced threat intelligence
- Multi-source correlation
- AI-assisted analysis
- Threat actor profiling
- MITRE ATT&CK mapping

## Scoring

- Basic attribution: 250 pts
- Complete profile: 400 pts
- Flag capture: 500 pts

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-01 "FLAG{your_answer}"
```

The hunt begins... 🕵️

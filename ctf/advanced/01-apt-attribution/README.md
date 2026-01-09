# APT Attribution

**Difficulty:** Advanced
**Points:** 500
**Prerequisite:** Lab 36 (Threat Actor Profiling)
**Time Estimate:** 90-120 minutes

## Challenge Description

Your threat intel team intercepted communications and artifacts from a sophisticated attack campaign. Multiple threat actors are suspected, but attribution is unclear.

Analyze the evidence using TTP mapping, infrastructure analysis, and code similarity to attribute the attack to known threat actors. The correct attribution unlocks the flag.

## Files Provided

- `data/malware_samples/` - 5 malware samples from the campaign
- `data/network_iocs.json` - C2 infrastructure indicators
- `data/attack_timeline.json` - Timeline of attack events
- `data/known_actors.json` - Database of known threat actor TTPs
- `data/previous_campaigns.json` - Historical campaign data

## Objectives

1. Map observed TTPs to MITRE ATT&CK
2. Analyze code similarities across samples
3. Correlate infrastructure with known actors
4. Make a confident attribution
5. Decode the flag using the actor's identifier

## Hints

<details>
<summary>Hint 1 (Cost: 50 points)</summary>

Focus on the unique combination of initial access (T1566.001) and persistence (T1053.005) techniques. Only two actors in the database use both.
</details>

<details>
<summary>Hint 2 (Cost: 100 points)</summary>

The malware's string encoding routine matches a known tool used by APT-PHANTOM. Compare the XOR key derivation.
</details>

<details>
<summary>Hint 3 (Cost: 150 points)</summary>

Cross-reference the C2 domain registration dates with the actor's known operational patterns. The flag is XOR'd with the actor's ID number.
</details>

## Scoring

- Full solution without hints: 500 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- MITRE ATT&CK mapping
- Threat actor TTP analysis
- Code similarity analysis
- Infrastructure correlation
- Diamond Model application

## Tools You Might Use

- MITRE ATT&CK Navigator
- YARA for code similarity
- Python for data analysis
- Network analysis tools

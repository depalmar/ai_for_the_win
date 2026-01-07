# Challenge 05: Ransomware Response

**Category:** Incident Response
**Points:** 250
**Difficulty:** Intermediate

## Description

A ransomware incident has been detected in progress. The IR team has collected initial artifacts and needs help analyzing the attack to understand the scope and identify the threat actor.

Your mission: Analyze the incident artifacts, trace the attack timeline, and find the flag hidden in the attacker's infrastructure.

## Objective

1. Analyze the ransomware note and encryption pattern
2. Identify the initial access vector
3. Trace lateral movement within the network
4. Find the flag hidden in the attacker's artifacts

## Files

- `ransom_note.txt` - The ransom note left by attackers
- `encrypted_files.json` - List of encrypted files with metadata
- `network_logs.json` - Network activity during the attack
- `timeline.json` - Event timeline from multiple sources

## Background

Ransomware incidents require rapid analysis to:
- Identify the ransomware family
- Determine initial access vector
- Assess scope of encryption
- Look for data exfiltration indicators

## Rules

- Analyze all provided artifacts
- The flag format is `FLAG{...}`
- AI can help correlate events across sources

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

The ransom note contains more than just demands - look carefully at all the text.

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

Ransomware authors sometimes leave artifacts or signatures in their notes - scroll through the entire document.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

The flag is hidden in plain sight within the ransom note text itself.

</details>

## Skills Tested

- Incident response
- Artifact analysis
- Timeline correlation
- AI-assisted investigation

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-05 "FLAG{your_answer}"
```

Respond swiftly! 🚨

# Challenge 01: Log Detective

**Category:** Log Analysis
**Points:** 100
**Difficulty:** Beginner

## Description

A security analyst has collected authentication logs from a compromised server. Hidden within these logs is evidence of an attack that led to unauthorized access.

Your mission: Use AI-powered analysis to find the attacker's footprint and discover the flag.

## Objective

Analyze the authentication logs to:
1. Identify the malicious activity
2. Find the attacker's IP address
3. Determine when the breach occurred
4. Extract the flag hidden in the attack pattern

## Files

- `auth_logs.json` - Authentication log entries

## Rules

- You may use any AI tool (Claude, GPT, etc.)
- The flag format is `FLAG{...}`
- Document your analysis approach

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

Look for failed login attempts followed by a successful one from the same IP.

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

The attacker's username contains part of the flag.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

Combine the suspicious IP's last octet with the timestamp hour.

</details>

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-01 "FLAG{your_answer}"
```

Good luck, detective! 🔍

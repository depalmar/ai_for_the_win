# Challenge 03: Hidden IOC

**Category:** Threat Intelligence
**Points:** 100
**Difficulty:** Beginner

## Description

A threat intelligence feed has provided a report on recent threat actor activity. The report contains various indicators of compromise (IOCs) embedded within the text, but some are obfuscated or encoded to evade detection.

Your mission: Parse the threat report, extract all IOCs, and find the flag hidden in the data.

## Objective

1. Parse the threat intelligence report
2. Extract all IOCs (IPs, domains, hashes, URLs)
3. Identify obfuscated or encoded indicators
4. Decode the hidden flag from the IOCs

## Files

- `threat_report.txt` - Raw threat intelligence report
- `ioc_patterns.json` - Common IOC patterns for reference

## IOC Types to Extract

- IP addresses (IPv4)
- Domain names
- File hashes (MD5, SHA256)
- URLs
- Email addresses

## Rules

- You may use any AI tool or regex patterns
- The flag format is `FLAG{...}`
- Some IOCs may be defanged (e.g., hxxp, [.])

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

One of the file hashes contains hex-encoded ASCII characters.

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

Look for a hash that's exactly 32 characters but doesn't match any real malware.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

Convert the fake MD5 hash from hex to ASCII to reveal the flag.

</details>

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-03 "FLAG{your_answer}"
```

Extract with precision! 🔬

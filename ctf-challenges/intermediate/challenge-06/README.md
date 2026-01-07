# Challenge 06: Web Shell Detective

**Category:** Web Security / DFIR
**Points:** 250
**Difficulty:** Intermediate

## Description

A web application was compromised, and the attacker deployed a web shell for persistent access. The security team has collected Apache access logs and a snapshot of PHP files from the web server.

Your mission: Analyze the logs to identify web shell activity, locate the malicious file, and extract the flag hidden in the attacker's commands.

## Objective

1. Analyze Apache access logs for suspicious requests
2. Identify patterns indicating web shell usage
3. Correlate log entries with PHP files
4. Decode attacker commands to find the flag

## Files

- `access_log.json` - Apache access log entries (parsed)
- `php_files.json` - List of PHP files with metadata and hashes
- `file_contents.json` - Contents of suspicious PHP files

## Background

Web shells are malicious scripts that provide remote access to a web server. Common indicators include:
- Unusual parameter names (cmd, exec, c, shell)
- Base64 or URL-encoded payloads
- POST requests to uncommon PHP files
- Requests from single IPs to specific files
- User-agent anomalies

## Rules

- Analyze all provided artifacts
- The flag format is `FLAG{...}`
- Pay attention to encoded data in requests

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

Look for requests with the parameter "cmd" or "c" - web shells often use these.

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

The attacker's commands are base64 encoded in the request parameters.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

Decode all base64 command parameters and look for the flag in one of them.

</details>

## Skills Tested

- Web server log analysis
- Web shell identification
- Base64 decoding
- Attack pattern recognition
- AI-assisted threat hunting

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-06 "FLAG{your_answer}"
```

Find that shell! 🐚

# CTF Beginner 02: Phish Finder

**Difficulty:** Easy
**Points:** 100
**Prerequisite:** Lab 01 (Phishing Classifier)
**API Key:** No

## Challenge Description

The Security Operations Center received reports of a phishing campaign targeting employees. You've been given a sample of emails to analyze.

Your mission: Identify the phishing emails and extract the hidden flag.

## Files Provided

- `emails/inbox.json` - Collection of email samples in JSON format

## Objective

Analyze the emails, identify the phishing attempts, and find the flag hidden within the malicious emails.

## Hints

<details>
<summary>Hint 1 (Cost: 10 points)</summary>

Look for common phishing indicators: urgency, suspicious links, spoofed senders.
</details>

<details>
<summary>Hint 2 (Cost: 25 points)</summary>

The flag is split across multiple phishing emails. Combine the suspicious elements.
</details>

<details>
<summary>Hint 3 (Cost: 50 points)</summary>

Extract the subdomain from each phishing URL and concatenate them in order of the email timestamp.
</details>

## Submit Your Flag

Once you find the flag, validate it matches the format: `FLAG{...}`

## Learning Objectives

By completing this challenge, you will practice:
- Phishing email identification
- URL analysis
- Pattern extraction from structured data
- Data correlation

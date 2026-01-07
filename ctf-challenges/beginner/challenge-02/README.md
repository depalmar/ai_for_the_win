# Challenge 02: Phish Finder

**Category:** Email Analysis
**Points:** 100
**Difficulty:** Beginner

## Description

Your security team has received a batch of emails flagged by users as potential phishing attempts. Not all of them are malicious - some are legitimate business communications that users mistakenly reported.

Your mission: Use AI-powered analysis to identify the actual phishing email and extract the hidden flag.

## Objective

1. Analyze each email for phishing indicators
2. Classify emails as phishing or legitimate
3. Extract IOCs from the malicious email
4. Find the flag hidden in the phishing attempt

## Files

- `emails.json` - Collection of reported emails

## Indicators to Look For

- Suspicious sender domains
- Urgent/threatening language
- Mismatched URLs
- Grammar/spelling errors
- Requests for sensitive information

## Rules

- You may use any AI tool (Claude, GPT, etc.)
- The flag format is `FLAG{...}`
- Document which indicators helped identify the phish

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

One email has a sender domain that looks like a legitimate company but has a subtle typo.

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

Check the email headers - SPF and DKIM failures are strong phishing indicators.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

The flag is hidden in the body of the phishing email. Look for the FLAG{...} format.

</details>

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-02 "FLAG{your_answer}"
```

Don't get hooked! 🎣

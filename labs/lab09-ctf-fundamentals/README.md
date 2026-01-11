# Lab 09: CTF Fundamentals

**Time:** 45-60 minutes
**Prerequisites:** Labs 01-02 recommended
**Difficulty:** Beginner
**API Keys Required:** None

## Overview

This lab bridges the gap between completing the foundational labs and successfully solving Capture The Flag (CTF) challenges. You'll learn the CTF mindset, common flag hiding techniques, and strategies for approaching security challenges.

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand CTF conventions and flag formats
2. Recognize common data hiding techniques
3. Apply systematic approaches to finding hidden information
4. Use AI assistants effectively for CTF challenges
5. Decode common encoding schemes

## What is a CTF?

**Capture The Flag (CTF)** competitions are cybersecurity challenges where participants solve security puzzles to find hidden "flags" - special strings that prove you solved the challenge.

### Flag Format

In this course, all flags follow this format:
```
FLAG{some_text_here}
```

Examples:
- `FLAG{HELLO_WORLD}`
- `FLAG{f0und_th3_s3cr3t}`
- `FLAG{192_168_1_1}`

**Key insight:** The flag is always somewhere in the data. Your job is to find it.

## The CTF Mindset

### Think Like an Investigator

CTF challenges are puzzles. Unlike labs where you build something step-by-step, CTFs require you to:

1. **Read everything carefully** - Challenge descriptions contain hints
2. **Examine all data** - Every file, field, and value could matter
3. **Question assumptions** - What looks normal might hide something
4. **Iterate and pivot** - First attempts often fail; that's expected

### The OODA Loop for CTFs

1. **Observe** - What data do you have? What's the challenge asking?
2. **Orient** - What techniques might apply? What's unusual?
3. **Decide** - Pick an approach to try
4. **Act** - Execute and evaluate results

Repeat until you find the flag.

## Common Flag Hiding Techniques

### 1. Plain Text (Hidden in Plain Sight)

The flag might be directly in the data but easy to miss:

```json
{
  "user": "admin",
  "message": "System alert: FLAG{H1DD3N_1N_PL41N_S1GHT}",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Strategy:** Search for "FLAG{" in all files.

### 2. Encoded Data

Common encodings used to hide flags:

#### Base64
```
RkxBR3tCQVNFNjRfREVDT0RFRH0=
```
Decode: `FLAG{BASE64_DECODED}`

#### Hex
```
464c41477b4845585f454e434f4445447d
```
Decode: `FLAG{HEX_ENCODED}`

#### URL Encoding
```
FLAG%7BURL_ENCODED%7D
```
Decode: `FLAG{URL_ENCODED}`

**Strategy:** Look for strings that look like encoded data and try decoding them.

### 3. Concatenation

The flag is split across multiple fields:

```json
{
  "error_code": "FLAG{SPLIT",
  "detail": "_ACROSS",
  "resolution": "_FIELDS}"
}
```

Combined: `FLAG{SPLIT_ACROSS_FIELDS}`

**Strategy:** Look for partial matches and combine related fields.

### 4. Metadata and Comments

Flags hidden in places often overlooked:

```python
# Configuration file
# Author: security_team
# Secret: FLAG{1N_TH3_C0MM3NTS}
API_KEY = "not_the_flag"
```

**Strategy:** Check comments, metadata, headers, and non-obvious locations.

### 5. Pattern Extraction

The flag is derived from patterns in data:

```
Failed login from 70.76.65.71 (F.L.A.G)
Failed login from 123.83.69.67 ({.S.E.C)
Failed login from 82.51.84.125 (R.3.T.})
```

ASCII values: 70=F, 76=L, 65=A, 71=G, 123={, etc.

Combined: `FLAG{S3CR3T}`

**Strategy:** Look for patterns, especially in IP addresses, timestamps, or numeric fields.

### 6. Steganography (Data in Data)

Information hidden within other information:

- Text hidden in whitespace (tabs vs spaces)
- Data in image EXIF metadata
- LSB (Least Significant Bit) encoding

**Strategy:** Use specialized tools or look for unusual file properties.

## Hands-On Practice

### Mini-Challenge 1: Find the Flag

Examine this log data. Where's the flag?

```
2024-01-15 10:00:01 INFO User login successful: admin
2024-01-15 10:00:02 INFO Session created: sess_abc123
2024-01-15 10:00:03 DEBUG Config loaded: FLAG{L0G_4N4LYS1S_101}
2024-01-15 10:00:04 INFO Request processed: /api/data
2024-01-15 10:00:05 INFO User logout: admin
```

<details>
<summary>Solution</summary>

The flag is in the DEBUG log entry on line 3:
```
FLAG{L0G_4N4LYS1S_101}
```

**Lesson:** Always check ALL log levels, not just ERROR or WARN.
</details>

---

### Mini-Challenge 2: Decode the Message

This string was found in a suspicious file:

```
RkxBR3tEM0MwRDNfVEgzX00zU1M0RzN9
```

<details>
<summary>Hint</summary>

The string ends with `=` padding sometimes removed. It looks like Base64.
</details>

<details>
<summary>Solution</summary>

Base64 decode the string:
```python
import base64
encoded = "RkxBR3tEM0MwRDNfVEgzX00zU1M0RzN9"
decoded = base64.b64decode(encoded).decode()
print(decoded)  # FLAG{D3C0D3_TH3_M3SS4G3}
```

**Flag:** `FLAG{D3C0D3_TH3_M3SS4G3}`
</details>

---

### Mini-Challenge 3: Connect the Dots

An attacker left traces across multiple log entries:

```json
[
  {"time": "10:00", "action": "login", "user": "FLAG{US3R"},
  {"time": "10:01", "action": "download", "file": "_CR0SS"},
  {"time": "10:02", "action": "logout", "note": "_F13LDS}"}
]
```

<details>
<summary>Hint</summary>

Look at all the VALUES, not just specific fields.
</details>

<details>
<summary>Solution</summary>

Concatenate values that look like flag parts:
- `user`: `FLAG{US3R`
- `file`: `_CR0SS`
- `note`: `_F13LDS}`

**Flag:** `FLAG{US3R_CR0SS_F13LDS}`

**Lesson:** Flags can span multiple fields or records.
</details>

---

### Mini-Challenge 4: The Hex Trail

Network traffic captured this suspicious payload:

```
Payload: 464c41477b4845585f5452414646494321217d
```

<details>
<summary>Hint</summary>

This is hexadecimal. Each pair of characters represents one ASCII character.
</details>

<details>
<summary>Solution</summary>

```python
hex_string = "464c41477b4845585f5452414646494321217d"
decoded = bytes.fromhex(hex_string).decode()
print(decoded)  # FLAG{HEX_TRAFFIC!!}
```

**Flag:** `FLAG{HEX_TRAFFIC!!}`
</details>

## Using AI for CTFs

AI assistants can help with CTF challenges, but use them strategically:

### Effective AI Prompts

**Good prompt:**
```
I have this log data from a CTF challenge. I need to find a flag
in format FLAG{...}. Can you help me analyze it for:
1. Any obvious flags in the text
2. Encoded strings that might decode to a flag
3. Patterns that could combine to form a flag

Here's the data:
[paste data]
```

**Less effective prompt:**
```
Solve this CTF for me
[paste data]
```

### When AI Helps Most

- Decoding/encoding (base64, hex, rot13, etc.)
- Pattern recognition across large datasets
- Correlating information from multiple sources
- Explaining what techniques might apply
- Writing quick scripts to extract data

### When to Think Manually

- Understanding the challenge context
- Making creative leaps
- Recognizing domain-specific clues (security jargon, tool names)
- Deciding which approach to try first

## CTF Strategy Checklist

Use this checklist when approaching any CTF challenge:

```
[ ] Read the challenge description completely
[ ] List all provided files and data sources
[ ] Search for "FLAG{" in all files
[ ] Check for encoded strings (base64, hex, URL encoding)
[ ] Examine metadata, comments, and headers
[ ] Look for patterns in IPs, timestamps, or numeric data
[ ] Consider what the challenge title/category hints at
[ ] Try the obvious approach first
[ ] Take notes on what you've tried
[ ] If stuck, re-read the hints (they cost points but help)
```

## Common Decoding Commands

Keep these handy:

```python
import base64
import urllib.parse

# Base64
base64.b64decode("encoded_string").decode()

# Hex
bytes.fromhex("hex_string").decode()

# URL decode
urllib.parse.unquote("url%20encoded")

# ROT13
import codecs
codecs.decode("rot13_text", 'rot_13')
```

```bash
# Command line alternatives
echo "base64string" | base64 -d
echo "68656c6c6f" | xxd -r -p
```

## Prerequisites Matrix

Before attempting CTF challenges, ensure you've completed relevant labs:

| CTF Challenge | Required Lab(s) | API Key Needed |
|---------------|-----------------|----------------|
| Beginner-01: Log Detective | Lab 35 | Yes |
| Beginner-02: Phish Finder | Lab 29 | No |
| Beginner-03: Hidden IOC | Lab 29, Lab 36 | Yes |
| Beginner-04: Malware Classifier | Lab 31 | No |
| Beginner-05: Prompt Injection | Lab 31 | No |
| Intermediate-01: C2 Hunter | Lab 35 | Yes |
| Intermediate-02: Memory Forensics | Lab 25 | No |
| Intermediate-03: Adversarial ML | Lab 38 | No |
| Intermediate-04: Agent Investigation | Lab 36 | Yes |
| Intermediate-05: Ransomware Response | Lab 25 | No |

## Summary

CTF challenges reward:
- **Careful reading** - Every word in the description matters
- **Systematic searching** - Check everything, not just obvious places
- **Persistence** - First attempts often fail
- **Pattern recognition** - Data often hides information in structure
- **Tool knowledge** - Know how to decode and transform data

The labs teach you security concepts. CTFs test if you can apply them creatively.

## Next Steps

Ready to try real CTF challenges?

1. Start with **Beginner-01: Log Detective** or **Beginner-02: Phish Finder**
2. Use the checklist above
3. Don't be afraid to use hints (they're there to help)
4. Learn from each challenge, even failed attempts

Good luck, and happy hunting!

---

**You've completed the intro labs!** You're now ready for the main course:

**Next Lab:** [Lab 29: Phishing Classifier](../Lab 29-phishing-classifier/) - Build your first ML security tool

Or explore: [CTF Challenges](../../ctf/) - Test your skills with capture-the-flag challenges

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│                  CTF QUICK REFERENCE                     │
├─────────────────────────────────────────────────────────┤
│ Flag Format:    FLAG{...}                               │
│                                                         │
│ First Steps:    1. Read challenge carefully             │
│                 2. grep -r "FLAG{" .                    │
│                 3. Check for encoded strings            │
│                                                         │
│ Common Encodings:                                       │
│   Base64: Letters/numbers ending in = or ==             │
│   Hex: Long strings of 0-9 and a-f                     │
│   URL: Contains %XX patterns                            │
│                                                         │
│ Decode Commands:                                        │
│   base64 -d <<< "string"                               │
│   echo "hex" | xxd -r -p                               │
│   python -c "import base64; print(base64.b64decode(    │
│              'string').decode())"                       │
│                                                         │
│ If Stuck:       - Re-read the challenge                │
│                 - Check ALL files                       │
│                 - Use hints (cost points, but help)     │
│                 - Ask AI to analyze patterns            │
└─────────────────────────────────────────────────────────┘
```

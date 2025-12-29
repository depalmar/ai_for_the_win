# Challenge 02: Memory Forensics

**Category:** DFIR
**Points:** 250
**Difficulty:** Intermediate

## Description

A suspected compromised workstation has been imaged for forensic analysis. The memory dump contains evidence of malicious activity, including a running process that was injecting code into legitimate applications.

Your mission: Analyze the memory artifacts to identify the malicious process and extract the flag hidden in the attack.

## Objective

1. Analyze the process list and identify suspicious processes
2. Examine process memory regions for injected code
3. Extract strings and artifacts from malicious memory regions
4. Find the flag hidden in the attacker's payload

## Files

- `process_list.json` - Running processes at time of capture
- `memory_regions.json` - Memory region metadata
- `extracted_strings.txt` - Strings extracted from suspicious regions
- `network_connections.json` - Active network connections

## Analysis Techniques

- Process tree analysis
- Parent-child relationship verification
- Memory region permission analysis
- String extraction and pattern matching
- Network connection correlation

## Rules

- Use AI to help correlate findings
- The flag format is `FLAG{...}`
- Focus on processes with unusual characteristics

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

Look for a process running from an unusual location (not System32 or Program Files).

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

The malicious process has injected code with RWX permissions - a classic red flag.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

The flag is hidden in the extracted strings from PID 4592's memory region.

</details>

## Skills Tested

- Memory forensics concepts
- Process analysis
- AI-assisted investigation
- Pattern recognition

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-02 "FLAG{your_answer}"
```

Dive into memory! 🧠

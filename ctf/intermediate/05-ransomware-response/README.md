# Ransomware Response

**Difficulty:** Intermediate
**Points:** 250
**Prerequisite:** Lab 31 (Ransomware Detection)
**Time Estimate:** 60-90 minutes

## Challenge Description

A company's file server was hit by ransomware. The attack was stopped mid-execution, leaving some files encrypted and others intact. The ransom note demands payment, but your job is to analyze the attack, not pay.

Fortunately, the ransomware author made a cryptographic mistake. Analyze the samples, find the weakness, and recover the flag from an encrypted file.

## Files Provided

- `data/encrypted_files/` - Partially encrypted file system snapshot
- `data/ransom_note.txt` - The ransom demand
- `data/ransomware_sample.bin` - The ransomware binary (defanged)
- `data/process_memory.bin` - Memory dump of the ransomware process
- `data/file_metadata.json` - Original file metadata

## Objectives

1. Analyze the ransomware's encryption routine
2. Identify the cryptographic weakness
3. Recover the encryption key (or exploit the weakness)
4. Decrypt the flag file

## Hints

<details>
<summary>Hint 1 (Cost: 25 points)</summary>

The ransomware uses AES-256-CBC, but examine how the IV is generated. Is it truly random?
</details>

<details>
<summary>Hint 2 (Cost: 50 points)</summary>

The IV is derived from the file path using a weak hash. Files in the same directory share predictable IV relationships.
</details>

<details>
<summary>Hint 3 (Cost: 75 points)</summary>

The key was still in memory when the process was dumped. Look for 32-byte sequences near AES-related strings.
</details>

## Scoring

- Full solution without hints: 250 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Ransomware reverse engineering basics
- Cryptographic weakness identification
- Memory forensics for key recovery
- Incident response under pressure

## Tools You Might Use

- Python with pycryptodome
- Hex editors
- Static analysis tools
- Memory analysis scripts

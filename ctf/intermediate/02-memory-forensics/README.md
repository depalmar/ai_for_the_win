# Memory Forensics

**Difficulty:** Intermediate
**Points:** 250
**Prerequisite:** Lab 13 (Memory Forensics AI)
**Time Estimate:** 45-60 minutes

## Challenge Description

A critical server was compromised during an incident. Before reimaging, the IR team captured a memory dump. Analysis suggests the attacker used process injection to hide their malware.

Your mission: Analyze the memory dump, identify the injected code, and extract the flag hidden within the malicious payload.

## Files Provided

- `data/compromised_server.raw` - Memory dump (simulated, ~50MB)
- `data/process_list.json` - Process listing at time of capture
- `data/network_connections.json` - Active network connections

## Objectives

1. Identify the suspicious process
2. Detect the process injection technique used
3. Extract the injected shellcode
4. Decode the payload to find the flag

## Hints

<details>
<summary>Hint 1 (Cost: 25 points)</summary>

Look for processes with memory regions that have RWX (read-write-execute) permissions - this is unusual for legitimate processes.
</details>

<details>
<summary>Hint 2 (Cost: 50 points)</summary>

The injection technique used is process hollowing. Compare the on-disk image with the in-memory image.
</details>

<details>
<summary>Hint 3 (Cost: 75 points)</summary>

The shellcode contains XOR-encoded strings. The key is a single byte that appears frequently in the code.
</details>

## Scoring

- Full solution without hints: 250 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Memory forensics with Volatility concepts
- Process injection detection (hollowing, DLL injection)
- Shellcode analysis basics
- XOR decryption techniques

## Tools You Might Use

- Volatility 3 (or concepts from Lab 13)
- Python for analysis
- Hex editors
- XOR brute-force scripts

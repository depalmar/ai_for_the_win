# Zero-Day Hunt

**Difficulty:** Advanced
**Points:** 500
**Prerequisite:** Lab 03 (Anomaly Detection)
**Time Estimate:** 90-120 minutes

## Challenge Description

Your EDR solution detected unusual process behavior that doesn't match any known signatures. The activity occurred on a critical server and may represent a zero-day exploit.

Using behavioral analysis and anomaly detection, identify the exploitation technique, understand the payload, and extract the flag from the attacker's toolkit.

## Files Provided

- `data/process_telemetry.json` - Process creation and behavior events
- `data/network_telemetry.json` - Network connection events
- `data/file_telemetry.json` - File system events
- `data/baseline_model.pkl` - Trained baseline behavior model
- `data/system_profile.json` - Normal system behavior profile

## Objectives

1. Identify anomalous behavior using the baseline model
2. Reconstruct the exploit chain
3. Analyze the payload without signatures
4. Extract the flag from the attacker's implant

## Hints

<details>
<summary>Hint 1 (Cost: 50 points)</summary>

The anomaly detection model flags high entropy in command-line arguments. Focus on processes with encoded PowerShell commands.
</details>

<details>
<summary>Hint 2 (Cost: 100 points)</summary>

The exploit uses a living-off-the-land technique chain: mshta -> wscript -> powershell. This bypasses application whitelisting.
</details>

<details>
<summary>Hint 3 (Cost: 150 points)</summary>

The final payload is a fileless implant stored in the registry. Decode the base64 data in HKCU\Software\Classes\CLSID.
</details>

## Scoring

- Full solution without hints: 500 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Behavioral anomaly detection
- Living-off-the-land binary analysis
- Fileless malware detection
- Zero-day hunting methodology

## Tools You Might Use

- Python with scikit-learn
- PowerShell/command-line decoders
- Registry analysis tools
- Statistical anomaly detection

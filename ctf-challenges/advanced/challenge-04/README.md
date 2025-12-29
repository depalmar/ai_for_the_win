# Challenge 04: Zero-Day Detection

**Category:** Detection Engineering
**Points:** 500
**Difficulty:** Advanced

## Description

Your threat detection team has noticed unusual patterns in network traffic that don't match any known signatures or threat intelligence. This could be a zero-day exploit or a novel attack technique.

Your mission: Use AI-powered anomaly detection to identify the attack pattern and find the flag hidden in the zero-day activity.

## Objective

1. Analyze network traffic for anomalous patterns
2. Identify the zero-day attack behavior
3. Correlate anomalies to form a coherent attack picture
4. Extract the flag from the attack's unique signature

## Files

- `baseline_traffic.json` - Normal network behavior baseline
- `suspicious_traffic.json` - Traffic containing the zero-day
- `anomaly_scores.json` - Pre-computed anomaly scores
- `protocol_analysis.json` - Deep packet analysis results

## Detection Techniques

- Statistical anomaly detection
- Behavioral baseline deviation
- Protocol anomaly analysis
- Machine learning classification

## Rules

- Use AI to identify patterns that traditional signatures miss
- The flag format is `FLAG{...}`
- The zero-day leaves a unique fingerprint

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

Look at the flows with the highest anomaly scores - they share a common pattern in the payload.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

The XOR-encoded payload in the anomalous packets contains a marker string.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

XOR decode the payload_hex with key 0x42: FLAG{Z3R0_D4Y_HUNT3R}

</details>

## Skills Tested

- Anomaly detection
- Network analysis
- Pattern recognition
- Zero-day hunting

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-04 "FLAG{your_answer}"
```

Hunt the unknown! 🎯

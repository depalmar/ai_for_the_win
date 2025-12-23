# Challenge 01: C2 Hunter

**Category:** Network Analysis
**Points:** 250
**Difficulty:** Intermediate

## Description

Our network security team has captured suspicious traffic patterns from an endpoint. The traffic appears to be communicating with a command and control server using a covert channel.

Your mission: Analyze the network traffic data to identify the C2 communication pattern and extract the hidden flag.

## Objective

1. Identify the beaconing pattern in the traffic
2. Decode the covert communication channel
3. Extract the C2 server's message containing the flag

## Files

- `traffic_capture.csv` - Network flow data
- `dns_queries.json` - DNS query log

## Background

C2 (Command and Control) traffic often exhibits:
- Regular timing intervals (beaconing)
- Encoded data in DNS queries
- Unusual destination ports or protocols
- Anomalous data volume patterns

## Rules

- Use AI tools to help identify patterns
- The flag format is `FLAG{...}`
- Consider both temporal and data patterns

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

Look for connections with suspiciously regular intervals - real users aren't that consistent.

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

The DNS queries contain base64-encoded data in the subdomain.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

Decode each DNS subdomain and concatenate the first character of each decoded string.

</details>

## Skills Tested

- Network traffic analysis
- Statistical pattern recognition
- Encoding/decoding
- AI-assisted investigation

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-01 "FLAG{your_answer}"
```

Happy hunting! 🎯

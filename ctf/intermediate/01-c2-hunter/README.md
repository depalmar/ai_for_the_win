# C2 Hunter

**Difficulty:** Intermediate
**Points:** 250
**Prerequisite:** Lab 14 (C2 Traffic Analysis)
**Time Estimate:** 45-60 minutes

## Challenge Description

Your SOC received an alert about unusual DNS traffic patterns from a workstation. Initial investigation suggests the machine may be compromised with malware using DNS for command-and-control communication.

The network team has provided a PCAP capture and DNS query logs. Your mission: identify the C2 channel, extract the hidden commands, and find the flag that proves you've cracked the communication protocol.

## Files Provided

- `data/suspicious_traffic.pcap` - Network capture from the suspect workstation
- `data/dns_queries.json` - Parsed DNS query log
- `data/baseline_traffic.json` - Normal traffic baseline for comparison

## Objectives

1. Identify the C2 beaconing pattern
2. Decode the DNS tunneling protocol
3. Extract the exfiltrated data
4. Find the hidden flag

## Hints

<details>
<summary>Hint 1 (Cost: 25 points)</summary>

Look for DNS queries with unusually long subdomain names. The data is encoded in the subdomain.
</details>

<details>
<summary>Hint 2 (Cost: 50 points)</summary>

The beacon interval is consistent but has slight jitter. Calculate the average interval to confirm C2 behavior.
</details>

<details>
<summary>Hint 3 (Cost: 75 points)</summary>

The subdomain encoding uses base32. After decoding, you'll find hex-encoded data.
</details>

## Scoring

- Full solution without hints: 250 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- DNS tunneling detection techniques
- Beaconing pattern analysis
- Traffic baseline comparison
- Data exfiltration identification

## Tools You Might Use

- Wireshark/tshark
- Python with scapy
- Base32/Base64 decoders
- Statistical analysis for beacon detection

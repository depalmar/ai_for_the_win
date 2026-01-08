# Full IR Scenario

**Difficulty:** Advanced
**Points:** 500
**Prerequisite:** Lab 10 (IR Copilot)
**Time Estimate:** 120-180 minutes

## Challenge Description

This is a comprehensive incident response scenario combining all skills from the course.

At 03:47 UTC, your SIEM alerted on suspicious authentication patterns. By 04:15, ransomware notes appeared on three servers. You have 4 hours of logs, memory dumps, and network captures.

Complete the full IR lifecycle: detection, analysis, containment, eradication, and recovery planning. Document your findings and extract the final flag.

## Files Provided

- `data/siem_alerts.json` - SIEM alerts from the incident window
- `data/auth_logs.json` - Authentication logs across systems
- `data/network_capture.pcap` - Network traffic during incident
- `data/memory_dumps/` - Memory dumps from affected systems
- `data/ransomware_artifacts/` - Ransom notes and encrypted samples
- `data/asset_inventory.json` - Network and system inventory
- `data/backup_status.json` - Backup system status

## Objectives

1. **Detection**: Identify initial compromise timestamp and vector
2. **Analysis**: Map the complete attack timeline
3. **Containment**: Identify systems requiring isolation
4. **Eradication**: Find all persistence mechanisms
5. **Recovery**: Determine viable recovery options
6. **Flag**: Combine findings to decode the final flag

## Hints

<details>
<summary>Hint 1 - Detection (Cost: 50 points)</summary>

The initial access was via a phishing email at 03:12 UTC. Look for the first successful authentication from an unusual source.
</details>

<details>
<summary>Hint 2 - Analysis (Cost: 75 points)</summary>

The attacker used Cobalt Strike. Beacon configuration is in the memory dump - look for the watermark and C2 config.
</details>

<details>
<summary>Hint 3 - Containment (Cost: 75 points)</summary>

Three systems have active C2: WKS-042, SRV-DB-01, SRV-FILE-02. Check for scheduled tasks on each.
</details>

<details>
<summary>Hint 4 - Flag (Cost: 100 points)</summary>

The flag is constructed from: attacker IP last octet + ransomware family initial + hours from initial access to encryption + number of affected systems.
</details>

## Scoring

- Full solution without hints: 500 points
- Each hint used reduces score
- Bonus points for complete timeline documentation

## Flag Format

`FLAG{...}`

## Learning Objectives

- Full incident response lifecycle
- Evidence correlation across data sources
- Timeline reconstruction
- Executive-level incident reporting
- Recovery planning and prioritization

## Deliverables

Beyond the flag, prepare:
1. Attack timeline (CSV or JSON)
2. IOC list for blocking
3. Affected systems list
4. Recovery priority ranking

## Tools You Might Use

- All tools from previous labs
- Timeline creation tools
- PCAP analysis (Wireshark)
- Memory forensics
- Log correlation

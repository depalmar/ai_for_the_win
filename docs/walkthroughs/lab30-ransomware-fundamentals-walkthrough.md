# Lab 30 Walkthrough: Ransomware Fundamentals

## Overview

This walkthrough covers the essential knowledge needed to understand ransomware attacks before building detection systems. You'll learn to identify ransomware families, map attacks to MITRE ATT&CK, and make informed response decisions.

**Time to complete walkthrough:** 40-50 minutes

---

## Step 1: Understanding Ransomware Evolution

### Why History Matters

Understanding ransomware evolution helps you:
- Recognize attack patterns that repeat across families
- Anticipate new evasion techniques
- Understand why certain defenses work (or don't)

### Key Evolutionary Milestones

| Era | Characteristics | Defense Implications |
|-----|-----------------|----------------------|
| **Early (1989-2012)** | Simple encryption, email delivery | Signature-based AV worked well |
| **Crypto Era (2013-2016)** | Strong encryption, Bitcoin | Backups became critical |
| **Worm Era (2017)** | Self-propagating (WannaCry) | Network segmentation essential |
| **Double Extortion (2019+)** | Data theft before encryption | Air-gapped backups not enough |
| **RaaS (2020+)** | Professional criminal enterprises | Need defense in depth |
| **AI-Assisted (2024+)** | AI-generated phishing, code | Behavioral detection required |

### The RaaS Business Model

```
Developer creates ransomware + infrastructure
    ↓
Affiliate joins program (often vetted)
    ↓
Affiliate deploys attacks
    ↓
Victim pays ransom ($1K - $70M+)
    ↓
Revenue split (typically 70% affiliate / 30% developer)
```

**Why this matters:** RaaS means more attackers with sophisticated tools. The barrier to entry is lower, but the attacks are more professional.

---

## Step 2: Identifying Ransomware Families

### Primary Identification Methods

**1. File Extension Analysis**

```python
EXTENSION_SIGNATURES = {
    # LockBit variants
    ".lockbit": "LockBit 2.0/3.0",
    ".abcd": "LockBit Black",

    # BlackCat/ALPHV
    # Uses random 6-7 character extensions

    # Classic families
    ".conti": "Conti",
    ".royal": "Royal",
    ".play": "Play",
    ".akira": "Akira",
    ".rhysida": "Rhysida",
    ".blacksuit": "BlackSuit",

    # Generic indicators
    ".encrypted": "Multiple families",
    ".locked": "Multiple families",
    ".enc": "Multiple families"
}

def identify_by_extension(extension: str) -> str:
    """
    First-pass identification by file extension.
    Note: Extensions can be spoofed; always verify with other indicators.
    """
    ext = extension.lower().strip()
    if ext in EXTENSION_SIGNATURES:
        return EXTENSION_SIGNATURES[ext]

    # Check for random extension pattern (BlackCat style)
    if len(ext) >= 6 and ext.isalnum():
        return "Possible BlackCat/ALPHV (random extension)"

    return "Unknown - check other indicators"
```

**2. Ransom Note Analysis**

```python
NOTE_PATTERNS = {
    "lockbit": [
        "LockBit",
        "Restore-My-Files.txt",
        "LB3Decryptor",
        ".onion"
    ],
    "blackcat": [
        "ALPHV",
        "RECOVER-",
        "BlackCat",
        "-FILES.txt"
    ],
    "conti": [
        "CONTI",
        "readme.txt",
        "All of your files are currently encrypted"
    ],
    "royal": [
        "Royal",
        "README.TXT",
        "royal team"
    ],
    "akira": [
        "akira",
        "akira_readme.txt",
        "contact us"
    ]
}

def identify_by_note_content(note_text: str) -> list[tuple[str, float]]:
    """
    Identify family by ransom note content.
    Returns list of (family, confidence) tuples.
    """
    note_lower = note_text.lower()
    matches = []

    for family, patterns in NOTE_PATTERNS.items():
        pattern_matches = sum(1 for p in patterns if p.lower() in note_lower)
        if pattern_matches > 0:
            confidence = pattern_matches / len(patterns)
            matches.append((family, confidence))

    return sorted(matches, key=lambda x: x[1], reverse=True)
```

**3. Behavioral Analysis**

Look for characteristic behaviors:
- **Encryption speed**: LockBit is notably fast (parallel encryption)
- **Network behavior**: Some families spread aggressively
- **Specific tools**: BlackCat often uses Rust-based binaries

### Common Error #1: Over-relying on Extensions

**Symptom:** Misidentifying family based solely on file extension.

**Problem:** Attackers can easily change extensions to mimic other families or confuse responders.

**Solution:** Always use multiple indicators:
```python
def identify_family(artifacts: dict) -> dict:
    """Multi-factor family identification."""

    identifications = []

    # Factor 1: Extension (weight: 30%)
    if "extension" in artifacts:
        ext_match = identify_by_extension(artifacts["extension"])
        identifications.append(("extension", ext_match, 0.3))

    # Factor 2: Ransom note (weight: 50%)
    if "note_content" in artifacts:
        note_matches = identify_by_note_content(artifacts["note_content"])
        if note_matches:
            identifications.append(("note", note_matches[0][0], 0.5 * note_matches[0][1]))

    # Factor 3: Behaviors (weight: 20%)
    if "behaviors" in artifacts:
        behavior_match = match_behaviors(artifacts["behaviors"])
        identifications.append(("behavior", behavior_match, 0.2))

    return aggregate_identifications(identifications)
```

---

## Step 3: Mapping to MITRE ATT&CK

### The Ransomware Kill Chain

Every ransomware attack follows a pattern. Mapping to ATT&CK helps you:
- Identify detection opportunities
- Understand where you can interrupt the attack
- Communicate with other security teams

### Phase-by-Phase Mapping

**Initial Access (how they get in)**
```
Technique     | ID         | Detection Point
--------------|------------|------------------
Phishing      | T1566      | Email gateway, user reports
Valid Accounts| T1078      | Impossible travel, unusual logins
Exploit Vuln  | T1190      | Vulnerability scans, patch status
```

**Execution (how malware runs)**
```
Technique     | ID         | Detection Point
--------------|------------|------------------
PowerShell    | T1059.001  | ScriptBlock logging (Event 4104)
Cmd           | T1059.003  | Process monitoring
Macros        | T1204.002  | Office process spawning child
```

**Persistence (how they stay)**
```
Technique       | ID        | Detection Point
----------------|-----------|------------------
Scheduled Task  | T1053.005 | Event 4698, schtasks.exe monitoring
Registry Run    | T1547.001 | Registry monitoring
Service Install | T1543.003 | Event 7045
```

**Impact (the actual ransomware)**
```
Technique               | ID     | Detection Point
------------------------|--------|------------------
Data Encrypted          | T1486  | File entropy, extension changes
Inhibit Recovery        | T1490  | vssadmin, wmic shadowcopy
Service Stop            | T1489  | Critical services stopping
Data Destruction        | T1485  | Mass file deletion
```

### Exercise: Map an Attack Timeline

Given this timeline:
```
09:00 - User opens Excel file from email attachment
09:01 - Excel spawns PowerShell
09:02 - PowerShell downloads beacon.exe from pastebin
09:15 - Scheduled task "WindowsUpdate" created
09:30 - adfind.exe runs, queries all domain computers
10:00 - beacon.exe uses PsExec to spread to 3 servers
14:00 - rclone.exe uploads 40GB to Mega cloud storage
15:00 - "vssadmin delete shadows /all /quiet" runs
15:01 - Files begin getting .lockbit extension
15:30 - Ransom note appears
```

**Mapping:**
```python
TIMELINE_MAPPING = [
    ("09:00", "T1566.001", "Phishing: Spearphishing Attachment"),
    ("09:01", "T1204.002", "User Execution: Malicious File"),
    ("09:01", "T1059.001", "PowerShell execution"),
    ("09:02", "T1105", "Ingress Tool Transfer"),
    ("09:15", "T1053.005", "Scheduled Task/Job"),
    ("09:30", "T1087.002", "Account Discovery: Domain Account"),
    ("10:00", "T1570", "Lateral Tool Transfer"),
    ("10:00", "T1021.002", "Remote Services: SMB"),
    ("14:00", "T1567.002", "Exfiltration Over Web Service"),
    ("15:00", "T1490", "Inhibit System Recovery"),
    ("15:01", "T1486", "Data Encrypted for Impact"),
]
```

---

## Step 4: Extracting IOCs from Ransom Notes

### What to Look For

Ransom notes contain valuable intelligence:
- **Onion URLs**: Access to negotiation portals
- **Bitcoin/Monero addresses**: For tracking payments
- **Email addresses**: Attacker communication channels
- **Victim IDs**: Unique identifiers (useful for tracking campaigns)
- **Family markers**: Text patterns unique to specific groups

### LLM-Assisted Extraction

```python
def extract_iocs_from_note(note_content: str) -> dict:
    """
    Use LLM to extract IOCs from ransom note.
    """
    from shared.llm_config import query_llm

    prompt = f"""Extract all indicators of compromise from this ransom note.

RANSOM NOTE:
---
{note_content}
---

Return JSON with these fields:
{{
    "family": "identified ransomware family or 'unknown'",
    "confidence": "high/medium/low",
    "onion_urls": ["list of .onion URLs"],
    "bitcoin_addresses": ["list of BTC addresses (starts with 1, 3, or bc1)"],
    "monero_addresses": ["list of XMR addresses"],
    "email_addresses": ["list of emails"],
    "victim_id": "unique victim identifier if present",
    "deadline": "payment deadline if mentioned",
    "ransom_amount": "amount demanded if specified",
    "family_indicators": ["unique phrases/markers identifying the family"]
}}

Return ONLY the JSON, no explanation."""

    response = query_llm(prompt, temperature=0)

    # Parse and validate
    import json
    try:
        result = json.loads(response)
        # Validate key fields
        result.setdefault("onion_urls", [])
        result.setdefault("bitcoin_addresses", [])
        result.setdefault("email_addresses", [])
        return result
    except json.JSONDecodeError:
        return {"error": "Failed to parse LLM response", "raw": response}
```

### Manual Regex Extraction (Backup)

```python
import re

def extract_iocs_regex(note_content: str) -> dict:
    """Regex-based IOC extraction as fallback."""

    # Bitcoin addresses (legacy, segwit, taproot)
    btc_pattern = r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})\b'

    # Onion URLs
    onion_pattern = r'[a-z2-7]{16,56}\.onion'

    # Email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    return {
        "bitcoin_addresses": re.findall(btc_pattern, note_content),
        "onion_urls": re.findall(onion_pattern, note_content, re.I),
        "email_addresses": re.findall(email_pattern, note_content)
    }
```

---

## Step 5: Recovery Decision Framework

### Key Questions for Decision Making

Before deciding on recovery approach, answer these:

1. **Backup Status**
   - When was the last backup?
   - Is it verified clean (not encrypted)?
   - What's the RPO (Recovery Point Objective)?

2. **Scope of Impact**
   - What percentage of systems affected?
   - Are critical systems encrypted?
   - Is Active Directory compromised?

3. **Data Exfiltration**
   - Was data stolen before encryption?
   - What type of data (PII, financial, IP)?
   - What are regulatory notification requirements?

4. **Business Impact**
   - How long can operations be down?
   - What's the cost per hour of downtime?
   - Are there contractual/SLA impacts?

### Decision Tree Implementation

```python
def recommend_recovery(scenario: dict) -> dict:
    """
    Recommend recovery approach based on scenario.

    Args:
        scenario: {
            "backup_age_hours": int,
            "backup_verified": bool,
            "systems_affected_pct": float,
            "data_exfiltrated": bool,
            "data_type": str,  # "pii", "financial", "ip", "other"
            "decryptor_available": bool,
            "ransom_amount_usd": float,
            "critical_systems_down": bool,
            "max_downtime_hours": int,
            "regulatory_requirements": list  # ["gdpr", "hipaa", etc.]
        }
    """
    recommendations = []
    rationale = []

    # Option 1: Free decryptor
    if scenario.get("decryptor_available"):
        recommendations.append({
            "option": "Free Decryptor",
            "priority": 1,
            "effort": "Low",
            "risk": "Low",
            "action": "Check nomoreransom.org for available decryptor"
        })
        rationale.append("Free decryptor available - always try this first")

    # Option 2: Restore from backup
    backup_age = scenario.get("backup_age_hours", 999)
    backup_verified = scenario.get("backup_verified", False)

    if backup_verified and backup_age < 72:  # Less than 3 days old
        recommendations.append({
            "option": "Restore from Backup",
            "priority": 2 if not scenario.get("decryptor_available") else 3,
            "effort": "Medium-High",
            "risk": "Low",
            "action": f"Restore from {backup_age}h old backup. Data loss: ~{backup_age}h",
            "considerations": [
                "Ensure malware is removed before restoration",
                "Validate backup integrity before restore",
                "Plan for data loss since last backup"
            ]
        })
        rationale.append(f"Clean backup available from {backup_age}h ago")
    elif not backup_verified:
        rationale.append("WARNING: Backup not verified - may be compromised")

    # Option 3: Pay ransom (last resort)
    ransom = scenario.get("ransom_amount_usd", 0)
    critical_down = scenario.get("critical_systems_down", False)

    pay_considerations = []
    if critical_down and backup_age > 168:  # Critical down, backup > 1 week old
        pay_considerations.append("Critical systems down with poor backup")
    if ransom < 50000 and not backup_verified:
        pay_considerations.append("Relatively low ransom with no verified backup")

    if pay_considerations:
        recommendations.append({
            "option": "Pay Ransom (LAST RESORT)",
            "priority": 99,  # Always last
            "effort": "Variable",
            "risk": "High",
            "considerations": [
                "No guarantee of receiving decryptor",
                "May be targeted again",
                "Funds criminal operations",
                "May violate sanctions (check OFAC list)",
                *pay_considerations
            ],
            "if_paying": [
                "Engage professional negotiators",
                "Verify proof of decryption capability",
                "Document everything for legal purposes"
            ]
        })

    # Regulatory actions
    regulatory = []
    if "gdpr" in scenario.get("regulatory_requirements", []):
        regulatory.append({
            "regulation": "GDPR",
            "action": "Notify supervisory authority within 72 hours",
            "data_subjects": scenario.get("data_exfiltrated", False)
        })
    if "hipaa" in scenario.get("regulatory_requirements", []):
        regulatory.append({
            "regulation": "HIPAA",
            "action": "Breach notification within 60 days",
            "hhs_notification": scenario.get("systems_affected_pct", 0) > 0.5
        })

    return {
        "recommendations": sorted(recommendations, key=lambda x: x["priority"]),
        "rationale": rationale,
        "regulatory_actions": regulatory,
        "immediate_actions": [
            "Isolate affected systems",
            "Preserve evidence (don't wipe yet)",
            "Identify attack vector",
            "Check for lateral movement"
        ]
    }
```

### Example Scenario Analysis

```python
scenario = {
    "backup_age_hours": 72,
    "backup_verified": True,
    "systems_affected_pct": 0.40,  # 40%
    "data_exfiltrated": True,
    "data_type": "pii",
    "decryptor_available": False,
    "ransom_amount_usd": 500000,
    "critical_systems_down": True,
    "max_downtime_hours": 48,
    "regulatory_requirements": ["gdpr"]
}

result = recommend_recovery(scenario)
print(json.dumps(result, indent=2))
```

**Expected output analysis:**
- Primary recommendation: Restore from backup (72h old, verified)
- Data loss: ~72 hours of work
- GDPR notification required within 72 hours (data was exfiltrated)
- Don't pay ransom - backup is available

---

## Key Takeaways

1. **Multi-factor identification** - Don't rely on single indicators
2. **MITRE ATT&CK mapping** - Essential for communication and detection
3. **IOC extraction** - Ransom notes contain valuable intelligence
4. **Recovery is contextual** - No one-size-fits-all answer
5. **Regulatory awareness** - Know your notification requirements

---

## Common Mistakes Summary

| Mistake | Impact | Prevention |
|---------|--------|------------|
| Single indicator identification | Misattribution | Use 3+ indicators |
| Paying without verification | Lost money, no decryption | Require proof of capability |
| Restoring without cleaning | Reinfection | Full remediation first |
| Missing regulatory deadlines | Fines, legal exposure | Know requirements before incident |
| Not preserving evidence | Can't investigate | Image before restore |

---

## Next Labs

| Goal | Recommended Lab |
|------|-----------------|
| Build ransomware detection | [Lab 11: Ransomware Detection](./lab31-ransomware-detection-walkthrough.md) |
| Purple team simulation | [Lab 12: Purple Team Simulation](./lab32-ransomware-simulation-walkthrough.md) |
| Memory forensics | [Lab 13: Memory Forensics AI](./lab33-memory-forensics-ai-walkthrough.md) |

---

## Resources

### Identification Tools
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) - Upload sample for identification
- [No More Ransom](https://www.nomoreransom.org/) - Free decryptors

### Threat Intelligence
- [CISA StopRansomware](https://www.cisa.gov/stopransomware)
- [Mandiant Ransomware Reports](https://www.mandiant.com/)
- [Microsoft Threat Intelligence](https://www.microsoft.com/security/blog/)
- [Unit 42 Ransomware Research](https://unit42.paloaltonetworks.com/category/ransomware/)

### SANS Resources
- [FOR528: Ransomware for Incident Responders](https://www.sans.org/cyber-security-courses/ransomware-incident-responders/)
- [SANS Ransomware Webcasts](https://www.sans.org/webcasts/)
- [Ryan Chapman's Research](https://www.sans.org/profiles/ryan-chapman/)

### Testing & Validation
- [Atomic Red Team T1486](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1486)
- [MITRE Caldera](https://caldera.mitre.org/)

# Lab 30: Ransomware Fundamentals [Bridge Lab]

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Lab 25 (DFIR), Lab 35

> **Bridge Lab:** This lab covers ransomware families, attack lifecycle, and indicators before building detection in Lab 31.

Understand ransomware attacks before building detection systems.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab30_ransomware_fundamentals.ipynb)

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand ransomware evolution (1989 → Modern RaaS)
2. Recognize major ransomware families and their characteristics
3. Map the ransomware attack lifecycle to MITRE ATT&CK
4. Identify key indicators and artifacts
5. Understand recovery options and response priorities

---

## 📖 Background: What is Ransomware?

**Ransomware** is malware that encrypts victim files and demands payment (ransom) for the decryption key.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RANSOMWARE ATTACK OVERVIEW                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   BEFORE                        DURING                      AFTER           │
│   ──────                        ──────                      ─────           │
│   ┌─────────┐                 ┌─────────┐               ┌─────────┐        │
│   │ Normal  │    Encrypt     │ Locked  │    Ransom    │ Pay or  │        │
│   │ Files   │ ─────────────► │ Files   │ ──────────►  │ Lose    │        │
│   │ .docx   │                │ .locked │   Demand     │ Data    │        │
│   │ .xlsx   │                │ .enc    │              │         │        │
│   └─────────┘                └─────────┘              └─────────┘        │
│                                   │                                        │
│                                   ▼                                        │
│                            ┌───────────────┐                               │
│                            │  RANSOM NOTE  │                               │
│                            │  ───────────  │                               │
│                            │  "Your files  │                               │
│                            │   are locked" │                               │
│                            │  Pay $$$$ BTC │                               │
│                            └───────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Ransomware Evolution

### Timeline

| Year      | Milestone    | Significance                                         |
| --------- | ------------ | ---------------------------------------------------- |
| **1989**  | AIDS Trojan  | First ransomware (floppy disk, symmetric encryption) |
| **2005**  | GPCode       | First to use asymmetric (RSA) encryption             |
| **2013**  | CryptoLocker | Bitcoin payments, professional operations            |
| **2016**  | Locky        | Mass email campaigns, macro-based delivery           |
| **2017**  | WannaCry     | Worm capabilities, global impact (SMB exploits)      |
| **2019**  | Maze         | Double extortion (encrypt + leak data)               |
| **2021**  | REvil/Kaseya | Supply chain attacks, $70M ransom                    |
| **2023+** | LockBit 3.0  | RaaS ecosystem, bug bounties, triple extortion       |

### AI/LLM Evolution in Ransomware

Modern ransomware groups are increasingly leveraging AI:

| AI Use Case             | How Attackers Use It                                          | Defensive Implications                                    |
| ----------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| **Phishing generation** | LLMs create convincing, personalized phishing emails at scale | Traditional detection struggles with AI-generated content |
| **Code obfuscation**    | AI generates polymorphic code to evade signatures             | Need behavioral detection, not just signatures            |
| **Target research**     | AI scrapes and analyzes victim organizations                  | Attackers arrive better prepared                          |
| **Negotiation**         | Chatbots handle ransom negotiations 24/7                      | More professional criminal operations                     |
| **Translation**         | Instant localization of ransom notes                          | Global reach without language barriers                    |

> ⚠️ **Defender's Edge**: AI works both ways. The same capabilities that help attackers can power better detection (Labs 09-11).

---

### Modern Ransomware-as-a-Service (RaaS)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RANSOMWARE-AS-A-SERVICE MODEL                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   DEVELOPERS                    AFFILIATES                   VICTIMS       │
│   ──────────                    ──────────                   ───────       │
│   ┌─────────┐                  ┌─────────┐                ┌─────────┐     │
│   │ Create  │   Provide        │ Deploy  │   Attack      │ Pay     │     │
│   │ Malware │ ────────────►    │ Attacks │ ──────────►   │ Ransom  │     │
│   │ + Panel │   (70-80%)       │         │               │         │     │
│   └─────────┘                  └─────────┘               └─────────┘     │
│       │                            │                          │            │
│       │                            │                          │            │
│       └──────────── Revenue Split (20-30%) ◄─────────────────┘            │
│                                                                             │
│   Key Features:                                                            │
│   • Affiliate portal with builder                                          │
│   • Negotiation chat support                                               │
│   • Leak site for double extortion                                         │
│   • 24/7 "customer support"                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎭 Major Ransomware Families

### Current Active Threats (2024-2025)

| Family              | Characteristics                        | Notable TTPs                           |
| ------------------- | -------------------------------------- | -------------------------------------- |
| **LockBit 3.0**     | Most prolific RaaS, bug bounty program | Fast encryption, StealBit exfiltration |
| **BlackCat/ALPHV**  | Rust-based, cross-platform             | Configurable, triple extortion         |
| **Cl0p**            | MOVEit exploits, data theft focus      | Mass exploitation campaigns            |
| **Play**            | Healthcare/critical infrastructure     | Living-off-the-land techniques         |
| **Akira**           | Enterprise targeting                   | VPN exploitation, Conti lineage        |
| **Royal/BlackSuit** | Government sector targeting            | Callback phishing, BazarLoader         |
| **Rhysida**         | Healthcare, education                  | PowerShell-heavy, PrintNightmare       |

### Family Identification Markers

```python
# Common ransomware indicators
RANSOMWARE_SIGNATURES = {
    "lockbit": {
        "extensions": [".lockbit", ".abcd", ".LockBit"],
        "note_files": ["Restore-My-Files.txt"],
        "registry_keys": ["HKCU\\Software\\LockBit"],
    },
    "blackcat": {
        "extensions": [".alphv", ".[random]"],  # Unique per victim
        "note_files": ["RECOVER-[victim]-FILES.txt"],
        "processes": ["rust-based binary"],
    },
    "conti": {
        "extensions": [".CONTI"],
        "note_files": ["readme.txt", "CONTI_README.txt"],
        "c2_pattern": "cobalt_strike_beacon",
    },
}
```

---

## 🔄 Ransomware Attack Lifecycle

### The Kill Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     RANSOMWARE ATTACK LIFECYCLE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. INITIAL ACCESS        2. EXECUTION           3. PERSISTENCE            │
│  ─────────────────        ─────────────          ──────────────            │
│  • Phishing emails        • PowerShell           • Scheduled tasks         │
│  • RDP brute force        • Macro execution      • Registry Run keys       │
│  • VPN exploits           • Script interpreters  • Services                │
│  • Supply chain           • LOLBins              • WMI subscriptions       │
│         │                       │                       │                  │
│         ▼                       ▼                       ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐     │
│  │                    DWELL TIME: Days to Weeks                      │     │
│  └──────────────────────────────────────────────────────────────────┘     │
│         │                       │                       │                  │
│         ▼                       ▼                       ▼                  │
│  4. DISCOVERY             5. LATERAL MOVEMENT    6. COLLECTION            │
│  ────────────             ─────────────────      ──────────────           │
│  • AD enumeration         • PsExec/WMI           • Identify valuable      │
│  • Network scanning       • RDP hijacking          files                  │
│  • Find backups           • Pass-the-hash        • Stage for exfil        │
│  • Identify DCs           • Cobalt Strike        • Compress/archive       │
│         │                       │                       │                  │
│         ▼                       ▼                       ▼                  │
│  7. EXFILTRATION          8. IMPACT              9. EXTORTION             │
│  ─────────────            ────────               ──────────               │
│  • Cloud storage          • Encrypt files        • Ransom note            │
│  • FTP/SFTP               • Delete backups       • Leak site threat       │
│  • Custom tools           • Stop services        • Negotiation            │
│  • Rclone, MEGAsync       • Wipe logs            • Timer/deadline         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Mapping

| Phase            | Technique ID | Technique Name                    |
| ---------------- | ------------ | --------------------------------- |
| Initial Access   | T1566        | Phishing                          |
| Initial Access   | T1190        | Exploit Public-Facing Application |
| Execution        | T1059.001    | PowerShell                        |
| Persistence      | T1053.005    | Scheduled Task                    |
| Discovery        | T1087        | Account Discovery                 |
| Lateral Movement | T1021.002    | SMB/Windows Admin Shares          |
| Collection       | T1560        | Archive Collected Data            |
| Exfiltration     | T1567        | Exfiltration Over Web Service     |
| **Impact**       | **T1486**    | **Data Encrypted for Impact**     |
| **Impact**       | **T1490**    | **Inhibit System Recovery**       |
| Impact           | T1489        | Service Stop                      |

---

## 🚨 Key Indicators to Recognize

### File System Artifacts

```python
FILE_INDICATORS = {
    # Encrypted file extensions
    "suspicious_extensions": [
        ".locked", ".encrypted", ".enc", ".crypted",
        ".lockbit", ".alphv", ".conti", ".royal",
        ".akira", ".play", ".rhysida", ".blacksuit"
    ],

    # Ransom note filenames
    "ransom_notes": [
        "README.txt", "DECRYPT.txt", "HOW_TO_DECRYPT.txt",
        "RECOVER-FILES.txt", "!README!.txt", "_readme.txt",
        "RESTORE_FILES.txt", "YOUR_FILES.txt"
    ],

    # Mass file operations (entropy change)
    "behavioral": [
        "Rapid file modifications (>100/min)",
        "High entropy file content (>7.9)",
        "Extension changes on multiple files",
        "Ransom note creation in multiple directories"
    ]
}
```

### Process/Event Indicators

```python
PROCESS_INDICATORS = {
    # Backup destruction
    "shadow_deletion": [
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog -quiet"
    ],

    # Service disruption
    "service_stops": [
        "net stop \"SQL Server\"",
        "net stop \"Exchange\"",
        "sc config vss start= disabled",
        "taskkill /f /im sqlservr.exe"
    ],

    # Encryption process patterns
    "encryption_behavior": [
        "High CPU usage from unknown process",
        "Rapid file I/O operations",
        "Access to network shares",
        "Enumeration of file extensions"
    ]
}
```

### Windows Event Log Indicators

| Event ID  | Log      | Indicator                                |
| --------- | -------- | ---------------------------------------- |
| 4688      | Security | Process creation (track PowerShell, cmd) |
| 4663      | Security | File access auditing (mass access)       |
| 7045      | System   | Service installation (persistence)       |
| 1102      | Security | Audit log cleared (defense evasion)      |
| 4624/4625 | Security | Logon events (lateral movement)          |
| 5140      | Security | Network share access                     |

---

## 🛡️ Recovery and Response

### Why Attackers Delete Backups

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BACKUP DESTRUCTION RATIONALE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   WITHOUT backup deletion:                WITH backup deletion:             │
│   ────────────────────────                ─────────────────────             │
│                                                                             │
│   Victim: "My files are       ──►        Victim: "My files are             │
│           encrypted!"                            encrypted AND             │
│              │                                   I have no backups!"       │
│              ▼                                          │                  │
│   "Let me restore from                                  ▼                  │
│    VSS/backup" ✓                         "I MUST pay the ransom" 💰        │
│              │                                                              │
│              ▼                                                              │
│   Attacker gets $0                                                         │
│                                                                             │
│   TECHNIQUES USED:                                                         │
│   • vssadmin delete shadows /all /quiet                                    │
│   • wmic shadowcopy delete                                                 │
│   • bcdedit /set {default} recoveryenabled no                              │
│   • del /f /q backup files                                                 │
│   • Disable backup services                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Double and Triple Extortion

| Type       | Description                                   | Pressure                   |
| ---------- | --------------------------------------------- | -------------------------- |
| **Single** | Encrypt files only                            | "Pay or lose data"         |
| **Double** | Encrypt + exfiltrate data                     | "Pay or we leak your data" |
| **Triple** | Encrypt + exfiltrate + DDoS/contact customers | "Pay or we attack more"    |

### Response Decision Framework

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RANSOMWARE RESPONSE DECISION TREE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. IMMEDIATE (First Hour)                                                 │
│   ─────────────────────────                                                 │
│   □ Isolate affected systems (network disconnect)                          │
│   □ Preserve evidence (don't reboot/wipe yet)                              │
│   □ Identify ransomware family (note, extension)                           │
│   □ Check for decryptors: nomoreransom.org                                 │
│   □ Notify incident response team                                          │
│                                                                             │
│   2. ASSESSMENT (Hours 1-4)                                                 │
│   ────────────────────────                                                  │
│   □ Determine scope (how many systems?)                                    │
│   □ Identify patient zero (initial infection)                              │
│   □ Check backup integrity                                                 │
│   □ Assess data exfiltration risk                                          │
│   □ Legal/regulatory notification requirements                             │
│                                                                             │
│   3. RECOVERY OPTIONS                                                       │
│   ───────────────────                                                       │
│                                                                             │
│   Option A: Restore from Backups                                           │
│   ┌─────────────────────────────────────────┐                              │
│   │ ✓ Best option if backups are clean      │                              │
│   │ ✓ Don't reward attackers                │                              │
│   │ ✗ May lose recent data                  │                              │
│   │ ✗ Takes time to rebuild                 │                              │
│   └─────────────────────────────────────────┘                              │
│                                                                             │
│   Option B: Free Decryptor                                                 │
│   ┌─────────────────────────────────────────┐                              │
│   │ ✓ No cost                               │                              │
│   │ ✓ May work for older variants           │                              │
│   │ ✗ Not available for most families       │                              │
│   │ Check: nomoreransom.org                 │                              │
│   └─────────────────────────────────────────┘                              │
│                                                                             │
│   Option C: Pay Ransom (Last Resort)                                       │
│   ┌─────────────────────────────────────────┐                              │
│   │ ✗ Funds criminal operations             │                              │
│   │ ✗ No guarantee of decryption            │                              │
│   │ ✗ May be targeted again                 │                              │
│   │ ✗ Legal implications in some regions    │                              │
│   │ ? May be only option for critical data  │                              │
│   └─────────────────────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Lab Tasks

### Task 1: Identify Ransomware Family (15 min)

Given these artifacts, identify the ransomware family:

```python
def identify_family(artifacts: dict) -> str:
    """
    Identify ransomware family from artifacts.

    Args:
        artifacts: {
            "encrypted_extension": ".lockbit",
            "ransom_note": "Restore-My-Files.txt",
            "note_content": "LockBit 3.0 ... contact us at ...",
            "processes": ["unknown_binary.exe"]
        }

    Returns:
        Family name and confidence

    TODO: Implement family identification logic
    """
    pass
```

### Task 2: Map Attack to MITRE ATT&CK (15 min)

Given this attack timeline, map each event to ATT&CK techniques:

```
09:00 - Phishing email with macro document
09:15 - PowerShell downloads beacon.exe
09:30 - Scheduled task created for persistence
10:00 - AdFind.exe runs for AD enumeration
11:00 - PsExec spreads to 5 other hosts
14:00 - Rclone uploads 50GB to cloud storage
15:00 - vssadmin deletes shadow copies
15:05 - Files begin encrypting (.lockbit extension)
15:30 - Ransom note appears on all systems
```

### Task 3: Indicator Extraction (15 min)

Use an LLM to extract IOCs from a ransom note:

```python
def extract_iocs_from_note(note_content: str) -> dict:
    """
    Use LLM to extract indicators from ransom note.

    Returns:
        {
            "onion_urls": [...],
            "bitcoin_addresses": [...],
            "email_addresses": [...],
            "victim_id": "...",
            "family_indicators": [...]
        }
    """
    pass
```

### Task 4: Recovery Decision (10 min)

Given a scenario, recommend the best recovery approach:

```
Scenario:
- 500 endpoints encrypted (40% of organization)
- Last backup: 3 days old, verified clean
- Data exfiltrated: Yes (HR records, financial data)
- Ransom demand: $500,000 in Bitcoin
- Decryptor available: No
- Critical operations: Down
- Regulatory: GDPR applies, must notify in 72 hours

Questions:
1. What is your recommended recovery approach?
2. What regulatory actions are required?
3. What should be the communication strategy?
```

---

## 📁 Files

```
lab30-ransomware-fundamentals/
├── README.md
├── starter/
│   └── main.py          # Exercises with TODOs
├── solution/
│   └── main.py          # Complete solutions
└── data/
    ├── ransom_notes/    # Sample ransom notes (sanitized)
    └── attack_timeline.json
```

---

## ✅ Success Criteria

- [ ] Can identify major ransomware families by artifacts
- [ ] Can map ransomware attacks to MITRE ATT&CK
- [ ] Understand the ransomware attack lifecycle
- [ ] Know key indicators (file, process, event log)
- [ ] Can make informed recovery decisions

---

## 📚 Resources

### Free Resources

- [No More Ransom Project](https://www.nomoreransom.org/) - Free decryptors
- [CISA StopRansomware](https://www.cisa.gov/stopransomware) - Alerts and guidance
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) - Family identification
- [Ransomware Overview (MITRE)](https://attack.mitre.org/techniques/T1486/)

### Purple Team & Detection Validation

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Library of tests mapped to MITRE ATT&CK
- [MITRE Caldera](https://caldera.mitre.org/) - Automated adversary emulation platform
- [Atomic Red Team - Ransomware Tests](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1486) - Specific T1486 tests
- [Purple Team Exercise Framework](https://github.com/scythe-io/purple-team-exercise-framework) - Structured exercises

### Threat Intelligence

- [Mandiant Ransomware Reports](https://www.mandiant.com/)
- [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/)
- [Cisco Talos](https://blog.talosintelligence.com/)
- [CrowdStrike Adversary Reports](https://www.crowdstrike.com/)
- [Unit 42 Ransomware Threat Reports](https://unit42.paloaltonetworks.com/category/ransomware/)

### SANS Resources

- [FOR528: Ransomware for Incident Responders](https://www.sans.org/cyber-security-courses/ransomware-incident-responders/) - Dedicated ransomware course by **Ryan Chapman**
- [GIAC GRIT](https://www.giac.org/certifications/response-industrial-defense-tactics-grit/) - Ransomware incident response certification
- [Ryan Chapman's Ransomware Research](https://www.sans.org/profiles/ryan-chapman/) - SANS instructor, ransomware specialist
- [SANS Webcasts - Ransomware](https://www.sans.org/webcasts/?focus-area=ransomware) - Free live and recorded webinars
- [SANS YouTube Channel](https://www.youtube.com/@SANSInstitute) - Search "ransomware" for free talks
- [SANS Ransomware Summit](https://www.sans.org/cyber-security-summit/) - Annual event
- [SANS Reading Room - Ransomware](https://www.sans.org/white-papers/)
- [GIAC GCIH](https://www.giac.org/certifications/certified-incident-handler-gcih/) - Incident handling certification

---

> 🌉 **Bridge Lab**: This lab provides the foundational knowledge needed for Lab 31 (Ransomware Detection) where you'll build actual detection algorithms using entropy analysis, behavioral patterns, and ML/LLM techniques.

**Next Lab**: [Lab 31 - Ransomware Detection](../lab31-ransomware-detection/)

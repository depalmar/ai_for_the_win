# Lab 30: Ransomware Fundamentals [Bridge Lab]

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Lab 25 (DFIR Fundamentals)

> **Updated November 2026**: Ransomware families and statistics reflect Check Point's Q1-Q3 2026 reports and Google's 2025 incident data: Qilin and The Gentlemen lead, DragonForce, Akira and Play stay active, LockBit is declining, and RansomHub and FunkSec are defunct.

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
| **2023**  | LockBit 3.0  | RaaS ecosystem, bug bounties, triple extortion       |
| **2024**  | BlackCat/ALPHV | $22M Change Healthcare ransom; final estimate 192.7M people affected ([HIPAA Journal](https://www.hipaajournal.com/change-healthcare-responding-to-cyberattack/), Aug 2025) |
| **2025**  | Fragmentation | RansomHub goes dark (Apr); record 85 active groups in Q3 ([Check Point](https://research.checkpoint.com/2026/the-state-of-ransomware-q1-2026/)); on-chain payments fall 8% to about $820M ([Chainalysis via The Register](https://www.theregister.com/2026/02/27/ransomware_chainalysis/)) |
| **2026**  | Qilin vs. The Gentlemen | Record 2,830 leak-site victims and 117 active brands in Q3 2026 ([Check Point](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/), 2026-11-18) |

### AI/LLM Evolution in Ransomware

Modern ransomware groups are increasingly leveraging AI:

| AI Use Case             | How Attackers Use It                                          | Defensive Implications                                    |
| ----------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| **Phishing generation** | LLMs create convincing, personalized phishing emails at scale | Traditional detection struggles with AI-generated content |
| **Code obfuscation**    | AI generates polymorphic code to evade signatures             | Need behavioral detection, not just signatures            |
| **Target research**     | AI scrapes and analyzes victim organizations                  | Attackers arrive better prepared                          |
| **Negotiation**         | Chatbots handle ransom negotiations 24/7                      | More professional criminal operations                     |
| **Translation**         | Instant localization of ransom notes                          | Global reach without language barriers                    |

**Documented cases (2025-2026):**

- **FunkSec** (defunct since March 2025) built its tools with AI help ([Check Point](https://research.checkpoint.com/2025/funksec-alleged-top-ransomware-group-powered-by-ai/), Jan 2025); a free decryptor followed in July 2025 ([The Hacker News](https://thehackernews.com/2025/07/funksec-ransomware-decryptor-released.html))
- An actor with basic skills used Claude to build ransomware and sold it for $400 to $1,200; another used Claude Code to steal data from at least 17 organizations and draft extortion notes ([Anthropic](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025), 2025-08-27)
- **The Gentlemen**'s admin built the group's ransomware panel in about three days with AI coding assistants, according to leaked backend data ([Check Point](https://blog.checkpoint.com/security/ransomware-didnt-slow-down-in-q2-2026-it-just-spread-out/), 2026-08-13)
- **PromptLock**, reported in August 2025 as the "first AI-powered ransomware", was an NYU research prototype, a reminder to check "first" claims ([NYU Tandon](https://engineering.nyu.edu/news/ai-powered-ransomware-sparked-concern-was-nyus-work))

> ⚠️ **Defender's Edge**: AI works both ways. The same capabilities that help attackers can power better detection (Lab 31, Ransomware Detection).

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

### Current Active Threats (2025-2026)

> **Post-LockBit/BlackCat landscape:** after the 2024 disruptions of LockBit and ALPHV/BlackCat, RansomHub took over much of the affiliate market until its infrastructure went dark on 2025-04-01 ([The Hacker News](https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html)). Since then Qilin has led every quarter, with The Gentlemen close behind. The market is fragmenting again: in Q3 2026, 117 brands posted 2,830 victims (a record) and the top ten groups held only 49% of victims, down from 71% in Q1 2026 ([Check Point](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/), 2026-11-18). Only about 23% of victims pay ([Check Point](https://research.checkpoint.com/2026/the-state-of-ransomware-q2-2026/), 2026-08-13).

| Family | Status (Nov 2026) | Characteristics | Notable TTPs |
| ------ | ----------------- | --------------- | ------------ |
| **Qilin** (Agenda) | Active, #1 in Q1-Q3 2026 | 338 victims in Q1 2026; top brand against industrial organizations since March 2025 ([Dragos](https://www.dragos.com/dragos-industrial-ransomware-analysis-q1-2026), 2026-06-03) | High-volume RaaS; an alleged core member was handed to Germany in Oct 2026 and the group kept operating ([BleepingComputer](https://www.bleepingcomputer.com/news/security/germany-arrests-alleged-core-qilin-ransomware-member-after-extradition/)) |
| **The Gentlemen** | Active, #2; led in June and September 2026 | Likely started as a Qilin affiliate (ArmCorp); active since at least July 2025; 90% affiliate payout ([Unit 42](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/), 2026-07-10) | C and Go lockers, GentleKiller EDR killer, edge-device exploitation |
| **DragonForce** | Active, white-label "cartel" | Affiliates run their own brands on its infrastructure ([Sophos](https://www.sophos.com/en-us/blog/dragonforce-targets-rivals-in-a-play-for-dominance), May 2025) | Encryptor used in the April 2025 Marks & Spencer attack linked to Scattered Spider ([BleepingComputer](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/)) |
| **Akira** | Active | Enterprise, VMware ESXi targeting | Linux variant encrypts ESXi VMs ([CISA AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a), updated 2025-11-13) |
| **Play** | Active | 121 victims in Q1 2026 ([Check Point](https://research.checkpoint.com/2026/the-state-of-ransomware-q1-2026/)) | New TTPs and IOCs in [CISA AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) (updated 2025-06-04) |
| **LockBit** | Declining | LockBit 5.0 (Sept 2025) for Windows, Linux and ESXi ([Trend Micro](https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html), 2025-09-25) | Random 16-character extensions; out of the top ten by Q3 2026 |
| **Cl0p** | Episodic | Mass exploitation of file-transfer and ERP software, then data-theft extortion | Oracle E-Business Suite zero-day CVE-2025-61882, exploited from about Aug 2025 ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation), 2025-10-09) |
| **RansomHub** | Defunct (April 2025) | Largest ALPHV successor in 2024 (historical) | Affiliates moved to other brands |
| **FunkSec** | Defunct (March 2025) | AI-assisted tooling | Free decryptor available since July 2025 |

### Key 2025-2026 Tactics

Figures come from Google's 2025 ransomware incident data ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape), 2026-03-16) unless noted.

| Tactic | Description | Defense |
| ------ | ----------- | ------- |
| **Data Theft Extortion** | Data stolen in 77% of intrusions (57% in 2024); some groups skip encryption entirely | Egress monitoring, DLP, incident response and legal prep |
| **Hypervisor Targeting** | About 43% of intrusions hit virtualization (29% in 2024): ESXi settings changed, SSH enabled, snapshots deleted | Lock down ESXi, alert on configuration changes |
| **EDR Killers / BYOVD** | Signed vulnerable drivers and custom killers disable security tools | Driver blocklists, tamper protection, behavioral detection |
| **Edge-Device Exploitation** | Exploited VPNs and firewalls in about a third of intrusions; stolen credentials in 21% | Patch edge devices fast, MFA everywhere, credential monitoring |
| **AI-Assisted Development** | AI coding assistants used to build ransomware and panels (Anthropic 2025, Check Point 2026) | Behavioral detection that does not rely on code signatures |

See also: [Threat Landscape 2025-2026 Reference](../../docs/guides/threat-landscape-2025.md)

### Family Identification Markers

```python
# Common ransomware indicators (2025-2026)
RANSOMWARE_SIGNATURES = {
    "ransomhub": {
        "extensions": [".ransomhub", ".[victim_id]"],
        "note_files": ["README.txt", "HOW_TO_RESTORE.txt"],
        "lineage": "ALPHV/BlackCat successor",
        "status": "Defunct since April 2025 (legacy samples still seen)",
    },
    "qilin": {
        "extensions": [".qilin", ".agenda"],
        "note_files": ["README-RECOVER.txt"],
        "c2_pattern": "Cobalt Strike, Sliver",
    },
    "dragonforce": {
        "extensions": [".dragonforce", ".locked"],
        "note_files": ["readme.txt"],
        "techniques": ["BYOVD", "cross-platform"],
    },
    "lockbit": {
        "extensions": [".lockbit", ".abcd", ".LockBit"],
        "note_files": ["Restore-My-Files.txt"],
        "registry_keys": ["HKCU\\Software\\LockBit"],
        "status": "Declining since 2024 takedown; LockBit 5.0 (2025) uses random 16-char extensions",
    },
    "akira": {
        "extensions": [".akira"],
        "note_files": ["akira_readme.txt"],
        "c2_pattern": "VPN exploitation, Conti lineage",
    },
    "play": {
        "extensions": [".play", ".PLAY"],
        "note_files": ["ReadMe.txt"],
        "techniques": ["LOLBins", "ProxyNotShell"],
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
    # Encrypted file extensions (2025-2026 families)
    "suspicious_extensions": [
        ".locked", ".encrypted", ".enc", ".crypted",
        ".qilin", ".dragonforce", ".akira", ".play",  # Active 2025-2026
        ".lockbit", ".rhysida",  # Older families (status varies)
        ".ransomhub", ".alphv", ".conti", ".royal", ".blacksuit"  # Legacy
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
- [CISA Ransomware Guides](https://www.cisa.gov/stopransomware)
- [MITRE ATT&CK - Ransomware](https://attack.mitre.org/)
- [Check Point Research: The State of Ransomware Q3 2026](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/) - Quarterly leak-site statistics (2026-11-18)
- [GTIG: Ransomware TTPs in a Shifting Threat Landscape](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape) - 2025 incident response data (2026-03-16)
- [Threat Landscape 2025-2026 Reference](../../docs/guides/threat-landscape-2025.md) - Curriculum's central threat intel page

### SANS Resources

- [FOR528: Ransomware for Incident Responders](https://www.sans.org/cyber-security-courses/ransomware-incident-responders/) - Dedicated ransomware course by **Ryan Chapman**
- [GIAC GCIH](https://www.giac.org/certifications/certified-incident-handler-gcih/) - Incident handling certification
- [Ryan Chapman's Ransomware Research](https://www.sans.org/profiles/ryan-chapman/) - SANS instructor, ransomware specialist
- [SANS Webcasts - Ransomware](https://www.sans.org/webcasts/?focus-area=ransomware) - Free live and recorded webinars
- [SANS YouTube Channel](https://www.youtube.com/@SANSInstitute) - Search "ransomware" for free talks
- [SANS Ransomware Summit](https://www.sans.org/cyber-security-summit/) - Annual event
- [SANS Reading Room - Ransomware](https://www.sans.org/white-papers/)

---

> 🌉 **Bridge Lab**: This lab provides the foundational knowledge needed for Lab 31 (Ransomware Detection) where you'll build actual detection algorithms using entropy analysis, behavioral patterns, and ML/LLM techniques.

**Next Lab**: [Lab 31 - Ransomware Detection](../lab31-ransomware-detection/)

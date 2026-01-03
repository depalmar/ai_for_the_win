# Sample Datasets

Sanitized, safe-to-use datasets for the AI Security Training Program labs.

> ⚠️ **Security Software Notice**: Some sample data contains realistic attack patterns, tool names, and command-line examples that may trigger antivirus or EDR alerts. This is **expected behavior** - these are educational datasets designed to teach threat detection. The data contains **no actual malware, no executable code, and no real credentials**. If your security software flags these files, you can safely add an exception for this educational repository.

```
data/
+-- README.md                 # This file
+-- phishing/                 # Email classification data
|   +-- emails.csv           # 500 phishing + legitimate emails
|   +-- urls.csv             # Malicious and benign URLs
+-- malware/                  # Malware metadata (no executables)
|   +-- samples.json         # PE file features and metadata
|   +-- family_labels.csv    # Malware family classifications
+-- logs/                     # Security log samples
|   +-- auth_logs.json       # Authentication events
|   +-- firewall_logs.csv    # Network firewall logs
|   +-- windows_events.json  # Windows Security events
+-- network/                  # Network traffic data
|   +-- traffic.csv          # Flow data with labels
|   +-- dns_queries.csv      # DNS query logs
|   +-- c2_beacons.json      # Simulated C2 beacon patterns
+-- threat-intel/             # Threat intelligence data
|   +-- iocs.json            # Indicators of Compromise
|   +-- attack_patterns.json # MITRE ATT&CK mapped attacks
|   +-- actor_profiles.json  # Threat actor TTPs
+-- forensics/                # Digital forensics artifacts
|   +-- prefetch/            # Windows Prefetch execution history
|   +-- registry/            # Registry persistence & artifacts
|   +-- filesystem/          # MFT entries, USN journal
|   +-- browser/             # Browser history, downloads
|   +-- memory/              # Process analysis, network connections
|   +-- super_timeline.json  # Consolidated forensic timeline
```

## Dataset Descriptions

### Phishing Data (`phishing/`)

| File         | Records | Description                                |
| ------------ | ------- | ------------------------------------------ |
| `emails.csv` | 500     | Phishing and legitimate emails with labels |
| `urls.csv`   | 1000    | URLs with malicious/benign classification  |

**Columns in emails.csv:**

- `id`: Unique identifier
- `subject`: Email subject line
- `body`: Email body text
- `sender`: Sender address (anonymized)
- `label`: 0 = legitimate, 1 = phishing
- `confidence`: Label confidence score

### Malware Metadata (`malware/`)

| File                | Records | Description                           |
| ------------------- | ------- | ------------------------------------- |
| `samples.json`      | 200     | PE file features (no actual binaries) |
| `family_labels.csv` | 200     | Malware family classifications        |

**Features in samples.json:**

- File entropy, section counts, import counts
- String patterns, API call frequencies
- Packer detection indicators
- Hash values (SHA256)

### Security Logs (`logs/`)

> ⚠️ **Content Notice**: Log data includes realistic command-line patterns from offensive tools for educational detection training. All patterns are descriptive text - no executable content.

| File                  | Records | Description                                          |
| --------------------- | ------- | ---------------------------------------------------- |
| `auth_logs.json`      | ~120    | Authentication events with realistic attack patterns |
| `firewall_logs.csv`   | -       | Network firewall allow/deny logs (coming soon)       |
| `windows_events.json` | -       | Windows Security Event Log entries (coming soon)     |

**Realistic attack patterns in auth_logs.json:**

| Category                 | Techniques                             | MITRE ATT&CK                    |
| ------------------------ | -------------------------------------- | ------------------------------- |
| **Initial Access**       | Password spray, compromised account    | T1110.003, T1078                |
| **Execution**            | Encoded PowerShell, LOLBins            | T1059.001, T1218                |
| **Persistence**          | Scheduled tasks, services, Run keys    | T1053.005, T1543.003, T1547.001 |
| **Privilege Escalation** | Kerberoasting, AS-REP roasting         | T1558.003, T1558.004            |
| **Credential Access**    | Mimikatz, DCSync, LSASS dump, SAM dump | T1003.001, T1003.006, T1003.002 |
| **Discovery**            | Net commands, BloodHound, PowerView    | T1069, T1087, T1018             |
| **Lateral Movement**     | PsExec, WMIC, SMB                      | T1021.002, T1047                |
| **Collection**           | Data staging, archiving                | T1560.001                       |
| **Exfiltration**         | Rclone to cloud                        | T1567.002                       |
| **Defense Evasion**      | Event log clearing                     | T1070.001                       |

**LOLBins included:**

- `certutil.exe` - download, decode (T1105, T1140)
- `mshta.exe` - HTA/VBScript execution (T1218.005)
- `regsvr32.exe` - Squiblydoo attack (T1218.010)
- `rundll32.exe` - script execution (T1218.011)
- `wmic.exe` - process creation, remote exec (T1047)
- `bitsadmin.exe` - file download (T1197)
- `msiexec.exe` - remote package install (T1218.007)
- `installutil.exe` - bypass application control (T1218.004)
- `msbuild.exe` - code execution (T1127.001)
- `cscript/wscript.exe` - script execution (T1059.005/007)

**Offensive tools referenced:**

- Mimikatz, Rubeus, BloodHound/SharpHound
- PowerView, PsExec, ProcDump, Rclone

### Network Data (`network/`)

| File              | Records | Description                   |
| ----------------- | ------- | ----------------------------- |
| `traffic.csv`     | 10000   | NetFlow-style traffic records |
| `dns_queries.csv` | 5000    | DNS queries with DGA labels   |
| `c2_beacons.json` | 500     | Simulated beacon patterns     |

### Threat Intelligence (`threat-intel/`)

| File                   | Records | Description                       |
| ---------------------- | ------- | --------------------------------- |
| `iocs.json`            | 1000    | IPs, domains, hashes with context |
| `attack_patterns.json` | 50      | Full attack chains with TTPs      |
| `actor_profiles.json`  | 20      | Threat actor profiles             |

### Digital Forensics Artifacts (`forensics/`)

> ⚠️ **AV/EDR Notice**: Forensics data contains realistic attack indicators (tool names, file paths, techniques) for educational purposes. These are **JSON metadata files only** - no executables, no encoded payloads, no actual malware.

Complete DFIR dataset simulating a compromised Windows environment.

| Directory             | Artifact Type     | Description                                             |
| --------------------- | ----------------- | ------------------------------------------------------- |
| `prefetch/`           | Execution history | Windows Prefetch files showing program execution        |
| `registry/`           | Persistence       | Run keys, services, Shimcache, Amcache, UserAssist      |
| `filesystem/`         | File activity     | MFT entries, USN journal showing file creation/deletion |
| `browser/`            | Web activity      | Chrome/Edge history, downloads, cookies                 |
| `memory/`             | Live analysis     | Process list, network connections, injected code        |
| `super_timeline.json` | Consolidated      | Plaso-style timeline of entire attack                   |

**Attack scenario covered:**

- Password spray → Initial access → PowerShell execution
- LOLBin abuse (certutil, mshta) → Payload download
- Kerberoasting → Lateral movement (PsExec)
- DCSync → LSASS dump → Golden ticket
- Data staging → Exfiltration → Log clearing

**Forensic artifacts included:**
| Artifact | Evidence Value |
| -------- | -------------- |
| Prefetch | Program execution with timestamps |
| Shimcache | Application compatibility cache |
| Amcache | Application install/execution |
| MFT | File creation/modification times |
| USN Journal | File system changes (even deleted) |
| Registry Run keys | Persistence mechanisms |
| Browser history | Payload download sources |
| Memory processes | Running malware, C2 connections |

**Usage:**

```python
import json

# Load super timeline
with open('data/forensics/super_timeline.json') as f:
    timeline = json.load(f)

# Filter for credential access events
cred_events = [
    e for e in timeline['timeline']
    if e['label'] == 'credential_access'
]

# Analyze attack progression
for event in timeline['timeline'][:10]:
    print(f"{event['timestamp']} - {event['description']}")
```

## Usage Examples

### Loading Phishing Emails

```python
import pandas as pd

# Load email dataset
emails = pd.read_csv('data/phishing/emails.csv')

# Split into features and labels
X = emails['body']
y = emails['label']

print(f"Total emails: {len(emails)}")
print(f"Phishing: {y.sum()}, Legitimate: {len(y) - y.sum()}")
```

### Loading Malware Features

```python
import json

# Load malware metadata
with open('data/malware/samples.json') as f:
    samples = json.load(f)

# Extract features for clustering
features = [
    [s['entropy'], s['section_count'], s['import_count']]
    for s in samples
]
```

### Loading Network Traffic

```python
import pandas as pd

# Load traffic data
traffic = pd.read_csv('data/network/traffic.csv')

# Filter for suspicious traffic
suspicious = traffic[traffic['label'] == 'malicious']
print(f"Suspicious flows: {len(suspicious)}")
```

### Loading Threat Intel

```python
import json

# Load IOCs
with open('data/threat-intel/iocs.json') as f:
    iocs = json.load(f)

# Get all malicious IPs
malicious_ips = [
    ioc['value'] for ioc in iocs
    if ioc['type'] == 'ip' and ioc['malicious']
]
```

## Data Generation

These datasets are synthetically generated for educational purposes. They are designed to:

1. **Be realistic** - Patterns mirror real-world security data
2. **Be safe** - No actual malware, credentials, or PII
3. **Be balanced** - Appropriate class distributions for ML
4. **Be documented** - Clear schemas and examples

### Regenerating Datasets

```bash
# Generate fresh datasets with different random seeds
python scripts/generate_datasets.py --seed 42

# Generate specific dataset types
python scripts/generate_datasets.py --type phishing --count 1000
python scripts/generate_datasets.py --type malware --count 500
```

## Lab Mapping

| Dataset                            | Used In Labs                                                       |
| ---------------------------------- | ------------------------------------------------------------------ |
| `phishing/emails.csv`              | Lab 01 (Phishing Classifier)                                       |
| `malware/samples.json`             | Lab 02 (Malware Clustering), Lab 07 (YARA)                         |
| `logs/auth_logs.json`              | Lab 03 (Anomaly), Lab 04 (Log Analysis), Lab 15 (Lateral Movement) |
| `network/traffic.csv`              | Lab 03 (Anomaly), Lab 14 (C2 Traffic)                              |
| `threat-intel/iocs.json`           | Lab 05 (Threat Intel), Lab 06 (RAG)                                |
| `threat-intel/actor_profiles.json` | Lab 16 (Actor Profiling)                                           |
| `forensics/`                       | Lab 10b (DFIR), Lab 13 (Memory Forensics)                          |
| `forensics/super_timeline.json`    | Lab 10 (IR Copilot), Lab 10b (DFIR Fundamentals)                   |

## Public Datasets for Production-Scale Practice

Our sample datasets are intentionally small for quick learning. For production-scale practice, we recommend these public datasets:

### Authentication & Logs

| Dataset            | Size       | Description                                            | Link                                                                                                 |
| ------------------ | ---------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| **Splunk BOTS**    | ~50GB      | Full attack simulation with Windows, network, web logs | [splunk.com/bots](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-data-set-released.html) |
| **LANL Auth Data** | 1B+ events | Real anonymized authentication logs                    | [csr.lanl.gov](https://csr.lanl.gov/data/cyber1/)                                                    |
| **SecRepo**        | Various    | Curated security log samples                           | [secrepo.com](https://www.secrepo.com/)                                                              |

### Malware & PE Files

| Dataset           | Size         | Description                       | Link                                                               |
| ----------------- | ------------ | --------------------------------- | ------------------------------------------------------------------ |
| **EMBER**         | 1.1M samples | PE file features (no binaries)    | [github.com/elastic/ember](https://github.com/elastic/ember)       |
| **SOREL-20M**     | 20M samples  | Malware/benign PE features        | [github.com/sophos/SOREL-20M](https://github.com/sophos/SOREL-20M) |
| **VirusShare**    | Millions     | Actual malware samples (careful!) | [virusshare.com](https://virusshare.com/)                          |
| **MalwareBazaar** | 100K+        | Tagged malware samples            | [bazaar.abuse.ch](https://bazaar.abuse.ch/)                        |

### Phishing & Email

| Dataset              | Size  | Description               | Link                                                                         |
| -------------------- | ----- | ------------------------- | ---------------------------------------------------------------------------- |
| **Nazario Phishing** | 4.5K+ | Phishing emails corpus    | [monkey.org/~jose/phishing](https://monkey.org/~jose/phishing/)              |
| **IWSPA-AP**         | 50K+  | Phishing website features | [kaggle.com](https://www.kaggle.com/datasets)                                |
| **SpamAssassin**     | 6K+   | Spam vs ham emails        | [spamassassin.apache.org](https://spamassassin.apache.org/old/publiccorpus/) |

### Network Traffic

| Dataset        | Size         | Description                 | Link                                                                   |
| -------------- | ------------ | --------------------------- | ---------------------------------------------------------------------- |
| **CICIDS2017** | 80GB+        | Intrusion detection dataset | [unb.ca/cic](https://www.unb.ca/cic/datasets/ids-2017.html)            |
| **CTU-13**     | 13 scenarios | Botnet traffic captures     | [stratosphereips.org](https://www.stratosphereips.org/datasets-ctu13)  |
| **UNSW-NB15**  | 2.5M flows   | Modern attack network data  | [unsw.edu.au](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |

### Threat Intelligence

| Dataset            | Size            | Description               | Link                                              |
| ------------------ | --------------- | ------------------------- | ------------------------------------------------- |
| **MITRE ATT&CK**   | 700+ techniques | Attack technique database | [attack.mitre.org](https://attack.mitre.org/)     |
| **AlienVault OTX** | Millions        | Community threat intel    | [otx.alienvault.com](https://otx.alienvault.com/) |
| **Abuse.ch**       | Various         | URLhaus, ThreatFox, etc.  | [abuse.ch](https://abuse.ch/)                     |

### Usage Tips

1. **Start small** - Use our sample data for learning
2. **Scale up** - Move to public datasets when ready
3. **Memory matters** - Large datasets need chunked processing
4. **Label quality** - Public datasets may have labeling issues

```python
# Example: Loading EMBER dataset (after download)
import pandas as pd

# EMBER provides train/test splits
ember_train = pd.read_csv('ember/train_features.csv')
print(f"EMBER training samples: {len(ember_train)}")

# Our small dataset for quick iteration
samples = pd.read_json('data/malware/samples.json')
print(f"Sample dataset: {len(samples)}")
```

## License

These datasets are provided under the MIT License for educational use.

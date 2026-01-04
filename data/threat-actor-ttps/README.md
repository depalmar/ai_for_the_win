# Threat Actor TTP Database

This directory contains comprehensive threat actor profiles, campaign data, and attack chain templates based on documented TTPs from MITRE ATT&CK and public threat intelligence reports.

## Purpose

This database serves as a shared data layer for:
- **Labs**: Realistic scenario generation and threat actor profiling exercises
- **CTF Challenges**: Evidence-based challenges requiring TTP analysis
- **Training**: Understanding real-world adversary behavior

## Directory Structure

```
threat-actor-ttps/
├── actors/           # Individual threat actor profiles (14 actors)
│   ├── apt28.json    # APT28 (Fancy Bear) - Russia/GRU
│   ├── apt29.json    # APT29 (Cozy Bear) - Russia/SVR
│   ├── apt41.json    # APT41 (Double Dragon) - China
│   ├── lazarus.json  # Lazarus Group - North Korea
│   ├── fin7.json     # FIN7 (Carbanak) - Financial crime
│   ├── lockbit.json  # LockBit ransomware
│   ├── alphv.json    # ALPHV/BlackCat ransomware
│   ├── scattered_spider.json  # Scattered Spider - Social engineering
│   ├── clop.json     # Cl0p ransomware
│   ├── conti.json    # Conti (historical, disbanded 2022)
│   ├── blackbasta.json  # Black Basta ransomware (2024 active)
│   ├── akira.json    # Akira ransomware (2024 active)
│   ├── rhysida.json  # Rhysida ransomware (2024 active)
│   └── play.json     # Play ransomware (2024 active)
├── campaigns/        # Notable attack campaigns (8 campaigns)
│   ├── solarwinds.json        # APT29 supply chain (2020)
│   ├── colonial_pipeline.json # DarkSide ransomware (2021)
│   ├── log4shell.json         # Mass exploitation (2021)
│   ├── moveit.json            # Cl0p mass exploitation (2023)
│   ├── kaseya.json            # REvil supply chain (2021)
│   ├── change_healthcare.json # ALPHV healthcare attack (2024)
│   ├── arup_deepfake_2024.json   # AI deepfake video conference BEC ($25M)
│   └── ivanti_exploitation.json # Mass VPN exploitation (2024)
└── attack-chains/    # Generic attack patterns (5 patterns)
    ├── double_extortion.json   # Modern ransomware playbook
    ├── supply_chain.json       # Software supply chain attacks
    ├── bec_fraud.json          # Business email compromise
    ├── insider_threat.json     # Insider threat patterns
    └── identity_compromise.json # Cloud/identity provider attacks
```

## Data Schema

### Actor Profile Schema

```json
{
  "id": "string",
  "name": "string",
  "aliases": ["string"],
  "country": "string",
  "motivation": "espionage|financial|hacktivism|destruction",
  "active_since": "YYYY",
  "sophistication": "basic|intermediate|advanced|expert",
  "ttps": [
    {
      "technique_id": "TXXXX.XXX",
      "technique_name": "string",
      "tactic": "string",
      "procedure": "string",
      "confidence": 0.0-1.0
    }
  ],
  "malware_families": ["string"],
  "tools": ["string"],
  "target_sectors": ["string"],
  "target_regions": ["string"],
  "infrastructure": {
    "c2_patterns": ["string"],
    "hosting_preferences": ["string"]
  },
  "notable_campaigns": ["string"],
  "references": ["url"]
}
```

### Campaign Schema

```json
{
  "id": "string",
  "name": "string",
  "threat_actor": "string",
  "timeframe": {
    "start": "YYYY-MM-DD",
    "end": "YYYY-MM-DD"
  },
  "attack_phases": [
    {
      "phase": "number",
      "name": "string",
      "techniques": ["TXXXX"],
      "description": "string",
      "indicators": ["string"]
    }
  ],
  "impact": {},
  "iocs": {}
}
```

## Usage

### Python Example

```python
import json
from pathlib import Path

def load_actor(actor_id: str) -> dict:
    """Load a threat actor profile."""
    path = Path(__file__).parent / "actors" / f"{actor_id}.json"
    with open(path) as f:
        return json.load(f)

# Load APT29 profile
apt29 = load_actor("apt29")
print(f"TTPs: {len(apt29['ttps'])} techniques")
```

### Lab Integration

Labs can reference this data for:
- Lab 14 (C2 Traffic): Use actor C2 patterns for traffic generation
- Lab 16 (Threat Actor Profiling): Compare incidents against known actor TTPs
- Lab 11 (Ransomware): Use ransomware group profiles for scenario creation

### CTF Integration

CTF challenges can use this data for:
- Generating realistic attack artifacts
- Creating attribution challenges
- Building multi-stage incident scenarios

## Data Sources

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [MITRE ATT&CK Software](https://attack.mitre.org/software/)
- [CISA Advisories](https://www.cisa.gov/cybersecurity-advisories)
- Public threat intelligence reports (Mandiant, CrowdStrike, Microsoft, etc.)

## Note on IOCs

All IP addresses, domains, and URLs in this database are:
- **Defanged** using `[.]` notation for safety
- **Fictional or historical** - not active infrastructure
- For **educational purposes only**

Use `shared.ioc_utils.refang_ioc()` to convert for analysis tools.

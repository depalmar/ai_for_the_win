# Threat Landscape 2025-2026

Quick reference for current threat actors, campaigns, tools, and TTPs. Updated January 2026.

## Nation-State APT Groups (CRINK)

The "CRINK" nations (China, Russia, Iran, North Korea) sponsor 77% of all suspected cyber operations.

### China

| Group | Aliases | Focus | Recent Activity (2025) |
|-------|---------|-------|----------------------|
| APT41 | Winnti, Barium | IP theft, espionage | Cloud provider targeting |
| APT40 | Leviathan | Maritime, defense | Indo-Pacific operations |
| Volt Typhoon | N/A | Critical infrastructure | Pre-positioning in CNI |
| Salt Typhoon | N/A | Telecom | US carrier infiltration |

**Key TTPs:**
- Zero-day exploitation (edge devices, VPNs)
- Living-off-the-land techniques
- Long-term persistence (years)
- Supply chain compromise

### Russia

| Group | Aliases | Focus | Recent Activity (2025) |
|-------|---------|-------|----------------------|
| APT28 | Fancy Bear, Unit 26165 | Government, military | AI-guided malware in Ukraine |
| APT29 | Cozy Bear | Diplomatic, political | Cloud service exploitation |
| Sandworm | Unit 74455 | Critical infrastructure | Wiper malware (Zerolot, Sting) |

**Key TTPs:**
- Outsourcing to criminal groups
- AI-adaptive malware (real-time LLM queries)
- Wiper attacks against Ukraine
- Credential harvesting campaigns

### Iran

| Group | Aliases | Focus | Recent Activity (2025) |
|-------|---------|-------|----------------------|
| APT33 | Elfin | Energy, aerospace | Middle East targeting |
| APT35 | Charming Kitten | Media, activists | Credential harvesting |
| MuddyWater | N/A | Government, telecom | Iraq, Yemen campaigns |

**Key TTPs:**
- Brute force MFA bypass
- PowerShell-based tooling
- Social engineering campaigns
- Regional espionage (Middle East)

### North Korea

| Group | Aliases | Focus | Recent Activity (2025) |
|-------|---------|-------|----------------------|
| Lazarus | APT38 | Financial, crypto | $1.7B+ crypto theft |
| Kimsuky | Velvet Chollima | Research, policy | Credential theft |
| DeceptiveDevelopment | N/A | Developers | Fake job offers |

**Key TTPs:**
- Fake job recruitment campaigns
- IT worker infiltration (European expansion)
- Cryptocurrency platform targeting
- Ransomware for regime funding

## C2 Frameworks (2025-2026)

Top command-and-control frameworks used by threat actors (Q2 2025 Kaspersky data):

| Framework | Type | Key Features | Detection Difficulty |
|-----------|------|--------------|---------------------|
| **Sliver** | Open Source | Cross-platform, encrypted comms, modular | High |
| **Havoc** | Open Source | MS Graph API C2, SharePoint staging | High |
| **Mythic** | Open Source | Web UI, multi-agent, microservices | Medium |
| **Brute Ratel C4** | Commercial | EDR bypass, sleep obfuscation | Very High |
| **Cobalt Strike** | Commercial (cracked) | Beacon, lateral movement, mature | Medium |
| **Metasploit** | Open Source | Wide exploit library | Low |

**Key Trends:**
- Move from Cobalt Strike to Sliver (open source, harder to detect)
- C2 traffic hidden in cloud services (Graph API, SharePoint)
- Modular payloads with in-memory execution
- AI-assisted evasion optimization

## Ransomware Groups (2025-2026)

Post-LockBit/BlackCat fragmentation: 85 active extortion groups, 45 new in 2025.

| Group | Status | Notable Tactics | Avg Ransom |
|-------|--------|-----------------|------------|
| **RansomHub** | Active | ALPHV successor, 80% affiliate share | $1.5M+ |
| **Qilin** | Rising | IAB partnerships, aggressive recruiting | $2M+ |
| **DragonForce** | Cartel | Multi-platform (Win/Linux/ESXi/NAS), BYOVD | $1.8M |
| **LockBit** | Diminished | Resurged Sept 2025, sanctions limiting payments | $1M+ |
| **Funksec** | Emerging | AI/LLM in tooling, WormGPT integration | Varies |

**Key Tactics (2025):**
- Multi-layered extortion (encrypt + leak + DDoS + regulatory reporting)
- AI-generated phishing at scale
- Cross-platform ransomware (Windows, Linux, ESXi, NAS)
- BYOVD (Bring Your Own Vulnerable Driver) for EDR bypass
- Ransomware-as-a-Service with mobile kits

**Financial Impact:**
- Average demand: $1.8M
- Average incident cost: $5.08M (including downtime, legal, reputation)

## AI-Enhanced Attacks

### APT28 AI-Guided Malware (July 2025)

CERT-UA reported APT28 using AI in novel ways:
- Malware queries LLM in real-time for next actions
- Adaptive behavior based on environment
- Not static pre-coded instructions

### First AI-Orchestrated Cyber Campaign (Sept 2025)

Anthropic detected unprecedented AI-autonomous attack:
- AI performed 80-90% of the campaign
- Human intervention only at 4-6 critical points
- Thousands of requests per second at peak
- Would have taken "vast amounts of time" for human team

### Nation-State AI Usage (Google Research)

57+ nation-state groups using AI tools:
- APT42 (Iran): 30%+ of Gemini abuse - phishing, recon, content generation
- Chinese APTs: Lateral movement research, privilege escalation
- North Korean actors: Fake job applications, cover letter generation

## C2 Detection Indicators

### Sliver

```yaml
Network:
  - MTLS on non-standard ports
  - HTTP(S) beacons to suspicious domains
  - DNS tunneling patterns

Process:
  - Injected processes with network activity
  - Shellcode execution patterns
  - Memory-only payloads
```

### Cobalt Strike

```yaml
Network:
  - Default malleable C2 profiles (if not customized)
  - Beacon sleep patterns
  - Named pipe indicators (\\.\pipe\)

Files:
  - Beacon DLL characteristics
  - Reflective loader artifacts
```

### Havoc

```yaml
Network:
  - Microsoft Graph API abuse
  - SharePoint file staging
  - Unusual cloud service traffic patterns
```

## MITRE ATT&CK References

### Most Used Techniques (2025)

| Technique | ID | Usage |
|-----------|-----|-------|
| Phishing | T1566 | Initial access via AI-enhanced lures |
| Valid Accounts | T1078 | Credential theft/purchase |
| Command & Scripting | T1059 | PowerShell, Python abuse |
| Remote Services | T1021 | RDP, SSH lateral movement |
| Exfiltration Over C2 | T1041 | Data theft via C2 channel |

### AI-Specific Techniques (MITRE ATLAS)

| Technique | Description |
|-----------|-------------|
| AML.T0051 | LLM Prompt Injection |
| AML.T0043 | Craft Adversarial Data |
| AML.T0044 | Full ML Model Access |
| AML.T0025 | Exfiltration via ML API |

## Recommended Defenses

### Against Nation-State APTs

1. **Assume breach mentality** - Focus on detection and response
2. **Zero trust architecture** - Verify continuously
3. **Edge device hardening** - VPNs, firewalls are prime targets
4. **Threat hunting** - Proactive search for pre-positioned access

### Against Ransomware

1. **Offline backups** - Air-gapped, tested regularly
2. **Patch aggressively** - Especially edge devices
3. **Network segmentation** - Limit lateral movement
4. **EDR with behavioral detection** - Signatures alone insufficient

### Against AI-Enhanced Attacks

1. **AI-based email filtering** - Fight AI with AI
2. **Out-of-band verification** - Phone/video for financial requests
3. **Code word systems** - Pre-established verification phrases
4. **Behavioral detection** - Focus on actions, not signatures

## Sources

- [Anthropic: Disrupting AI Espionage](https://www.anthropic.com/news/disrupting-AI-espionage)
- [Google TAG: Nation-State AI Usage](https://thehackernews.com/2025/01/google-over-57-nation-state-threat.html)
- [DFIR Report: Cobalt Strike to LockBit](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- [Flashpoint: RaaS Groups 2025](https://flashpoint.io/blog/new-ransomware-as-a-service-raas-groups-to-watch-in-2025/)
- [DeepStrike: State-Sponsored Hacking 2025](https://deepstrike.io/blog/state-sponsored-hacking-apt-threats-2025)
- [CISA: Nation-State Threats](https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors)
- [Microsoft: Sliver C2](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)

# Threat Landscape 2025-2026

Quick reference for current threat actors, campaigns, tools, and TTPs. Updated November 2026 (sources checked through 2026-11-18).

> **How to read this page:** every claim links a dated source. "Vendor-only" marks a claim that comes from one vendor and that no government or second independent source confirmed during this update. Leak-site victim counts differ between trackers because each one counts differently, so compare trends rather than exact totals. Material labeled *historical* is kept because it still teaches something.

## Nation-State APT Groups (CRINK)

China, Russia, Iran and North Korea ("CRINK") account for 77% of the state-sponsored operations in the [Council on Foreign Relations Cyber Operations Tracker](https://www.cfr.org/cyber-operations). That is a cumulative count of publicly attributed incidents since 2005 (*historical, cumulative*), not a 2025-2026 rate.

**Naming note:** in 2026 Google started publishing new names for some groups it tracks, for example CALANQUE ION for APT42, SANDWORM RELIC for APT44 (Sandworm) and RAVINE CASTLE for APT24 ([GTIG, 2026-09-08](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai)). Vendors still use different names, so map aliases with [MITRE ATT&CK Groups](https://attack.mitre.org/groups/).

### China

| Group | Aliases | Focus | Recent Activity (2025-2026) |
|-------|---------|-------|-----------------------------|
| APT41 | Winnti, Barium | IP theft, espionage | TOUGHPROGRESS malware used Google Calendar events for C2 and was delivered from a compromised government website ([GTIG, May 2025](https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics)) |
| Salt Typhoon | Partial overlaps: OPERATOR PANDA, RedMike, UNC5807, GhostEmperor | Telecom, government, transport, military networks | Exploits routers at telecom providers and other infrastructure worldwide; joint advisory from CISA, NSA, FBI and partners in more than a dozen countries ([CISA AA25-239A, 2025-08-27](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)) |
| Volt Typhoon | N/A | Critical infrastructure | Pre-positioning in US critical infrastructure IT networks ([CISA AA24-038A, February 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), 2024 baseline). Its KV Botnet, mainly vulnerable Cisco and NetGear routers, is named in the April 2026 joint advisory on China-nexus covert networks ([NCSC-UK, CISA, NSA, FBI and partners, April 2026](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/defending-against-china-nexus-covert-networks-of-compromised-devices)) |
| UNC7228 | Overlaps Microsoft's STORM-0940 | Enterprise software, industrial automation, semiconductors, telecom (US, Europe) | Has used the ARTEX multi-agent offensive framework since at least August 2026; moved from a first compromised account to deep system access in about four hours, once in 15 minutes ([GTIG/Mandiant, 2026-10-30](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)) |
| APT40 | Leviathan | Maritime, defense | *Historical:* no 2025-2026 primary source was re-verified in this update; see [MITRE ATT&CK G0065](https://attack.mitre.org/groups/G0065/) |

ESET counted China-aligned groups as the largest share of recorded attack sources from October 2025 to March 2026. Examples include FamousSparrow against a Venezuelan maritime-affairs body (January 2026) and NegativeGlimmer against a South Korean AI and robotics company ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)). From April to September 2026 one China-aligned cluster targeted Taiwanese semiconductor organizations ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)).

**Key TTPs:**
- Exploitation of routers, VPNs and other edge devices ([CISA AA25-239A, 2025-08-27](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a))
- Covert networks of compromised SOHO routers, IoT devices and NAS to hide origin; static IP blocklists age quickly ([joint covert-networks advisory, April 2026](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/defending-against-china-nexus-covert-networks-of-compromised-devices))
- C2 over legitimate cloud services such as calendar APIs ([GTIG, May 2025](https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics))
- Local LLM infrastructure deployed inside compromised networks to avoid commercial API monitoring (UNC6508, [GTIG, 2026-09-08](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai))
- Long-term persistence and living-off-the-land remain the baseline expectation (*historical pattern*, see AA24-038A)

### Russia

| Group | Aliases | Focus | Recent Activity (2025-2026) |
|-------|---------|-------|-----------------------------|
| APT28 | Fancy Bear, Unit 26165, Sednit | Government, military | LAMEHUG (also called PROMPTSTEAL) queried Qwen2.5-Coder-32B-Instruct through the Hugging Face API to generate Windows commands; CERT-UA attributes it to APT28 with medium confidence ([The Hacker News, July 2025](https://thehackernews.com/2025/07/cert-ua-discovers-lamehug-malware.html)). Sednit used Covenant and BeardShell against Ukrainian military personnel and drone makers, October 2025 to March 2026 ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)) |
| APT29 | Cozy Bear, Midnight Blizzard | Diplomatic, government | Watering-hole pages pushed visitors into Microsoft device code authentication; Amazon disrupted the campaign ([AWS Security Blog, August 2025](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)). Anthropic describes a Russian espionage actor (GTG-20006) that used AI workflows to rebuild malware to evade detection (vendor-only, [Anthropic, September 2026](https://www.anthropic.com/threat-intelligence-report-september-2026)) |
| Sandworm | APT44, Unit 74455; Google: SANDWORM RELIC | Critical infrastructure | New wipers ZeroRays (Rust) and NAUGHTYWIPE in winter 2025-2026; DynoWiper hit a Polish energy company in December 2025, attributed with medium confidence ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)) |

From April to September 2026 Gamaredon activity dropped sharply, and Belarus-aligned groups increasingly acted as "cyberproxies or force multipliers for Russia" ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)).

**Key TTPs:**
- Destructive wipers against Ukraine and nearby energy targets ([ESET, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/))
- Malware that queries an LLM at runtime for its next commands (LAMEHUG, above)
- Anti-AI-analysis: UAC-0099 put a decoy request about building a nuclear weapon in a script comment, apparently to trip LLM safety guardrails and block AI-assisted analysis ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/))
- Token theft through device code phishing ([AWS, August 2025](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/))

### Iran

ESET reports that a war in Iran began in late February 2026. Activity by established Iran-aligned APT groups dropped, partly because of Iranian internet restrictions, while pro-Iranian proxy and hacktivist groups stepped up attacks on Israel and the United States ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)). US agencies report Iranian-affiliated APT actors disrupting internet-exposed PLCs in US water, energy and local government since at least March 2026, campaigns that "have recently escalated, likely in response to hostilities between Iran, and the United States and Israel" ([CISA AA26-097A, 2026-04-07, updated 2026-07-22](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)). Several established groups resumed operations from April to September 2026 ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)).

| Group | Aliases | Focus | Recent Activity (2025-2026) |
|-------|---------|-------|-----------------------------|
| APT35 / APT42 | Charming Kitten; Google: CALANQUE ION (APT42) | Policy, media, activists | Over 30% of Iranian APT actors' Gemini use was linked to APT42 (phishing, research, content) ([GTIG, 2025-01-29](https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai)) |
| MuddyWater | N/A | Government, telecom | Resumed operations April to September 2026, mostly against Israeli targets, with some US companies hit ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)) |
| FilthyFeline | OilRig subgroup | Israel, Central Asian telecom | Resumed operations April to September 2026 ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)) |
| Iranian-affiliated PLC actors | N/A | Water, energy, local government OT | Downloaded malicious project files to PLCs and manipulated HMI data ([CISA AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)) |
| APT33 | Elfin | Energy, aerospace | *Historical:* no 2025-2026 primary source was re-verified in this update |

**Key TTPs:**
- Disruption of internet-exposed PLCs and HMIs ([CISA AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a))
- Wipers from unattributed clusters with Iranian characteristics, such as the Rusty Boots bootkit-style wiper against Israeli device makers ([ESET, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/))
- Proxy and hacktivist personas during the 2026 conflict (same source)
- AI for phishing content and research ([GTIG, 2025-01-29](https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai))

### North Korea

| Group | Aliases | Focus | Recent Activity (2025-2026) |
|-------|---------|-------|-----------------------------|
| Lazarus / TraderTraitor | APT38, BlueNoroff (overlapping clusters) | Financial, crypto, developers | Stole about $1.5B from Bybit on 2025-02-21 ([FBI PSA, 2025-02-26](https://www.ic3.gov/PSA/2025/PSA250226)). Published trojanized axios npm releases after tricking the maintainer; online for about three hours, attributed by researchers to BlueNoroff ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)). Recruitment-themed lures against the drone sector, April to September 2026 ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)) |
| Kimsuky | Velvet Chollima | Research, policy, defense | July 2025 spear-phishing used a ChatGPT-generated fake South Korean military ID (Genians research, vendor-only; [The Record, 2025-09-15](https://therecord.media/north-korea-kimsuky-hackers-phishing-fake-military-ids-chatgpt)) |
| Andariel | N/A | Defense, engineering | Deployed TigerRAT and Rook ransomware at a South Korean engineering firm, March 2026 ([ESET via Help Net Security, 2026-05-28](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)) |
| Remote IT worker schemes | N/A | Western tech employers | Operatives used Claude to get and keep remote jobs at US Fortune 500 technology companies ([Anthropic, 2025-08-27](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025)) |

North Korea stole at least $2.02B in cryptocurrency in 2025, a record and about 60% of all crypto theft that year (Chainalysis data, [Fortune, 2025-12-18](https://fortune.com/2025/12/18/north-korea-stole-a-record-amount-of-crypto/)).

**Key TTPs:**
- Fake recruitment and fake collaboration lures (ESET reports above)
- Open-source package compromise through maintainer social engineering (axios case)
- IT worker fraud, now assisted by LLMs (Anthropic)
- Ransomware for revenue (Andariel and Rook)

## C2 Frameworks (2025-2026)

Two datasets complement each other: Kaspersky's quarterly count of C2 frameworks seen in attacks according to open sources (weighted toward APT reporting), and Google's ransomware incident response data.

| Quarter | Most used C2 frameworks (Kaspersky, open-source data) | Source |
|---------|--------------------------------------------------------|--------|
| H1 2025 | Sliver, Metasploit, Havoc and Brute Ratel C4 | [Securelist Q2 2025](https://securelist.com/vulnerabilities-and-exploits-in-q2-2025/117333/) |
| Q4 2025 | Sliver first, Mythic second, Havoc third | [Securelist, 2026-03-06](https://securelist.com/vulnerabilities-and-exploits-in-q4-2025/119105/) |
| Q1 2026 | Metasploit back on top; Sliver and Havoc share second; Covenant and Mythic follow | [Securelist, 2026-05-07](https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/) |
| Q2 2026 | "Sliver, Havoc, AdaptixC2, and Metasploit remain the most widely used" (no order given) | [Securelist, 2026-08-26](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/) |

| Framework | Type | Key Features | 2025-2026 Evidence |
|-----------|------|--------------|--------------------|
| **Sliver** | Open source | Cross-platform Go implants; mTLS, HTTP(S) and DNS C2 | Top or near the top in every Kaspersky quarter above |
| **Havoc** | Open source | Demon agent; a 2025 campaign used SharePoint and the Microsoft Graph API as its C2 channel | FortiGuard ClickFix campaign ([The Hacker News, 2025-03-03](https://thehackernews.com/2025/03/hackers-use-clickfix-trick-to-deploy.html)); Kaspersky top tier |
| **AdaptixC2** | Open source (new) | Post-exploitation and adversary emulation framework built for penetration testers | Seen in attacks since May 2025, deployed alongside Fog ransomware ([Unit 42, 2025-09-10](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)); about 8% of 2025 ransomware intrusions ([GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape)) |
| **Mythic** | Open source | Web UI, multiple agents | Kaspersky Q4 2025 second place |
| **Metasploit** | Open source | Large exploit library, Meterpreter | Kaspersky Q1 2026 first place |
| **Covenant** | Open source | .NET C2 | Kaspersky Q1 2026; used by Sednit (APT28) per ESET (2026-05-28) |
| **Brute Ratel C4** | Commercial | EDR-evasion focus | Kaspersky top four in H1 2025 |
| **Cobalt Strike** | Commercial (often cracked) | Beacon; mature and heavily signatured | BEACON in about 2% of 2025 ransomware intrusions, down from 11% in 2024 ([GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape)) |
| **ARTEX** | Open source, agentic | Multi-agent, LLM-driven pentest and offensive C2 platform written in Go | Abused by extortion groups and suspected espionage operators; original repository taken down in October 2026 but forks circulate ([GTIG/Mandiant, 2026-10-30](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)) |

**Key Trends:**
- Free frameworks keep displacing Cobalt Strike: post-exploitation C2 frameworks appeared in about 15% of 2025 ransomware intrusions, while BEACON fell to about 2% ([GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape))
- C2 hidden in cloud services: Havoc over SharePoint and Graph (2025), APT41 over Google Calendar (2025)
- Tunnelers and remote management tools: CLOUDFLARED in 8% of ransomware intrusions (about 4% in 2024) and at least one RMM tool in about 24% (same GTIG source)
- Agentic frameworks act in bursts of roughly 2 to 25 seconds and leave noisy trial-and-error traces, which gives defenders a detection opportunity ([GTIG/Mandiant, 2026-10-30](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks))

## Ransomware Groups (2025-2026)

**Post-LockBit/ALPHV landscape:** after the 2024 disruptions of LockBit (Operation Cronos) and ALPHV/BlackCat (*historical*), RansomHub took over much of the affiliate market. RansomHub's infrastructure went dark on 2025-04-01 ([The Hacker News, April 2025](https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html)). DragonForce then posted as if the two groups were collaborating, which Sophos describes as more of a hostile takeover ([Sophos, May 2025](https://www.sophos.com/en-us/blog/dragonforce-targets-rivals-in-a-play-for-dominance)). Since then Qilin has led every quarter, with The Gentlemen close behind.

| Quarter | Victims on leak sites | Active groups | Top-10 share | Leaders | Source |
|---------|----------------------|---------------|--------------|---------|--------|
| Q1 2026 | 2,122 | 71 | 71.1% | Qilin 338, The Gentlemen 166, LockBit 163, Play 121, DragonForce 101 | [Check Point, 2026-05-11](https://research.checkpoint.com/2026/the-state-of-ransomware-q1-2026/) |
| Q2 2026 | 2,139 | 93 | 57.6% | Qilin 279, The Gentlemen 269; The Gentlemen led in June | [Check Point, 2026-08-13](https://research.checkpoint.com/2026/the-state-of-ransomware-q2-2026/) |
| Q3 2026 | 2,830 (record) | 117 brands with at least one claim | 49% | Qilin narrowly ahead of The Gentlemen; LockBit out of the top ten | [Check Point, 2026-11-18](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/) |

Sources disagree on details: the Q3 report gives 91 active groups for Q2, while the Q2 report gave 93. Other trackers count differently; for Q2 2026 [ReliaQuest](https://reliaquest.com/blog/threat-spotlight-ransomware-and-cyber-extortion-in-q2-2026/) put The Gentlemen ahead of Qilin, while Check Point had Qilin ahead.

| Group | Status (Nov 2026) | Notable Tactics | Sources |
|-------|-------------------|-----------------|---------|
| **Qilin** (Agenda) | Active; first in Check Point Q1 to Q3 2026 | Top ransomware brand against industrial organizations since March 2025 (198 industrial incidents in Q1 2026). An alleged core member was detained in Japan in May 2026 and handed to Germany in October 2026; the group kept operating | [Dragos, 2026-06-03](https://www.dragos.com/dragos-industrial-ransomware-analysis-q1-2026); [BleepingComputer, 2026-10-09](https://www.bleepingcomputer.com/news/security/germany-arrests-alleged-core-qilin-ransomware-member-after-extradition/) |
| **The Gentlemen** | Active; second, led Qilin in June and September 2026 | Operators were likely a Qilin affiliate (ArmCorp) first; active since at least July 2025; 90% affiliate payout; lockers in C and Go; GentleKiller EDR killer; edge-device exploitation | [Unit 42, 2026-07-10](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/); [Check Point, 2026-08-13](https://research.checkpoint.com/2026/the-state-of-ransomware-q2-2026/) |
| **DragonForce** | Active; white-label "cartel" | Affiliates run their own brands on its infrastructure; its ransomware was deployed in the April 2025 Marks & Spencer attack linked to Scattered Spider; Check Point calls the cartel "smaller than advertised" | [Sophos, May 2025](https://www.sophos.com/en-us/blog/dragonforce-targets-rivals-in-a-play-for-dominance); [BleepingComputer, July 2025](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/); [Check Point, 2026-05-11](https://research.checkpoint.com/2026/the-state-of-ransomware-q1-2026/) |
| **Akira** | Active | Linux variant that encrypts VMware ESXi virtual machines | [CISA AA24-109A, updated 2025-11-13](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) |
| **Play** | Active | Advisory refreshed with new TTPs and IOCs; 121 victims in Q1 2026 | [CISA AA23-352A, updated 2025-06-04](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) |
| **LockBit** | Declining | LockBit 5.0 (September 2025) for Windows, Linux and ESXi with random 16-character extensions; out of the top ten by Q3 2026 | [Trend Micro, 2025-09-25](https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html); [Check Point, 2026-11-18](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/) |
| **Cl0p** | Episodic mass exploitation | Oracle E-Business Suite zero-day CVE-2025-61882 exploited from about 2025-08-09, extortion emails from 2025-09-29 (GTIG notes FIN11 and CL0P overlaps but no formal attribution); drove Q1 2026 counts, then "nearly vanished" in Q2 | [GTIG, 2025-10-09](https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation); [Check Point blog, 2026-08-13](https://blog.checkpoint.com/security/ransomware-didnt-slow-down-in-q2-2026-it-just-spread-out/) |
| **RansomHub** | Defunct since April 2025 | Was the largest ALPHV successor in 2024 (*historical*) | [The Hacker News, April 2025](https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html) |
| **FunkSec** | Defunct; no new victims since March 2025 | AI-assisted tooling; free decryptor released July 2025 | [Check Point, January 2025](https://research.checkpoint.com/2025/funksec-alleged-top-ransomware-group-powered-by-ai/); [The Hacker News, July 2025](https://thehackernews.com/2025/07/funksec-ransomware-decryptor-released.html) |

**Key Tactics (from 2025 incident response data, [GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape), unless noted):**
- Data theft in 77% of analyzed ransomware intrusions (57% in 2024); Cl0p has moved mostly to data-theft-only extortion
- Virtualization targeting in about 43% of intrusions (29% in 2024): disabling ESXi `execInstalledOnly`, enabling SSH, deleting snapshots and backups before encryption
- Initial access through exploited VPNs and firewalls in about a third of intrusions and stolen credentials in 21%. Voice phishing drove several data-theft campaigns but was not seen in GTIG's ransomware cases, even though the 2025 Marks & Spencer intrusion began with social engineering ([BleepingComputer, July 2025](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/))
- EDR killers: signed-driver tools such as TERMINATOR and WATCHDOGKILLER in a handful of intrusions, and The Gentlemen's GentleKiller ([Unit 42, 2026-07-10](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/))
- Backup destruction: Veeam Backup & Replication targeted for credentials in about 10% of intrusions
- AI-assisted development: The Gentlemen's admin built the ransomware panel in about three days with AI coding assistants, according to leaked backend data ([Check Point blog, 2026-08-13](https://blog.checkpoint.com/security/ransomware-didnt-slow-down-in-q2-2026-it-just-spread-out/)); a low-skill actor sold AI-built ransomware for $400 to $1,200 ([Anthropic, 2025-08-27](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025))

**Financial Impact:**
- On-chain ransomware payments exceeded $820M in 2025, down 8% from $892M in 2024, while leak-site events rose about 50% to nearly 8,000 (Chainalysis data, [The Register, 2026-02-27](https://www.theregister.com/2026/02/27/ransomware_chainalysis/))
- Payment rate near 23%, a multi-year low ([Check Point, 2026-08-13](https://research.checkpoint.com/2026/the-state-of-ransomware-q2-2026/)); Chainalysis-based reporting gives about 28% for 2025, so sources differ
- Q3 2026: average payment fell 45% quarter over quarter to just over $1M, while the median rose 167% to $400,000 ([Check Point, 2026-11-18](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/))

## AI-Enhanced Attacks

### Documented Cases (2025-2026)

| Date | Case | What Happened | Source |
|------|------|---------------|--------|
| 2025-01-29 | State actors using Gemini | APT groups from more than 20 countries used Gemini, mostly from Iran and China; North Korean actors drafted cover letters for IT worker schemes; Google saw no "novel capabilities". Secondary coverage tallies 57+ APT and information-operations groups | [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai) |
| July 2025 | APT28 LAMEHUG | Python malware asked a hosted LLM for Windows commands at runtime (CERT-UA, medium confidence) | [The Hacker News](https://thehackernews.com/2025/07/cert-ua-discovers-lamehug-malware.html) |
| 2025-08-27 | Claude Code data extortion | At least 17 organizations in healthcare, emergency services, government and religious institutions; AI automated reconnaissance, credential harvesting and ransom notes; demands sometimes exceeded $500,000 | [Anthropic](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025) |
| August 2025 | PromptLock | ESET reported the "first AI-powered ransomware"; it turned out to be an NYU Tandon research prototype. Lesson: verify "first" claims | [ESET](https://www.eset.com/us/about/newsroom/research/eset-discovers-promptlock-the-first-ai-powered-ransomware/); [NYU Tandon](https://engineering.nyu.edu/news/ai-powered-ransomware-sparked-concern-was-nyus-work) |
| 2025-11-05 | "Just-in-time" AI malware | PROMPTFLUX, an experimental VBScript dropper that asks the Gemini API to rewrite its own code, and PROMPTSTEAL (APT28's LAMEHUG) in live operations | [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools) |
| 2025-11-13 | AI-orchestrated espionage | A Chinese state-sponsored group (Anthropic: high confidence), detected mid-September 2025, used Claude Code against about 30 targets; AI did 80-90% of the work with 4-6 human decision points; a small number of intrusions succeeded; the model sometimes hallucinated credentials | [Anthropic](https://www.anthropic.com/news/disrupting-AI-espionage) |
| 2026-08-13 | AI-built ransomware panel | The Gentlemen's admin built the panel in about three days with AI coding assistants; AI wrote software but did not run operations or pick targets | [Check Point](https://blog.checkpoint.com/security/ransomware-didnt-slow-down-in-q2-2026-it-just-spread-out/) |
| 2026-09-08 | GTIG AI Threat Tracker | UNC6508 (PRC nexus) ran local LLMs inside victim networks; UNC6780 (TeamPCP) backdoored MCP servers in open-source supply chains; an agent-enabled mass credential harvest took under six hours; infostealers now target AI developer configuration files | [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai) |
| September 2026 | Anthropic report (Dec 2025 to Aug 2026) | "From assistant to orchestrator": actors drove Claude through multi-agent frameworks for reconnaissance, exploitation and exfiltration, while humans set targets and reviewed stolen data | [Anthropic](https://www.anthropic.com/threat-intelligence-report-september-2026) |
| 2026-10-30 | ARTEX abuse | Financially motivated and suspected PRC-nexus actors used the ARTEX multi-agent framework; humans supplied stolen credentials and goals, the framework ran later stages | [GTIG/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks) |
| 2026-11-16 | Agentic threshold | CAIRN and PentAGI observed in the wild; an exposed staging server hosted `exploit_agent`, a framework that "fully automates vulnerability discovery and exploitation without a human in the loop for the first time"; stolen LLM access resold through "LLM Mixers" (LLMjacking) | [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold) |

### How Much Has AI Changed Attacks?

Sources disagree, and the disagreement is worth teaching:
- Google says agentic threat activity has crossed "a significant threshold", but notes the tools "trade stealth for velocity" and leave distinct traces ([GTIG, 2026-11-16](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold))
- Google and Mandiant call adversary use of autonomous frameworks "still in early stages", with "broad and noisy, but still successful campaigns" ([GTIG/Mandiant, 2026-10-30](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks))
- ESET saw APT groups use AI mainly to speed up malware development and build decoy websites, and "has not noticed AI substantially reshaping the APT landscape" ([ESET, 2026-10-28](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/))

### AI Security Frameworks and Regulation

- **OWASP Top 10 for LLM Applications 2026** (published 2026-08-03): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure (formerly System Prompt Leakage), LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling. Excessive Agency rose from sixth to third ([OWASP GenAI, 2026-08-03](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/))
- **OWASP Top 10 for Agentic Applications** (published 2025-12-09): ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents ([OWASP GenAI, 2025-12-09](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agent))
- **EU AI Act timing:** the Digital Omnibus on AI (Regulation (EU) 2026/1744, in force 2026-07-27) moved stand-alone (Annex III) high-risk obligations from 2026-08-02 to 2027-12-02 and Annex I product obligations to 2028-08-02; Article 50 transparency duties still applied from 2026-08-02. Based on law-firm summaries ([Lewis Silkin, 2026-07-27](https://www.lewissilkin.com/insights/2026/07/27/the-digital-omnibus-on-ai-enters-into-force-today); [Orrick, July 2026](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes)); the EUR-Lex text was not checked in this update

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
# FortiGuard ClickFix campaign, reported 2025-03-03
Network:
  - Microsoft Graph API calls to SharePoint from unexpected processes
  - SharePoint file staging (paired check-in and response files)
  - Token requests to the Microsoft identity platform from script interpreters
  - Unusual cloud service traffic patterns
```

### Agentic Offensive Frameworks (ARTEX, PentAGI)

```yaml
# GTIG/Mandiant, 2026-10-30
Behavior:
  - Bursts of commands within 2-25 seconds, then pauses
  - Rapid trial-and-error with many failed commands (hundreds of log events)
  - Fast control-plane API activity: permission testing, credential retrieval
  - Write-read-delete sequences and bulk object access in cloud storage
Network:
  - Egress to webhook services, OAST, tunneling and LLM platforms
  - Logins from unfamiliar ASNs, hosting providers or regions
```

## MITRE ATT&CK References

### Techniques Seen Most in 2025 Ransomware Intrusions

Figures come from Google's 2025 incident response data ([GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape)).

| Technique | ID | Evidence |
|-----------|-----|----------|
| Exploit Public-Facing Application | T1190 | About a third of intrusions, mostly VPNs and firewalls |
| Valid Accounts | T1078 | 21% of intrusions with a known initial access vector |
| Remote Desktop Protocol | T1021.001 | About 85% of intrusions |
| Exfiltration to Cloud Storage | T1567.002 | Rclone in about 28% of intrusions with data theft |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Registry changes to disable built-in antivirus; signed-driver EDR killers |
| Data Encrypted for Impact | T1486 | Virtualization infrastructure targeted in about 43% |
| Inhibit System Recovery | T1490 | Shadow copy deletion, backup server targeting |
| Phishing | T1566 | Initial access in APT campaigns above (Kimsuky, APT29 device code lures) |

### AI-Specific Techniques (MITRE ATLAS)

| Technique | Name |
|-----------|------|
| AML.T0051 | LLM Prompt Injection |
| AML.T0054 | LLM Jailbreak |
| AML.T0043 | Craft Adversarial Data |
| AML.T0044 | Full AI Model Access |
| AML.T0024 | Exfiltration via AI Inference API |
| AML.T0025 | Exfiltration via Cyber Means |
| AML.T0053 | AI Agent Tool Invocation |
| AML.T0070 | RAG Poisoning |
| AML.T0080 | AI Agent Context Poisoning |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation |

Names checked against [MITRE ATLAS](https://atlas.mitre.org/) in November 2026. The previous edition of this page listed AML.T0025 as "Exfiltration via ML API"; that name belongs to AML.T0024 (now "Exfiltration via AI Inference API").

## Recommended Defenses

### Against Nation-State APTs

1. **Assume breach mentality** - Focus on detection and response
2. **Zero trust architecture** - Verify continuously
3. **Edge device hardening** - VPNs, routers and firewalls are prime targets; replace end-of-life SOHO and edge devices ([covert-networks advisory, April 2026](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/defending-against-china-nexus-covert-networks-of-compromised-devices))
4. **Threat hunting** - Proactive search for pre-positioned access; track covert networks with NetFlow and hunting rather than static IP blocklists (same advisory)
5. **Keep OT off the internet** - Remove internet exposure of PLCs and HMIs ([CISA AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a))

### Against Ransomware

1. **Offline backups** - Air-gapped, tested regularly; protect backup consoles and their credentials
2. **Patch aggressively** - Especially VPNs, firewalls and other edge devices
3. **Network segmentation** - Limit lateral movement over RDP and SMB
4. **EDR with behavioral detection** - Signatures alone are not enough; alert on EDR tampering and vulnerable-driver loads
5. **Watch the hypervisor layer** - Alert on ESXi `execInstalledOnly` changes, new SSH enablement and snapshot deletion ([GTIG, 2026-03-16](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape))
6. **Detect exfiltration, not only encryption** - Most 2025 intrusions stole data; monitor Rclone, FTP/SFTP clients and bulk cloud uploads (same source)

### Against AI-Enhanced Attacks

1. **AI-based email filtering** - Fight AI with AI
2. **Out-of-band verification** - Phone/video for financial requests
3. **Code word systems** - Pre-established verification phrases
4. **Behavioral detection** - Focus on actions, not signatures; agentic tooling is fast and noisy
5. **Egress control** - Restrict and monitor traffic to LLM platforms, webhook and tunneling services ([GTIG/Mandiant, 2026-10-30](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks))
6. **Protect AI credentials** - Treat AI API keys and developer configuration files as secrets; LLMjacking and infostealers target them ([GTIG, 2026-11-16](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold))
7. **Constrain your own agents** - Treat retrieved content and tool output as untrusted and give tools least privilege (OWASP ASI01 and ASI02)

## Sources

Checked in November 2026. Dates are publication dates.

**Government**
- [CISA AA25-239A: Countering Chinese State-Sponsored Actors (2025-08-27)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [CISA AA24-038A: PRC State-Sponsored Actors Compromise US Critical Infrastructure (February 2024, historical baseline)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [Joint advisory (NCSC-UK, CISA, NSA, FBI and partners): Defending Against China-Nexus Covert Networks of Compromised Devices (April 2026)](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/defending-against-china-nexus-covert-networks-of-compromised-devices)
- [CISA AA26-097A: Iranian-Affiliated Cyber Actors Exploit PLCs (2026-04-07, updated 2026-07-22)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)
- [CISA AA24-109A: Akira Ransomware (updated 2025-11-13)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [CISA AA23-352A: Play Ransomware (updated 2025-06-04)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
- [FBI PSA I-022625-PSA: North Korea Responsible for Bybit Theft (2025-02-26)](https://www.ic3.gov/PSA/2025/PSA250226)
- [CISA: Nation-State Threats](https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors)

**Vendor and research reports**
- [GTIG: Agentic Threat Activity Crosses a Significant Threshold (2026-11-16)](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold)
- [GTIG/Mandiant: ARTEX and Friends, Agentic Offensive Frameworks (2026-10-30)](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- [GTIG AI Threat Tracker: From Prompting to Autonomy (2026-09-08)](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai)
- [GTIG: Ransomware TTPs in a Shifting Threat Landscape (2026-03-16)](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape)
- [GTIG: AI Threat Tracker, threat actor usage of AI tools (2025-11-05)](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools)
- [GTIG: Oracle E-Business Suite Zero-Day Exploitation (2025-10-09)](https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation)
- [GTIG: APT41 Innovative Tactics (May 2025)](https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics)
- [GTIG: Adversarial Misuse of Generative AI (2025-01-29)](https://cloud.google.com/blog/topics/threat-intelligence/adversarial-misuse-generative-ai)
- [Anthropic: Countering Misuse of AI, September 2026](https://www.anthropic.com/threat-intelligence-report-september-2026)
- [Anthropic: Disrupting AI Espionage (2025-11-13)](https://www.anthropic.com/news/disrupting-AI-espionage)
- [Anthropic: Threat Intelligence Report, August 2025 (2025-08-27)](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025)
- [Check Point Research: The State of Ransomware Q3 2026 (2026-11-18)](https://research.checkpoint.com/2026/the-state-of-ransomware-q3-2026/)
- [Check Point Research: The State of Ransomware Q2 2026 (2026-08-13)](https://research.checkpoint.com/2026/the-state-of-ransomware-q2-2026/)
- [Check Point blog: Ransomware Didn't Slow Down in Q2 2026 (2026-08-13)](https://blog.checkpoint.com/security/ransomware-didnt-slow-down-in-q2-2026-it-just-spread-out/)
- [Check Point Research: The State of Ransomware Q1 2026 (2026-05-11)](https://research.checkpoint.com/2026/the-state-of-ransomware-q1-2026/)
- [Check Point Research: FunkSec (January 2025)](https://research.checkpoint.com/2025/funksec-alleged-top-ransomware-group-powered-by-ai/)
- [ESET APT Activity Report Q2-Q3 2026 (2026-10-28)](https://www.eset.com/us/about/newsroom/research/eset-apt-report-iran-belarus-russia-cyber-activity/)
- [ESET APT Activity Report Q4 2025-Q1 2026, via Help Net Security (2026-05-28)](https://www.helpnetsecurity.com/2026/05/28/eset-apt-activity-report/)
- [ESET: PromptLock (August 2025)](https://www.eset.com/us/about/newsroom/research/eset-discovers-promptlock-the-first-ai-powered-ransomware/)
- [NYU Tandon: PromptLock was an academic prototype (2025)](https://engineering.nyu.edu/news/ai-powered-ransomware-sparked-concern-was-nyus-work)
- [Unit 42: The Gentlemen Ransomware (2026-07-10)](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/)
- [Unit 42: AdaptixC2 (2025-09-10)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [Dragos: Industrial Ransomware Analysis Q1 2026 (2026-06-03)](https://www.dragos.com/dragos-industrial-ransomware-analysis-q1-2026)
- [Trend Micro: LockBit 5.0 (2025-09-25)](https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html)
- [Sophos: DragonForce Targets Rivals (May 2025)](https://www.sophos.com/en-us/blog/dragonforce-targets-rivals-in-a-play-for-dominance)
- [AWS Security Blog: Amazon Disrupts APT29 Watering Hole Campaign (August 2025)](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)
- [ReliaQuest: Ransomware and Cyber Extortion in Q2 2026](https://reliaquest.com/blog/threat-spotlight-ransomware-and-cyber-extortion-in-q2-2026/)
- [Kaspersky Securelist: Vulnerabilities and Exploits Q2 2026 (2026-08-26)](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)
- [Kaspersky Securelist: Vulnerabilities and Exploits Q1 2026 (2026-05-07)](https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/)
- [Kaspersky Securelist: Vulnerabilities and Exploits Q4 2025 (2026-03-06)](https://securelist.com/vulnerabilities-and-exploits-in-q4-2025/119105/)
- [Kaspersky Securelist: Vulnerabilities and Exploits Q2 2025](https://securelist.com/vulnerabilities-and-exploits-in-q2-2025/117333/)

**Frameworks and regulation**
- [OWASP GenAI LLM Top 10 2026 (2026-08-03)](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP Top 10 for Agentic Applications (2025-12-09)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agent)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Council on Foreign Relations Cyber Operations Tracker](https://www.cfr.org/cyber-operations)
- [Lewis Silkin: The Digital Omnibus on AI Enters Into Force (2026-07-27)](https://www.lewissilkin.com/insights/2026/07/27/the-digital-omnibus-on-ai-enters-into-force-today)
- [Orrick: Digital Omnibus Finalizes 8 Compliance Changes (July 2026)](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes)

**News coverage**
- [The Hacker News: CERT-UA Discovers LAMEHUG (July 2025)](https://thehackernews.com/2025/07/cert-ua-discovers-lamehug-malware.html)
- [The Hacker News: RansomHub Went Dark (April 2025)](https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html)
- [The Hacker News: ClickFix Deploys Havoc via SharePoint (2025-03-03)](https://thehackernews.com/2025/03/hackers-use-clickfix-trick-to-deploy.html)
- [The Hacker News: FunkSec Decryptor Released (July 2025)](https://thehackernews.com/2025/07/funksec-ransomware-decryptor-released.html)
- [The Record: Kimsuky Fake Military IDs Made With ChatGPT (2025-09-15)](https://therecord.media/north-korea-kimsuky-hackers-phishing-fake-military-ids-chatgpt)
- [Fortune: North Korea Stole a Record Amount of Crypto (2025-12-18)](https://fortune.com/2025/12/18/north-korea-stole-a-record-amount-of-crypto/)
- [The Register: Ransomware Payments Cratered in 2025 (2026-02-27)](https://www.theregister.com/2026/02/27/ransomware_chainalysis/)
- [BleepingComputer: Four Arrested Over M&S, Co-op, Harrods Attacks (July 2025)](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/)
- [BleepingComputer: Germany Arrests Alleged Core Qilin Member (2026-10-09)](https://www.bleepingcomputer.com/news/security/germany-arrests-alleged-core-qilin-ransomware-member-after-extradition/)

**Historical references (kept for context)**
- [DFIR Report: Cobalt Strike to LockBit (2025-01-27)](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- [Flashpoint: RaaS Groups to Watch in 2025](https://flashpoint.io/blog/new-ransomware-as-a-service-raas-groups-to-watch-in-2025/)
- [Microsoft: Hunting for Sliver C2 (2022)](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)

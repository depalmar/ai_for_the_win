# Sources and Attribution

This document lists all external sources, tools, frameworks, and documentation used in creating the AI for the Win training program.

## Overview

**All content in this repository is based exclusively on publicly available information.** This project focuses on open-source tooling and publicly documented security concepts to ensure complete transparency and independence.

---

## Open-Source Security Tools

### SIEM and Data Platforms

- **[Elasticsearch](https://www.elastic.co/elasticsearch/)** - Open-source search and analytics engine
  - [EQL (Event Query Language)](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) - Public documentation
  - [ES|QL](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html) - Public documentation
  - License: Elastic License 2.0 and SSPL

- **[OpenSearch](https://opensearch.org/)** - Open-source search and analytics suite (Elasticsearch fork)
  - [OpenSearch Documentation](https://opensearch.org/docs/latest/)
  - License: Apache 2.0

### Endpoint Detection and Response (EDR)

- **[Wazuh](https://github.com/wazuh/wazuh)** - Open-source security platform for threat detection, incident response
  - [Wazuh Documentation](https://documentation.wazuh.com/)
  - License: GPL-2.0

- **[OSSEC](https://github.com/ossec/ossec-hids)** - Host-based intrusion detection system
  - [OSSEC Documentation](https://www.ossec.net/docs/)
  - License: GPL-2.0

### Detection Engineering

- **[Sigma](https://github.com/SigmaHQ/sigma)** - Generic signature format for SIEM systems
  - [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
  - License: LGPL-2.1

- **[YARA](https://github.com/VirusTotal/yara)** - Pattern matching tool for malware research
  - [YARA Documentation](https://yara.readthedocs.io/)
  - License: BSD-3-Clause

### Security Orchestration, Automation and Response (SOAR)

- **[Shuffle](https://github.com/Shuffle/Shuffle)** - Open-source SOAR platform
  - [Shuffle Documentation](https://shuffler.io/docs/)
  - License: AGPL-3.0

- **[TheHive](https://github.com/TheHive-Project/TheHive)** - Scalable security incident response platform
  - [TheHive Documentation](https://docs.thehive-project.org/)
  - License: AGPL-3.0

### Threat Intelligence and Frameworks

- **[MITRE ATT&CK](https://attack.mitre.org/)** - Knowledge base of adversary tactics and techniques
  - [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  - License: Public domain (Terms of Use apply)

- **[MITRE D3FEND](https://d3fend.mitre.org/)** - Knowledge graph of cybersecurity countermeasures
  - License: Public domain

- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Framework for managing cybersecurity risk
  - License: Public domain (U.S. government work)

### Malware Analysis

- **[pefile](https://github.com/erocarrera/pefile)** - Python module for working with Portable Executable files
  - License: MIT

- **[Volatility](https://github.com/volatilityfoundation/volatility3)** - Memory forensics framework
  - License: Volatility Software License

---

## Machine Learning and AI Frameworks

### Core ML Libraries

- **[scikit-learn](https://scikit-learn.org/)** - Machine learning library for Python
  - License: BSD-3-Clause

- **[PyTorch](https://pytorch.org/)** - Open-source machine learning framework
  - License: BSD-3-Clause

- **[Hugging Face Transformers](https://huggingface.co/docs/transformers/)** - State-of-the-art NLP models
  - License: Apache 2.0

### LLM and Agent Frameworks

- **[LangChain](https://python.langchain.com/)** - Framework for building LLM applications
  - [LangChain Documentation](https://python.langchain.com/docs/get_started/introduction)
  - License: MIT

- **[LangGraph](https://langchain-ai.github.io/langgraph/)** - Library for building stateful multi-actor applications
  - License: MIT

- **[LiteLLM](https://github.com/BerriAI/litellm)** - Unified interface for 100+ LLM providers
  - License: MIT

- **[Instructor](https://github.com/jxnl/instructor)** - Structured outputs from LLMs
  - License: MIT

### Vector Databases

- **[ChromaDB](https://www.trychroma.com/)** - Open-source embedding database
  - [ChromaDB Documentation](https://docs.trychroma.com/)
  - License: Apache 2.0

- **[sentence-transformers](https://www.sbert.net/)** - Framework for state-of-the-art sentence embeddings
  - License: Apache 2.0

---

## LLM Provider APIs

All LLM integrations use publicly documented APIs:

- **[Anthropic Claude API](https://docs.anthropic.com/)** - Public API documentation
  - [Claude Model Documentation](https://docs.anthropic.com/en/docs/models-overview)

- **[OpenAI API](https://platform.openai.com/docs/)** - Public API documentation
  - [GPT-4 Documentation](https://platform.openai.com/docs/models/gpt-4)

- **[Google Gemini API](https://ai.google.dev/docs)** - Public API documentation
  - [Gemini Models](https://ai.google.dev/models/gemini)

- **[Ollama](https://ollama.ai/)** - Local LLM runtime (no API key required)
  - License: MIT

---

## Web Frameworks and UI Tools

- **[Gradio](https://www.gradio.app/)** - Framework for building ML web interfaces
  - License: Apache 2.0

- **[Streamlit](https://streamlit.io/)** - Framework for data apps
  - License: Apache 2.0

- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern web framework for APIs
  - License: MIT

---

## Data Sources and Datasets

All datasets used in this project are either:

1. **Synthetic/Generated** - Created specifically for training purposes
2. **Public domain** - Freely available without restrictions
3. **Open-source licensed** - Used in accordance with license terms

Specific data sources are documented within individual lab directories.

---

## Educational Resources

This project draws on concepts from publicly available educational materials:

- Academic research papers (cited where used)
- Public conference presentations (DEF CON, Black Hat, RSA)
- Open-source project documentation
- Publicly available vendor blog posts and white papers
- Community-contributed tutorials and guides

**All references are to publicly available materials only.**

---

## Threat Intelligence Sources

Public sources cited by the threat intelligence content ([docs/guides/threat-landscape-2025.md](guides/threat-landscape-2025.md), Labs 30, 31, 37 and 40, and the threat table in [docs/LAB_DEPENDENCY_GRAPH.md](LAB_DEPENDENCY_GRAPH.md)). All are publicly available government advisories, vendor research blogs, standards pages or news reports. Last verified: November 2026. Dates are publication dates.

### Government Advisories

- [CISA AA25-239A: Countering Chinese State-Sponsored Actors (2025-08-27)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [CISA AA24-038A: PRC State-Sponsored Actors Compromise US Critical Infrastructure (February 2024)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [Joint advisory (NCSC-UK, CISA, NSA, FBI and partners): Defending Against China-Nexus Covert Networks of Compromised Devices (April 2026, ASD's ACSC page)](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/defending-against-china-nexus-covert-networks-of-compromised-devices)
- [CISA AA26-097A: Iranian-Affiliated Cyber Actors Exploit PLCs (2026-04-07, updated 2026-07-22)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a)
- [CISA AA24-109A: Akira Ransomware (updated 2025-11-13)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [CISA AA23-352A: Play Ransomware (updated 2025-06-04)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
- [CISA AA23-320A: Scattered Spider (updated 2025-07-29)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [CISA #StopRansomware](https://www.cisa.gov/stopransomware)
- [FBI PSA I-022625-PSA: North Korea Responsible for Bybit Theft (2025-02-26)](https://www.ic3.gov/PSA/2025/PSA250226)
- [HHS HC3 Threat Actor Profile: Scattered Spider (2024-10-24, AHA mirror)](https://www.aha.org/system/files/media/file/2024/10/hc3%20tlp%20clear%20threat%20actor%20profile%20scattered%20spider-10-24-2024.pdf)

### Vendor and Research Reports

- [Google Threat Intelligence Group: Agentic Threat Activity Crosses a Significant Threshold (2026-11-16)](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold)
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
- [NYU Tandon: PromptLock Was an Academic Prototype (2025)](https://engineering.nyu.edu/news/ai-powered-ransomware-sparked-concern-was-nyus-work)
- [Unit 42: The Gentlemen Ransomware (2026-07-10)](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/)
- [Unit 42: AdaptixC2 Post-Exploitation Framework (2025-09-10)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [Dragos: Industrial Ransomware Analysis Q1 2026 (2026-06-03)](https://www.dragos.com/dragos-industrial-ransomware-analysis-q1-2026)
- [Trend Micro: LockBit 5.0 Targets Windows, Linux and ESXi (2025-09-25)](https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html)
- [Sophos: DragonForce Targets Rivals in a Play for Dominance (May 2025)](https://www.sophos.com/en-us/blog/dragonforce-targets-rivals-in-a-play-for-dominance)
- [AWS Security Blog: Amazon Disrupts Watering Hole Campaign by Russia's APT29 (August 2025)](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)
- [ReliaQuest: Ransomware and Cyber Extortion in Q2 2026](https://reliaquest.com/blog/threat-spotlight-ransomware-and-cyber-extortion-in-q2-2026/)
- [Kaspersky Securelist: Vulnerabilities and Exploits in Q2 2026 (2026-08-26)](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)
- [Kaspersky Securelist: Vulnerabilities and Exploits in Q1 2026 (2026-05-07)](https://securelist.com/vulnerabilities-and-exploits-in-q1-2026/119733/)
- [Kaspersky Securelist: Vulnerabilities and Exploits in Q4 2025 (2026-03-06)](https://securelist.com/vulnerabilities-and-exploits-in-q4-2025/119105/)
- [Kaspersky Securelist: Vulnerabilities and Exploits in Q2 2025](https://securelist.com/vulnerabilities-and-exploits-in-q2-2025/117333/)

### Frameworks, Standards and Regulation

- [OWASP GenAI LLM Top 10 2026 (2026-08-03)](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP Top 10 for Agentic Applications (2025-12-09)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agent)
- [MITRE ATLAS](https://atlas.mitre.org/) - Adversarial Threat Landscape for AI Systems
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [Council on Foreign Relations Cyber Operations Tracker](https://www.cfr.org/cyber-operations)
- [Lewis Silkin: The Digital Omnibus on AI Enters Into Force (2026-07-27)](https://www.lewissilkin.com/insights/2026/07/27/the-digital-omnibus-on-ai-enters-into-force-today)
- [Orrick: EU AI Act Update, Digital Omnibus Finalizes 8 Compliance Changes (July 2026)](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes)

### News Coverage

- [The Hacker News: CERT-UA Discovers LAMEHUG Malware (July 2025)](https://thehackernews.com/2025/07/cert-ua-discovers-lamehug-malware.html)
- [The Hacker News: RansomHub Went Dark April 1 (April 2025)](https://thehackernews.com/2025/04/ransomhub-went-dark-april-1-affiliates.html)
- [The Hacker News: ClickFix Trick Deploys Havoc via SharePoint (2025-03-03)](https://thehackernews.com/2025/03/hackers-use-clickfix-trick-to-deploy.html)
- [The Hacker News: FunkSec Ransomware Decryptor Released (July 2025)](https://thehackernews.com/2025/07/funksec-ransomware-decryptor-released.html)
- [The Record: Kimsuky Fake Military IDs Made With ChatGPT (2025-09-15)](https://therecord.media/north-korea-kimsuky-hackers-phishing-fake-military-ids-chatgpt)
- [Fortune: North Korea Stole a Record Amount of Crypto (2025-12-18)](https://fortune.com/2025/12/18/north-korea-stole-a-record-amount-of-crypto/)
- [The Register: Ransomware Payments Cratered in 2025 (2026-02-27)](https://www.theregister.com/2026/02/27/ransomware_chainalysis/)
- [HIPAA Journal: Change Healthcare Cyberattack (updated August 2025)](https://www.hipaajournal.com/change-healthcare-responding-to-cyberattack/)
- [BleepingComputer: Four Arrested in UK Over M&S, Co-op, Harrods Cyberattacks (July 2025)](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/)
- [BleepingComputer: Germany Arrests Alleged Core Qilin Ransomware Member (2026-10-09)](https://www.bleepingcomputer.com/news/security/germany-arrests-alleged-core-qilin-ransomware-member-after-extradition/)

---

## Commercial Security Platforms

### Current Status: Open-Source Only

This project **currently focuses exclusively on open-source security tooling** (Elasticsearch, OpenSearch, Sigma, YARA) to ensure complete independence from proprietary vendor implementations.

### Future Considerations

Commercial security platform references may be added in the future **only if**:

1. ✅ Based entirely on **publicly available vendor documentation**
2. ✅ Cleared by appropriate **legal review**
3. ✅ Clearly **documented with public sources**
4. ✅ Used for **educational comparison purposes only**
5. ✅ Does **not** include proprietary implementations, architectures, or trade secrets

Any future additions will be documented in this file with:
- Public documentation URLs
- Specific features/capabilities referenced
- Date of last verification
- Legal clearance confirmation

---

## Verification and Transparency

### How to Verify Public Availability

All sources listed above can be independently verified:

1. **Official documentation links** - Direct URLs to public vendor docs
2. **Open-source repositories** - Publicly accessible GitHub/GitLab projects
3. **License information** - Clearly stated and verifiable
4. **Archive availability** - Most sources archived via Internet Archive

### Updates and Maintenance

This document is updated whenever:
- New tools or frameworks are introduced
- External dependencies change
- Documentation sources are updated
- Commercial platform references are considered

---

## Contact

If you have questions about the sources used in this project or believe any content may not be properly attributed, please [open an issue](https://github.com/depalmar/ai_for_the_win/issues) or contact the author.

---

*Last updated: November 2026*

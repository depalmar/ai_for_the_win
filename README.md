<p align="center">
  <img src="docs/assets/images/logo.png" alt="AI for the Win Logo" width="150" height="150">
</p>

# AI for the Win

### Build AI-Powered Security Tools | Hands-On Learning

[![CI](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml/badge.svg)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/depalmar/ai_for_the_win/badge)](https://scorecard.dev/viewer/?uri=github.com/depalmar/ai_for_the_win)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Dual](https://img.shields.io/badge/License-Dual%20(MIT%20%2B%20CC%20BY--NC--SA)-blue.svg)](./LICENSE)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](./Dockerfile)

> **Disclaimer**: This is a personal educational project created and maintained on personal time. It is not affiliated with, endorsed by, or sponsored by any employer, organization, or vendor. All tool and platform references are for educational purposes only and do not constitute endorsement or recommendation. The author's views are their own.

> **Responsible Use:** This material is for defensive security education only. Do not use techniques described here for unauthorized access or attacks. See [RESPONSIBLE_USE.md](./RESPONSIBLE_USE.md).

A hands-on training program for security practitioners who want to build AI-powered tools for threat detection, incident response, and security automation. **40+ labs** (including 8 intro labs and 12 bridge labs), **4 capstone projects**, **15 CTF challenges**. Includes **sample datasets** and **solution walkthroughs**. Designed for **vibe coding** with AI assistants like Cursor, Claude Code, and Copilot.

---

## Resources

| Resource                                                          | Description                      |
| ----------------------------------------------------------------- | -------------------------------- |
| [Environment Setup](./labs/lab00-environment-setup/)              | First-time setup                 |
| [API Keys Guide](./docs/guides/api-keys-guide.md)                 | Get API keys, manage costs       |
| [Troubleshooting](./docs/guides/troubleshooting-guide.md)         | Fix common issues                |
| [Lab Walkthroughs](./docs/walkthroughs/)                          | Step-by-step solutions           |
| [Role-Based Paths](./resources/role-based-learning-paths.md)      | SOC, IR, hunting, red team paths |
| [Security-to-AI Glossary](./resources/security-to-ai-glossary.md) | AI terms for security folks      |
| [All Guides](./docs/guides/)                                      | 28 guides: tools, APIs, advanced |

**Issues?** Open a [GitHub issue](https://github.com/depalmar/ai_for_the_win/issues)

---

## Get Started in 5 Minutes

### Option 1: Zero Setup (Google Colab)

No installation needed — run labs directly in your browser:

[![Open Lab 01 in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb) [![Open Lab 04 in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab04_llm_log_analysis.ipynb)

> All notebooks are in the [`notebooks/`](./notebooks/) folder — open any `.ipynb` file in Colab.

### Option 2: Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# 2. Install Python dependencies
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# 3. Start with Lab 00 (environment setup) - NO API KEY NEEDED!
cd labs/lab00-environment-setup
# Read the lab instructions (or just open README.md in your editor)
cat README.md      # Linux/Mac
type README.md     # Windows

# 4. Work through intro labs: 00a → 00b → 00c → 00d → 01
# Or jump straight to Lab 01 if you know Python/ML basics
cd ../lab01-phishing-classifier
python solution/main.py
```

### Ready for LLM-Powered Labs? (Labs 04+)

```bash
# Configure API key (choose ONE provider)
cp .env.example .env
echo "ANTHROPIC_API_KEY=your-key-here" >> .env  # Get from console.anthropic.com
# OR use OpenAI/Google - see .env.example for all options

# Verify your setup
python scripts/verify_setup.py

# Run your first LLM lab
cd labs/lab04-llm-log-analysis
python solution/main.py
```

> 📖 **New to Python or ML?** Start with Labs 00a-00b-01-02-03 (no API keys required!)
> 📖 **Know ML, want LLMs?** Jump to Lab 04 and get an API key first
> 📖 **Need help?** Read [GETTING_STARTED.md](./docs/GETTING_STARTED.md) for detailed setup
> 📖 **Having issues?** See [Troubleshooting Guide](./docs/guides/troubleshooting-guide.md)
> 📖 **Lost in the docs?** See [Documentation Guide](./docs/documentation-guide.md) for navigation

---

## What It Looks Like

### The AI Defense Pipeline

This architecture (from **Lab 09**) shows how we combine cheap, fast ML models with smart, reasoning LLMs:

```
Logs & Events → [ML Filter: Fast & Cheap] → 99% Benign → Discard
                         ↓
                   Suspicious (1%)
                         ↓
               [LLM Analysis: Reasoning] → Alert + Report
```

> **The key insight**: ML handles volume (cheap, fast), LLMs handle complexity (smart, expensive). Lab 09 builds this end-to-end.

**Lab 01 - Phishing Classifier** catches what rules miss:

```text
$ python labs/lab01-phishing-classifier/solution/main.py

[+] Training on 1,000 labeled emails...
[+] Model: Random Forest + TF-IDF (847 features)
[+] Accuracy: 96.2% | Precision: 94.1% | Recall: 97.8%

📬 Scanning inbox (4 new emails)...

  From: security@amaz0n-verify.com
  Subj: "Your account will be suspended in 24 hours"
  ──→ 🚨 PHISHING (98.2%)  [urgency + spoofed domain]

  From: sarah.jones@company.com
  Subj: "Q3 budget report attached"
  ──→ ✅ LEGIT (94.6%)

  From: helpdesk@paypa1.com
  Subj: "Click here to verify your identity"
  ──→ 🚨 PHISHING (96.7%)  [link mismatch + typosquat]

  From: it-dept@company.com
  Subj: "Password expires in 7 days - reset here"
  ──→ ⚠️  SUSPICIOUS (67.3%)  [needs review]

📊 Top features that caught phishing:
   urgency_words: +0.34  (suspend, verify, immediately)
   url_mismatch:  +0.28  (display ≠ actual link)
   domain_spoof:  +0.22  (amaz0n, paypa1)
```

**Lab 04 - LLM Log Analysis** finds attacks in noise:

```text
┌──────────────────────────────────────────────────────┐
│ Lab 04: LLM-Powered Security Log Analysis - SOLUTION │
└──────────────────────────────────────────────────────┘
Security Log Analysis Pipeline

Step 1: Initializing LLM...
  LLM initialized: READY
Step 2: Parsing log entries...
  Parsing entry 1/5...
  Parsing entry 2/5...
  Parsing entry 3/5...
  Parsing entry 4/5...
  Parsing entry 5/5...
  Parsed 5 log entries
Step 3: Analyzing for threats...
  Found 2 threats
  Severity: 8/10
Step 4: Extracting IOCs...
  Extracted 12 IOCs
Step 5: Generating incident report...
  Report generated

============================================================
INCIDENT REPORT
============================================================

┌──────────────────────────────────────────────────────────────────────────────┐
│                           Security Incident Report                           │
└──────────────────────────────────────────────────────────────────────────────┘


                               Executive Summary

A critical security incident involving multi-stage attack behavior was detected
on WORKSTATION01 involving user 'jsmith'. The attack progression includes
initial PowerShell execution downloading a payload from a suspicious external
domain, followed by system discovery commands, and culminating in persistence
establishment via Registry Run keys and Scheduled Tasks. The presence of known
malicious domains and persistence mechanisms indicates a high-risk compromise
requiring immediate containment.


                                    Timeline

 1 2025-01-15 03:22:10 - PowerShell script block execution: Downloaded content
   from hxxp://evil-c2[.]com/payload.ps1 using Net.WebClient.
 2 2025-01-15 03:22:15 - Discovery commands executed (whoami, hostname,
   ipconfig) via cmd.exe.
 3 2025-01-15 03:22:18 - Network connection detected from powershell.exe to
   evil-c2[.]com (185.143.223.47) over port 443.
 4 2025-01-15 03:23:00 - Persistence established: reg.exe added malware.exe to
   HKCU Run keys.
 5 2025-01-15 03:25:00 - Persistence established: Scheduled Task SecurityUpdate
   created pointing to malware.exe.


                                Technical Analysis

The attacker utilized a "Living off the Land" strategy, leveraging built-in
Windows tools (PowerShell, cmd.exe, reg.exe) to evade initial detection.

 • Initial Access/Execution: A PowerShell download cradle (New-Object
   System.Net.WebClient) retrieved a remote script.
 • C2/Exfiltration: Encrypted traffic (port 443) was observed to evil-c2[.]com.
 • Persistence: Dual persistence mechanisms were created:
    • Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    • Scheduled Task: \Microsoft\Windows\Maintenance\SecurityUpdate
      (Masquerading as a legitimate update task).


                                Attribution Analysis

High Confidence (Attributed to FIN7/Carbanak) based on:
 • Tooling: Use of modified `certutil` and `DNS-based C2` matches known campaigns.
 • Infrastructure: `evil-c2[.]com` has historical associations with FIN7 (Mock Intel).
 • TTP Overlap: The specific sequence of PowerShell obfuscation -> Registry Run Key
   is a signature behavior pattern.


                              MITRE ATT&CK Mapping


  Technique ID   Technique Name                  Evidence
 ──────────────────────────────────────────────────────────────────────────────
  T1059.001      Command and Scripting           powershell.exe,
                 Interpreter: PowerShell         DownloadString, IEX
  T1082          System Information Discovery    whoami, hostname, ipconfig
  T1547.001      Boot or Logon Autostart         reg add ...
                 Execution: Registry Run Keys    CurrentVersion\Run
  T1053.005      Scheduled Task/Job: Scheduled   TaskName: ...SecurityUpdate
                 Task
  T1105          Ingress Tool Transfer           DownloadString('http://evil-…
```

---

## Interactive Lab Navigator

**Click any lab to explore** — Your learning journey from setup to expert:

<table style="width:100%; table-layout:fixed;">
<tr>
<td width="20%" align="center"><a href="./labs/lab00-environment-setup/"><img src="https://img.shields.io/badge/00-Setup-gray?style=for-the-badge" alt="Lab 00"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00a-python-security-fundamentals/"><img src="https://img.shields.io/badge/00a-Python-gray?style=for-the-badge" alt="Lab 00a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00b-ml-concepts-primer/"><img src="https://img.shields.io/badge/00b-ML_Intro-gray?style=for-the-badge" alt="Lab 00b"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00c-intro-prompt-engineering/"><img src="https://img.shields.io/badge/00c-Prompts-gray?style=for-the-badge" alt="Lab 00c"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00d-ai-in-security-operations/"><img src="https://img.shields.io/badge/00d-AI_in_SOC-gray?style=for-the-badge" alt="Lab 00d"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab00e-visualization-stats/"><img src="https://img.shields.io/badge/00e-Stats-gray?style=for-the-badge" alt="Lab 00e"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00f-hello-world-ml/"><img src="https://img.shields.io/badge/00f-HelloML-gray?style=for-the-badge" alt="Lab 00f"/></a></td>
<td width="20%" align="center"><a href="./labs/lab00g-working-with-apis/"><img src="https://img.shields.io/badge/00g-APIs-gray?style=for-the-badge" alt="Lab 00g"/></a></td>
<td width="20%" align="center"></td>
<td width="20%" align="center"></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab01-phishing-classifier/"><img src="https://img.shields.io/badge/01-Phishing-10a981?style=for-the-badge" alt="Lab 01"/></a></td>
<td width="20%" align="center"><a href="./labs/lab02-malware-clustering/"><img src="https://img.shields.io/badge/02-Malware-10a981?style=for-the-badge" alt="Lab 02"/></a></td>
<td width="20%" align="center"><a href="./labs/lab03-anomaly-detection/"><img src="https://img.shields.io/badge/03-Anomaly-10a981?style=for-the-badge" alt="Lab 03"/></a></td>
<td width="20%" align="center"><a href="./labs/lab03b-ml-vs-llm/"><img src="https://img.shields.io/badge/03b-ML_vs_LLM-10a981?style=for-the-badge" alt="Lab 03b"/></a></td>
<td width="20%" align="center"></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab04-llm-log-analysis/"><img src="https://img.shields.io/badge/04-Logs-6366f1?style=for-the-badge" alt="Lab 04"/></a></td>
<td width="20%" align="center"><a href="./labs/lab04b-first-ai-agent/"><img src="https://img.shields.io/badge/04b-Agent-6366f1?style=for-the-badge" alt="Lab 04b"/></a></td>
<td width="20%" align="center"><a href="./labs/lab05-threat-intel-agent/"><img src="https://img.shields.io/badge/05-Intel-6366f1?style=for-the-badge" alt="Lab 05"/></a></td>
<td width="20%" align="center"><a href="./labs/lab06a-embeddings-vectors/"><img src="https://img.shields.io/badge/06a-Vectors-6366f1?style=for-the-badge" alt="Lab 06a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab06-security-rag/"><img src="https://img.shields.io/badge/06-RAG-6366f1?style=for-the-badge" alt="Lab 06"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab07a-binary-basics/"><img src="https://img.shields.io/badge/07a-Binary-6366f1?style=for-the-badge" alt="Lab 07a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab07-yara-generator/"><img src="https://img.shields.io/badge/07-YARA-6366f1?style=for-the-badge" alt="Lab 07"/></a></td>
<td width="20%" align="center"><a href="./labs/lab07b-sigma-fundamentals/"><img src="https://img.shields.io/badge/07b-Sigma-6366f1?style=for-the-badge" alt="Lab 07b"/></a></td>
<td width="20%" align="center"><a href="./labs/lab08-vuln-scanner-ai/"><img src="https://img.shields.io/badge/08-Vuln-f59e0b?style=for-the-badge" alt="Lab 08"/></a></td>
<td width="20%" align="center"><a href="./labs/lab09-detection-pipeline/"><img src="https://img.shields.io/badge/09-Pipeline-f59e0b?style=for-the-badge" alt="Lab 09"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab09b-monitoring-ai-systems/"><img src="https://img.shields.io/badge/09b-Monitor-f59e0b?style=for-the-badge" alt="Lab 09b"/></a></td>
<td width="20%" align="center"><a href="./labs/lab10a-dfir-fundamentals/"><img src="https://img.shields.io/badge/10a-DFIR-f59e0b?style=for-the-badge" alt="Lab 10a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab10-ir-copilot/"><img src="https://img.shields.io/badge/10-IR_Bot-f59e0b?style=for-the-badge" alt="Lab 10"/></a></td>
<td width="20%" align="center"><a href="./labs/lab11a-ransomware-fundamentals/"><img src="https://img.shields.io/badge/11a-RansomFund-ef4444?style=for-the-badge" alt="Lab 11a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab11-ransomware-detection/"><img src="https://img.shields.io/badge/11-Ransom-ef4444?style=for-the-badge" alt="Lab 11"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab12-ransomware-simulation/"><img src="https://img.shields.io/badge/12-Purple-ef4444?style=for-the-badge" alt="Lab 12"/></a></td>
<td width="20%" align="center"><a href="./labs/lab13-memory-forensics-ai/"><img src="https://img.shields.io/badge/13-Memory-ef4444?style=for-the-badge" alt="Lab 13"/></a></td>
<td width="20%" align="center"><a href="./labs/lab14-c2-traffic-analysis/"><img src="https://img.shields.io/badge/14-C2-ef4444?style=for-the-badge" alt="Lab 14"/></a></td>
<td width="20%" align="center"><a href="./labs/lab15-lateral-movement-detection/"><img src="https://img.shields.io/badge/15-Lateral-ef4444?style=for-the-badge" alt="Lab 15"/></a></td>
<td width="20%" align="center"><a href="./labs/lab16-threat-actor-profiling/"><img src="https://img.shields.io/badge/16-Actors-ef4444?style=for-the-badge" alt="Lab 16"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab16b-ai-powered-threat-actors/"><img src="https://img.shields.io/badge/16b-AI_Threat-ef4444?style=for-the-badge" alt="Lab 16b"/></a></td>
<td width="20%" align="center"><a href="./labs/lab17a-ml-security-intro/"><img src="https://img.shields.io/badge/17a-MLSec-ef4444?style=for-the-badge" alt="Lab 17a"/></a></td>
<td width="20%" align="center"><a href="./labs/lab17-adversarial-ml/"><img src="https://img.shields.io/badge/17-AdvML-ef4444?style=for-the-badge" alt="Lab 17"/></a></td>
<td width="20%" align="center"><a href="./labs/lab18-fine-tuning-security/"><img src="https://img.shields.io/badge/18-Tuning-ef4444?style=for-the-badge" alt="Lab 18"/></a></td>
<td width="20%" align="center"><a href="./labs/lab19a-cloud-security-fundamentals/"><img src="https://img.shields.io/badge/19a-CloudFund-ef4444?style=for-the-badge" alt="Lab 19a"/></a></td>
</tr>
<tr>
<td width="20%" align="center"><a href="./labs/lab19-cloud-security-ai/"><img src="https://img.shields.io/badge/19-Cloud-ef4444?style=for-the-badge" alt="Lab 19"/></a></td>
<td width="20%" align="center"><a href="./labs/lab20-llm-red-teaming/"><img src="https://img.shields.io/badge/20-RedTeam-ef4444?style=for-the-badge" alt="Lab 20"/></a></td>
<td width="20%" align="center"><a href="./labs/lab20b-purple-team-ai/"><img src="https://img.shields.io/badge/20b-PurpleAI-ef4444?style=for-the-badge" alt="Lab 20b"/></a></td>
<td width="20%" align="center"></td>
<td width="20%" align="center"></td>
</tr>
<tr>
<td align="center" colspan="5"><strong>Legend:</strong> ⚪ Intro (Free) | 🟢 ML (Free) | 🟣 LLM | 🟠 Advanced | 🔴 Expert DFIR</td>
</tr>
</table>

---

## Learning Paths

### Recommended Paths by Background

| Your Background                   | Start   | Path                          |
| --------------------------------- | ------- | ----------------------------- |
| **Complete beginner** (no Python) | Lab 00a | 00a → 00b → 01 → 02 → 03 → 04 |
| **Know Python**, new to ML        | Lab 00b | 00b → 01 → 02 → 03 → 04 → 05  |
| **Know Python & ML**, new to LLMs | Lab 04  | 04 → 06 → 05 → 07-10          |
| **Blue Team / SOC**               | Lab 01  | 01 → 03 → 04 → 11 → 13        |
| **Security engineer**             | Lab 01  | 01 → 03 → 04 → 08 → 09 → 10   |

**💡 Pro Tip**: Labs 01-03 require NO API keys - perfect for learning ML foundations cost-free!

📚 **Want complete paths including DFIR labs (11-16) and expert labs (17-20)?** See [Role-Based Learning Paths](./resources/role-based-learning-paths.md)

---

## What You'll Build

### Labs Overview

| Lab     | Project                         | What You'll Learn                                                                                         |
| ------- | ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **00a** | **Python for Security**         | Variables, files, APIs, regex, security-focused Python basics                                             |
| **00b** | **ML Concepts Primer**          | Supervised/unsupervised learning, features, training, evaluation metrics                                  |
| **00c** | **Intro to Prompt Engineering** | LLM basics with free playgrounds, prompting fundamentals, hallucination detection, security templates     |
| **00d** | **AI in Security Operations**   | Where AI fits in SOC, human-in-the-loop, AI as attack surface, compliance considerations                  |
| **00e** | **Visualization & Statistics**  | Matplotlib, Seaborn, Plotly for security dashboards, statistical analysis of security events              |
| **00f** | **Hello World ML**              | Your first ML model end-to-end, simple classification, understanding the ML workflow                      |
| **00g** | **Working with APIs**           | REST APIs, authentication, rate limiting, integrating threat intel APIs                                   |
| **01**  | **Phishing Classifier**         | Text preprocessing, TF-IDF vectorization, Random Forest classification, model evaluation metrics          |
| **02**  | **Malware Clusterer**           | Feature extraction from binaries, K-Means & DBSCAN clustering, dimensionality reduction, cluster analysis |
| **03**  | **Anomaly Detector**            | Statistical baselines, Isolation Forest, Local Outlier Factor, threshold optimization for security        |
| **03b** | **ML vs LLM Decision Lab**      | When to use ML vs LLM, cost/accuracy tradeoffs, hybrid approaches for security tasks                      |
| **04**  | **Log Analyzer**                | Prompt engineering for security, structured output parsing, IOC extraction, LLM-powered analysis          |
| **04b** | **Your First AI Agent**         | Building a simple ReAct agent from scratch, tool calling basics, agent loops                              |
| **05**  | **Threat Intel Agent**          | ReAct pattern implementation, tool use with LangChain, autonomous investigation workflows                 |
| **06a** | **Embeddings & Vectors**        | Understanding embeddings, similarity search, vector databases, semantic search for security               |
| **06**  | **Security RAG**                | Document chunking, vector embeddings, ChromaDB, retrieval-augmented generation for Q&A                    |
| **07a** | **Binary Analysis Basics**      | PE file structure, imports/exports, entropy analysis, static analysis fundamentals                        |
| **07**  | **YARA Generator**              | Static malware analysis, pattern extraction, AI-assisted rule generation, rule validation                 |
| **07b** | **Sigma Fundamentals**          | Sigma rule syntax, log-based detection, SIEM query conversion, LLM rule generation                        |
| **08**  | **Vuln Prioritizer**            | CVSS scoring, risk-based prioritization, remediation planning with LLMs                                   |
| **09**  | **Detection Pipeline**          | Multi-stage architectures, ML filtering, LLM enrichment, alert correlation                                |
| **09b** | **Monitoring AI Systems**       | Observability for AI, logging LLM calls, cost tracking, performance monitoring                            |
| **10a** | **DFIR Fundamentals**           | Digital forensics basics, evidence collection, timeline analysis, artifact interpretation                 |
| **10**  | **IR Copilot**                  | Conversational agents, state management, playbook execution, incident documentation                       |
| **11a** | **Ransomware Fundamentals**     | Ransomware evolution, families, attack lifecycle, indicators, recovery decisions                          |
| **11**  | **Ransomware Detector**         | Entropy analysis, behavioral detection, ransom note IOC extraction, response automation                   |
| **12**  | **Purple Team Sim**             | Safe adversary emulation, detection validation, gap analysis, purple team exercises                       |
| **13**  | **Memory Forensics AI**         | Volatility3 integration, process injection detection, credential dumping, LLM artifact analysis           |
| **14**  | **C2 Traffic Analysis**         | Beaconing detection, DNS tunneling, encrypted C2, JA3 fingerprinting, traffic classification              |
| **15**  | **Lateral Movement Detection**  | Auth anomaly detection, remote execution (PsExec/WMI/WinRM), graph-based attack paths                     |
| **16**  | **Threat Actor Profiling**      | TTP extraction, campaign clustering, malware attribution, actor profile generation                        |
| **16b** | **AI-Powered Threat Actors**    | How adversaries use AI, deepfakes, AI-generated phishing, detecting AI-assisted attacks                   |
| **17a** | **ML Security Foundations**     | Threats to ML systems, data poisoning basics, model security considerations                               |
| **17**  | **Adversarial ML**              | Evasion attacks, poisoning attacks, adversarial training, robust ML defenses                              |
| **18**  | **Fine-Tuning for Security**    | Custom embeddings, LoRA fine-tuning, security-specific models, deployment                                 |
| **19a** | **Cloud Security Fundamentals** | Cloud security basics, shared responsibility, IAM, cloud-native threats                                   |
| **19**  | **Cloud Security AI**           | AWS/Azure/GCP security, CloudTrail analysis, multi-cloud threat detection                                 |
| **20**  | **LLM Red Teaming**             | Prompt injection, jailbreaking defenses, guardrails, LLM security testing                                 |
| **20b** | **Purple Team AI**              | AI-assisted red/blue team exercises, automated attack simulation, detection validation                    |

**💰 Cost Note**: Labs 01-03 are FREE (no API keys). LLM labs (04+) cost ~$5-25 total using free tiers from Anthropic, Google AI Studio, or OpenAI.

### When to Use ML vs LLM

| Security Task          | Best Approach | Why                                        |
| ---------------------- | ------------- | ------------------------------------------ |
| Malware classification | **ML**        | Fast, interpretable, structured features   |
| Log anomaly detection  | **ML**        | High volume, real-time capable             |
| Threat report analysis | **LLM**       | Natural language understanding             |
| IOC extraction         | **LLM**       | Flexible parsing of unstructured text      |
| Phishing detection     | **Hybrid**    | ML for volume, LLM for sophisticated cases |
| Detection pipeline     | **Hybrid**    | ML filters 90%, LLM analyzes 10%           |

> 📖 **Full comparison**: See [ML vs LLM Decision Framework](./docs/learning-guide.md#choosing-the-right-tool-ml-vs-llm) for detailed guidance, cost analysis, and hybrid architecture patterns.

---

## Repository Structure

```
ai_for_the_win/
├── labs/               # 40+ hands-on labs (00-20 + bridge labs)
├── notebooks/          # Jupyter notebooks (Colab-ready)
├── capstone-projects/  # 4 comprehensive projects
├── ctf-challenges/     # 15 CTF challenges
├── data/               # Sample datasets & threat actor TTPs
├── templates/          # Reusable agents, prompts, integrations
├── resources/          # Tools guide, glossary, learning paths
├── docs/               # Guides & walkthroughs
└── tests/              # Test suite (839 tests)
```

---

## Technology Stack

| Category           | Tools                                            |
| ------------------ | ------------------------------------------------ |
| **LLM Providers**  | Claude 4.5, GPT-5, Gemini 3.0, Ollama (local)    |
| **LLM Frameworks** | LangChain, LangGraph, LiteLLM, Instructor        |
| **ML/AI**          | scikit-learn, PyTorch, Hugging Face Transformers |
| **Vector DB**      | ChromaDB, sentence-transformers                  |
| **Security**       | YARA, Sigma, MITRE ATT&CK, pefile                |
| **Web/UI**         | FastAPI, Gradio, Streamlit                       |
| **Vibe Coding**    | Cursor, Claude Code, GitHub Copilot, Windsurf    |
| **Development**    | Python 3.10+, pytest, Docker, GitHub Actions     |

---

## Capstone Projects

Choose one to demonstrate mastery:

| Project                          | Difficulty   | Focus                     |
| -------------------------------- | ------------ | ------------------------- |
| **Security Analyst Copilot**     | Advanced     | LLM agents, IR automation |
| **Automated Threat Hunter**      | Advanced     | ML detection, pipelines   |
| **Malware Analysis Assistant**   | Intermediate | Static analysis, YARA     |
| **Vulnerability Intel Platform** | Intermediate | RAG, prioritization       |

Each project includes starter code, requirements, and evaluation criteria.

---

## Templates & Integrations

Jumpstart your projects with ready-to-use templates:

- **Agent Templates**: LangChain security agent, RAG agent
- **n8n Workflows**: IOC enrichment, alert triage with AI
- **SIEM Integrations**: Elasticsearch, Microsoft Sentinel
- **Prompt Library**: Log analysis, threat detection, report generation

---

## Development

### Test Status

**Current Status**: 839/839 tests passing (100%) ✅

All 20 labs have comprehensive test coverage!

| Lab    | Tests | Status  | Focus Area                         |
| ------ | ----- | ------- | ---------------------------------- |
| Lab 01 | 14/14 | ✅ 100% | Phishing Classifier (ML)           |
| Lab 02 | 9/9   | ✅ 100% | Malware Clustering (ML)            |
| Lab 03 | 11/11 | ✅ 100% | Anomaly Detection (ML)             |
| Lab 04 | 18/18 | ✅ 100% | Log Analysis (LLM)                 |
| Lab 05 | 21/21 | ✅ 100% | Threat Intel Agent (LangChain)     |
| Lab 06 | 7/7   | ✅ 100% | Security RAG (Vector DB)           |
| Lab 07 | 8/8   | ✅ 100% | YARA Generator (Code Gen)          |
| Lab 08 | 11/11 | ✅ 100% | Vuln Scanner (Risk Prioritization) |
| Lab 09 | 15/15 | ✅ 100% | Detection Pipeline (Multi-stage)   |
| Lab 10 | 28/28 | ✅ 100% | IR Copilot (Conversational)        |
| Lab 11 | 37/37 | ✅ 100% | Ransomware Detection (DFIR)        |
| Lab 12 | 44/44 | ✅ 100% | Purple Team Sim (Safe Emulation)   |
| Lab 13 | 71/71 | ✅ 100% | Memory Forensics AI                |
| Lab 14 | 85/85 | ✅ 100% | C2 Traffic Analysis                |
| Lab 15 | 69/69 | ✅ 100% | Lateral Movement Detection         |
| Lab 16 | 90/90 | ✅ 100% | Threat Actor Profiling             |
| Lab 17 | 73/73 | ✅ 100% | Adversarial ML                     |
| Lab 18 | 76/76 | ✅ 100% | Fine-Tuning for Security           |
| Lab 19 | 64/64 | ✅ 100% | Cloud Security AI                  |
| Lab 20 | 88/88 | ✅ 100% | LLM Red Teaming                    |

**API Requirements**: Labs 04-20 require at least one LLM provider API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`). Labs 01-03 work without API keys.

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific lab tests
pytest tests/test_lab01_phishing_classifier.py -v

# Run with coverage
pytest tests/ --cov=labs --cov-report=html

# Run in Docker
docker-compose run test
```

### Code Quality

```bash
# Format code
black .
isort .

# Lint
flake8 .

# Security scan
bandit -r labs/
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable             | Description       | Required                |
| -------------------- | ----------------- | ----------------------- |
| `ANTHROPIC_API_KEY`  | Claude API key    | One LLM key required    |
| `OPENAI_API_KEY`     | OpenAI GPT-4 key  | One LLM key required    |
| `GOOGLE_API_KEY`     | Google Gemini key | One LLM key required    |
| `VIRUSTOTAL_API_KEY` | VirusTotal API    | Optional (threat intel) |
| `ABUSEIPDB_API_KEY`  | AbuseIPDB API     | Optional (threat intel) |

> **Note:** You only need ONE LLM provider key. All labs support multiple providers.

---

## Author

Created by **Raymond DePalma**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/depalmar)

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting PRs.

Ways to contribute:

- Fix bugs or improve existing labs
- Add new sample data or test cases
- Improve documentation
- Share your capstone projects

---

## License

This project uses a **dual license model**:

| Content Type | License | Commercial Use |
|--------------|---------|----------------|
| Documentation, labs, prose | CC BY-NC-SA 4.0 | Requires commercial license |
| Code samples and scripts | MIT | Permitted |

See the [LICENSE](./LICENSE) file for full details. For commercial licensing inquiries, please [contact the author](https://linkedin.com/in/depalmar).

---

## Disclaimer

This training material is intended for **educational purposes** and **authorized security testing only**. Users are responsible for ensuring compliance with all applicable laws and obtaining proper authorization before using any offensive techniques.

---

<p align="center">
  <b>Ready to build AI-powered security tools?</b><br>
  <a href="./labs/lab00-environment-setup/">Get Started</a> |
  <a href="./docs/ai-security-training-program.md">View Full Curriculum</a>
</p>

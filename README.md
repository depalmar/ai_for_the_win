<p align="center">
  <img src="docs/assets/images/logo.png" alt="AI for the Win - Security AI Training Platform Logo" width="150" height="150">
</p>

# AI for the Win

### Build AI-Powered Security Tools | Hands-On Learning

[![CI](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml/badge.svg)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/depalmar/ai_for_the_win/badge)](https://scorecard.dev/viewer/?uri=github.com/depalmar/ai_for_the_win)
[![Python 3.10-3.12](https://img.shields.io/badge/python-3.10--3.12-blue.svg)](https://www.python.org/downloads/)
[![License: Dual](https://img.shields.io/badge/License-Dual%20(MIT%20%2B%20CC%20BY--NC--SA)-blue.svg)](./LICENSE)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab10_phishing_classifier.ipynb)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](./Dockerfile)

A hands-on training program for security practitioners who want to build AI-powered tools for threat detection, incident response, and security automation. **50+ labs** (including 9 intro labs and 12 bridge labs), **4 capstone projects**, **18 CTF challenges**. Includes **sample datasets**, **solution walkthroughs**, and **Docker lab environment**. Designed for **vibe coding** with AI assistants like Cursor, Claude Code, and Copilot.

---

## 🎬 What You'll Build

**Lab 29 - Phishing Classifier** catches what rules miss:

```text
$ python labs/lab10-phishing-classifier/solution/main.py

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

**Lab 35 - LLM Log Analysis** finds attacks in noise:

```text
┌──────────────────────────────────────────────────────┐
│ Lab 35: LLM-Powered Security Log Analysis - SOLUTION │
└──────────────────────────────────────────────────────┘
Security Log Analysis Pipeline

Step 1: Initializing LLM...
  LLM initialized: READY
Step 2: Parsing log entries...
  Parsing entry 1/5... ✓
  Parsing entry 2/5... ✓
  Parsing entry 3/5... ✓
  Parsing entry 4/5... ✓
  Parsing entry 5/5... ✓
  Parsed 5 log entries
Step 3: Analyzing for threats...
  Found 2 threats
  Severity: 8/10
Step 4: Extracting IOCs...
  Extracted 12 IOCs
Step 5: Generating incident report...
  Report generated

════════════════════════════════════════════════════════════════
                        INCIDENT REPORT
════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────┐
│                    Executive Summary                          │
└──────────────────────────────────────────────────────────────┘
A critical security incident involving multi-stage attack behavior
was detected on WORKSTATION01 involving user 'jsmith'. The attack
progression includes initial PowerShell execution downloading a
payload from a suspicious external domain, followed by system
discovery commands, and culminating in persistence establishment
via Registry Run keys and Scheduled Tasks.

┌──────────────────────────────────────────────────────────────┐
│                        Timeline                               │
└──────────────────────────────────────────────────────────────┘
 1  2025-01-15 03:22:10 - PowerShell downloaded payload from
                          hxxp://evil-c2[.]com/payload.ps1
 2  2025-01-15 03:22:15 - Discovery commands executed
                          (whoami, hostname, ipconfig)
 3  2025-01-15 03:22:18 - Network connection to evil-c2[.]com
                          (185[.]143[.]223[.]47:443)
 4  2025-01-15 03:23:00 - Registry persistence: HKCU Run keys
 5  2025-01-15 03:25:00 - Scheduled Task: SecurityUpdate created

┌──────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK Mapping                       │
└──────────────────────────────────────────────────────────────┘
  Technique ID   Technique Name                    Evidence
 ─────────────────────────────────────────────────────────────
  T1059.001      PowerShell                        DownloadString, IEX
  T1082          System Information Discovery      whoami, hostname
  T1547.001      Registry Run Keys                 HKCU\...\Run
  T1053.005      Scheduled Task                    SecurityUpdate
  T1105          Ingress Tool Transfer             DownloadString

┌──────────────────────────────────────────────────────────────┐
│                   Attribution Analysis                        │
└──────────────────────────────────────────────────────────────┘
High Confidence: FIN7/Carbanak
• Tooling matches known campaigns (PowerShell obfuscation)
• Infrastructure historically associated with FIN7
• TTP sequence is signature behavior pattern
```

---

## ⚡ Start in 60 Seconds

**No installation needed** — click and run in your browser:

[![Open Lab 29 in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab10_phishing_classifier.ipynb) ← ML basics (no API key)

[![Open Lab 35 in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab15_llm_log_analysis.ipynb) ← LLM-powered (needs API key)

> All 50+ notebooks are in [`notebooks/`](./notebooks/) — open any `.ipynb` in Colab

---

## 🚀 Pick Your Starting Point

| Your Background | Start Here | Next Steps |
|-----------------|------------|------------|
| **New to AI/ML?** | [Lab 29: Phishing Classifier](./labs/lab10-phishing-classifier/) | → Lab 31 → Lab 32 |
| **Know Python, want LLM tools?** | [Lab 35: LLM Log Analysis](./labs/lab15-llm-log-analysis/) | → Lab 36 → Lab 42 |
| **Want DFIR focus?** | [Lab 31: Ransomware Detection](./labs/lab31-ransomware-detection/) | → Lab 33 → Lab 34 |

**💡 Tip**: Labs 01-03 are FREE (no API keys). LLM labs (04+) need an API key (~$5-25 total).

---

## 🗺️ Lab Navigator

**Click any lab to explore** — Your learning journey from setup to expert:

<table border="1" cellspacing="0" cellpadding="8">
<tr>
<td align="center"><a href="./labs/lab00-environment-setup/"><img src="https://img.shields.io/badge/00-Setup-555?style=for-the-badge" alt="Lab 00"/></a></td>
<td align="center"><a href="./labs/lab01-python-security-fundamentals/"><img src="https://img.shields.io/badge/01-Python-555?style=for-the-badge" alt="Lab 29"/></a></td>
<td align="center"><a href="./labs/lab04-ml-concepts-primer/"><img src="https://img.shields.io/badge/04-ML_Intro-555?style=for-the-badge" alt="Lab 35"/></a></td>
<td align="center"><a href="./labs/lab02-intro-prompt-engineering/"><img src="https://img.shields.io/badge/02-Prompts-555?style=for-the-badge" alt="Lab 31"/></a></td>
<td align="center"><a href="./labs/lab05-ai-in-security-operations/"><img src="https://img.shields.io/badge/05-AI_SOC-555?style=for-the-badge" alt="Lab 36"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab06-visualization-stats/"><img src="https://img.shields.io/badge/06-Stats-555?style=for-the-badge" alt="Lab 42"/></a></td>
<td align="center"><a href="./labs/lab07-hello-world-ml/"><img src="https://img.shields.io/badge/07-Hello_ML-555?style=for-the-badge" alt="Lab 21"/></a></td>
<td align="center"><a href="./labs/lab08-working-with-apis/"><img src="https://img.shields.io/badge/08-APIs-555?style=for-the-badge" alt="Lab 22"/></a></td>
<td align="center"><a href="./labs/lab03-vibe-coding-with-ai/"><img src="https://img.shields.io/badge/03-Vibe_Code-555?style=for-the-badge" alt="Lab 32"/></a></td>
<td align="center"><a href="./labs/lab09-ctf-fundamentals/"><img src="https://img.shields.io/badge/09-CTF_Fund-555?style=for-the-badge" alt="Lab 23"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab10-phishing-classifier/"><img src="https://img.shields.io/badge/01-Phishing-10b981?style=for-the-badge" alt="Lab 29"/></a></td>
<td align="center"><a href="./labs/lab11-malware-clustering/"><img src="https://img.shields.io/badge/02-Malware-10b981?style=for-the-badge" alt="Lab 31"/></a></td>
<td align="center"><a href="./labs/lab12-anomaly-detection/"><img src="https://img.shields.io/badge/03-Anomaly-10b981?style=for-the-badge" alt="Lab 32"/></a></td>
<td align="center"><a href="./labs/lab33-ml-vs-llm/"><img src="https://img.shields.io/badge/03b-ML_vs_LLM-10b981?style=for-the-badge" alt="Lab 33"/></a></td>
<td align="center"><a href="./labs/lab15-llm-log-analysis/"><img src="https://img.shields.io/badge/04-Logs-6366f1?style=for-the-badge" alt="Lab 35"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab34-first-ai-agent/"><img src="https://img.shields.io/badge/04b-Agent-6366f1?style=for-the-badge" alt="Lab 34"/></a></td>
<td align="center"><a href="./labs/lab16-threat-intel-agent/"><img src="https://img.shields.io/badge/05-Intel-6366f1?style=for-the-badge" alt="Lab 36"/></a></td>
<td align="center"><a href="./labs/lab17-embeddings-vectors/"><img src="https://img.shields.io/badge/06a-Vectors-6366f1?style=for-the-badge" alt="Lab 39"/></a></td>
<td align="center"><a href="./labs/lab18-security-rag/"><img src="https://img.shields.io/badge/06-RAG-6366f1?style=for-the-badge" alt="Lab 42"/></a></td>
<td align="center"><a href="./labs/lab45-binary-basics/"><img src="https://img.shields.io/badge/07a-Binary-6366f1?style=for-the-badge" alt="Lab 45"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab21-yara-generator/"><img src="https://img.shields.io/badge/07-YARA-6366f1?style=for-the-badge" alt="Lab 21"/></a></td>
<td align="center"><a href="./labs/lab20-sigma-fundamentals/"><img src="https://img.shields.io/badge/07b-Sigma-6366f1?style=for-the-badge" alt="Lab 49"/></a></td>
<td align="center"><a href="./labs/lab22-vuln-scanner-ai/"><img src="https://img.shields.io/badge/08-Vuln-f59e0b?style=for-the-badge" alt="Lab 22"/></a></td>
<td align="center"><a href="./labs/lab23-detection-pipeline/"><img src="https://img.shields.io/badge/09-Pipeline-f59e0b?style=for-the-badge" alt="Lab 23"/></a></td>
<td align="center"><a href="./labs/lab24-monitoring-ai-systems/"><img src="https://img.shields.io/badge/09b-Monitor-f59e0b?style=for-the-badge" alt="Lab 24"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab25-dfir-fundamentals/"><img src="https://img.shields.io/badge/10a-DFIR-f59e0b?style=for-the-badge" alt="Lab 25"/></a></td>
<td align="center"><a href="./labs/lab29-ir-copilot/"><img src="https://img.shields.io/badge/10-IR_Bot-f59e0b?style=for-the-badge" alt="Lab 29"/></a></td>
<td align="center"><a href="./labs/lab26-windows-event-log-analysis/"><img src="https://img.shields.io/badge/10b-WinLogs-f59e0b?style=for-the-badge" alt="Lab 26"/></a></td>
<td align="center"><a href="./labs/lab27-windows-registry-forensics/"><img src="https://img.shields.io/badge/10c-Registry-f59e0b?style=for-the-badge" alt="Lab 27"/></a></td>
<td align="center"><a href="./labs/lab28-live-response/"><img src="https://img.shields.io/badge/10d-LiveIR-f59e0b?style=for-the-badge" alt="Lab 28"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab30-ransomware-fundamentals/"><img src="https://img.shields.io/badge/11a-Ransom_Fund-ef4444?style=for-the-badge" alt="Lab 30"/></a></td>
<td align="center"><a href="./labs/lab31-ransomware-detection/"><img src="https://img.shields.io/badge/11-Ransom-ef4444?style=for-the-badge" alt="Lab 31"/></a></td>
<td align="center"><a href="./labs/lab32-ransomware-simulation/"><img src="https://img.shields.io/badge/12-Purple-ef4444?style=for-the-badge" alt="Lab 32"/></a></td>
<td align="center"><a href="./labs/lab33-memory-forensics-ai/"><img src="https://img.shields.io/badge/13-Memory-ef4444?style=for-the-badge" alt="Lab 33"/></a></td>
<td align="center"><a href="./labs/lab34-c2-traffic-analysis/"><img src="https://img.shields.io/badge/14-C2-ef4444?style=for-the-badge" alt="Lab 34"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab35-lateral-movement-detection/"><img src="https://img.shields.io/badge/15-Lateral-ef4444?style=for-the-badge" alt="Lab 35"/></a></td>
<td align="center"><a href="./labs/lab36-threat-actor-profiling/"><img src="https://img.shields.io/badge/16-Actors-ef4444?style=for-the-badge" alt="Lab 36"/></a></td>
<td align="center"><a href="./labs/lab37-ai-powered-threat-actors/"><img src="https://img.shields.io/badge/16b-AI_Threat-ef4444?style=for-the-badge" alt="Lab 37"/></a></td>
<td align="center"><a href="./labs/lab38-ml-security-intro/"><img src="https://img.shields.io/badge/17a-MLSec-ef4444?style=for-the-badge" alt="Lab 38"/></a></td>
<td align="center"><a href="./labs/lab39-adversarial-ml/"><img src="https://img.shields.io/badge/17-AdvML-ef4444?style=for-the-badge" alt="Lab 39"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab40-llm-security-testing/"><img src="https://img.shields.io/badge/17b-LLMSec-ef4444?style=for-the-badge" alt="Lab 40"/></a></td>
<td align="center"><a href="./labs/lab41-model-monitoring/"><img src="https://img.shields.io/badge/17c-Monitor-ef4444?style=for-the-badge" alt="Lab 41"/></a></td>
<td align="center"><a href="./labs/lab42-fine-tuning-security/"><img src="https://img.shields.io/badge/18-Tuning-ef4444?style=for-the-badge" alt="Lab 42"/></a></td>
<td align="center"><a href="./labs/lab43-rag-security/"><img src="https://img.shields.io/badge/18b-RAGSec-ef4444?style=for-the-badge" alt="Lab 43"/></a></td>
<td align="center"><a href="./labs/lab44-cloud-security-fundamentals/"><img src="https://img.shields.io/badge/19a-CloudFund-ef4444?style=for-the-badge" alt="Lab 44"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab45-cloud-security-ai/"><img src="https://img.shields.io/badge/19-Cloud-ef4444?style=for-the-badge" alt="Lab 45"/></a></td>
<td align="center"><a href="./labs/lab46-container-security/"><img src="https://img.shields.io/badge/19b-Container-ef4444?style=for-the-badge" alt="Lab 46"/></a></td>
<td align="center"><a href="./labs/lab47-serverless-security/"><img src="https://img.shields.io/badge/19c-Serverless-ef4444?style=for-the-badge" alt="Lab 47"/></a></td>
<td align="center"><a href="./labs/lab48-cloud-ir-automation/"><img src="https://img.shields.io/badge/19d-CloudIR-ef4444?style=for-the-badge" alt="Lab 48"/></a></td>
<td align="center"><a href="./labs/lab49-llm-red-teaming/"><img src="https://img.shields.io/badge/20-RedTeam-ef4444?style=for-the-badge" alt="Lab 49"/></a></td>
</tr>
<tr>
<td align="center"><a href="./labs/lab50-purple-team-ai/"><img src="https://img.shields.io/badge/20b-PurpleAI-ef4444?style=for-the-badge" alt="Lab 50"/></a></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
</table>

**Legend:** ⬜ Intro (Free) · 🟢 ML (Free) · 🟣 LLM · 🟠 Advanced · 🔴 Expert DFIR

<details>
<summary><strong>📋 Detailed Lab Descriptions</strong></summary>

### ⚪ Intro Labs (01-09) — Setup & Foundations, no API keys

| Lab | Topic | Description |
|-----|-------|-------------|
| [00](./labs/lab00-environment-setup/) | Setup | Environment configuration |
| [01](./labs/lab01-python-security-fundamentals/) | Python | Security-focused Python basics |
| [04](./labs/lab04-ml-concepts-primer/) | ML Intro | Supervised/unsupervised, features, evaluation |
| [02](./labs/lab02-intro-prompt-engineering/) | Prompts | LLM basics with free playgrounds |
| [05](./labs/lab05-ai-in-security-operations/) | AI in SOC | Where AI fits, human-in-the-loop |
| [06](./labs/lab06-visualization-stats/) | Stats | Matplotlib, Seaborn for dashboards |
| [07](./labs/lab07-hello-world-ml/) | Hello ML | Your first ML model end-to-end |
| [08](./labs/lab08-working-with-apis/) | APIs | REST APIs, authentication, rate limiting |
| [03](./labs/lab03-vibe-coding-with-ai/) | Vibe Coding | AI assistants for accelerated learning |
| [09](./labs/lab09-ctf-fundamentals/) | CTF Fundamentals | CTF mindset, encoding, flag hunting |

### 🟢 ML Labs (01-03) — Machine Learning, no API keys

| Lab | Topic | Description |
|-----|-------|-------------|
| [01](./labs/lab10-phishing-classifier/) | Phishing | TF-IDF, Random Forest, classification |
| [02](./labs/lab11-malware-clustering/) | Malware | K-Means, DBSCAN, clustering binaries |
| [03](./labs/lab12-anomaly-detection/) | Anomaly | Isolation Forest, LOF, baselines |
| [03b](./labs/lab33-ml-vs-llm/) | ML vs LLM | When to use each, cost tradeoffs |

### 🟣 LLM Labs (04-07) — Language Models & Agents

| Lab | Topic | Description |
|-----|-------|-------------|
| [04](./labs/lab15-llm-log-analysis/) | Logs | Prompt engineering, IOC extraction |
| [04b](./labs/lab34-first-ai-agent/) | Agent | ReAct pattern, tool calling basics |
| [05](./labs/lab16-threat-intel-agent/) | Intel | LangChain, autonomous investigation |
| [06a](./labs/lab17-embeddings-vectors/) | Vectors | Embeddings, similarity search |
| [06](./labs/lab18-security-rag/) | RAG | ChromaDB, retrieval-augmented Q&A |
| [07a](./labs/lab45-binary-basics/) | Binary | PE structure, entropy analysis |
| [07](./labs/lab21-yara-generator/) | YARA | AI-assisted rule generation |
| [07b](./labs/lab20-sigma-fundamentals/) | Sigma | Log-based detection rules |

### 🟠 Advanced Labs (08-10) — Pipelines & Automation

| Lab | Topic | Description |
|-----|-------|-------------|
| [08](./labs/lab22-vuln-scanner-ai/) | Vuln | CVSS, risk prioritization |
| [09](./labs/lab23-detection-pipeline/) | Pipeline | ML filtering + LLM enrichment |
| [09b](./labs/lab24-monitoring-ai-systems/) | Monitor | Observability, cost tracking |
| [10a](./labs/lab25-dfir-fundamentals/) | DFIR | Forensics basics, evidence collection |
| [10](./labs/lab29-ir-copilot/) | IR Bot | Conversational IR, playbook execution |
| [10b](./labs/lab26-windows-event-log-analysis/) | Windows Logs | Event log parsing, detection |
| [10c](./labs/lab27-windows-registry-forensics/) | Registry | Registry forensics, persistence |
| [10d](./labs/lab28-live-response/) | Live IR | Live response, triage procedures |

### 🔴 Expert Labs (11-21) — DFIR, Adversarial, Cloud

| Lab | Topic | Description |
|-----|-------|-------------|
| [11a](./labs/lab30-ransomware-fundamentals/) | Ransom Fund | Ransomware families, attack lifecycle |
| [11](./labs/lab31-ransomware-detection/) | Ransom | Entropy, behavioral detection |
| [12](./labs/lab32-ransomware-simulation/) | Purple | Safe adversary emulation |
| [13](./labs/lab33-memory-forensics-ai/) | Memory | Volatility3, process injection |
| [14](./labs/lab34-c2-traffic-analysis/) | C2 | Beaconing, DNS tunneling, JA3 |
| [15](./labs/lab35-lateral-movement-detection/) | Lateral | Auth anomalies, graph paths |
| [16](./labs/lab36-threat-actor-profiling/) | Actors | TTP extraction, attribution |
| [16b](./labs/lab37-ai-powered-threat-actors/) | AI Threat | Deepfakes, AI-generated phishing |
| [17a](./labs/lab38-ml-security-intro/) | MLSec | Data poisoning, model security |
| [17](./labs/lab39-adversarial-ml/) | Adv ML | Evasion attacks, robust defenses |
| [17b](./labs/lab40-llm-security-testing/) | LLM Security | Prompt injection testing, jailbreaks |
| [17c](./labs/lab41-model-monitoring/) | Model Monitor | Drift detection, adversarial inputs |
| [18](./labs/lab42-fine-tuning-security/) | Tuning | LoRA, custom embeddings |
| [18b](./labs/lab43-rag-security/) | RAG Security | KB poisoning, context sanitization |
| [19a](./labs/lab44-cloud-security-fundamentals/) | Cloud Fund | Shared responsibility, IAM |
| [19](./labs/lab45-cloud-security-ai/) | Cloud | AWS/Azure/GCP, CloudTrail |
| [19b](./labs/lab46-container-security/) | Container | Kubernetes, runtime detection |
| [19c](./labs/lab47-serverless-security/) | Serverless | Lambda, event injection |
| [19d](./labs/lab48-cloud-ir-automation/) | Cloud IR | Automated containment, evidence |
| [20](./labs/lab49-llm-red-teaming/) | Red Team | Prompt injection, jailbreaks |
| [20b](./labs/lab50-purple-team-ai/) | Purple AI | Automated attack simulation |

</details>

---

## 🏗️ Capstone Projects

| Project | Difficulty | Focus |
|---------|------------|-------|
| **Security Analyst Copilot** | Advanced | LLM agents, IR automation |
| **Automated Threat Hunter** | Advanced | ML detection, pipelines |
| **Malware Analysis Assistant** | Intermediate | Static analysis, YARA |
| **Vulnerability Intel Platform** | Intermediate | RAG, prioritization |

Each includes starter code, requirements, and evaluation criteria. See [`capstone-projects/`](./capstone-projects/).

---

## 🛠️ Local Setup

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Python** | 3.10 | 3.10-3.12 (PyTorch not yet available for 3.13+) |
| **RAM** | 8GB | 16GB (for local LLMs) |
| **OS** | Windows, macOS, Linux | Any |
| **Editor** | Any | VS Code, Cursor, PyCharm |
| **Git** | Required | - |
| **Docker** | Optional | For containerized labs |
| **API Key** | Labs 04+ only | Free tiers available |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start with Lab 00 (no API key needed)
cd labs/lab00-environment-setup
```

### API Keys (for Labs 04+)

```bash
# Copy example env
cp .env.example .env

# Edit .env with your preferred editor and add API key
# IMPORTANT: Don't paste keys in terminal (saved in history)
# Example: ANTHROPIC_API_KEY=your-key-here

# Verify setup
python scripts/verify_setup.py
```

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude API | One LLM key required |
| `OPENAI_API_KEY` | GPT-4/5 API | One LLM key required |
| `GOOGLE_API_KEY` | Gemini API | One LLM key required |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Optional |

> You only need ONE LLM provider. All labs support multiple providers.

### Docker Lab Environment (New!)

One-command setup with all services pre-configured:

```bash
cd docker
docker compose up -d

# Access services:
# - Jupyter Lab: http://localhost:8888 (token: aiforthewin)
# - Kibana: http://localhost:5601
# - MinIO: http://localhost:9001 (minioadmin/minioadmin)
```

Includes: Jupyter Lab, Elasticsearch, Kibana, PostgreSQL, Redis, MinIO, Ollama (local LLMs), ChromaDB (vectors).

See [`docker/README.md`](./docker/README.md) for full details.

### Running Tests

```bash
pytest tests/ -v                    # All tests
pytest tests/test_lab01*.py -v     # Single lab
pytest tests/ --cov=labs           # With coverage
docker compose run test            # In Docker
```

---

## 📖 Resources

| Resource | Description |
|----------|-------------|
| [Environment Setup](./labs/lab00-environment-setup/) | First-time setup |
| [API Keys Guide](./docs/guides/api-keys-guide.md) | Get API keys, manage costs |
| [Troubleshooting](./docs/guides/troubleshooting-guide.md) | Fix common issues |
| [Lab Walkthroughs](./docs/walkthroughs/) | Step-by-step solutions |
| [Role-Based Paths](./resources/role-based-learning-paths.md) | SOC, IR, hunting paths |
| [Security-to-AI Glossary](./resources/security-to-ai-glossary.md) | AI terms for security folks |
| [All Guides](./docs/guides/) | 28 guides: tools, APIs, advanced |

**Issues?** Open a [GitHub issue](https://github.com/depalmar/ai_for_the_win/issues)

### Technology Stack

| Category | Tools |
|----------|-------|
| **LLM Providers** | Claude (Sonnet/Opus/Haiku), GPT-5, Gemini 3, Ollama |
| **LLM Frameworks** | LangChain, LangGraph, LiteLLM |
| **ML/AI** | scikit-learn, PyTorch, Transformers |
| **Vector DB** | ChromaDB, sentence-transformers |
| **Security** | YARA, Sigma, MITRE ATT&CK, pefile |
| **Vibe Coding** | Cursor, Claude Code, Copilot, Windsurf |

---

## 👤 Author

Created by **Raymond DePalma**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/raymond-depalma/)

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

---

## License

| Content Type | License | Commercial Use |
|--------------|---------|----------------|
| Documentation, labs, prose | CC BY-NC-SA 4.0 | Requires commercial license |
| Code samples and scripts | MIT | Permitted |

See [LICENSE](./LICENSE) for details. For commercial licensing, [contact the author](https://www.linkedin.com/in/raymond-depalma/).

---

## Troubleshooting

### Antivirus Blocking Sample Files

Some labs and CTF challenges include sample malware metadata, IOC patterns, or simulated attack artifacts that may trigger antivirus software. **These files contain analysis data for educational purposes, not actual malware.**

**Paths to exclude in your antivirus software:**
- `ai_for_the_win/` - The entire repository (recommended)
- `ctf-challenges/**/challenge/` - CTF challenge files with simulated web shells, persistence mechanisms
- `labs/lab21-yara-generator/data/` - Malware metadata for YARA rule generation
- `data/malware/` - Sample malware analysis artifacts

Add folder exclusions for these paths in your AV settings if files are being quarantined.

### Accessibility

This project aims to be accessible to all learners:
- Lab difficulty indicators use both color AND text labels (e.g., "🟢 Beginner")
- All code examples include descriptive comments
- Documentation uses high-contrast text

If you encounter accessibility issues, please [open an issue](https://github.com/depalmar/ai_for_the_win/issues).

---

## Disclaimer

> **Responsible Use:** This material is for defensive security education only. Do not use techniques described here for unauthorized access or attacks. See [RESPONSIBLE_USE.md](./RESPONSIBLE_USE.md).

> This is a personal educational project created and maintained on personal time. It is not affiliated with, endorsed by, or sponsored by any employer, organization, or vendor.

---

<p align="center">
  <b>Ready to build AI-powered security tools?</b><br>
  <a href="https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab10_phishing_classifier.ipynb">Start in Colab</a> |
  <a href="./labs/lab00-environment-setup/">Local Setup</a> |
  <a href="./docs/ai-security-training-program.md">Full Curriculum</a>
</p>

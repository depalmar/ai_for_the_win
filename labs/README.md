# 🧪 Hands-On Labs

Practical labs for building AI-powered security tools.

> 📖 **New to the course?** Start with [GETTING_STARTED.md](../docs/GETTING_STARTED.md) for setup, then see [Learning Guide](../docs/learning-guide.md) for learning paths.

---

## Labs in Recommended Order

Follow this progression for the best learning experience. Labs build on each other.

### 🎯 Getting Started: Prerequisites

**New to Python, ML, or LLMs?** Start here before Lab 10.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 00 | [Environment Setup](./lab00-environment-setup/) | Setup | Python, venv, API keys, tools installation |
| 01 | [Python for Security](./lab01-python-security-fundamentals/) | Python basics | Variables, files, APIs, security examples |
| 02 | [Intro to Prompt Engineering](./lab02-intro-prompt-engineering/) | LLM prompting | Prompt design, hallucination detection, AI Studio |
| 03 | [Vibe Coding with AI](./lab03-vibe-coding-with-ai/) | AI assistants | Claude Code, Cursor, Copilot, accelerated learning |
| 04 | [ML Concepts Primer](./lab04-ml-concepts-primer/) | ML theory | Supervised/unsupervised, features, evaluation |
| 05 | [AI in Security Operations](./lab05-ai-in-security-operations/) | SOC integration | Where AI fits, human-in-the-loop, compliance |
| 06 | [Visualization & Statistics](./lab06-visualization-stats/) | Data viz | Plotly, Gradio, statistics, dashboards |
| 07 | [Hello World ML](./lab07-hello-world-ml/) | First classifier | 4-step ML workflow, accuracy, precision, recall |
| 08 | [Working with APIs](./lab08-working-with-apis/) | HTTP & REST | requests library, JSON, API keys, rate limiting |
| 09 | [CTF Fundamentals](./lab09-ctf-fundamentals/) | CTF skills | Flag formats, encoding, systematic approaches |

**Who should do these:**
- Brand new to everything → Start with **Lab 00** (environment setup)
- No Python experience → Start with **Lab 01**
- Python OK, new to ML → Start with **Lab 04** then **Lab 07**
- Want to use LLMs effectively → Do **Lab 02** (highly recommended!)
- Want SOC/operational context → Do **Lab 05** (conceptual, no coding)
- Need visualization skills → Do **Lab 06** (Plotly, Gradio, dashboards)
- First ML model → Do **Lab 07** before Lab 10 (simpler intro)
- API skills → Do **Lab 08** before Labs 14-18 (LLM APIs)
- CTF practice → Do **Lab 09** to learn challenge-solving approaches
- Accelerate your learning → Do **Lab 03** to use AI assistants throughout the course
- Comfortable with all → Skip to Lab 10

```
Lab 01 (Python) → Lab 04 (ML) → Lab 07 (First ML) → Lab 10 (Phishing)
     ↓                 ↓                 ↓                   ↓
 "Learn Python    "Understand       "Build your         "Build real
  basics"          ML theory"        FIRST model"        classifier"

Lab 02 (Prompts) → Lab 08 (APIs) → Lab 15 (LLM Log Analysis)
     ↓                  ↓                   ↓
 "Master LLM        "HTTP & JSON       "Use LLMs
  prompting"         skills"            for security"
```

> 💡 **Pro Tip:** Even experienced developers should do **Lab 02** and **Lab 05** - prompt engineering and SOC context are critical for real-world deployment!

---

### 🟢 Foundation: ML Basics

Start here if you're new to ML for security. These labs teach core concepts.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 10 | [Phishing Classifier](./lab10-phishing-classifier/) | Text classification | TF-IDF, Random Forest, precision/recall |
| 11 | [Malware Clustering](./lab11-malware-clustering/) | Unsupervised learning | K-Means, t-SNE, PE file features |
| 12 | [Anomaly Detection](./lab12-anomaly-detection/) | Outlier detection | Isolation Forest, network features |
| 13 | [ML vs LLM Decision](./lab13-ml-vs-llm/) | **Bridge lab** | When to use ML vs LLM, hybrid systems |

**Progression:**
```
Lab 10 (Text ML) → Lab 11 (Clustering) → Lab 12 (Anomaly) → Lab 13 (ML vs LLM)
     ↓                  ↓                      ↓                   ↓
 "Classify           "Group              "Find unusual        "When to use
  emails"            malware"             traffic"             ML vs LLM?"
```

**Bridge to LLMs:** Lab 13 is the critical bridge between ML and LLM sections. It teaches you when to use each approach and how to combine them effectively.

---

### 🟡 Core Skills: LLM Security Tools

Learn to apply Large Language Models to security problems.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 14 | [Your First AI Agent](./lab14-first-ai-agent/) | **Bridge lab** | Tool calling, ReAct basics |
| 15 | [LLM Log Analysis](./lab15-llm-log-analysis/) | Prompt engineering | Structured outputs, IOC extraction |
| 16 | [Threat Intel Agent](./lab16-threat-intel-agent/) | AI agents | Full ReAct pattern, tools, memory |
| 17 | [Embeddings & Vectors](./lab17-embeddings-vectors/) | **Bridge lab** | How embeddings work, semantic search |
| 18 | [Security RAG](./lab18-security-rag/) | Vector search + LLM | Embeddings, ChromaDB, retrieval |
| 19 | [Binary Analysis Basics](./lab19-binary-basics/) | **Bridge lab** | PE structure, entropy, imports |
| 20 | [Sigma Fundamentals](./lab20-sigma-fundamentals/) | Detection rules | Sigma syntax, converters |
| 21 | [YARA Generator](./lab21-yara-generator/) | AI code generation | Binary analysis, rule generation |

**Progression:**
```
Lab 14 (First Agent) → Lab 15 (Log Analysis) → Lab 16 (Threat Intel) → Lab 17 (Embeddings) → Lab 18 (RAG) → Lab 21 (YARA)
        ↓                      ↓                      ↓                       ↓                   ↓              ↓
   "Simple tools"       "Parse logs"          "Full agent"          "How vectors        "Build RAG      "Generate
                                                                     work"               system"         YARA rules"
```

**Bridge to Full Agents:** Lab 14 teaches basic tool calling. This prepares you for Lab 16's full ReAct agent with memory and multiple tools.

> ⚠️ **Note about Lab 16**: Despite its number, Lab 16 (Threat Intel Agent) is more advanced because it builds on concepts from Labs 14-15. Do Lab 14 first if agents feel complex!

---

### 🟠 Advanced: Autonomous Systems

Build AI agents and multi-stage pipelines.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 22 | [Vuln Scanner AI](./lab22-vuln-scanner-ai/) | Risk prioritization | CVSS, business context |
| 23 | [Detection Pipeline](./lab23-detection-pipeline/) | ML + LLM pipeline | Multi-stage detection |
| 24 | [Monitoring AI Systems](./lab24-monitoring-ai-systems/) | **Bridge lab** | Observability, drift detection, logging |
| 29 | [IR Copilot](./lab29-ir-copilot/) | Conversational AI | Orchestration, confirmation |

**Progression:**
```
Lab 14 (First Agent) → Lab 16 (Full Agent) → Lab 22 (Vuln) → Lab 23 (Pipeline) → Lab 24 (Monitoring) → Lab 29 (IR)
        ↓                       ↓                  ↓                ↓                    ↓                  ↓
   "Simple tools"        "ReAct + memory"    "Prioritize      "Combine           "Monitor          "Conversational
                                              risks"           ML + LLM"          in prod"           IR assistant"
```

---

### 🔴 Expert: DFIR & Red Team

Deep dive into incident response, threat simulation, and offensive security analysis.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 25 | [DFIR Fundamentals](./lab25-dfir-fundamentals/) | **Bridge lab** | IR lifecycle, artifacts, ATT&CK mapping |
| 26 | [Windows Event Log Analysis](./lab26-windows-event-log-analysis/) | Windows forensics | Event IDs, lateral movement, credential theft |
| 27 | [Windows Registry Forensics](./lab27-windows-registry-forensics/) | Registry analysis | Persistence hunting, forensic artifacts |
| 28 | [Live Response](./lab28-live-response/) | Triage | Collection techniques, triage checklist |
| 30 | [Ransomware Fundamentals](./lab30-ransomware-fundamentals/) | **Bridge lab** | Evolution, families, indicators, recovery |
| 31 | [Ransomware Detection](./lab31-ransomware-detection/) | Behavioral detection | Entropy, TTPs, response |
| 32 | [Purple Team](./lab32-ransomware-simulation/) | Adversary emulation | Safe simulation, gap analysis |
| 33 | [Memory Forensics AI](./lab33-memory-forensics-ai/) | Memory analysis | Volatility3, process injection, credential dumping |
| 34 | [C2 Traffic Analysis](./lab34-c2-traffic-analysis/) | Network forensics | Beaconing, DNS tunneling, encrypted C2 |
| 35 | [Lateral Movement Detection](./lab35-lateral-movement-detection/) | Attack detection | Auth anomalies, remote execution, graph analysis |
| 36 | [Threat Actor Profiling](./lab36-threat-actor-profiling/) | Attribution | TTP analysis, clustering, actor profiles |
| 37 | [AI-Powered Threats](./lab37-ai-powered-threat-actors/) | Emerging threats | AI-generated phishing, deepfakes |
| 38 | [ML Security Intro](./lab38-ml-security-intro/) | **Bridge lab** | ML threat models, attack taxonomy |
| 39 | [Adversarial ML](./lab39-adversarial-ml/) | Attack/Defense | Evasion, poisoning, robust ML defenses |
| 40 | [LLM Security Testing](./lab40-llm-security-testing/) | LLM security | Prompt injection, jailbreaks, data extraction |
| 41 | [Model Monitoring](./lab41-model-monitoring/) | Production ML | Drift detection, adversarial detection |
| 42 | [Fine-Tuning for Security](./lab42-fine-tuning-security/) | Custom models | LoRA, security embeddings, deployment |
| 43 | [RAG Security](./lab43-rag-security/) | RAG hardening | KB poisoning, context sanitization |
| 44 | [Cloud Security Fundamentals](./lab44-cloud-security-fundamentals/) | **Bridge lab** | AWS/Azure/GCP basics, IAM, CloudTrail |
| 45 | [Cloud Security AI](./lab45-cloud-security-ai/) | Multi-cloud | CloudTrail, AWS/Azure/GCP threat detection |
| 46 | [Container Security](./lab46-container-security/) | Kubernetes | Runtime detection, container escapes |
| 47 | [Serverless Security](./lab47-serverless-security/) | Lambda/Functions | Event injection, IAM analysis |
| 48 | [Cloud IR Automation](./lab48-cloud-ir-automation/) | Automation | Automated containment, evidence collection |
| 49 | [LLM Red Teaming](./lab49-llm-red-teaming/) | Offensive AI | Prompt injection, jailbreaking, agentic attacks |
| 50 | [Purple Team AI](./lab50-purple-team-ai/) | Full exercise | Attack simulation, detection validation |

**Progression:**
```
Lab 25 (DFIR) → Lab 26-28 (Windows) → Lab 30-32 (Ransomware) → Lab 33 (Memory) → Lab 34-36 (Network/Attribution)
     ↓                  ↓                      ↓                      ↓                      ↓
 "IR lifecycle"   "Windows forensics"   "Ransomware response"   "Memory analysis"   "Network forensics"

Lab 38-41 (ML Security) → Lab 42-43 (Custom Models) → Lab 44-48 (Cloud) → Lab 49-50 (Red Team)
        ↓                          ↓                        ↓                     ↓
   "Attack/defend ML"      "Fine-tune & secure"      "Cloud detection"    "Offensive AI"
```

**Bridge from Core:** Labs 25-50 build on detection skills from Labs 19-24 and apply them to advanced DFIR, adversarial ML, and cloud security scenarios. Lab 39 teaches how to attack and defend ML models. Lab 44 introduces cloud security fundamentals for those new to AWS/Azure/GCP. Labs 42-43 cover custom model training and RAG security. Lab 49 focuses on offensive security for LLM applications - prompt injection, jailbreaking, and exploiting agentic AI systems.

---

## 🎯 Quick Paths by Goal

Choose based on your objectives:

| Your Goal | Labs | Prerequisites |
|-----------|------|---------------|
| **"I'm completely new"** | 01 → 04 → 07 → 10 | Nothing! |
| **"I know Python, new to ML"** | 04 → 07 → 10 → 11 | Python basics |
| **"I know ML, teach me LLMs"** | 02 → 14 → 15 → 16 | ML experience |
| **"I want to build agents"** | 14 → 16 → 29 | API key |
| **"SOC/Detection focus"** | 10 → 12 → 23 → 31 → 35 | Python + ML basics |
| **"DFIR specialist"** | 25 → 26 → 31 → 33 → 34 | Security background |
| **"Red Team/Offensive"** | 32 → 34 → 35 → 36 → 49 | Security experience |
| **"Threat Intel Analyst"** | 16 → 18 → 34 → 36 | TI fundamentals |
| **"ML Security/Adversarial"** | 10 → 11 → 23 → 39 → 49 | ML fundamentals |
| **"LLM Security/Red Team"** | 15 → 16 → 40 → 49 | LLM + security basics |
| **"Complete everything"** | All 50 labs | Dedication |

---

## 🖥️ Interactive Demos

Each lab includes a Gradio demo for quick experimentation:

```bash
# Run any lab's demo
python labs/lab15-llm-log-analysis/scripts/app.py

# Or use the unified demo launcher
python scripts/launcher.py
```

---

## 🔄 Workflow Orchestration

Labs 22-29 use workflow orchestration for multi-stage pipelines:

```python
# Example from Lab 23: Detection Pipeline
from langgraph.graph import StateGraph

pipeline = StateGraph(DetectionState)
pipeline.add_node("ingest", ingest_events)
pipeline.add_node("ml_filter", isolation_forest_filter)
pipeline.add_node("llm_enrich", enrich_with_context)
pipeline.add_node("correlate", correlate_alerts)

pipeline.add_edge("ingest", "ml_filter")
pipeline.add_edge("ml_filter", "llm_enrich")
pipeline.add_edge("llm_enrich", "correlate")
```

---

## 🤖 Multi-Provider LLM Support

All LLM labs support multiple providers:

```python
# Choose your provider
llm = setup_llm(provider="anthropic")  # Claude
llm = setup_llm(provider="openai")     # GPT
llm = setup_llm(provider="gemini")     # Gemini
llm = setup_llm(provider="ollama")     # Local Llama
```

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10-3.12** installed (3.13+ not yet supported by PyTorch)
2. **Virtual environment** set up
3. **API keys** configured (see [Setup Guide](../docs/guides/dev-environment-setup.md))

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **RAM** | 8 GB | 16 GB (for local LLMs/embeddings) |
| **Disk Space** | 5 GB | 20 GB (with models/datasets) |
| **GPU** | Not required | CUDA-capable (for fine-tuning labs) |
| **OS** | Windows 10, macOS 10.15, Ubuntu 20.04 | Latest versions |
| **Internet** | Required for API labs | Stable connection |

> **Note:** Labs 00-13 (foundation + ML) have minimal requirements. LLM labs (14+) benefit from more RAM for embeddings.

### Running a Lab

```bash
# Navigate to lab directory
cd labs/lab10-phishing-classifier

# Install dependencies
pip install -r requirements.txt  # If present
# Or install from main requirements

# Run starter code
python starter/main.py

# Compare with solution
python solution/main.py
```

---

## 📚 Lab Structure

Each lab follows this structure:

```
labXX-topic-name/
├── README.md           # Instructions, objectives, hints
├── starter/            # Starter code with TODOs
│   └── main.py
├── solution/           # Reference implementation
│   └── main.py
└── data/               # Sample datasets (most labs)
    └── *.csv
```

> **Note:** Test coverage is provided at the repository level in `tests/` rather than per-lab. Run `pytest tests/test_labXX*.py` to test specific labs.

---

## 🎯 Learning Path

### Foundation Path

Build core ML skills for security:

```
Lab 10 → Lab 11 → Lab 12
   ↓        ↓        ↓
 Text    Clustering  Anomaly
  ML                Detection
```

### LLM Path

Master LLMs for security applications:

```
Lab 15 → Lab 16 → Lab 18 → Lab 21
   ↓        ↓        ↓        ↓
  Log     Agents    RAG     YARA
Analysis            Docs   Generation
```

### Advanced Path

Build production systems:

```
Lab 22 → Lab 23 → Lab 29
   ↓        ↓        ↓
 Vuln    Detection   IR
Scanner  Pipeline  Copilot
```

---

## 🏆 Lab Summaries

### Lab 10: Phishing Email Classifier

**Build a machine learning classifier to detect phishing emails.**

Skills learned:
- Text preprocessing and feature extraction
- TF-IDF vectorization
- Random Forest classification
- Model evaluation (precision, recall, F1)

Key files:
- `starter/main.py` - Complete the TODOs
- `solution/main.py` - Reference implementation

---

### Lab 11: Malware Sample Clustering

**Use unsupervised learning to cluster malware samples by characteristics.**

Skills learned:
- Feature engineering for malware
- K-Means and DBSCAN clustering
- t-SNE/UMAP visualization
- Cluster analysis and interpretation

Key concepts:
- Import hashes (imphash)
- PE file structure
- Entropy analysis

---

### Lab 12: Network Anomaly Detection

**Build an anomaly detection system for network traffic.**

Skills learned:
- Network flow features
- Isolation Forest algorithm
- Autoencoder-based detection
- Threshold tuning and evaluation

Attack types detected:
- C2 beaconing
- Data exfiltration
- Port scanning
- DDoS indicators

---

### Lab 15: LLM-Powered Log Analysis

**Use Large Language Models to analyze and explain security logs.**

Skills learned:
- LLM prompt engineering
- Structured output parsing
- IOC extraction
- MITRE ATT&CK mapping

Key capabilities:
- Log parsing and normalization
- Threat pattern recognition
- Incident summarization
- Response recommendations

---

### Lab 16: Threat Intelligence Agent

**Build an AI agent that autonomously gathers and correlates threat intel.**

Skills learned:
- ReAct agent pattern
- Tool design for agents
- Memory management
- Multi-step reasoning

Agent capabilities:
- IP/domain reputation lookup
- Hash analysis
- CVE research
- ATT&CK technique mapping

---

### Lab 18: Security RAG System

**Build a Retrieval-Augmented Generation system for security documentation.**

Skills learned:
- Document loading and chunking
- Vector embeddings and ChromaDB
- Semantic search implementation
- Context-aware LLM responses

Use cases:
- CVE lookup and analysis
- MITRE ATT&CK technique queries
- Playbook recommendations
- Security policy Q&A

---

### Lab 21: AI YARA Rule Generator

**Use LLMs to automatically generate YARA rules from malware samples.**

Skills learned:
- Binary analysis basics
- String and pattern extraction
- LLM-powered rule generation
- YARA syntax validation

Key capabilities:
- Malware sample analysis
- Suspicious string detection
- Rule optimization
- False positive reduction

---

### Lab 22: Vulnerability Scanner AI

**Build an AI-enhanced vulnerability scanner with intelligent prioritization.**

Skills learned:
- Vulnerability assessment
- CVSS scoring interpretation
- Risk-based prioritization
- Remediation planning

Features:
- Asset-aware scanning
- Business context integration
- Automated report generation
- Remediation recommendations

---

### Lab 23: Threat Detection Pipeline

**Build a multi-stage threat detection pipeline combining ML and LLMs.**

Skills learned:
- Event ingestion and normalization
- ML-based filtering (Isolation Forest)
- LLM enrichment and analysis
- Event correlation techniques

Pipeline stages:
1. Ingest & normalize events
2. ML filter (reduce noise)
3. LLM enrich (add context)
4. Correlate related events
5. Generate verdicts & alerts

---

### Lab 29: IR Copilot Agent

**Build a conversational AI copilot for incident response.**

Skills learned:
- Conversational agent design
- Multi-tool orchestration
- State management
- Confirmation workflows

Copilot capabilities:
- SIEM/SOAR queries and log analysis (Elasticsearch, OpenSearch, etc.)
- IOC lookup and enrichment
- Host isolation and containment
- Timeline and report generation
- Playbook-guided response

---

### Lab 31: Ransomware Detection & Response (DFIR)

**Build an AI-powered system to detect, analyze, and respond to ransomware attacks.**

Skills learned:
- Ransomware behavioral detection
- Entropy-based encryption detection
- Ransom note analysis with LLMs
- Automated incident response playbooks

Key capabilities:
- File system event analysis
- Shadow copy deletion detection
- IOC extraction from ransom notes
- YARA/Sigma rule generation
- Recovery planning assistance

---

### Lab 32: Ransomware Attack Simulation (Purple Team)

**Build safe simulation tools for testing ransomware defenses.**

Skills learned:
- Adversary emulation planning
- Safe simulation techniques
- Detection validation frameworks
- Gap analysis and reporting

Purple team capabilities:
- Attack scenario generation
- Safe ransomware behavior simulation
- Detection coverage testing
- Adversary emulation playbooks
- Exercise orchestration

**Ethical Note:** This lab emphasizes safe, authorized testing only.

---

### Lab 33: AI-Powered Memory Forensics

**Use AI/ML to analyze memory dumps and detect advanced threats.**

Skills learned:
- Memory forensics with Volatility3
- Process injection detection
- Credential dumping identification
- Rootkit and hiding technique detection
- LLM-powered artifact interpretation

Key capabilities:
- Automated memory artifact extraction
- Process anomaly detection with ML
- Malicious code pattern recognition
- Credential exposure assessment
- IOC extraction from memory

---

### Lab 34: C2 Traffic Analysis

**Detect and analyze command-and-control communications.**

Skills learned:
- Network traffic feature extraction
- Beaconing detection algorithms
- DNS tunneling identification
- Encrypted C2 traffic analysis
- JA3/JA3S fingerprinting

Detection capabilities:
- Beacon pattern detection (jitter, intervals)
- DNS exfiltration identification
- HTTP C2 pattern matching
- TLS fingerprint anomalies
- LLM-powered traffic interpretation

---

### Lab 35: Lateral Movement Detection

**Detect adversary lateral movement techniques in enterprise environments.**

Skills learned:
- Authentication anomaly detection
- Remote execution technique identification
- Graph-based attack path analysis
- Windows security event correlation
- LLM-powered alert triage

Detection capabilities:
- PsExec, WMI, WinRM execution detection
- Unusual authentication patterns
- First-time host access alerts
- Service account abuse detection
- Attack path visualization

---

### Lab 36: Threat Actor Profiling

**Build AI systems to profile and attribute threat actors.**

Skills learned:
- TTP extraction and encoding
- Campaign clustering for attribution
- Malware code similarity analysis
- LLM-powered profile generation
- Diamond Model analysis

Attribution capabilities:
- MITRE ATT&CK technique mapping
- Known actor matching
- Behavioral pattern clustering
- Infrastructure overlap analysis
- Predictive actor behavior modeling

---

### Lab 39: Adversarial Machine Learning

**Attack and defend AI security models.**

Skills learned:
- Evasion attack techniques (FGSM, PGD)
- Data poisoning and backdoor attacks
- Adversarial training for robustness
- Input validation and sanitization
- Ensemble defenses

Security capabilities:
- Attack malware classifiers with perturbations
- Defend against adversarial inputs
- Build robust ML-based detectors
- Evaluate model robustness
- Understand real-world ML attacks

---

### Lab 42: Fine-Tuning for Security

**Build custom security-focused AI models.**

Skills learned:
- Custom embedding training for security data
- LoRA (Low-Rank Adaptation) fine-tuning
- Security-specific model evaluation
- Model deployment best practices

Key capabilities:
- Train embeddings on security datasets
- Fine-tune LLMs for security tasks
- Create specialized classification models
- Deploy models in production environments
- Evaluate security-specific metrics

---

### Lab 45: Cloud Security AI

**Build AI-powered multi-cloud security tools.**

Skills learned:
- AWS CloudTrail log analysis
- Azure and GCP security monitoring
- Multi-cloud threat detection patterns
- Cloud-native security automation

Detection capabilities:
- Suspicious IAM activity detection
- Resource enumeration alerts
- Privilege escalation detection
- Cross-cloud attack correlation
- Cloud misconfiguration identification

---

### Lab 49: LLM Red Teaming

**Attack AI systems - prompt injection, jailbreaking, and agentic exploits.**

Skills learned:
- Prompt injection attacks (direct and indirect)
- System prompt extraction techniques
- Jailbreaking and safety bypass methods
- Agentic AI exploitation (goal hijacking, tool abuse)
- Defense strategies for LLM applications

Attack capabilities:
- Extract secrets from LLM applications
- Bypass safety guardrails
- Hijack autonomous AI agents
- Exploit RAG systems with poisoned data
- Build red team testing frameworks

---

## 💡 Tips for Success

### Before Starting

1. **Read the README** completely before coding
2. **Understand the objectives** - know what you're building
3. **Set up your environment** - all dependencies installed
4. **Configure API keys** - especially for LLM labs

### While Working

1. **Start with starter code** - don't look at solutions first
2. **Work through TODOs** in order
3. **Test incrementally** - run code frequently
4. **Use hints sparingly** - try to solve problems yourself

### When Stuck

1. **Re-read the instructions**
2. **Check the hints** (expandable sections)
3. **Review the background** information
4. **Peek at solution** as last resort

### After Completing

1. **Compare with solution** - learn different approaches
2. **Try bonus challenges** - extend your learning
3. **Document learnings** - update your notes
4. **Share and discuss** - with study group

---

## 🔧 Common Issues

### Import Errors

```bash
# Make sure you're in virtual environment
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install missing packages
pip install <package_name>
```

### API Key Issues

```bash
# Check environment variables
echo $ANTHROPIC_API_KEY   # Linux/Mac
echo %ANTHROPIC_API_KEY%  # Windows

# Or add to .env file
echo "ANTHROPIC_API_KEY=your_key" >> .env
```

### Data File Not Found

```python
# Use Path for cross-platform paths
from pathlib import Path

data_path = Path(__file__).parent.parent / "data" / "file.csv"
```

---

## 📊 Progress Tracking

Track your progress:

**Prerequisites (Optional but Recommended)**
- [ ] Lab 00: Environment Setup
- [ ] Lab 01: Python for Security Fundamentals
- [ ] Lab 02: Intro to Prompt Engineering
- [ ] Lab 03: Vibe Coding with AI
- [ ] Lab 04: ML Concepts Primer
- [ ] Lab 05: AI in Security Operations (conceptual)
- [ ] Lab 06: Visualization & Statistics
- [ ] Lab 07: Hello World ML (first classifier!)
- [ ] Lab 08: Working with APIs (HTTP/JSON skills)
- [ ] Lab 09: CTF Fundamentals

**Core Labs**
- [ ] Lab 10: Phishing Classifier
- [ ] Lab 11: Malware Clustering
- [ ] Lab 12: Anomaly Detection
- [ ] Lab 13: ML vs LLM Decision (bridge lab)
- [ ] Lab 14: Your First AI Agent (bridge lab)
- [ ] Lab 15: LLM Log Analysis
- [ ] Lab 16: Threat Intel Agent
- [ ] Lab 17: Embeddings & Vectors
- [ ] Lab 18: Security RAG
- [ ] Lab 19: Binary Analysis Basics
- [ ] Lab 20: Sigma Fundamentals
- [ ] Lab 21: YARA Generator
- [ ] Lab 22: Vuln Scanner AI
- [ ] Lab 23: Detection Pipeline
- [ ] Lab 24: Monitoring AI Systems
- [ ] Lab 25: DFIR Fundamentals
- [ ] Lab 26: Windows Event Log Analysis
- [ ] Lab 27: Windows Registry Forensics
- [ ] Lab 28: Live Response
- [ ] Lab 29: IR Copilot
- [ ] Lab 30: Ransomware Fundamentals
- [ ] Lab 31: Ransomware Detection
- [ ] Lab 32: Ransomware Simulation
- [ ] Lab 33: Memory Forensics AI
- [ ] Lab 34: C2 Traffic Analysis
- [ ] Lab 35: Lateral Movement Detection
- [ ] Lab 36: Threat Actor Profiling
- [ ] Lab 37: AI-Powered Threats
- [ ] Lab 38: ML Security Intro
- [ ] Lab 39: Adversarial ML
- [ ] Lab 40: LLM Security Testing
- [ ] Lab 41: Model Monitoring
- [ ] Lab 42: Fine-Tuning for Security
- [ ] Lab 43: RAG Security
- [ ] Lab 44: Cloud Security Fundamentals
- [ ] Lab 45: Cloud Security AI
- [ ] Lab 46: Container Security
- [ ] Lab 47: Serverless Security
- [ ] Lab 48: Cloud IR Automation
- [ ] Lab 49: LLM Red Teaming
- [ ] Lab 50: Purple Team AI

---

## 🎯 CTF Challenges

Test your skills with capture-the-flag challenges! These are separate from labs and provide hands-on practice.

### Beginner Challenges (100 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [Log Detective](../ctf/beginner/01-log-detective/) | Lab 15 | Log analysis, pattern recognition |
| [Phish Finder](../ctf/beginner/02-phish-finder/) | Lab 10 | Email classification, IOC extraction |

### Intermediate Challenges (250 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [C2 Hunter](../ctf/intermediate/01-c2-hunter/) | Lab 34 | Beaconing, DNS tunneling |
| [Memory Forensics](../ctf/intermediate/02-memory-forensics/) | Lab 33 | Process injection, shellcode |
| [Adversarial Samples](../ctf/intermediate/03-adversarial-samples/) | Lab 39 | ML evasion, PE analysis |
| [Agent Investigation](../ctf/intermediate/04-agent-investigation/) | Lab 16 | Prompt injection, ReAct debugging |
| [Ransomware Response](../ctf/intermediate/05-ransomware-response/) | Lab 31 | Crypto weakness, key recovery |

### Advanced Challenges (500 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [APT Attribution](../ctf/advanced/01-apt-attribution/) | Lab 36 | TTP mapping, actor profiling |
| [Model Poisoning](../ctf/advanced/02-model-poisoning/) | Lab 39 | Backdoor detection, data poisoning |
| [Cloud Compromise](../ctf/advanced/03-cloud-compromise/) | Lab 45 | Multi-cloud forensics |
| [Zero-Day Hunt](../ctf/advanced/04-zero-day-hunt/) | Lab 12 | Behavioral anomaly detection |
| [Full IR Scenario](../ctf/advanced/05-full-ir-scenario/) | Lab 29 | Complete IR lifecycle |

> 💡 **Tip**: Complete the recommended lab before attempting each CTF challenge for the best learning experience. Labs teach the concepts; CTFs test your skills!

> 📝 **More challenges coming soon!** Intermediate and advanced CTF challenges are in development.

---

## 🤝 Contributing

Found an issue or have an improvement?

1. Open an issue describing the problem
2. Submit a PR with fixes
3. Add new test cases
4. Improve documentation

---

## 📚 Additional Resources

- [Curriculum Overview](../docs/ai-security-training-program.md)
- [Development Setup](../docs/guides/dev-environment-setup.md)
- [Tools & Resources](../resources/tools-and-resources.md)
- [Cursor IDE Guide](../docs/guides/cursor-ide-guide.md)

---

Happy Hacking! 🛡️

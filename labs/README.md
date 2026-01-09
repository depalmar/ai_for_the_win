# 🧪 Hands-On Labs

Practical labs for building AI-powered security tools.

> 📖 **New to the course?** Start with [GETTING_STARTED.md](../docs/GETTING_STARTED.md) for setup, then see [Learning Guide](../docs/learning-guide.md) for learning paths.

---

## Labs in Recommended Order

Follow this progression for the best learning experience. Labs build on each other.

### 🎯 Getting Started: Prerequisites

**New to Python, ML, or LLMs?** Start here before Lab 29.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 01 | [Python for Security](./lab01-python-security-fundamentals/) | Python basics | Variables, files, APIs, security examples |
| 04 | [ML Concepts Primer](./lab04-ml-concepts-primer/) | ML theory | Supervised/unsupervised, features, evaluation |
| 02 | [Intro to Prompt Engineering](./lab02-intro-prompt-engineering/) | LLM prompting | Prompt design, hallucination detection, AI Studio |
| 05 | [AI in Security Operations](./lab05-ai-in-security-operations/) | SOC integration | Where AI fits, human-in-the-loop, compliance |
| 06 | [Visualization & Statistics](./lab06-visualization-stats/) | Data viz | Plotly, Gradio, statistics, dashboards |
| 07 | [Hello World ML](./lab07-hello-world-ml/) | First classifier | 4-step ML workflow, accuracy, precision, recall |
| 08 | [Working with APIs](./lab08-working-with-apis/) | HTTP & REST | requests library, JSON, API keys, rate limiting |
| 03 | [Vibe Coding with AI](./lab03-vibe-coding-with-ai/) | AI assistants | Claude Code, Cursor, Copilot, accelerated learning |

**Who should do these:**
- No Python experience → Start with **01**
- Python OK, new to ML → Start with **04** then **07**
- Want to use LLMs effectively → Do **02** (highly recommended!)
- Want SOC/operational context → Do **05** (conceptual, no coding)
- Need visualization skills → Do **06** (Plotly, Gradio, dashboards)
- **New! First ML model** → Do **07** before Lab 29 (simpler intro)
- **New! API skills** → Do **08** before Labs 04-07 (LLM APIs)
- **New! Accelerate your learning** → Do **03** to use AI assistants throughout the course
- Comfortable with all → Skip to Lab 29

```
Lab 29 (Python) → Lab 35 (ML) → Lab 21 (First ML) → Lab 29 (Phishing)
     ↓                 ↓                 ↓                   ↓
 "Learn Python    "Understand       "Build your         "Build real
  basics"          ML theory"        FIRST model"        classifier"

Lab 31 (Prompts) → Lab 22 (APIs) → Lab 35 (LLM Log Analysis)
     ↓                  ↓                   ↓
 "Master LLM        "HTTP & JSON       "Use LLMs
  prompting"         skills"            for security"
```

> 💡 **Pro Tip:** Even experienced developers should do **Lab 31** and **Lab 36** - prompt engineering and SOC context are critical for real-world deployment!

---

### 🟢 Foundation: ML Basics

Start here if you're new to ML for security. These labs teach core concepts.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 01 | [Phishing Classifier](./lab10-phishing-classifier/) | Text classification | TF-IDF, Random Forest, precision/recall |
| 02 | [Malware Clustering](./lab11-malware-clustering/) | Unsupervised learning | K-Means, t-SNE, PE file features |
| 03 | [Anomaly Detection](./lab12-anomaly-detection/) | Outlier detection | Isolation Forest, network features |
| 03b | [ML vs LLM Decision](./lab33-ml-vs-llm/) | **NEW! Bridge lab** | When to use ML vs LLM, hybrid systems |

**Progression:**
```
Lab 29 (Text ML) → Lab 31 (Clustering) → Lab 32 (Anomaly) → Lab 33 (ML vs LLM)
     ↓                  ↓                      ↓                   ↓
 "Classify           "Group              "Find unusual        "When to use
  emails"            malware"             traffic"             ML vs LLM?"
```

**Bridge to LLMs:** Lab 33 is the critical bridge between ML and LLM sections. It teaches you when to use each approach and how to combine them effectively.

---

### 🟡 Core Skills: LLM Security Tools

Learn to apply Large Language Models to security problems.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 04 | [LLM Log Analysis](./lab15-llm-log-analysis/) | Prompt engineering | Structured outputs, IOC extraction |
| 04b | [Your First AI Agent](./lab34-first-ai-agent/) | **NEW! Bridge lab** | Tool calling, ReAct basics |
| 06a | [Embeddings & Vectors](./lab17-embeddings-vectors/) | **NEW! Bridge lab** | How embeddings work, semantic search |
| 06 | [Security RAG](./lab18-security-rag/) | Vector search + LLM | Embeddings, ChromaDB, retrieval |
| 07a | [Binary Analysis Basics](./lab45-binary-basics/) | **NEW! Bridge lab** | PE structure, entropy, imports |
| 07 | [YARA Generator](./lab21-yara-generator/) | AI code generation | Binary analysis, rule generation |

**Progression:**
```
Lab 35 (Prompts) → Lab 34 (First Agent) → Lab 39 (Embeddings) → Lab 42 (RAG) → Lab 21 (YARA)
     ↓                   ↓                        ↓                    ↓              ↓
 "Parse logs       "Simple tool           "How vectors        "Build RAG      "Generate
  with LLM"         calling"               work"               system"         YARA rules"
```

**Bridge to Full Agents:** Lab 34 teaches basic tool calling. This prepares you for Lab 36's full ReAct agent with memory and multiple tools.

> ⚠️ **Note about Lab 36**: Despite its number, Lab 36 is in the "Advanced" section below because it builds on concepts from Labs 04-07. Do Lab 34 first if agents feel complex!

---

### 🟠 Advanced: Autonomous Systems

Build AI agents and multi-stage pipelines.

> 💡 **Why is Lab 36 here?** Lab 36 is numbered "05" but lives in the Advanced section because it requires understanding tool calling (Lab 34), RAG (Lab 42), and prompt engineering (Lab 35). The numbering is historical - follow the progression below, not the numbers!

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 05 | [Threat Intel Agent](./lab16-threat-intel-agent/) | AI agents | Full ReAct pattern, tools, memory |
| 08 | [Vuln Scanner AI](./lab22-vuln-scanner-ai/) | Risk prioritization | CVSS, business context |
| 09 | [Detection Pipeline](./lab23-detection-pipeline/) | ML + LLM pipeline | Multi-stage detection |
| 09b | [Monitoring AI Systems](./lab24-monitoring-ai-systems/) | **NEW! Bridge lab** | Observability, drift detection, logging |
| 10 | [IR Copilot](./lab29-ir-copilot/) | Conversational AI | Orchestration, confirmation |

**Progression:**
```
Lab 34 (First Agent) → Lab 36 (Full Agent) → Lab 22 (Vuln) → Lab 23 (Pipeline) → Lab 24 (Monitoring)
        ↓                       ↓                  ↓                ↓                    ↓
   "Simple tools"        "ReAct + memory"    "Prioritize      "Combine           "Monitor
                                              risks"           ML + LLM"          in prod"
```

---

### 🔴 Expert: DFIR & Red Team

Deep dive into incident response, threat simulation, and offensive security analysis.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 10a | [DFIR Fundamentals](./lab25-dfir-fundamentals/) | **Bridge lab** | IR lifecycle, artifacts, ATT&CK mapping |
| 10b | [Windows Event Log Analysis](./lab26-windows-event-log-analysis/) | **NEW!** | Event IDs, lateral movement, credential theft |
| 10c | [Windows Registry Forensics](./lab27-windows-registry-forensics/) | **NEW!** | Persistence hunting, forensic artifacts |
| 10d | [Live Response](./lab28-live-response/) | **NEW!** | Collection techniques, triage checklist |
| 11a | [Ransomware Fundamentals](./lab30-ransomware-fundamentals/) | **NEW! Bridge lab** | Evolution, families, indicators, recovery |
| 11 | [Ransomware Detection](./lab31-ransomware-detection/) | Behavioral detection | Entropy, TTPs, response |
| 12 | [Purple Team](./lab32-ransomware-simulation/) | Adversary emulation | Safe simulation, gap analysis |
| 13 | [Memory Forensics AI](./lab33-memory-forensics-ai/) | Memory analysis | Volatility3, process injection, credential dumping |
| 14 | [C2 Traffic Analysis](./lab34-c2-traffic-analysis/) | Network forensics | Beaconing, DNS tunneling, encrypted C2 |
| 15 | [Lateral Movement Detection](./lab35-lateral-movement-detection/) | Attack detection | Auth anomalies, remote execution, graph analysis |
| 16 | [Threat Actor Profiling](./lab36-threat-actor-profiling/) | Attribution | TTP analysis, clustering, actor profiles |
| 17a | [ML Security Intro](./lab38-ml-security-intro/) | **NEW! Bridge lab** | ML threat models, attack taxonomy |
| 17 | [Adversarial ML](./lab39-adversarial-ml/) | Attack/Defense | Evasion, poisoning, robust ML defenses |
| 17b | [LLM Security Testing](./lab40-llm-security-testing/) | **NEW!** | Prompt injection, jailbreaks, data extraction |
| 17c | [Model Monitoring](./lab41-model-monitoring/) | **NEW!** | Drift detection, adversarial detection |
| 18 | [Fine-Tuning for Security](./lab42-fine-tuning-security/) | Custom models | LoRA, security embeddings, deployment |
| 18b | [RAG Security](./lab43-rag-security/) | **NEW!** | KB poisoning, context sanitization |
| 19a | [Cloud Security Fundamentals](./lab44-cloud-security-fundamentals/) | **NEW! Bridge lab** | AWS/Azure/GCP basics, IAM, CloudTrail |
| 19 | [Cloud Security AI](./lab45-cloud-security-ai/) | Multi-cloud | CloudTrail, AWS/Azure/GCP threat detection |
| 19b | [Container Security](./lab46-container-security/) | **NEW!** | Kubernetes, runtime detection, escapes |
| 19c | [Serverless Security](./lab47-serverless-security/) | **NEW!** | Lambda analysis, event injection, IAM |
| 19d | [Cloud IR Automation](./lab48-cloud-ir-automation/) | **NEW!** | Automated containment, evidence collection |
| 20 | [LLM Red Teaming](./lab49-llm-red-teaming/) | Offensive AI Security | Prompt injection, jailbreaking, agentic attacks |

**Progression:**
```
Lab 25 (DFIR Fundamentals) → Lab 30 (Ransomware Basics) → Lab 31 (Detection) → Lab 32 (Purple Team) → Lab 33 (Memory)
     ↓                           ↓                     ↓                      ↓
 "Learn IR              "Detect              "Validate              "Analyze
  lifecycle"             ransomware"          detections"            memory dumps"

Lab 34 (C2 Traffic) → Lab 35 (Lateral Movement) → Lab 36 (Attribution) → Lab 39 (Adversarial)
     ↓                      ↓                          ↓                      ↓
 "Detect C2            "Track attacker           "Profile             "Attack/defend
  communications"        movement"                threat actors"        ML models"

Lab 42 (Fine-Tuning) → Lab 44 (Cloud Fundamentals) → Lab 45 (Cloud Security AI) → Lab 49 (LLM Red Team)
     ↓                          ↓                           ↓                          ↓
 "Build custom            "Learn cloud                 "AI-powered              "Attack AI
  security models"         security basics"             cloud detection"          systems"
```

**Bridge from Core:** Labs 11-20 build on detection skills from Labs 09-10 and apply them to advanced DFIR, adversarial ML, and cloud security scenarios. Lab 39 teaches how to attack and defend ML models. Lab 44 introduces cloud security fundamentals for those new to AWS/Azure/GCP. Labs 18-19 cover custom model training and multi-cloud security. Lab 49 focuses on offensive security for LLM applications - prompt injection, jailbreaking, and exploiting agentic AI systems.

---

## 🎯 Quick Paths by Goal

Choose based on your objectives:

| Your Goal | Labs | Prerequisites |
|-----------|------|---------------|
| **"I'm completely new"** | 01 → 04 → 02 → 01 | Nothing! |
| **"I know Python, new to ML"** | 04 → 02 → 01 → 02 | Python basics |
| **"I know ML, teach me LLMs"** | 02 → 04 → 06 → 05 | ML experience |
| **"I want to build agents"** | 04 → 05 → 10 | API key |
| **"SOC/Detection focus"** | 01 → 03 → 09 → 11 → 15 | Python + ML basics |
| **"DFIR specialist"** | 04 → 05 → 11 → 13 → 14 | Security background |
| **"Red Team/Offensive"** | 12 → 14 → 15 → 16 → 20 | Security experience |
| **"Threat Intel Analyst"** | 05 → 06 → 14 → 16 | TI fundamentals |
| **"ML Security/Adversarial"** | 01 → 02 → 09 → 17 → 20 | ML fundamentals |
| **"LLM Security/Red Team"** | 04 → 05 → 17 → 20 | LLM + security basics |
| **"Complete everything"** | All 24 labs | Dedication |

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

Labs 09-12 use workflow orchestration for multi-stage pipelines:

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
llm = setup_llm(provider="openai")     # GPT-4
llm = setup_llm(provider="gemini")     # Gemini 1.5 Pro
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

> **Note:** Labs 00-03 (ML only) have minimal requirements. LLM labs (04+) benefit from more RAM for embeddings.

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
Lab 29 → Lab 31 → Lab 32
   ↓        ↓        ↓
 Text    Clustering  Anomaly
  ML                Detection
```

### LLM Path

Master LLMs for security applications:

```
Lab 35 → Lab 36 → Lab 42 → Lab 21
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

### Lab 29: Phishing Email Classifier

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

### Lab 31: Malware Sample Clustering

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

### Lab 32: Network Anomaly Detection

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

### Lab 35: LLM-Powered Log Analysis

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

### Lab 36: Threat Intelligence Agent

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

### Lab 42: Security RAG System

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
- SIEM/SOAR queries and log analysis (Splunk, Elastic, Sentinel, etc.)
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
- [ ] Lab 29: Python for Security Fundamentals
- [ ] Lab 35: ML Concepts Primer
- [ ] Lab 31: Intro to Prompt Engineering
- [ ] Lab 36: AI in Security Operations (conceptual)
- [ ] Lab 42: Visualization & Statistics
- [ ] Lab 21: Hello World ML (NEW - first classifier!)
- [ ] Lab 22: Working with APIs (NEW - HTTP/JSON skills)
- [ ] Lab 32: Vibe Coding with AI (NEW - AI-assisted development)

**Core Labs**
- [ ] Lab 29: Phishing Classifier
- [ ] Lab 31: Malware Clustering
- [ ] Lab 32: Anomaly Detection
- [ ] Lab 33: ML vs LLM Decision (bridge lab)
- [ ] Lab 35: LLM Log Analysis
- [ ] Lab 34: Your First AI Agent (NEW - bridge lab)
- [ ] Lab 39: Embeddings & Vectors (how vectors work)
- [ ] Lab 45: Binary Analysis Basics (PE fundamentals)
- [ ] Lab 36: Threat Intel Agent
- [ ] Lab 42: Security RAG
- [ ] Lab 21: YARA Generator
- [ ] Lab 22: Vuln Scanner AI
- [ ] Lab 23: Detection Pipeline
- [ ] Lab 24: Monitoring AI Systems (NEW - production observability)
- [ ] Lab 29: IR Copilot
- [ ] Lab 25: DFIR Fundamentals (IR lifecycle prep)
- [ ] Lab 26: Windows Event Log Analysis (NEW)
- [ ] Lab 27: Windows Registry Forensics (NEW)
- [ ] Lab 28: Live Response (NEW)
- [ ] Lab 30: Ransomware Fundamentals (NEW - bridge lab)
- [ ] Lab 31: Ransomware Detection
- [ ] Lab 32: Ransomware Simulation
- [ ] Lab 33: Memory Forensics AI
- [ ] Lab 34: C2 Traffic Analysis
- [ ] Lab 35: Lateral Movement Detection
- [ ] Lab 36: Threat Actor Profiling
- [ ] Lab 38: ML Security Intro (threat models for ML)
- [ ] Lab 39: Adversarial ML
- [ ] Lab 42: Fine-Tuning for Security
- [ ] Lab 44: Cloud Security Fundamentals (NEW - cloud basics)
- [ ] Lab 45: Cloud Security AI
- [ ] Lab 49: LLM Red Teaming

---

## 🎯 CTF Challenges

Test your skills with capture-the-flag challenges! These are separate from labs and provide hands-on practice.

### Beginner Challenges (100 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [Log Detective](../ctf/beginner/01-log-detective/) | Lab 35 | Log analysis, pattern recognition |
| [Phish Finder](../ctf/beginner/02-phish-finder/) | Lab 29 | Email classification, IOC extraction |

### Intermediate Challenges (250 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [C2 Hunter](../ctf/intermediate/01-c2-hunter/) | Lab 34 | Beaconing, DNS tunneling |
| [Memory Forensics](../ctf/intermediate/02-memory-forensics/) | Lab 33 | Process injection, shellcode |
| [Adversarial Samples](../ctf/intermediate/03-adversarial-samples/) | Lab 39 | ML evasion, PE analysis |
| [Agent Investigation](../ctf/intermediate/04-agent-investigation/) | Lab 36 | Prompt injection, ReAct debugging |
| [Ransomware Response](../ctf/intermediate/05-ransomware-response/) | Lab 31 | Crypto weakness, key recovery |

### Advanced Challenges (500 pts each)

| Challenge | After Lab | Skills Tested |
|-----------|-----------|---------------|
| [APT Attribution](../ctf/advanced/01-apt-attribution/) | Lab 36 | TTP mapping, actor profiling |
| [Model Poisoning](../ctf/advanced/02-model-poisoning/) | Lab 39 | Backdoor detection, data poisoning |
| [Cloud Compromise](../ctf/advanced/03-cloud-compromise/) | Lab 45 | Multi-cloud forensics |
| [Zero-Day Hunt](../ctf/advanced/04-zero-day-hunt/) | Lab 32 | Behavioral anomaly detection |
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

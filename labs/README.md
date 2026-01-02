# 🧪 Hands-On Labs

Practical labs for building AI-powered security tools.

> 📖 **New to the course?** Start with [GETTING_STARTED.md](../GETTING_STARTED.md) for setup, then see [Learning Guide](../docs/learning-guide.md) for learning paths.

---

## Labs in Recommended Order

Follow this progression for the best learning experience. Labs build on each other.

### 🎯 Getting Started: Prerequisites

**New to Python, ML, or LLMs?** Start here before Lab 01.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 00a | [Python for Security](./lab00a-python-security-fundamentals/) | Python basics | Variables, files, APIs, security examples |
| 00b | [ML Concepts Primer](./lab00b-ml-concepts-primer/) | ML theory | Supervised/unsupervised, features, evaluation |
| 00c | [Intro to Prompt Engineering](./lab00c-intro-prompt-engineering/) | LLM prompting | Prompt design, hallucination detection, AI Studio |
| 00d | [AI in Security Operations](./lab00d-ai-in-security-operations/) | SOC integration | Where AI fits, human-in-the-loop, compliance |
| 00e | [Visualization & Statistics](./lab00e-visualization-stats/) | Data viz | Plotly, statistics, dashboards, distributions |

**Who should do these:**
- No Python experience → Start with **00a**
- Python OK, new to ML → Start with **00b**
- Want to use LLMs effectively → Do **00c** (highly recommended!)
- Want SOC/operational context → Do **00d** (conceptual, no coding)
- Need visualization skills → Do **00e** (Plotly, stats, dashboards)
- Comfortable with all → Skip to Lab 01

```
Lab 00a (Python) → Lab 00b (ML Concepts) → Lab 00c (Prompting) → Lab 00d (SOC) → Lab 00e (Viz) → Lab 01
     ↓                   ↓                       ↓                    ↓               ↓             ↓
 "Learn Python      "Understand ML         "Master LLM          "Understand     "Master        "Build your
  with security      theory before          prompts &            where AI fits    Plotly &       first ML
  examples"          coding"                verification"        in SOC"          dashboards"    classifier"
```

> 💡 **Pro Tip:** Even experienced developers should do **Lab 00c** and **Lab 00d** - prompt engineering and SOC context are critical for real-world deployment!

---

### 🟢 Foundation: ML Basics

Start here if you're new to ML for security. These labs teach core concepts.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 01 | [Phishing Classifier](./lab01-phishing-classifier/) | Text classification | TF-IDF, Random Forest, precision/recall |
| 02 | [Malware Clustering](./lab02-malware-clustering/) | Unsupervised learning | K-Means, t-SNE, PE file features |
| 03 | [Anomaly Detection](./lab03-anomaly-detection/) | Outlier detection | Isolation Forest, network features |

**Progression:**
```
Lab 01 (Text ML) → Lab 02 (Clustering) → Lab 03 (Anomaly Detection)
     ↓                  ↓                      ↓
 "Classify           "Group              "Find unusual
  emails"            malware"             network traffic"
```

**Bridge to LLMs:** After Lab 03, you understand ML classification and anomaly detection. Lab 04 introduces how LLMs can enhance these with natural language understanding.

---

### 🟡 Core Skills: LLM Security Tools

Learn to apply Large Language Models to security problems.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 04 | [LLM Log Analysis](./lab04-llm-log-analysis/) | Prompt engineering | Structured outputs, IOC extraction |
| 06 | [Security RAG](./lab06-security-rag/) | Vector search + LLM | Embeddings, ChromaDB, retrieval |
| 07 | [YARA Generator](./lab07-yara-generator/) | AI code generation | Binary analysis, rule generation |

**Progression:**
```
Lab 04 (Prompts) → Lab 06 (RAG) → Lab 07 (Code Gen)
     ↓                 ↓              ↓
 "Parse logs      "Search docs     "Generate
  with LLM"        with AI"         YARA rules"
```

**Bridge to Agents:** Labs 04-07 teach you to use LLMs for specific tasks. Lab 05 combines these into an autonomous agent that can reason and use tools.

---

### 🟠 Advanced: Autonomous Systems

Build AI agents and multi-stage pipelines.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 05 | [Threat Intel Agent](./lab05-threat-intel-agent/) | AI agents | ReAct pattern, tools, memory |
| 08 | [Vuln Scanner AI](./lab08-vuln-scanner-ai/) | Risk prioritization | CVSS, business context |
| 09 | [Detection Pipeline](./lab09-detection-pipeline/) | ML + LLM pipeline | Multi-stage detection |
| 10 | [IR Copilot](./lab10-ir-copilot/) | Conversational AI | Orchestration, confirmation |

**Progression:**
```
Lab 05 (Agents) → Lab 08 (Vuln) → Lab 09 (Pipeline) → Lab 10 (Copilot)
     ↓                ↓                ↓                   ↓
 "Autonomous       "Prioritize      "Combine           "Interactive
  investigation"    risks"           ML + LLM"          assistant"
```

---

### 🔴 Expert: DFIR & Red Team

Deep dive into incident response, threat simulation, and offensive security analysis.

| # | Lab | Topic | What You'll Learn |
|---|-----|-------|-------------------|
| 11 | [Ransomware Detection](./lab11-ransomware-detection/) | Behavioral detection | Entropy, TTPs, response |
| 12 | [Purple Team](./lab12-ransomware-simulation/) | Adversary emulation | Safe simulation, gap analysis |
| 13 | [Memory Forensics AI](./lab13-memory-forensics-ai/) | Memory analysis | Volatility3, process injection, credential dumping |
| 14 | [C2 Traffic Analysis](./lab14-c2-traffic-analysis/) | Network forensics | Beaconing, DNS tunneling, encrypted C2 |
| 15 | [Lateral Movement Detection](./lab15-lateral-movement-detection/) | Attack detection | Auth anomalies, remote execution, graph analysis |
| 16 | [Threat Actor Profiling](./lab16-threat-actor-profiling/) | Attribution | TTP analysis, clustering, actor profiles |
| 17 | [Adversarial ML](./lab17-adversarial-ml/) | Attack/Defense | Evasion, poisoning, robust ML defenses |
| 18 | [Fine-Tuning for Security](./lab18-fine-tuning-security/) | Custom models | LoRA, security embeddings, deployment |
| 19 | [Cloud Security AI](./lab19-cloud-security-ai/) | Multi-cloud | CloudTrail, AWS/Azure/GCP threat detection |
| 20 | [LLM Red Teaming](./lab20-llm-red-teaming/) | Offensive AI Security | Prompt injection, jailbreaking, agentic attacks |

**Progression:**
```
Lab 11 (Ransomware) → Lab 12 (Purple Team) → Lab 13 (Memory Forensics)
     ↓                     ↓                      ↓
 "Detect              "Validate              "Analyze
  ransomware"          detections"            memory dumps"

Lab 14 (C2 Traffic) → Lab 15 (Lateral Movement) → Lab 16 (Attribution) → Lab 17 (Adversarial)
     ↓                      ↓                          ↓                      ↓
 "Detect C2            "Track attacker           "Profile             "Attack/defend
  communications"        movement"                threat actors"        ML models"

Lab 18 (Fine-Tuning) → Lab 19 (Cloud Security) → Lab 20 (LLM Red Team)
     ↓                      ↓                          ↓
 "Build custom          "Secure cloud             "Attack AI
  security models"       environments"             systems"
```

**Bridge from Core:** Labs 11-20 build on detection skills from Labs 09-10 and apply them to advanced DFIR, adversarial ML, and cloud security scenarios. Lab 17 teaches how to attack and defend ML models. Labs 18-19 cover custom model training and multi-cloud security. Lab 20 focuses on offensive security for LLM applications - prompt injection, jailbreaking, and exploiting agentic AI systems.

---

## 🎯 Quick Paths by Goal

Choose based on your objectives:

| Your Goal | Labs | Prerequisites |
|-----------|------|---------------|
| **"I'm completely new"** | 00a → 00b → 00c → 01 | Nothing! |
| **"I know Python, new to ML"** | 00b → 00c → 01 → 02 | Python basics |
| **"I know ML, teach me LLMs"** | 00c → 04 → 06 → 05 | ML experience |
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
python labs/lab04-llm-log-analysis/scripts/app.py

# Or use the unified demo launcher
python scripts/launcher.py
```

---

## 🔄 Workflow Orchestration

Labs 09-12 use workflow orchestration for multi-stage pipelines:

```python
# Example from Lab 09: Detection Pipeline
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

1. **Python 3.10+** installed
2. **Virtual environment** set up
3. **API keys** configured (see [Setup Guide](../docs/guides/dev-environment-setup.md))

### Running a Lab

```bash
# Navigate to lab directory
cd labs/lab01-phishing-classifier

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
├── data/               # Sample datasets
│   └── *.csv
└── tests/              # Unit tests (optional)
    └── test_*.py
```

---

## 🎯 Learning Path

### Foundation Path

Build core ML skills for security:

```
Lab 01 → Lab 02 → Lab 03
   ↓        ↓        ↓
 Text    Clustering  Anomaly
  ML                Detection
```

### LLM Path

Master LLMs for security applications:

```
Lab 04 → Lab 05 → Lab 06 → Lab 07
   ↓        ↓        ↓        ↓
  Log     Agents    RAG     YARA
Analysis            Docs   Generation
```

### Advanced Path

Build production systems:

```
Lab 08 → Lab 09 → Lab 10
   ↓        ↓        ↓
 Vuln    Detection   IR
Scanner  Pipeline  Copilot
```

---

## 🏆 Lab Summaries

### Lab 01: Phishing Email Classifier

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

### Lab 02: Malware Sample Clustering

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

### Lab 03: Network Anomaly Detection

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

### Lab 04: LLM-Powered Log Analysis

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

### Lab 05: Threat Intelligence Agent

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

### Lab 06: Security RAG System

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

### Lab 07: AI YARA Rule Generator

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

### Lab 08: Vulnerability Scanner AI

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

### Lab 09: Threat Detection Pipeline

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

### Lab 10: IR Copilot Agent

**Build a conversational AI copilot for incident response.**

Skills learned:
- Conversational agent design
- Multi-tool orchestration
- State management
- Confirmation workflows

Copilot capabilities:
- SIEM queries and log analysis
- IOC lookup and enrichment
- Host isolation and containment
- Timeline and report generation
- Playbook-guided response

---

### Lab 11: Ransomware Detection & Response (DFIR)

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

### Lab 12: Ransomware Attack Simulation (Purple Team)

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

### Lab 13: AI-Powered Memory Forensics

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

### Lab 14: C2 Traffic Analysis

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

### Lab 15: Lateral Movement Detection

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

### Lab 16: Threat Actor Profiling

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

### Lab 17: Adversarial Machine Learning

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

### Lab 18: Fine-Tuning for Security

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

### Lab 19: Cloud Security AI

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

### Lab 20: LLM Red Teaming

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
- [ ] Lab 00a: Python for Security Fundamentals
- [ ] Lab 00b: ML Concepts Primer
- [ ] Lab 00c: Intro to Prompt Engineering
- [ ] Lab 00d: AI in Security Operations (conceptual)
- [ ] Lab 00e: Visualization & Statistics

**Core Labs**
- [ ] Lab 01: Phishing Classifier
- [ ] Lab 02: Malware Clustering
- [ ] Lab 03: Anomaly Detection
- [ ] Lab 04: LLM Log Analysis
- [ ] Lab 05: Threat Intel Agent
- [ ] Lab 06: Security RAG
- [ ] Lab 07: YARA Generator
- [ ] Lab 08: Vuln Scanner AI
- [ ] Lab 09: Detection Pipeline
- [ ] Lab 10: IR Copilot
- [ ] Lab 11: Ransomware Detection
- [ ] Lab 12: Ransomware Simulation
- [ ] Lab 13: Memory Forensics AI
- [ ] Lab 14: C2 Traffic Analysis
- [ ] Lab 15: Lateral Movement Detection
- [ ] Lab 16: Threat Actor Profiling
- [ ] Lab 17: Adversarial ML
- [ ] Lab 18: Fine-Tuning for Security
- [ ] Lab 19: Cloud Security AI
- [ ] Lab 20: LLM Red Teaming

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

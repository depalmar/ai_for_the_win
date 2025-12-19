# 🧪 Hands-On Labs

Practical labs for building AI-powered security tools.

---

## Lab Overview

| Lab | Topic | Difficulty | Time | Status |
|-----|-------|------------|------|--------|
| [01](./lab01-phishing-classifier/) | Phishing Email Classifier | ⭐ Beginner | 45-60 min | ✅ Ready |
| [02](./lab02-malware-clustering/) | Malware Sample Clustering | ⭐⭐ Intermediate | 60-75 min | ✅ Ready |
| [03](./lab03-anomaly-detection/) | Network Anomaly Detection | ⭐⭐ Intermediate | 60-75 min | ✅ Ready |
| [04](./lab04-llm-log-analysis/) | LLM-Powered Log Analysis | ⭐⭐ Intermediate | 60-90 min | ✅ Ready |
| [05](./lab05-threat-intel-agent/) | Threat Intelligence Agent | ⭐⭐⭐ Advanced | 90-120 min | ✅ Ready |
| [06](./lab06-security-rag/) | RAG for Security Docs | ⭐⭐ Intermediate | 75-90 min | ✅ Ready |
| [07](./lab07-yara-generator/) | AI YARA Rule Generator | ⭐⭐ Intermediate | 60-75 min | ✅ Ready |
| [08](./lab08-vuln-scanner-ai/) | Vulnerability Scanner AI | ⭐⭐⭐ Advanced | 90-120 min | ✅ Ready |
| [09](./lab09-detection-pipeline/) | Threat Detection Pipeline | ⭐⭐⭐ Advanced | 120-150 min | ✅ Ready |
| [10](./lab10-ir-copilot/) | IR Copilot Agent | ⭐⭐⭐ Advanced | 120-150 min | ✅ Ready |
| [11](./lab11-ransomware-detection/) | Ransomware Detection & Response | ⭐⭐⭐ Advanced | 240-300 min | ✅ Ready |
| [12](./lab12-ransomware-simulation/) | Ransomware Simulation (Purple Team) | ⭐⭐⭐ Advanced | 240-300 min | ✅ Ready |

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+** installed
2. **Virtual environment** set up
3. **API keys** configured (see [Setup Guide](../setup/dev-environment-setup.md))

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

### Foundation Path (Weeks 1-8)

Build core ML skills for security:

```
Lab 01 → Lab 02 → Lab 03
   ↓        ↓        ↓
 Text    Clustering  Anomaly
  ML                Detection
```

### LLM Path (Weeks 9-16)

Master LLMs for security applications:

```
Lab 04 → Lab 05 → Lab 06 → Lab 07
   ↓        ↓        ↓        ↓
  Log     Agents    RAG     YARA
Analysis            Docs   Generation
```

### Advanced Path (Weeks 17-24)

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

---

## 🤝 Contributing

Found an issue or have an improvement?

1. Open an issue describing the problem
2. Submit a PR with fixes
3. Add new test cases
4. Improve documentation

---

## 📚 Additional Resources

- [Curriculum Overview](../curriculum/ai-security-training-program.md)
- [Development Setup](../setup/dev-environment-setup.md)
- [Tools & Resources](../resources/tools-and-resources.md)
- [Cursor IDE Guide](../setup/guides/cursor-ide-guide.md)

---

Happy Hacking! 🛡️

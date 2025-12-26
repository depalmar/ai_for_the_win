# AI for the Win

### Build AI-Powered Security Tools | From Zero to Production

[![CI](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml/badge.svg)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-201%2F212%20passing-brightgreen)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](./Dockerfile)

A hands-on training program for security practitioners who want to build AI-powered tools for threat detection, incident response, and security automation. **23 labs** (including 3 intro labs), **4 capstone projects**, **15 CTF challenges**. Includes **sample datasets** and **solution walkthroughs**. Designed for **vibe coding** with AI assistants like Cursor, Claude Code, and Copilot.

---

## Get Started in 5 Minutes

```bash
# 1. Clone and setup
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure API key (get one from console.anthropic.com)
cp .env.example .env
echo "ANTHROPIC_API_KEY=your-key-here" >> .env

# 3. Verify setup
python scripts/verify_setup.py

# 4. Run your first lab
cd labs/lab01-phishing-classifier
python solution/main.py
```

> 📖 **First time?** Read [GETTING_STARTED.md](./GETTING_STARTED.md) for detailed setup instructions.

---

## Learning Paths

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CHOOSE YOUR PATH                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   🎯 INTRO             🟢 FOUNDATION        🟡 LLM TOOLS                │
│   Labs 00a-00c         Labs 01-03           Labs 04-07                  │
│   ────────────         ─────────────        ───────────                 │
│   • Python Basics      • Text ML            • Prompt Eng                │
│   • ML Concepts        • Clustering         • RAG Systems               │
│   • Prompt Mastery     • Anomaly Det        • Code Generation           │
│                                                                         │
│   🟠 ADVANCED          🔴 EXPERT: Labs 11-19                            │
│   Labs 05,08-10        ─────────────────────                            │
│   ─────────────        • Ransomware Detection    • Memory Forensics     │
│   • AI Agents          • Purple Team Sim         • C2 Traffic           │
│   • Pipelines          • Adversarial ML          • Fine-tuning          │
│   • IR Automation      • Cloud Security          • Threat Attribution   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

| Your Background | Recommended Path |
|-----------------|------------------|
| Completely new (no Python) | Labs 00a → 00b → 00c → 01 |
| Know Python, new to ML | Labs 00b → 00c → 01 → 02 |
| Know ML, new to LLMs | Labs 00c → 04 → 06 → 05 |
| Want to build agents | Labs 00c → 04 → 05 → 10 |
| DFIR focus | Labs 04 → 05 → 11 → 13 → 14 |
| Red Team/Offensive | Labs 12 → 14 → 15 → 16 |
| Threat Intel Analyst | Labs 05 → 06 → 14 → 16 |

---

## What You'll Build

### Labs Overview

| Lab | Project | What You'll Learn |
|-----|---------|-------------------|
| **00a** | **Python for Security** | Variables, files, APIs, regex, security-focused Python basics |
| **00b** | **ML Concepts Primer** | Supervised/unsupervised learning, features, training, evaluation metrics |
| **00c** | **Prompt Engineering Mastery** | Beginner-to-advanced prompting, AI Studio, hallucination detection, Plotly visualizations |
| **01** | **Phishing Classifier** | Text preprocessing, TF-IDF vectorization, Random Forest classification, model evaluation metrics |
| **02** | **Malware Clusterer** | Feature extraction from binaries, K-Means & DBSCAN clustering, dimensionality reduction, cluster analysis |
| **03** | **Anomaly Detector** | Statistical baselines, Isolation Forest, Local Outlier Factor, threshold optimization for security |
| **04** | **Log Analyzer** | Prompt engineering for security, structured output parsing, IOC extraction, LLM-powered analysis |
| **05** | **Threat Intel Agent** | ReAct pattern implementation, tool use with LangChain, autonomous investigation workflows |
| **06** | **Security RAG** | Document chunking, vector embeddings, ChromaDB, retrieval-augmented generation for Q&A |
| **07** | **YARA Generator** | Static malware analysis, pattern extraction, AI-assisted rule generation, rule validation |
| **08** | **Vuln Prioritizer** | CVSS scoring, risk-based prioritization, remediation planning with LLMs |
| **09** | **Detection Pipeline** | Multi-stage architectures, ML filtering, LLM enrichment, alert correlation |
| **10** | **IR Copilot** | Conversational agents, state management, playbook execution, incident documentation |
| **11** | **Ransomware Detector** | Entropy analysis, behavioral detection, ransom note IOC extraction, response automation |
| **12** | **Purple Team Sim** | Safe adversary emulation, detection validation, gap analysis, purple team exercises |
| **13** | **Memory Forensics AI** | Volatility3 integration, process injection detection, credential dumping, LLM artifact analysis |
| **14** | **C2 Traffic Analysis** | Beaconing detection, DNS tunneling, encrypted C2, JA3 fingerprinting, traffic classification |
| **15** | **Lateral Movement Detection** | Auth anomaly detection, remote execution (PsExec/WMI/WinRM), graph-based attack paths |
| **16** | **Threat Actor Profiling** | TTP extraction, campaign clustering, malware attribution, actor profile generation |
| **17** | **Adversarial ML** | Evasion attacks, poisoning attacks, adversarial training, robust ML defenses |
| **18** | **Fine-Tuning for Security** | Custom embeddings, LoRA fine-tuning, security-specific models, deployment |
| **19** | **Cloud Security AI** | AWS/Azure/GCP security, CloudTrail analysis, multi-cloud threat detection |

### Skills Progression

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│  INTRO          │  FOUNDATIONS      │  INTERMEDIATE       │  ADVANCED       │  EXPERT             │
│  Labs 00a-00b   │  Labs 01-03       │  Labs 04-07         │  Labs 08-10     │  Labs 11-16         │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────┼─────────────────────┤
│  • Python       │  • Supervised ML  │  • Prompt Eng       │  • System       │  • DFIR             │
│  • ML Concepts  │  • Unsupervised   │  • AI Agents        │    Design       │  • Memory Forensics │
│                 │  • Feature Eng    │  • RAG Systems      │  • ML+LLM       │  • C2 Detection     │
│                 │  • Evaluation     │  • Code Gen         │  • Production   │  • Attribution      │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set up API keys
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

# Run your first lab
cd labs/lab01-phishing-classifier
python solution/main.py
```

### Docker Quick Start

```bash
# Build and run with Docker Compose
docker-compose up dev

# Run tests in container
docker-compose run test

# Launch Jupyter notebooks
docker-compose up notebook
# Open http://localhost:8888
```

### Google Colab

Run labs directly in your browser - no setup required:

| Lab | Colab Link |
|-----|------------|
| Lab 01: Phishing Classifier | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb) |
| Lab 02: Malware Clustering | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab02_malware_clustering.ipynb) |
| Lab 03: Anomaly Detection | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab03_anomaly_detection.ipynb) |
| Lab 04: Log Analysis | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab04_llm_log_analysis.ipynb) |
| Lab 05: Threat Intel Agent | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab05_threat_intel_agent.ipynb) |
| Lab 06: Security RAG | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab06_security_rag.ipynb) |
| All 23 labs available | [Browse notebooks →](./notebooks/) |

---

## Repository Structure

```
ai_for_the_win/
├── labs/                          # 23 hands-on labs
│   ├── lab00a-python-security-fundamentals/ # Python basics for security
│   ├── lab00b-ml-concepts-primer/ # ML theory before coding
│   ├── lab00c-prompt-engineering-mastery/ # Prompt design & verification
│   ├── lab01-phishing-classifier/ # ML text classification
│   ├── lab02-malware-clustering/  # Unsupervised learning
│   ├── lab03-anomaly-detection/   # Network security
│   ├── lab04-llm-log-analysis/    # Prompt engineering
│   ├── lab05-threat-intel-agent/  # ReAct agents
│   ├── lab06-security-rag/        # Vector search + LLM
│   ├── lab07-yara-generator/      # AI code generation
│   ├── lab08-vuln-scanner-ai/     # Risk prioritization
│   ├── lab09-detection-pipeline/  # Multi-stage ML+LLM
│   ├── lab10-ir-copilot/          # Conversational IR
│   ├── lab11-ransomware-detection/# DFIR + behavioral analysis
│   ├── lab12-ransomware-simulation/# Purple team exercises
│   ├── lab13-memory-forensics-ai/ # Memory forensics with AI
│   ├── lab14-c2-traffic-analysis/ # C2 detection & analysis
│   ├── lab15-lateral-movement-detection/ # Attack path detection
│   └── lab16-threat-actor-profiling/ # Attribution & profiling
├── notebooks/                     # Jupyter notebooks (Colab-ready)
├── capstone-projects/             # 4 comprehensive projects
├── templates/                     # Reusable code templates
│   ├── agents/                    # LangChain agent templates
│   ├── prompts/                   # Security prompt library
│   ├── visualizations/            # Dashboards & diagrams
│   └── reports/                   # Report generators
├── resources/                     # Tools, datasets, MCP servers guide
├── setup/                         # Environment setup guides
│   └── guides/                    # Troubleshooting & error handling
├── tests/                         # Comprehensive test suite
├── Dockerfile                     # Multi-stage Docker build
└── docker-compose.yml             # Dev, test, notebook services
```

---

## Learning Paths

### Path 1: ML Foundations (Weeks 1-8)

Build core machine learning skills for security:

```
Lab 01 ──► Lab 02 ──► Lab 03
  │          │          │
  ▼          ▼          ▼
Text ML   Clustering  Anomaly
                      Detection
```

**Skills**: Supervised learning, unsupervised learning, feature engineering, model evaluation

### Path 2: LLM & Agents (Weeks 9-16)

Master LLMs for security applications:

```
Lab 04 ──► Lab 05 ──► Lab 06 ──► Lab 07
  │          │          │          │
  ▼          ▼          ▼          ▼
Prompts   Agents      RAG       Code Gen
```

**Skills**: Prompt engineering, ReAct agents, RAG systems, tool use

### Path 3: Production Systems (Weeks 17-24)

Build production-ready security systems:

```
Lab 08 ──► Lab 09 ──► Lab 10 ──► Capstone
  │          │          │          │
  ▼          ▼          ▼          ▼
Vuln Scan  Pipeline   IR Bot    Your Project
```

**Skills**: System design, multi-stage pipelines, conversational AI, deployment

---

## Lab Progress Tracker

Track your progress through the labs:

**Intro (Recommended)**
- [ ] **Lab 00a**: Python for Security Fundamentals
- [ ] **Lab 00b**: ML Concepts Primer
- [ ] **Lab 00c**: Prompt Engineering Mastery

**Core Labs**
- [ ] **Lab 01**: Phishing Email Classifier
- [ ] **Lab 02**: Malware Sample Clustering
- [ ] **Lab 03**: Network Anomaly Detection
- [ ] **Lab 04**: LLM-Powered Log Analysis
- [ ] **Lab 05**: Threat Intelligence Agent
- [ ] **Lab 06**: Security RAG System
- [ ] **Lab 07**: AI YARA Rule Generator
- [ ] **Lab 08**: Vulnerability Scanner AI
- [ ] **Lab 09**: Threat Detection Pipeline
- [ ] **Lab 10**: IR Copilot Agent
- [ ] **Lab 11**: Ransomware Detection & Response
- [ ] **Lab 12**: Ransomware Simulation (Purple Team)
- [ ] **Lab 13**: Memory Forensics AI
- [ ] **Lab 14**: C2 Traffic Analysis
- [ ] **Lab 15**: Lateral Movement Detection
- [ ] **Lab 16**: Threat Actor Profiling
- [ ] **Capstone**: Complete one capstone project

---

## Technology Stack

| Category | Tools |
|----------|-------|
| **LLM Providers** | Claude, GPT-4, Gemini, Ollama (local) |
| **LLM Frameworks** | LangChain, LangGraph, LiteLLM, Instructor |
| **ML/AI** | scikit-learn, PyTorch, Hugging Face Transformers |
| **Vector DB** | ChromaDB, sentence-transformers |
| **Security** | YARA, Sigma, MITRE ATT&CK, pefile |
| **Web/UI** | FastAPI, Gradio, Streamlit |
| **Vibe Coding** | Cursor, Claude Code, GitHub Copilot, Windsurf |
| **Development** | Python 3.10+, pytest, Docker, GitHub Actions |

---

## Capstone Projects

Choose one to demonstrate mastery:

| Project | Difficulty | Focus |
|---------|------------|-------|
| **Security Analyst Copilot** | Advanced | LLM agents, IR automation |
| **Automated Threat Hunter** | Advanced | ML detection, pipelines |
| **Malware Analysis Assistant** | Intermediate | Static analysis, YARA |
| **Vulnerability Intel Platform** | Intermediate | RAG, prioritization |

Each project includes starter code, requirements, and evaluation criteria.

---

## Templates & Integrations

Jumpstart your projects with ready-to-use templates:

- **Agent Templates**: LangChain security agent, RAG agent
- **n8n Workflows**: IOC enrichment, alert triage with AI
- **SIEM Integrations**: Splunk, Elasticsearch, Microsoft Sentinel
- **Prompt Library**: Log analysis, threat detection, report generation

---

## Development

### Test Status

**Current Status**: 201/212 tests passing (94.8%)

| Lab | Tests | Status | Notes |
|-----|-------|--------|-------|
| Lab01 | 15/15 | ✅ 100% | Phishing Classifier |
| Lab02 | 11/11 | ✅ 100% | Malware Clustering |
| Lab03 | 11/11 | ✅ 100% | Anomaly Detection |
| Lab05 | 13/17 | ⚠️ 76% | Non-agent tests pass |
| Lab06 | 7/7 | ✅ 100% | Security RAG |
| Lab07 | 8/8 | ✅ 100% | YARA Generator |
| Lab08 | 11/11 | ✅ 100% | Vuln Scanner |
| Lab12 | 0/11 | ❌ 0% | API key detection issue |

**API-Dependent Labs**: Labs 06, 07, 08 require `ANTHROPIC_API_KEY` environment variable (or equivalent LLM provider key) to run. Set up your API key in `.env` to use these labs.

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

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude API key | One LLM key required |
| `OPENAI_API_KEY` | OpenAI GPT-4 key | One LLM key required |
| `GOOGLE_API_KEY` | Google Gemini key | One LLM key required |
| `VIRUSTOTAL_API_KEY` | VirusTotal API | Optional (threat intel) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API | Optional (threat intel) |

> **Note:** You only need ONE LLM provider key. All labs support multiple providers.

---

## Getting Help

- **Troubleshooting**: Check the [troubleshooting guide](./setup/guides/troubleshooting-guide.md)
- **Error Handling**: See [error handling best practices](./setup/guides/error-handling-guide.md)
- **Documentation**: Browse [setup guides](./setup/) and [resources](./resources/)
- **Issues**: Open a [GitHub issue](https://github.com/depalmar/ai_for_the_win/issues)

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

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## Disclaimer

This training material is intended for **educational purposes** and **authorized security testing only**. Users are responsible for ensuring compliance with all applicable laws and obtaining proper authorization before using any offensive techniques.

---

<p align="center">
  <b>Ready to build AI-powered security tools?</b><br>
  <a href="./labs/lab01-phishing-classifier/">Start with Lab 01</a> |
  <a href="./curriculum/ai-security-training-program.md">View Full Curriculum</a>
</p>

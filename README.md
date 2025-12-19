# AI for the Win

### Build AI-Powered Security Tools | From Zero to Production

[![CI](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml/badge.svg)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive 24-week training program for security practitioners who want to build AI-powered tools for threat detection, incident response, and security automation.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   Week 1-8          Week 9-16           Week 17-24                      │
│   ─────────         ──────────          ───────────                     │
│   ML Foundations    LLM & Agents        Production Systems              │
│                                                                         │
│   • Classification  • Prompt Eng        • Detection Pipelines           │
│   • Clustering      • RAG Systems       • IR Automation                 │
│   • Anomaly Det     • AI Agents         • Capstone Projects             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What You'll Build

| Project | Description | Skills |
|---------|-------------|--------|
| **Phishing Classifier** | ML model to detect phishing emails | Text classification, TF-IDF, Random Forest |
| **Malware Clusterer** | Group malware samples by behavior | K-Means, DBSCAN, feature engineering |
| **Anomaly Detector** | Find threats in network traffic | Isolation Forest, LOF, baseline detection |
| **Log Analyzer** | LLM-powered security log analysis | Prompt engineering, IOC extraction |
| **Threat Intel Agent** | Autonomous threat research agent | ReAct pattern, tool use, LangChain |
| **Security RAG** | Q&A over security documentation | Vector search, ChromaDB, embeddings |
| **YARA Generator** | AI-generated detection rules | Code generation, malware analysis |
| **Vuln Prioritizer** | Smart vulnerability triage | Risk scoring, remediation planning |
| **Detection Pipeline** | Multi-stage threat detection | ML filtering, LLM enrichment, correlation |
| **IR Copilot** | Conversational IR assistant | Agents, state management, playbooks |

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

---

## Repository Structure

```
ai_for_the_win/
├── curriculum/                    # 24-week training program
│   └── ai-security-training-program.md
├── labs/                          # 10 hands-on labs
│   ├── lab01-phishing-classifier/
│   ├── lab02-malware-clustering/
│   ├── lab03-anomaly-detection/
│   ├── lab04-llm-log-analysis/
│   ├── lab05-threat-intel-agent/
│   ├── lab06-security-rag/
│   ├── lab07-yara-generator/
│   ├── lab08-vuln-scanner-ai/
│   ├── lab09-detection-pipeline/
│   └── lab10-ir-copilot/
├── capstone-projects/             # 4 comprehensive projects
│   ├── security-analyst-copilot/
│   ├── automated-threat-hunter/
│   ├── malware-analysis-assistant/
│   └── vuln-intel-platform/
├── templates/                     # Reusable code templates
│   ├── agents/                    # LangChain agent templates
│   ├── n8n/                       # Automation workflows
│   ├── prompts/                   # Security prompt library
│   └── integrations/              # SIEM integrations
├── resources/                     # Tools, datasets, guides
├── setup/                         # Environment setup guides
└── tests/                         # Test suite
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
- [ ] **Capstone**: Complete one capstone project

---

## Technology Stack

| Category | Tools |
|----------|-------|
| **AI/ML** | Claude API, LangChain, scikit-learn, PyTorch |
| **Vector DB** | ChromaDB, embeddings |
| **Security** | YARA, Sigma, MITRE ATT&CK |
| **Automation** | n8n, Python scripts |
| **Development** | Python 3.9+, pytest, GitHub Actions |

---

## Capstone Projects

Choose one to demonstrate mastery:

| Project | Difficulty | Duration | Focus |
|---------|------------|----------|-------|
| **Security Analyst Copilot** | Advanced | 40-60 hrs | LLM agents, IR automation |
| **Automated Threat Hunter** | Advanced | 40-60 hrs | ML detection, pipelines |
| **Malware Analysis Assistant** | Intermediate | 30-40 hrs | Static analysis, YARA |
| **Vulnerability Intel Platform** | Intermediate | 30-40 hrs | RAG, prioritization |

Each project includes starter code, requirements, and evaluation criteria.

---

## Templates & Integrations

Jumpstart your projects with ready-to-use templates:

- **Agent Templates**: LangChain security agent, RAG agent
- **n8n Workflows**: IOC enrichment, alert triage with AI
- **SIEM Integrations**: Splunk, Elasticsearch, Microsoft Sentinel
- **Prompt Library**: Log analysis, threat detection, report generation

---

## Getting Help

- **Documentation**: Check the [setup guides](./setup/) and [resources](./resources/)
- **Issues**: Open a [GitHub issue](https://github.com/depalmar/ai_for_the_win/issues)
- **Discussions**: Join [GitHub Discussions](https://github.com/depalmar/ai_for_the_win/discussions)

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

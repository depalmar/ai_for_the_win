# 🎓 Capstone Projects

Demonstrate your skills with comprehensive real-world projects.

---

## Overview

Each capstone project integrates multiple concepts from the training program. Complete at least one to earn your certificate of completion.

| Project | Difficulty | Duration | Skills Demonstrated |
|---------|------------|----------|---------------------|
| [Security Analyst Copilot](#project-1-security-analyst-copilot) | ⭐⭐⭐ Advanced | 40-60 hrs | LLM, Agents, RAG, Tools |
| [Automated Threat Hunter](#project-2-automated-threat-hunter) | ⭐⭐⭐ Advanced | 40-60 hrs | ML, Detection, Pipeline |
| [Malware Analysis Assistant](#project-3-malware-analysis-assistant) | ⭐⭐⭐ Advanced | 30-40 hrs | LLM, Static Analysis, YARA |
| [Vulnerability Intelligence Platform](#project-4-vulnerability-intelligence-platform) | ⭐⭐ Intermediate | 30-40 hrs | RAG, API, Dashboard |

---

## Project 1: Security Analyst Copilot

### Description

Build a conversational AI assistant that helps security analysts investigate alerts, gather context, and take response actions.

### Requirements

#### Core Features
- [ ] Chat interface for natural language interaction
- [ ] SIEM integration for log queries
- [ ] Threat intelligence lookups (IP, domain, hash)
- [ ] MITRE ATT&CK mapping
- [ ] Incident documentation generation

#### Advanced Features
- [ ] Multi-turn conversation memory
- [ ] Playbook execution assistance
- [ ] Alert correlation
- [ ] Response action suggestions
- [ ] Learning from analyst feedback

### Technical Stack

```
Frontend:  Streamlit or Gradio
Backend:   Python + LangChain/LangGraph
LLM:       Claude API or Ollama
Database:  ChromaDB (RAG) + SQLite (state)
Integrations: Elastic, VirusTotal, AbuseIPDB
```

### Deliverables

1. **Working Application**
   - Deployable Docker container
   - Configuration documentation
   - User guide

2. **Demo Video** (5-10 min)
   - Show investigation workflow
   - Demonstrate key features
   - Explain architecture

3. **Technical Documentation**
   - Architecture diagram
   - API documentation
   - Security considerations

### Evaluation Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Functionality | 30% | All core features working |
| Code Quality | 20% | Clean, documented, testable |
| UX/UI | 15% | Intuitive and efficient |
| Security | 15% | Secure handling of data/keys |
| Documentation | 10% | Clear and comprehensive |
| Innovation | 10% | Creative problem solving |

---

## Project 2: Automated Threat Hunter

### Description

Create an automated system that continuously hunts for threats across your environment using ML-based detection and LLM-powered analysis.

### Requirements

#### Core Features
- [ ] Log ingestion from multiple sources
- [ ] ML-based anomaly detection
- [ ] Rule-based detection (Sigma/YARA)
- [ ] LLM-powered alert analysis
- [ ] Detection priority scoring

#### Advanced Features
- [ ] Behavioral baselines per user/host
- [ ] Attack chain detection
- [ ] Automated enrichment pipeline
- [ ] Alert suppression/tuning
- [ ] Metrics dashboard

### Technical Stack

```
Data Pipeline:  Python + Kafka/Redis
ML Models:      Scikit-learn, Isolation Forest
Detection:      Sigma rules + custom ML
Analysis:       Claude/GPT for enrichment
Storage:        Elasticsearch or TimescaleDB
Dashboard:      Grafana or custom
```

### Deliverables

1. **Detection System**
   - Data pipeline code
   - ML models (trained and serialized)
   - Detection rules

2. **Demo Environment**
   - Docker Compose setup
   - Sample attack scenarios
   - Expected detections

3. **Documentation**
   - Detection logic explanation
   - Tuning guide
   - Performance benchmarks

### Sample Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Sysmon    │────►│              │────►│  ML Filter  │
│   Windows   │     │  Log Router  │     │  (Stage 1)  │
│   Network   │────►│              │────►│             │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                           ┌────────────────────┘
                           ▼
                    ┌──────────────┐     ┌─────────────┐
                    │  LLM Enrich  │────►│  Correlate  │
                    │  (Stage 2)   │     │  (Stage 3)  │
                    └──────────────┘     └──────┬──────┘
                                                │
                           ┌────────────────────┘
                           ▼
                    ┌──────────────┐     ┌─────────────┐
                    │   Verdict    │────►│   Alert     │
                    │  (Stage 4)   │     │  Dashboard  │
                    └──────────────┘     └─────────────┘
```

---

## Project 3: Malware Analysis Assistant

### Description

Build an AI-powered assistant that helps analysts understand malware samples through automated static analysis and LLM-generated explanations.

### Requirements

#### Core Features
- [ ] PE file parsing and feature extraction
- [ ] String extraction and analysis
- [ ] Import/export analysis
- [ ] LLM-powered behavior prediction
- [ ] YARA rule generation

#### Advanced Features
- [ ] Similarity search against known samples
- [ ] Automated sandbox integration
- [ ] Family classification
- [ ] IOC extraction
- [ ] Report generation

### Technical Stack

```
Analysis:    pefile, yara-python, LIEF
LLM:         Claude API
Database:    SQLite + ChromaDB
Interface:   CLI + Web UI
Sandbox:     CAPE/Cuckoo integration (optional)
```

### Deliverables

1. **Analysis Tool**
   - CLI for batch processing
   - Web interface for interactive analysis
   - API for integration

2. **Sample Analysis Reports**
   - 5+ analyzed samples
   - Generated YARA rules
   - Accuracy assessment

3. **Documentation**
   - Analysis methodology
   - YARA rule quality guide
   - API reference

### Sample Output

```markdown
# Malware Analysis Report

## Sample: suspicious.exe
**SHA256:** abc123def456...
**File Type:** PE32 executable
**Size:** 245,760 bytes

## AI Assessment

This sample appears to be a **Cobalt Strike beacon** based on:

1. **Characteristic imports**: VirtualAlloc, CreateRemoteThread
2. **String patterns**: Matching known C2 communication
3. **Code sections**: High entropy indicating packing/encryption

**Confidence:** 87%

## MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|-----------|------|----------|
| T1059.001 | PowerShell | Spawns PowerShell process |
| T1055 | Process Injection | CreateRemoteThread import |

## Generated YARA Rule

```yara
rule CobaltStrike_Beacon_Sample {
    meta:
        description = "Detects Cobalt Strike beacon variant"
        author = "AI Analysis"
        date = "2024-01-15"
    ...
}
```
```

---

## Project 4: Vulnerability Intelligence Platform

### Description

Create a platform that aggregates vulnerability data, provides intelligent prioritization, and generates actionable remediation guidance.

### Requirements

#### Core Features
- [ ] CVE data ingestion (NVD API)
- [ ] Asset inventory integration
- [ ] Risk-based prioritization
- [ ] RAG-powered Q&A on CVEs
- [ ] Remediation recommendations

#### Advanced Features
- [ ] Scan result import (Nessus/Qualys/Nuclei)
- [ ] Exploit availability tracking
- [ ] Patch tracking and verification
- [ ] Executive reporting
- [ ] Trend analysis

### Technical Stack

```
Backend:     FastAPI
Database:    PostgreSQL + ChromaDB
LLM:         Claude API (analysis + RAG)
Frontend:    React or Streamlit
APIs:        NVD, EPSS, Exploit-DB
```

### Deliverables

1. **Platform**
   - Web application
   - REST API
   - Documentation

2. **Demo Environment**
   - Sample asset inventory
   - Import scan results
   - Generated reports

3. **Documentation**
   - API reference
   - Integration guide
   - User manual

---

## Submission Guidelines

### Repository Structure

```
capstone-project-name/
├── README.md           # Project overview and setup
├── docs/
│   ├── architecture.md
│   ├── user-guide.md
│   └── api-reference.md
├── src/
│   └── ... (source code)
├── tests/
│   └── ... (unit tests)
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/
│   └── video-link.md   # Link to demo video
└── requirements.txt
```

### Evaluation Process

1. **Self-Assessment**: Complete checklist in project README
2. **Peer Review**: Get feedback from study group
3. **Demo**: Record 5-10 minute video
4. **Submission**: Open GitHub issue with project link

### Grading Rubric

| Grade | Criteria |
|-------|----------|
| **A** | All core + 3 advanced features, excellent documentation, innovative approaches |
| **B** | All core + 1 advanced feature, good documentation, solid implementation |
| **C** | Most core features, basic documentation, functional implementation |
| **D** | Some core features, minimal documentation, needs improvement |

---

## Tips for Success

### Planning

1. **Start small**: Get a basic version working first
2. **Iterate**: Add features incrementally
3. **Test early**: Write tests as you develop
4. **Document**: Keep notes as you build

### Technical

1. **Use templates**: Start from lab code
2. **Handle errors**: Graceful failure > crashes
3. **Secure by default**: No hardcoded secrets
4. **Performance**: Profile and optimize

### Presentation

1. **Clean UI**: First impressions matter
2. **Clear demo**: Show the happy path first
3. **Honest limitations**: Document what doesn't work
4. **Future roadmap**: Show you've thought ahead

---

## Resources

- [Lab Solutions](../labs/) - Reference implementations
- [Tool Guides](../docs/guides/) - Development environment
- [Sample Data](../labs/*/data/) - Test datasets
- [GitHub Discussions](https://github.com/depalmar/ai_for_the_win/discussions) - Get help from peers

---

Good luck! 🚀


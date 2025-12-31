# AI Security Training - Learning Guide

A structured path from beginner to advanced AI-powered security tools.

> 📖 **Quick setup needed?** See [GETTING_STARTED.md](./GETTING_STARTED.md) first.

---

## How This Course is Organized

The 24 labs are designed to build on each other, progressing from foundational ML concepts through advanced DFIR, adversarial ML, and offensive AI security. Here's the recommended flow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RECOMMENDED LEARNING PATH                            │
│                                                                             │
│   FOUNDATION (ML)      CORE (LLM)          ADVANCED            EXPERT       │
│   ───────────────      ──────────          ────────            ──────       │
│                                                                             │
│   Lab 01 ────────────► Lab 04 ────────────► Lab 05 ────────────► Lab 11    │
│   Phishing             Log Analysis         Threat Intel         Ransomware │
│   (classify emails)    (parse with LLM)     (AI agents)          (DFIR)     │
│        │                    │                    │                   │      │
│        ▼                    ▼                    ▼                   ▼      │
│   Lab 02               Lab 06               Lab 08               Lab 12     │
│   Malware              Security             Vuln Scanner         Purple     │
│   Clustering           RAG                  AI                   Team       │
│        │                    │                    │                          │
│        ▼                    ▼                    ▼                          │
│   Lab 03               Lab 07               Lab 09                          │
│   Anomaly              YARA                 Detection                       │
│   Detection            Generator            Pipeline                        │
│                                                  │                          │
│                                                  ▼                          │
│                                              Lab 10                         │
│                                              IR Copilot                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Transitions

| From | To | What Changes |
|------|-----|--------------|
| Lab 03 → Lab 04 | **ML to LLM** | You go from building ML models to using LLMs with prompts |
| Lab 07 → Lab 05 | **Tasks to Agents** | You go from single-task LLM to autonomous multi-step agents |
| Lab 10 → Lab 11 | **General to DFIR** | You apply all skills to real-world incident response |

---

## Quick Start - Which Path?

| Your Background | Start With | What You'll Learn |
|-----------------|------------|-------------------|
| New to ML/AI | Lab 01 → 02 → 03 | Classification, clustering, anomaly detection |
| Know ML, new to LLMs | Lab 04 → 06 → 07 | Prompt engineering, RAG, code generation |
| Know LLMs, want agents | Lab 05 → 08 → 10 | ReAct agents, orchestration, copilots |
| Want SOC context first | Lab 00d → 04 → 09 | Where AI fits, human-in-the-loop, pipelines |
| Production systems | Lab 09 → 10 | Multi-stage pipelines, conversational AI |
| DFIR specialist | Lab 11 → 13 → 14 | Ransomware, memory forensics, C2 detection |
| Red Team/Offensive | Lab 12 → 15 → 16 | Purple team, lateral movement, attribution |
| ML Security | Lab 17 → 18 → 19 | Adversarial ML, fine-tuning, cloud security |

---

## Choosing the Right Tool: ML vs LLM

One of the most important decisions in AI-powered security is knowing when to use traditional machine learning versus large language models. Each has strengths and trade-offs.

### Decision Matrix

| Security Task | Best Approach | Why |
|--------------|---------------|-----|
| **Malware classification** | ML (Random Forest, XGBoost) | Fast, interpretable, works on structured features |
| **Phishing detection** | ML + LLM hybrid | ML for volume, LLM for sophisticated cases |
| **Log anomaly detection** | ML (Isolation Forest) | Handles high volume, real-time capable |
| **Threat report analysis** | LLM | Natural language understanding required |
| **IOC extraction** | LLM | Flexible parsing of unstructured text |
| **YARA rule generation** | LLM | Code generation from examples |
| **Network intrusion detection** | ML | Numerical features, speed requirements |
| **Incident summarization** | LLM | Language generation, context synthesis |
| **User behavior analytics** | ML | Time-series patterns, baseline comparison |
| **Threat hunting queries** | LLM | Natural language to query translation |

### When to Use ML

```
Choose ML when you need:
┌────────────────────────────────────────────────────────┐
│  ✓ High-speed inference (milliseconds)                 │
│  ✓ Processing millions of events                       │
│  ✓ Explainable decisions (feature importance)         │
│  ✓ Consistent, reproducible outputs                   │
│  ✓ Low cost per prediction                            │
│  ✓ Works offline / air-gapped                         │
└────────────────────────────────────────────────────────┘
```

**Best Use Cases:**
- Real-time detection pipelines
- High-volume alert triage
- Binary classification (malicious/benign)
- Anomaly scoring on numerical data

### When to Use LLMs

```
Choose LLMs when you need:
┌────────────────────────────────────────────────────────┐
│  ✓ Understanding unstructured text                     │
│  ✓ Generating human-readable explanations             │
│  ✓ Flexible parsing without rigid schemas             │
│  ✓ Multi-step reasoning                               │
│  ✓ Code/rule generation                               │
│  ✓ Adapting to new formats without retraining         │
└────────────────────────────────────────────────────────┘
```

**Best Use Cases:**
- Threat intelligence analysis
- Incident report generation
- Natural language security queries
- Code review and vulnerability explanation

### Cost Comparison

| Factor | Traditional ML | LLM API |
|--------|----------------|---------|
| **Per-prediction cost** | ~$0.000001 | ~$0.001-0.01 |
| **1 million predictions** | ~$1 | ~$1,000-10,000 |
| **Training cost** | One-time compute | None (pre-trained) |
| **Latency** | 1-10ms | 100-2000ms |
| **Accuracy on structured data** | High | Medium |
| **Accuracy on unstructured text** | Medium | High |
| **Maintenance** | Retrain periodically | Prompt updates |

### The Hybrid Pattern: Best of Both Worlds

Most production security systems use ML and LLMs together:

```
                    HIGH VOLUME INPUT
                          │
                          ▼
              ┌───────────────────────┐
              │   ML FAST FILTER      │  ← Cheap, fast
              │   (Isolation Forest)  │     Handles 90% of volume
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
        [BENIGN]               [SUSPICIOUS]
        Auto-close                    │
                                      ▼
                          ┌───────────────────────┐
                          │   LLM DEEP ANALYSIS   │  ← Expensive, smart
                          │   (Claude/GPT-4)      │     Top 10% only
                          └───────────┬───────────┘
                                      │
                          ┌───────────┴───────────┐
                          │                       │
                          ▼                       ▼
                    [FALSE POSITIVE]        [TRUE POSITIVE]
                    Auto-close              → Human Review
```

**Implementation Example (from Lab 09):**

```python
def hybrid_detection_pipeline(events: list) -> list:
    """Two-stage detection: ML filtering + LLM analysis."""

    results = []

    for event in events:
        # Stage 1: Fast ML scoring
        ml_score = isolation_forest.score(event.features)

        if ml_score < BENIGN_THRESHOLD:
            results.append({"event": event, "action": "auto_close"})
            continue

        # Stage 2: LLM deep analysis (only for suspicious events)
        llm_analysis = llm.analyze(
            f"Analyze this security event: {event.raw_data}"
        )

        if llm_analysis.severity >= HIGH_THRESHOLD:
            results.append({
                "event": event,
                "action": "escalate",
                "analysis": llm_analysis
            })
        else:
            results.append({"event": event, "action": "log_only"})

    return results
```

**Cost Savings with Hybrid:**
- 10,000 events/day
- ML processes all: $0.01
- LLM processes 10% (1,000): $5.00
- **Total: $5.01/day** vs $50+/day for LLM-only

### Quick Reference: Which Tool for Your Task?

```
START: What type of data?

├─► Structured (logs, network flows, metrics)
│   └─► Use ML (Labs 01-03, 09)
│
├─► Unstructured text (reports, emails, tickets)
│   └─► Use LLM (Labs 04-07)
│
├─► Mixed / both types
│   └─► Use Hybrid (Lab 09)
│
└─► Need reasoning + tools?
    └─► Use AI Agents (Labs 05, 08, 10)
```

### Learn More

| Topic | Where to Learn |
|-------|----------------|
| ML fundamentals | Labs 01, 02, 03 |
| LLM prompting | Labs 04, 00c |
| Hybrid pipelines | Lab 09 |
| AI agents | Labs 05, 08, 10 |
| Cost management | [Cost Management Guide](./setup/guides/cost-management.md) |
| Provider selection | [Provider Comparison Guide](./setup/guides/llm-provider-comparison.md) |

---

## Labs by Difficulty

### 🟢 Foundation Labs (Start Here)

These three labs teach core ML concepts. Do them in order.

#### Lab 01: Phishing Email Classifier
**Difficulty:** ⭐ Easy | **Prerequisites:** Basic Python

**What You'll Learn:**
- Text preprocessing and feature extraction
- TF-IDF vectorization for text
- Random Forest classification
- Model evaluation metrics (precision, recall, F1)

**Key Concepts:**
```
Email Text → Preprocess → Extract Features → Train Model → Classify
     │            │              │               │            │
     ▼            ▼              ▼               ▼            ▼
 Raw text    Lowercase,     TF-IDF          Random      Phishing/
             remove HTML    vectors         Forest      Legitimate
```

**Why This Matters:**
Phishing remains the #1 attack vector. Understanding how ML classifies malicious content is foundational for security automation.

---

#### Lab 02: Malware Sample Clustering
**Difficulty:** ⭐⭐ Easy-Medium | **Prerequisites:** Lab 01

**What You'll Learn:**
- Feature engineering for malware analysis
- K-Means and DBSCAN clustering
- t-SNE/UMAP visualization
- Cluster interpretation

**Key Concepts:**
```
Malware Samples → Extract Features → Cluster → Visualize → Analyze
       │               │               │          │           │
       ▼               ▼               ▼          ▼           ▼
   PE files,       Imports,        K-Means    t-SNE      Family
   scripts        entropy,         DBSCAN     plots      groupings
                  strings
```

**Why Clustering?**
New malware variants are released constantly. Clustering helps identify families and track evolution without needing labels for every sample.

**Bridge from Lab 01:**
In Lab 01, you learned supervised learning (labeled data). Lab 02 teaches unsupervised learning - finding patterns without labels.

---

#### Lab 03: Network Anomaly Detection
**Difficulty:** ⭐⭐ Easy-Medium | **Prerequisites:** Lab 02

**What You'll Learn:**
- Network flow feature engineering
- Isolation Forest for anomaly detection
- Threshold tuning and evaluation
- Autoencoder-based detection (optional)

**Key Concepts:**
```
Network Flows → Feature Engineering → Anomaly Score → Alert
      │                │                    │           │
      ▼                ▼                    ▼           ▼
  Packets,        bytes/sec,          Isolation     C2, DDoS,
  connections     port entropy         Forest       exfil detected
```

**Attack Types Detected:**
- C2 beaconing patterns
- Data exfiltration
- Port scanning
- DDoS indicators

**Bridge from Lab 02:**
Lab 02 taught clustering (grouping similar items). Lab 03 uses anomaly detection (finding outliers). Both are unsupervised, but anomaly detection focuses on "what doesn't belong."

---

### 🌉 Transition: From ML to LLMs

**Congratulations!** After completing Labs 01-03, you understand:
- Supervised learning (classification with labels)
- Unsupervised learning (clustering without labels)
- Anomaly detection (finding outliers)

**What's Next?**
Labs 04-07 introduce Large Language Models (LLMs). Instead of training models on data, you'll:
- Write prompts that guide AI behavior
- Parse natural language into structured data
- Build systems that combine search + generation (RAG)

**Key Difference:**
- ML (Labs 01-03): You train models on your data
- LLMs (Labs 04-07): You use pre-trained models with clever prompts

---

### 🟡 Core Skills Labs (LLM-Powered)

#### Lab 04: LLM-Powered Log Analysis
**Difficulty:** ⭐⭐ Intermediate | **Prerequisites:** API key

**What You'll Learn:**
- Prompt engineering for security
- Structured output parsing
- IOC extraction with LLMs
- MITRE ATT&CK mapping

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    LLM LOG ANALYSIS                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Raw Logs ──► System Prompt ──► LLM ──► Structured JSON    │
│                    │                         │              │
│                    ▼                         ▼              │
│            "You are a security       {                      │
│             log parser..."            "severity": 8,        │
│                                       "technique": "T1059", │
│                                       "iocs": [...]         │
│                                      }                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Prompt Engineering Tips:**
1. **Role Definition:** "You are a security analyst..."
2. **Output Format:** Explicitly define JSON schema
3. **Constraints:** "Return ONLY valid JSON"
4. **Context:** Include MITRE ATT&CK knowledge

---

#### Lab 06: Security RAG System
**Difficulty:** ⭐⭐ Intermediate | **Prerequisites:** Lab 04

**What You'll Learn:**
- Document chunking strategies
- Vector embeddings with ChromaDB
- Semantic search implementation
- Context-aware LLM responses

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    RAG ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Documents ──► Chunk ──► Embed ──► Store in Vector DB     │
│        │                              │                     │
│        │                              ▼                     │
│        │         Query ──► Embed ──► Similarity Search     │
│        │                              │                     │
│        │                              ▼                     │
│        └────────────► Context + Query ──► LLM ──► Answer   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Use Cases:**
- CVE lookup and analysis
- MITRE ATT&CK technique queries
- Security playbook recommendations
- Policy and compliance Q&A

---

#### Lab 07: AI YARA Rule Generator
**Difficulty:** ⭐⭐ Intermediate | **Prerequisites:** Lab 02, Lab 04

**What You'll Learn:**
- Binary analysis basics
- String and pattern extraction
- LLM-powered rule generation
- YARA syntax validation

**Key Concepts:**
```
Sample ──► Static Analysis ──► Extract Patterns ──► LLM ──► YARA Rule
   │             │                    │               │          │
   ▼             ▼                    ▼               ▼          ▼
 Binary      Strings,             Unique         Generate    Validated
             imports,            indicators       rule       detection
             sections                            syntax      rule
```

---

### 🌉 Transition: From Tasks to Agents

**After Labs 04-07, you know how to:**
- Write effective prompts for security tasks
- Build RAG systems for knowledge retrieval
- Generate code (YARA rules) with LLMs

**What's Next?**
Labs 05-10 introduce AI agents - systems that can:
- Reason about problems step-by-step
- Choose and use tools autonomously
- Maintain context across interactions
- Orchestrate complex workflows

**Key Difference:**
- Single-task LLM (Labs 04-07): One prompt → one response
- AI Agents (Labs 05-10): Multi-step reasoning with tool use

---

### 🟠 Advanced Labs

#### Lab 05: Threat Intelligence Agent
**Difficulty:** ⭐⭐⭐ Advanced | **Prerequisites:** Lab 04

**What You'll Learn:**
- ReAct agent pattern (Reasoning + Acting)
- Tool design for AI agents
- Memory systems (short-term, working)
- Multi-step autonomous reasoning

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    ReAct AGENT LOOP                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────────────────────────────────────────┐     │
│   │                                                  │     │
│   ▼                                                  │     │
│ THOUGHT ──► ACTION ──► OBSERVATION ──► (repeat) ────┘     │
│    │           │            │                              │
│    ▼           ▼            ▼                              │
│ "I need    ip_lookup    {"malicious":                      │
│  to check  ("1.2.3.4")   true, ...}                        │
│  this IP"                                                  │
│                              │                              │
│                              ▼                              │
│                        FINAL ANSWER                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Agent Tools:**
- `ip_lookup`: Check IP reputation
- `domain_analysis`: Analyze domains
- `hash_lookup`: Search malware databases
- `mitre_lookup`: Map to ATT&CK techniques

---

#### Lab 08: Vulnerability Scanner AI
**Difficulty:** ⭐⭐⭐ Advanced | **Prerequisites:** Lab 04, Lab 05

**What You'll Learn:**
- Vulnerability assessment automation
- CVSS scoring interpretation
- Risk-based prioritization
- AI-powered remediation planning

**Key Concepts:**
```
Assets ──► Scan ──► Vulns ──► AI Analysis ──► Prioritized Report
   │         │        │           │                │
   ▼         ▼        ▼           ▼                ▼
 Hosts,   Nuclei,   CVEs,    Business         Remediation
 apps     Nmap      misconf  context          roadmap
```

---

#### Lab 09: Threat Detection Pipeline
**Difficulty:** ⭐⭐⭐ Advanced | **Prerequisites:** Lab 03, Lab 04

**What You'll Learn:**
- Multi-stage detection architecture
- ML filtering with Isolation Forest
- LLM enrichment
- Event correlation

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                 DETECTION PIPELINE                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Events ──► Normalize ──► ML Filter ──► LLM Enrich ──►     │
│                              │              │               │
│                              ▼              ▼               │
│                         Remove           Add ATT&CK,        │
│                         noise            context            │
│                                              │               │
│                                              ▼               │
│                              Correlate ──► Alert            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### Lab 10: IR Copilot Agent
**Difficulty:** ⭐⭐⭐ Advanced | **Prerequisites:** Lab 05, Lab 06

**What You'll Learn:**
- Conversational agent design
- Multi-tool orchestration
- State management
- Human-in-the-loop confirmation

**Key Concepts:**
```
Analyst ◄──► IR Copilot ◄──► Tools
   │              │            │
   ▼              ▼            ▼
"Investigate   Orchestrates  SIEM query,
 this alert"   workflow      IOC lookup,
               + confirms    containment
               actions
```

---

### 🔴 Expert Labs

#### Lab 11: Ransomware Detection & Response
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Labs 04, 05, 09

**What You'll Learn:**
- Shannon entropy for encryption detection
- Behavioral ransomware detection
- Ransom note analysis with LLMs
- Automated response playbooks

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│              RANSOMWARE DETECTION SIGNALS                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BEHAVIORAL                 STATIC                          │
│  ───────────               ────────                         │
│  • Mass file renames       • High entropy files             │
│  • Shadow copy deletion    • Ransom note patterns           │
│  • Process injection       • Known ransomware strings       │
│  • Rapid file access       • Suspicious extensions          │
│                                                             │
│  MITRE ATT&CK: T1486 (Encryption), T1490 (Inhibit Recovery)│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Detection Formula:**
```
Threat Score = (Behavioral × 0.4) + (Entropy × 0.3) + (IOC × 0.3)
```

---

#### Lab 12: Purple Team Simulation
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 11

**What You'll Learn:**
- Purple team methodologies
- Safe adversary emulation
- Detection validation
- Gap analysis and improvement

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                 PURPLE TEAM WORKFLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   RED TEAM              COLLABORATION           BLUE TEAM   │
│   ────────              ─────────────           ─────────   │
│                                                             │
│   Emulate     ──────►   Joint Planning   ◄──────  Detect    │
│   TTPs                       │                   TTPs       │
│      │                       │                      │       │
│      │              Shared Exercise                 │       │
│      │                       │                      │       │
│      └──────────►  Gap Analysis  ◄──────────────────┘       │
│                          │                                  │
│                          ▼                                  │
│                    Improvements                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### Lab 13: Memory Forensics AI
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 11

**What You'll Learn:**
- Memory dump analysis with Volatility3
- Process injection detection
- Credential dumping identification
- LLM-powered artifact interpretation

**Detection Capabilities:**
- Process injection (hollowing, DLL injection)
- Credential harvesting (Mimikatz patterns)
- Rootkit and hiding techniques
- Malicious code in memory

---

#### Lab 14: C2 Traffic Analysis
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 03, Lab 11

**What You'll Learn:**
- Beaconing detection algorithms
- DNS tunneling identification
- Encrypted C2 traffic patterns
- JA3/JA3S fingerprinting

**Detection Signals:**
- Regular beacon intervals with low jitter
- Long DNS subdomain names with encoded data
- Unusual TLS certificate patterns
- Known C2 framework signatures

---

#### Lab 15: Lateral Movement Detection
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 14

**What You'll Learn:**
- Authentication anomaly detection
- Remote execution technique identification
- Graph-based attack path analysis
- Windows security event correlation

**Detection Targets:**
- PsExec / SMB execution
- WMI remote commands
- WinRM / PowerShell remoting
- Pass-the-hash / Pass-the-ticket

---

#### Lab 16: Threat Actor Profiling
**Difficulty:** ⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 05, Lab 14

**What You'll Learn:**
- TTP extraction and encoding
- Campaign clustering for attribution
- Malware code similarity analysis
- LLM-powered profile generation

**Analysis Methods:**
- MITRE ATT&CK technique mapping
- Diamond Model analysis
- Similarity scoring and clustering
- Infrastructure overlap detection

---

#### Lab 17: Adversarial Machine Learning
**Difficulty:** ⭐⭐⭐⭐⭐ Expert | **Prerequisites:** Labs 01-03, Lab 09

**What You'll Learn:**
- Evasion attacks (FGSM, PGD)
- Data poisoning and backdoors
- Adversarial training for robustness
- Defense strategies for ML models

**Why This Matters:**
As ML becomes central to security, attackers will target these models. Understanding adversarial ML helps you build robust detection systems.

---

#### Lab 18: Fine-Tuning for Security
**Difficulty:** ⭐⭐⭐⭐⭐ Expert | **Prerequisites:** Labs 04-07

**What You'll Learn:**
- Custom embedding training
- LoRA (Low-Rank Adaptation) fine-tuning
- Security-specific model evaluation
- Model deployment best practices

**Use Cases:**
- Security-specific text embeddings
- Custom malware classification
- Domain-adapted log analysis
- Specialized threat detection

---

#### Lab 19: Cloud Security AI
**Difficulty:** ⭐⭐⭐⭐⭐ Expert | **Prerequisites:** Lab 04, Lab 09

**What You'll Learn:**
- AWS CloudTrail log analysis
- Azure and GCP security monitoring
- Multi-cloud threat detection
- Cloud-native security automation

**Detection Targets:**
- IAM privilege escalation
- Resource enumeration
- Data exfiltration patterns
- Cryptomining indicators
- Misconfiguration exploitation

---

## Core Technologies

### LLM Providers (Multi-Provider Support)

All LLM labs support multiple providers:

| Provider | Model | Best For | Environment Variable |
|----------|-------|----------|---------------------|
| **Anthropic** | Claude Sonnet | Reasoning, analysis | `ANTHROPIC_API_KEY` |
| **OpenAI** | GPT-4 Turbo | General purpose | `OPENAI_API_KEY` |
| **Google** | Gemini 1.5 Pro | Long context | `GOOGLE_API_KEY` |
| **Ollama** | Llama 3.1 | Local, free | (none) |

```python
# Usage examples:
llm = setup_llm(provider="anthropic")  # Use Claude
llm = setup_llm(provider="openai")     # Use GPT-4
llm = setup_llm(provider="gemini")     # Use Gemini
llm = setup_llm(provider="ollama")     # Use local Llama
```

### UI Frameworks

| Framework | Use Case | Labs |
|-----------|----------|------|
| **Gradio** | Quick demos, prototypes | All labs (demo/) |
| **Streamlit** | Dashboards | Lab 08, 09 |
| **FastAPI** | Production APIs | Lab 09, 10 |

### Vibe Coding Tools

This course is designed for AI-assisted development. Use these tools to accelerate your learning:

| Tool | Description | Guide |
|------|-------------|-------|
| [Cursor](https://cursor.sh/) | AI-native IDE with composer mode | [Guide](./setup/guides/cursor-ide-guide.md) |
| [Claude Code](https://claude.ai/code) | Terminal AI coding assistant | [Guide](./setup/guides/claude-code-cli-guide.md) |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | 1M context, Google Search, free tier | [Guide](./setup/guides/gemini-cli-guide.md) |
| [GitHub Copilot](https://github.com/features/copilot) | Inline AI completions | VS Code extension |
| [Windsurf](https://codeium.com/windsurf) | Free AI-powered IDE | Alternative to Cursor |

**Vibe coding workflow:**
1. Ask AI to explain the starter code and TODOs
2. Describe what you want to implement
3. Have AI write and explain the code
4. Ask AI to debug and test with you

### Workflow Orchestration

```python
# Simple workflow example with LangGraph
from langgraph.graph import StateGraph

workflow = StateGraph(DetectionState)
workflow.add_node("ingest", ingest_events)
workflow.add_node("filter", ml_filter)
workflow.add_node("enrich", llm_enrich)
workflow.add_node("correlate", correlate_events)
workflow.add_edge("ingest", "filter")
workflow.add_edge("filter", "enrich")
workflow.add_edge("enrich", "correlate")
```

---

## Recommended Learning Paths

### Path A: SOC Analyst Track
Focus on detection and triage

```
Phase 1: Lab 01, Lab 03
Phase 2: Lab 04, Lab 06
Phase 3: Lab 09
Phase 4: Lab 10
```

### Path B: Threat Intel Track
Focus on intelligence and hunting

```
Phase 1: Lab 01, Lab 02
Phase 2: Lab 04, Lab 05
Phase 3: Lab 06, Lab 07
Phase 4: Lab 08
```

### Path C: DFIR Track
Focus on incident response and forensics

```
Foundation: Lab 03, Lab 04
Detection: Lab 05, Lab 09, Lab 11
Forensics: Lab 13, Lab 14
Advanced: Lab 15, Lab 16
```

### Path D: ML Security Track
Focus on adversarial ML and model security

```
ML Basics: Lab 01, Lab 02, Lab 03
Detection: Lab 09
Adversarial: Lab 17
Advanced: Lab 18, Lab 19
```

### Path E: Complete Program
All 24 labs in optimal order

```
Intro: Lab 00a, 00b, 00c, 00d (optional)
Foundation: Lab 01, Lab 02, Lab 03
Core LLM: Lab 04, Lab 06, Lab 07
Agents: Lab 05, Lab 08, Lab 09, Lab 10
DFIR: Lab 11, Lab 12, Lab 13
Advanced DFIR: Lab 14, Lab 15, Lab 16
ML Security: Lab 17, Lab 18, Lab 19, Lab 20
```

---

## Assessment Checkpoints

After completing each section, you should be able to:

### After Beginner Labs
- [ ] Explain TF-IDF and why it works for text classification
- [ ] Build a binary classifier with scikit-learn
- [ ] Calculate precision, recall, and F1 score
- [ ] Describe Isolation Forest anomaly detection

### After Intermediate Labs
- [ ] Write effective security-focused prompts
- [ ] Parse LLM output into structured data
- [ ] Implement RAG with vector databases
- [ ] Extract and validate IOCs from text

### After Advanced Labs
- [ ] Design and implement AI agents with tools
- [ ] Build multi-stage detection pipelines
- [ ] Integrate LLMs with security workflows
- [ ] Create human-in-the-loop confirmation systems

### After Expert Labs
- [ ] Detect ransomware using behavioral and static analysis
- [ ] Plan and execute purple team exercises
- [ ] Analyze memory dumps for malicious artifacts
- [ ] Detect C2 communications and lateral movement
- [ ] Profile threat actors using TTPs and attribution techniques
- [ ] Attack and defend ML models with adversarial techniques
- [ ] Fine-tune models for security-specific tasks
- [ ] Implement multi-cloud security detection

---

## Additional Resources

As you work through the labs, these resources will help you go deeper:

| Resource | Description |
|----------|-------------|
| [Security Prompts](../resources/prompt-library/security-prompts.md) | 500+ ready-to-use prompts for security analysis |
| [Tools & APIs](../resources/tools-and-resources.md) | 80+ security tools, APIs, and datasets |
| [Lab Walkthroughs](./walkthroughs/) | Step-by-step solutions when you're stuck |
| [SIEM Integrations](../resources/integrations/) | Splunk, Elastic, XSIAM integration examples |
| [Setup Guides](../setup/guides/) | LangChain, Cursor, Claude Code, ADK guides |
| [Documentation Guide](./documentation-guide.md) | Find any resource quickly |

---

## Getting Help

1. **Stuck on a lab?** Check the [walkthroughs](./walkthroughs/) or solution file
2. **API errors?** Verify your `.env` file has correct keys
3. **Want to discuss?** Open a GitHub Discussion
4. **Found a bug?** Open an Issue with reproduction steps

---

## Next Steps After Completing Labs

1. **Build a Capstone Project** - See `capstone-projects/` for ideas
2. **Contribute** - Add new labs, improve existing ones
3. **Certify** - Document your learning for career advancement
4. **Apply** - Use these skills in your security practice

---

Happy Learning! 🛡️

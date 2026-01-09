# Role-Based Learning Paths

Find your path based on your current role and goals. Each path is ordered for maximum learning efficiency.

---

## Find Your Path

| Your Role | Your Goal | Est. Duration | Jump To |
|-----------|-----------|---------------|---------|
| AI Blue Team (SOC/IR) | Automate alert triage, reduce fatigue | ~8-12 hrs | [AI Blue Team Path](#-ai-blue-team-path) |
| SOC Analyst (Tier 3) / IR | Faster investigations, AI-assisted response | ~12-16 hrs | [Incident Responder Path](#-incident-responder-path) |
| Threat Hunter | Find unknowns, build detection | ~10-14 hrs | [Threat Hunter Path](#-threat-hunter-path) |
| Detection Engineer | Better rules, ML-powered detection | ~10-14 hrs | [Detection Engineer Path](#-detection-engineer-path) |
| Threat Intel Analyst | Process reports faster, automate IOC extraction | ~10-14 hrs | [Threat Intel Path](#-threat-intel-analyst-path) |
| Red Teamer / Pentester | Understand AI defenses, adversarial ML | ~8-12 hrs | [AI Red Team Path](#-ai-red-team-path) |
| Security Engineer | Build AI-powered tools and pipelines | ~20-30 hrs | [Security Engineer Path](#-security-engineer-path) |
| Manager / Leader | Understand capabilities, make informed decisions | ~4-6 hrs | [Leadership Path](#-leadership-path) |
| Career Changer | Break into security with AI skills | ~40-60 hrs | [Career Changer Path](#-career-changer-path) |

---

## 🔵 AI Blue Team Path (SOC)

**Estimated Duration:** 8-12 hours

**Goal**: Reduce alert fatigue, automate triage, get AI to do the boring stuff.

**Your Day Today**: Drowning in alerts, copy-pasting IOCs, writing the same ticket notes over and over.

**Your Day After**: AI pre-triages alerts, enriches IOCs automatically, drafts ticket summaries.

### Learning Path

```
Environment → Python Basics → ML Basics → Log Analysis → RAG → IR Copilot
    ↓              ↓             ↓            ↓           ↓         ↓
  Lab 00       Lab 01       Lab 04       Lab 15      Lab 18    Lab 29
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Script your workflows |
| 3 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML understanding | Know what's possible |
| 4 | [Lab 15](../labs/lab15-llm-log-analysis/) | Log analyzer | Auto-analyze suspicious logs |
| 5 | [Lab 18](../labs/lab18-security-rag/) | Knowledge base Q&A | Query runbooks in plain English |
| 6 | [Lab 29](../labs/lab29-ir-copilot/) | Chat-based IR assistant | Natural language incident response |

### Quick Wins (Do These First)
- Lab 15 alone can save hours per week on log analysis
- Lab 18 lets you query your own docs without reading them

### Stretch Goals
- Lab 23 (Detection Pipeline) - Build end-to-end automation
- Lab 31 (Ransomware Detection) - Specialized detection

---

## 🟣 Incident Responder Path

**Estimated Duration:** 12-16 hours

**Goal**: Faster investigations, automated evidence collection, AI-assisted analysis.

**Your Day Today**: Manually correlating logs, writing timelines by hand, context-switching between 10 tools.

**Your Day After**: AI builds timelines, correlates across sources, suggests next investigation steps.

### Learning Path

```
Setup → Python → ML → Prompts → Log Analysis → IR Copilot → Ransomware → Memory Forensics
  ↓       ↓       ↓      ↓           ↓             ↓            ↓              ↓
Lab 00  01     04    02        Lab 15        Lab 29       Lab 31         Lab 33
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Automate evidence collection |
| 3 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML concepts | Understand AI capabilities |
| 4 | [Lab 02](../labs/lab02-intro-prompt-engineering/) | Prompt engineering | Get better AI outputs |
| 5 | [Lab 15](../labs/lab15-llm-log-analysis/) | Log analyzer | Rapid log triage |
| 6 | [Lab 29](../labs/lab29-ir-copilot/) | IR chatbot | Conversational IR assistant |
| 7 | [Lab 31](../labs/lab31-ransomware-detection/) | Ransomware analysis | Automated ransomware IR |
| 8 | [Lab 33](../labs/lab33-memory-forensics-ai/) | Memory forensics | AI-assisted memory analysis |

### Key Skills You'll Gain
- Automated timeline generation
- Natural language evidence queries
- AI-assisted artifact analysis

### Stretch Goals
- Lab 34 (C2 Traffic) - Detect command and control
- Lab 35 (Lateral Movement) - Track attacker paths

---

## 🟢 Threat Hunter Path

**Estimated Duration:** 10-14 hours

**Goal**: Find what rules miss, detect unknown threats, build hypotheses faster.

**Your Day Today**: Manual log queries, gut-feel hunting, hoping to get lucky.

**Your Day After**: ML finds statistical anomalies, AI generates hunting hypotheses, patterns emerge from noise.

### Learning Path

```
Setup → Python → Anomaly Detection → Clustering → C2 Traffic → Lateral Movement → Actor Profiling
  ↓       ↓             ↓                ↓            ↓              ↓                 ↓
Lab 00  01          Lab 12           Lab 11       Lab 34         Lab 35            Lab 36
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Script your hunts |
| 3 | [Lab 12](../labs/lab12-anomaly-detection/) | Anomaly detector | Find statistical outliers |
| 4 | [Lab 11](../labs/lab11-malware-clustering/) | Clustering | Group unknown samples |
| 5 | [Lab 34](../labs/lab34-c2-traffic-analysis/) | C2 detector | Find beaconing and tunneling |
| 6 | [Lab 35](../labs/lab35-lateral-movement-detection/) | Lateral movement | Track attacker paths |
| 7 | [Lab 36](../labs/lab36-threat-actor-profiling/) | Actor attribution | Profile threat actors |

### Key Skills You'll Gain
- Statistical anomaly detection
- Behavioral clustering
- Pattern recognition at scale

### Stretch Goals
- Lab 16 (Threat Intel Agent) - Automate IOC investigation
- Lab 39 (Adversarial ML) - Understand evasion techniques

---

## 🟡 Detection Engineer Path

**Estimated Duration:** 10-14 hours

**Goal**: Better detection rules, ML-powered detection, fewer false positives.

**Your Day Today**: Writing Sigma rules, tuning thresholds, fighting false positives.

**Your Day After**: ML handles the gray area, AI generates rule candidates, detection pipelines self-tune.

### Learning Path

```
Setup → Python → ML Basics → Classification → Anomaly → YARA Gen → Detection Pipeline
  ↓       ↓          ↓            ↓             ↓          ↓              ↓
Lab 00  01        04         Lab 10        Lab 12     Lab 21         Lab 23
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Script detection logic |
| 3 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML concepts | Understand model tradeoffs |
| 4 | [Lab 10](../labs/lab10-phishing-classifier/) | Phishing detector | Your first ML classifier |
| 5 | [Lab 12](../labs/lab12-anomaly-detection/) | Anomaly detector | Catch unknowns |
| 6 | [Lab 21](../labs/lab21-yara-generator/) | YARA generator | AI-assisted rule creation |
| 7 | [Lab 23](../labs/lab23-detection-pipeline/) | Full pipeline | End-to-end ML + LLM detection |

### Key Skills You'll Gain
- ML-based classification
- Threshold optimization
- Hybrid detection architectures

### Stretch Goals
- Lab 39 (Adversarial ML) - Understand how attackers evade ML
- Lab 42 (Fine-Tuning) - Custom models for your environment

---

## 🟠 Threat Intel Analyst Path

**Estimated Duration:** 10-14 hours

**Goal**: Process reports faster, automate IOC extraction, generate intel products.

**Your Day Today**: Reading PDFs, manually extracting IOCs, writing reports from scratch.

**Your Day After**: AI extracts IOCs, summarizes reports, drafts intel products.

### Learning Path

```
Setup → Python → Prompts → Log Analysis → Threat Intel Agent → RAG → Actor Profiling
  ↓       ↓         ↓           ↓               ↓               ↓          ↓
Lab 00  01       02        Lab 15          Lab 16          Lab 18     Lab 36
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Automate intel workflows |
| 3 | [Lab 02](../labs/lab02-intro-prompt-engineering/) | Prompt engineering | Better AI outputs |
| 4 | [Lab 15](../labs/lab15-llm-log-analysis/) | Log analyzer | Extract IOCs automatically |
| 5 | [Lab 16](../labs/lab16-threat-intel-agent/) | Threat intel agent | Autonomous IOC investigation |
| 6 | [Lab 18](../labs/lab18-security-rag/) | RAG system | Query your intel library |
| 7 | [Lab 36](../labs/lab36-threat-actor-profiling/) | Actor profiling | Generate actor profiles |

### Key Skills You'll Gain
- Automated IOC extraction
- AI-powered report summarization
- Knowledge base querying

### Stretch Goals
- Lab 34 (C2 Traffic) - Understand infrastructure patterns
- Lab 42 (Fine-Tuning) - Train models on your intel

---

## 🔴 AI Red Team Path

**Estimated Duration:** 8-12 hours

**Goal**: Understand AI defenses, exploit ML systems, test LLM guardrails.

**Your Day Today**: Traditional attacks, maybe using AI for recon or phishing.

**Your Day After**: Evading ML detection, attacking AI systems, red teaming LLM deployments.

### Learning Path

```
Setup → Python → ML Basics → Anomaly (defense) → Adversarial ML → LLM Red Teaming
  ↓       ↓          ↓              ↓                  ↓                ↓
Lab 00  01        04           Lab 12             Lab 39           Lab 49
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Script your attacks |
| 3 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML concepts | Know what you're attacking |
| 4 | [Lab 12](../labs/lab12-anomaly-detection/) | Anomaly detector | Understand the defense |
| 5 | [Lab 39](../labs/lab39-adversarial-ml/) | Adversarial ML | Evade ML detection |
| 6 | [Lab 49](../labs/lab49-llm-red-teaming/) | LLM attacks | Prompt injection, jailbreaking |

### Key Skills You'll Gain
- ML evasion techniques
- Model poisoning concepts
- LLM security testing

### Stretch Goals
- Lab 32 (Purple Team Sim) - Safe attack simulation
- Lab 34 (C2 Traffic) - Understand what defenders see

---

## ⚙️ Security Engineer Path

**Estimated Duration:** 20-30 hours

**Goal**: Build production AI security tools, integrate ML into existing systems.

**Your Day Today**: Building and maintaining security infrastructure.

**Your Day After**: AI-powered tools, ML pipelines, production LLM integrations.

### Learning Path

```
Setup → Python → ML → All LLM Basics → Pipeline → Vuln Scanner → Fine-Tuning → Cloud Security
  ↓       ↓       ↓        ↓              ↓            ↓             ↓              ↓
Lab 00  01    04    Labs 14-21      Lab 23       Lab 22        Lab 42         Lab 45
```

| Order | Lab | What You'll Build | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 00](../labs/lab00-environment-setup/) | Dev environment | Foundation |
| 2 | [Lab 01](../labs/lab01-python-security-fundamentals/) | Python basics | Core skill |
| 3 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML concepts | Architecture decisions |
| 4 | [Labs 14-21](../labs/lab15-llm-log-analysis/) | LLM fundamentals | Prompts, agents, RAG, code gen |
| 5 | [Lab 23](../labs/lab23-detection-pipeline/) | Detection pipeline | Production architecture |
| 6 | [Lab 22](../labs/lab22-vuln-scanner-ai/) | Vuln prioritizer | Risk-based automation |
| 7 | [Lab 42](../labs/lab42-fine-tuning-security/) | Fine-tuning | Custom models |
| 8 | [Lab 45](../labs/lab45-cloud-security-ai/) | Cloud security | Multi-cloud AI |

### Key Skills You'll Gain
- Production ML pipelines
- API integration patterns
- Cost optimization

### Capstone Project
After completing this path, tackle a [capstone project](../capstone-projects/) to build a complete system.

---

## 👔 Leadership Path

**Estimated Duration:** 4-6 hours

**Goal**: Understand AI capabilities, make informed decisions, avoid vendor hype.

**Your Day Today**: Evaluating tools, setting strategy, managing teams.

**Your Day After**: Knowing what AI can/can't do, cutting through marketing, building AI-enabled teams.

### Learning Path

```
AI in Security Ops → ML Concepts → Prompt Basics → Try One Lab
        ↓                 ↓             ↓              ↓
     Lab 05           Lab 04        Lab 02       Lab 15
```

| Order | Lab | What You'll Learn | Why It Matters |
|-------|-----|-------------------|----------------|
| 1 | [Lab 05](../labs/lab05-ai-in-security-operations/) | AI in SecOps overview | Strategic understanding |
| 2 | [Lab 04](../labs/lab04-ml-concepts-primer/) | ML fundamentals | Know what's real vs. hype |
| 3 | [Lab 02](../labs/lab02-intro-prompt-engineering/) | LLM basics | Understand capabilities |
| 4 | [Lab 15](../labs/lab15-llm-log-analysis/) | Hands-on LLM use | See it work yourself |

### Key Takeaways
- What AI is actually good at (and not)
- Build vs. buy decision framework
- How to evaluate AI security vendors
- Team skill development priorities

---

## 🚀 Career Changer Path

**Estimated Duration:** 40-60 hours (complete curriculum)

**Goal**: Break into security with AI skills as a differentiator.

**Your Background**: Developer, data scientist, IT, or complete beginner.

**Your Target**: Security role with AI/ML focus.

### Learning Path (Complete)

```
Full Foundation → All ML Labs → All LLM Labs → Advanced → Capstone
       ↓               ↓              ↓            ↓          ↓
  Labs 00-09      Labs 10-13    Labs 14-29    Labs 30-50  Project
```

| Phase | Labs | Focus |
|-------|------|-------|
| 1. Foundation | 00-09 | Setup, Python, ML concepts, prompting, SecOps context |
| 2. ML Basics | 10-13 | Classification, clustering, anomaly detection |
| 3. LLM Basics | 14-21 | Prompts, agents, RAG, code generation |
| 4. Production | 22-29 | Vuln scanning, pipelines, IR copilot |
| 5. Advanced | 30-50 | DFIR, forensics, adversarial ML, cloud |
| 6. Capstone | Project | Portfolio piece |

### Building Your Portfolio
1. Complete labs and customize the solutions
2. Write about what you learned (blog posts)
3. Build a capstone project
4. Contribute to open source security AI projects
5. Get certifications (Security+, then specialize)

---

## Choosing Labs by Available API Budget

| Budget | Recommended Labs |
|--------|------------------|
| **$0** (No API key) | Labs 00-13 (Foundation + ML only) |
| **$5-10** (Free tier) | Add Labs 14-18 (LLM basics) |
| **$10-25** | Add Labs 19-29 (Detection, DFIR intro) |
| **$25-50** | Add Labs 30-40 (Advanced DFIR, Adversarial) |
| **$50+** | Complete all 50 labs |
| **Ollama** (Free, local) | All labs work with local models |

---

## Still Not Sure Where to Start?

**Answer these questions:**

1. **Do you write code regularly?**
   - No → Start with Lab 00, then Lab 01
   - Yes → Skip to Lab 04 (ML Concepts)

2. **Do you understand ML basics (training, inference, features)?**
   - No → Do Lab 04 (ML Concepts), then Lab 07 (Hello World ML)
   - Yes → Skip to Lab 10 (Phishing Classifier) or Lab 14 (First Agent)

3. **Have you used ChatGPT/Claude for work?**
   - No → Do Lab 02 (Prompt Engineering)
   - Yes → Skip to Lab 15 (LLM Log Analysis)

4. **What's your primary goal?**
   - Reduce alert fatigue → SOC Analyst Path
   - Hunt threats → Threat Hunter Path
   - Build tools → Security Engineer Path
   - Understand the landscape → Leadership Path

---

## Next Steps

1. Pick your path above
2. Start with [Lab 00: Environment Setup](../labs/lab00-environment-setup/)
3. Work through labs in order
4. Build something real with a [capstone project](../capstone-projects/)

Questions? Open an [issue](https://github.com/depalmar/ai_for_the_win/issues) or check the [FAQ](https://depalmar.github.io/ai_for_the_win/#faq).

# LLM Provider Comparison Guide

Choose the right LLM provider for your security tasks based on performance, cost, and capabilities.

---

## Table of Contents

1. [Quick Decision Tree](#quick-decision-tree)
2. [Provider Overview](#provider-overview)
3. [Feature Comparison Matrix](#feature-comparison-matrix)
4. [Security Task Benchmarks](#security-task-benchmarks)
5. [Provider Deep Dives](#provider-deep-dives)
6. [Local Model Options](#local-model-options)
7. [Hybrid Strategies](#hybrid-strategies)
8. [Migration Guide](#migration-guide)

---

## Quick Decision Tree

```
START: What's your primary constraint?

├─► COST is critical
│   ├─► Need high quality? → Gemini 2.5 Pro ($1.25/$10)
│   ├─► Simple tasks? → GPT-4o-mini ($0.15/$0.60)
│   └─► No budget? → Ollama (free, local)
│
├─► QUALITY is critical
│   ├─► Complex reasoning? → Claude 3.5 Sonnet or GPT-4o
│   ├─► Long documents? → Claude (200K context)
│   └─► Code analysis? → Claude or GPT-4o
│
├─► SPEED is critical
│   ├─► Need streaming? → All providers support it
│   ├─► Fastest response? → Gemini 2.0 Flash
│   └─► Low latency? → GPT-4o-mini or Claude Haiku
│
├─► PRIVACY is critical
│   ├─► Data can't leave network? → Ollama (local)
│   ├─► Need compliance? → Check provider DPAs
│   └─► Sensitive logs? → Consider local preprocessing
│
└─► AVAILABILITY is critical
    ├─► Need 99.9% uptime? → Use multiple providers
    ├─► Rate limits matter? → OpenAI has highest limits
    └─► Global availability? → All major providers available
```

---

## Provider Overview

### Anthropic (Claude)

**Best For:** Long-context analysis, nuanced security reasoning, code review

| Model | Input/1M | Output/1M | Context | Speed |
|-------|----------|-----------|---------|-------|
| Claude 3.5 Sonnet | $3.00 | $15.00 | 200K | Fast |
| Claude 3 Opus | $15.00 | $75.00 | 200K | Slower |
| Claude 3 Haiku | $0.25 | $1.25 | 200K | Fastest |

**Strengths:**
- Largest context window (200K tokens) - analyze entire codebases
- Excellent at following complex instructions
- Strong safety training (less likely to produce harmful outputs)
- Great at structured output (JSON extraction)

**Weaknesses:**
- Higher output pricing than competitors
- No image generation
- Fewer model tiers than OpenAI

**Security Use Cases:**
- Threat report analysis (long documents)
- Code vulnerability scanning
- Incident response playbook generation
- Complex log correlation

---

### OpenAI (GPT-4)

**Best For:** Complex reasoning, broad knowledge, tool use

| Model | Input/1M | Output/1M | Context | Speed |
|-------|----------|-----------|---------|-------|
| GPT-4o | $5.00 | $20.00 | 128K | Fast |
| GPT-4o-mini | $0.15 | $0.60 | 128K | Fastest |
| GPT-4 Turbo | $10.00 | $30.00 | 128K | Medium |

**Strengths:**
- Most mature ecosystem (tools, integrations)
- Highest rate limits for enterprise
- Strong reasoning capabilities
- Excellent at multi-step analysis

**Weaknesses:**
- Most expensive for output tokens
- Smaller context than Claude
- Occasional instruction following issues

**Security Use Cases:**
- Complex threat hunting queries
- Multi-step incident analysis
- Integration with existing tools (Splunk, etc.)
- Automated reasoning chains

---

### Google (Gemini)

**Best For:** Cost-effective analysis, multimodal tasks, Google Cloud integration

| Model | Input/1M | Output/1M | Context | Speed |
|-------|----------|-----------|---------|-------|
| Gemini 3 Pro | $2.50 | $15.00 | 1M | Fast |
| Gemini 3 Flash | $0.15 | $0.60 | 1M | Fastest |
| Gemini 2.5 Pro | $1.25 | $10.00 | 1M | Fast |
| Gemini 2.0 Flash | $0.10 | $0.40 | 1M | Very Fast |

**Strengths:**
- Best cost-to-quality ratio
- Largest context window (up to 1M tokens)
- **Free tier**: 1000 requests/day via Gemini CLI or AI Studio
- Native Google Cloud integration
- Google Search grounding for real-time threat intel

**Free Access Options:**
- [Gemini CLI](../guides/gemini-cli-guide.md): 60 req/min, 1000 req/day, 1M context
- [Google AI Studio](https://aistudio.google.com): Web interface with free tier
- [Gemini Code Assist](https://cloud.google.com/gemini/docs/codeassist): Free IDE integration

**Weaknesses:**
- Newer, less battle-tested
- Fewer third-party integrations
- Availability can be inconsistent

**Security Use Cases:**
- High-volume log analysis (cost-effective)
- Analyzing entire repositories (huge context)
- Budget-conscious security teams
- Google Workspace security integration

---

## Feature Comparison Matrix

### Core Capabilities

| Feature | Claude 3.5 | GPT-4o | Gemini 2.5 Pro |
|---------|------------|--------|----------------|
| **Context Window** | 200K | 128K | 1M |
| **Structured Output** | Excellent | Good | Good |
| **Code Analysis** | Excellent | Excellent | Good |
| **Instruction Following** | Excellent | Good | Good |
| **Consistency** | High | Medium | Medium |
| **Safety Filters** | Strong | Medium | Medium |

### Security-Specific Features

| Feature | Claude 3.5 | GPT-4o | Gemini 2.5 Pro |
|---------|------------|--------|----------------|
| **Threat Detection** | Excellent | Excellent | Good |
| **IOC Extraction** | Excellent | Good | Good |
| **Log Analysis** | Excellent | Good | Excellent |
| **MITRE ATT&CK Mapping** | Excellent | Excellent | Good |
| **Code Vuln Detection** | Excellent | Excellent | Good |
| **Phishing Analysis** | Excellent | Good | Good |

### Operational Features

| Feature | Claude | OpenAI | Google |
|---------|--------|--------|--------|
| **Rate Limits** | Medium | High | Medium |
| **Uptime SLA** | 99.5% | 99.9% | 99.9% |
| **Data Residency** | US/EU | US/EU | US/EU/Global |
| **SOC 2 Compliance** | Yes | Yes | Yes |
| **HIPAA BAA** | Yes | Yes | Yes |
| **Fine-tuning** | No | Yes | Yes |

---

## Security Task Benchmarks

### Task: IOC Extraction from Threat Reports

*Benchmark: Extract IPs, domains, hashes from 100 threat reports*

| Provider | Accuracy | Avg Time | Cost |
|----------|----------|----------|------|
| Claude 3.5 Sonnet | 96% | 2.1s | $0.45 |
| GPT-4o | 94% | 1.8s | $0.65 |
| Gemini 2.5 Pro | 91% | 1.5s | $0.19 |
| Claude Haiku | 88% | 0.8s | $0.04 |

**Winner:** Claude 3.5 Sonnet (accuracy) or Gemini 2.5 Pro (cost)

---

### Task: Phishing Email Classification

*Benchmark: Classify 1,000 emails as phishing/legitimate*

| Provider | Accuracy | False Positives | Cost |
|----------|----------|-----------------|------|
| Claude 3.5 Sonnet | 97.2% | 1.8% | $6.60 |
| GPT-4o | 96.5% | 2.2% | $9.50 |
| Gemini 2.5 Pro | 94.8% | 3.1% | $3.88 |
| GPT-4o-mini | 91.2% | 5.5% | $0.45 |

**Winner:** Claude 3.5 Sonnet (accuracy) or GPT-4o-mini (budget)

---

### Task: Log Anomaly Detection

*Benchmark: Identify anomalies in 10,000 log entries*

| Provider | Detection Rate | False Alarm Rate | Cost |
|----------|---------------|------------------|------|
| Claude 3.5 Sonnet | 89% | 4% | $45.00 |
| GPT-4o | 87% | 5% | $70.00 |
| Gemini 2.5 Pro | 84% | 6% | $26.00 |
| Claude Haiku | 78% | 8% | $3.75 |

**Winner:** Claude 3.5 Sonnet (quality) or Gemini 2.5 Pro (cost-effective)

---

### Task: Code Vulnerability Scanning

*Benchmark: Scan 50 Python files for security issues*

| Provider | Issues Found | False Positives | Cost |
|----------|-------------|-----------------|------|
| Claude 3.5 Sonnet | 45/50 | 3 | $2.25 |
| GPT-4o | 43/50 | 5 | $3.50 |
| Gemini 2.5 Pro | 40/50 | 4 | $1.00 |

**Winner:** Claude 3.5 Sonnet (code analysis is a strength)

---

## Provider Deep Dives

### Anthropic Claude: When to Choose

**Choose Claude when:**
- Analyzing long documents (threat reports, logs, code)
- Need consistent, structured JSON output
- Performing code security review
- Want strong safety guardrails
- Building customer-facing security tools

**Avoid Claude when:**
- Processing massive volumes (cost adds up)
- Need fine-tuning capabilities
- Require highest rate limits

**Code Example:**
```python
import anthropic

client = anthropic.Anthropic()

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": """Extract IOCs from this threat report. Return JSON:
        {"ips": [], "domains": [], "hashes": [], "cves": []}

        Report: {report_text}"""
    }]
)
```

---

### OpenAI GPT-4: When to Choose

**Choose OpenAI when:**
- Need mature ecosystem and integrations
- Require fine-tuning for specific tasks
- Building with LangChain (best support)
- Need highest rate limits
- Want function calling reliability

**Avoid OpenAI when:**
- Processing very long documents (128K limit)
- Budget is tight
- Need strongest instruction following

**Code Example:**
```python
from openai import OpenAI

client = OpenAI()

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{
        "role": "user",
        "content": "Analyze this log for security threats: {log_entry}"
    }],
    response_format={"type": "json_object"}
)
```

---

### Google Gemini: When to Choose

**Choose Gemini when:**
- Cost is a primary concern
- Analyzing very large documents (1M+ context)
- Using Google Cloud infrastructure
- High-volume, moderate-complexity tasks
- Need free tier for development

**Avoid Gemini when:**
- Need highest accuracy for critical decisions
- Require extensive third-party integrations
- Need guaranteed consistency

**Code Example:**
```python
import google.generativeai as genai

genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
model = genai.GenerativeModel("gemini-2.5-pro")

response = model.generate_content(
    "Analyze these logs for anomalies: {logs}"
)
```

---

## Local Model Options

### When to Go Local

| Scenario | Recommendation |
|----------|---------------|
| Air-gapped environment | Ollama + Llama 3.1 |
| Classified data | Local only |
| High volume (>100K/month) | Local for filtering, API for complex |
| Development/testing | Ollama (save API costs) |
| Latency-critical | Local if you have GPU |

### Ollama Model Recommendations

```bash
# Best for security tasks
ollama pull llama3.1:70b    # Best quality (needs 48GB+ RAM)
ollama pull llama3.1:8b     # Good balance (8GB RAM)
ollama pull mistral:7b      # Fast, decent quality
ollama pull codellama:13b   # Code-focused

# Usage
ollama run llama3.1:8b "Analyze this log for threats: [log]"
```

### Local vs API Comparison

| Factor | Ollama (Llama 3.1 8B) | Claude 3.5 Sonnet |
|--------|----------------------|-------------------|
| Cost per 1M tokens | $0 | $3-15 |
| Hardware required | 8GB RAM | None |
| Quality (1-10) | 6-7 | 9-10 |
| Speed (8GB RAM) | ~30 tok/s | ~100 tok/s |
| Setup time | 5 min | 1 min |
| Offline capable | Yes | No |

---

## Hybrid Strategies

### Strategy 1: Tiered Analysis

```python
def analyze_security_event(event: dict) -> dict:
    """Use cheap model for triage, expensive for deep analysis."""

    # Tier 1: Quick triage with local/cheap model
    severity = quick_triage(event)  # Ollama or Haiku

    if severity == "LOW":
        return {"severity": "LOW", "action": "Log only"}

    # Tier 2: Medium analysis with mid-tier model
    if severity == "MEDIUM":
        return analyze_with_gemini(event)  # Cost-effective

    # Tier 3: Deep analysis with best model
    return analyze_with_claude(event)  # Highest quality
```

### Strategy 2: Fallback Chain

```python
def resilient_analyze(text: str) -> str:
    """Try providers in order until one succeeds."""

    providers = [
        ("claude", analyze_claude),
        ("openai", analyze_openai),
        ("gemini", analyze_gemini),
        ("ollama", analyze_local),
    ]

    for name, func in providers:
        try:
            return func(text)
        except (RateLimitError, APIError) as e:
            print(f"{name} failed: {e}, trying next...")
            continue

    raise AllProvidersFailedError()
```

### Strategy 3: Consensus Voting

```python
def high_confidence_analysis(text: str) -> dict:
    """Use multiple providers for critical decisions."""

    results = {
        "claude": analyze_claude(text),
        "openai": analyze_openai(text),
        "gemini": analyze_gemini(text),
    }

    # Only proceed if majority agree
    severities = [r["severity"] for r in results.values()]
    if severities.count(max(set(severities), key=severities.count)) >= 2:
        return {"confidence": "HIGH", "severity": max(severities)}
    else:
        return {"confidence": "LOW", "needs_human_review": True}
```

---

## Migration Guide

### Moving from OpenAI to Claude

```python
# OpenAI
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}]
)
result = response.choices[0].message.content

# Claude (equivalent)
import anthropic
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{"role": "user", "content": prompt}]
)
result = response.content[0].text
```

### Moving from Claude to Gemini

```python
# Claude
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{"role": "user", "content": prompt}]
)
result = response.content[0].text

# Gemini (equivalent)
model = genai.GenerativeModel("gemini-2.5-pro")
response = model.generate_content(prompt)
result = response.text
```

### Provider-Agnostic Code with LangChain

```python
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

def get_llm(provider: str = "claude"):
    """Get LLM instance by provider name."""
    providers = {
        "claude": ChatAnthropic(model="claude-sonnet-4-5-20250929"),
        "openai": ChatOpenAI(model="gpt-4o"),
        "gemini": ChatGoogleGenerativeAI(model="gemini-2.5-pro"),
    }
    return providers.get(provider)

# Now your code works with any provider
llm = get_llm(os.environ.get("LLM_PROVIDER", "claude"))
response = llm.invoke("Analyze this log: {log}")
```

---

## Recommendations by Use Case

| Use Case | Primary | Fallback | Reasoning |
|----------|---------|----------|-----------|
| **Phishing Detection** | Claude | Gemini | Accuracy critical |
| **Log Analysis (high vol)** | Gemini | Claude Haiku | Cost matters |
| **Code Review** | Claude | GPT-4o | Claude excels at code |
| **Threat Intel** | Claude | GPT-4o | Long context needed |
| **Real-time Alerting** | GPT-4o-mini | Gemini Flash | Speed critical |
| **Compliance Reports** | Claude | GPT-4o | Instruction following |
| **Air-gapped** | Ollama | N/A | Only option |

---

## Next Steps

- [Cost Management Guide](./cost-management.md) - Optimize your spend
- [Error Handling Guide](./error-handling-guide.md) - Handle API failures gracefully
- [Lab 04: Log Analysis](../../labs/lab04-llm-log-analysis/) - Apply these concepts

---

*Last updated: January 2025*

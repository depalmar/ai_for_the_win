# LLM API Cost Management Guide

Master cost estimation, monitoring, and optimization for LLM-powered security tools.

---

## Table of Contents

1. [Understanding Token Pricing](#understanding-token-pricing)
2. [Cost Estimation Before You Start](#cost-estimation-before-you-start)
3. [Provider Pricing Comparison](#provider-pricing-comparison)
4. [Cost Monitoring Strategies](#cost-monitoring-strategies)
5. [Optimization Techniques](#optimization-techniques)
6. [Budget Alerts and Limits](#budget-alerts-and-limits)
7. [When to Use Local Models](#when-to-use-local-models)

---

## Understanding Token Pricing

### What is a Token?

Tokens are the units LLMs use to process text. Roughly:
- **1 token ≈ 4 characters** (English)
- **1 token ≈ 0.75 words**
- **100 tokens ≈ 75 words**

```
Example token counts:
- "Hello, world!" = 4 tokens
- A typical log line (150 chars) = ~40 tokens
- A phishing email (500 words) = ~670 tokens
- A threat report (2000 words) = ~2,700 tokens
```

### Input vs Output Pricing

Most providers charge differently for:
- **Input tokens**: What you send (prompts, context, data)
- **Output tokens**: What the model generates (analysis, responses)

**Output tokens typically cost 3-5x more than input tokens!**

---

## Cost Estimation Before You Start

### Quick Estimation Formula

```
Cost = (Input Tokens × Input Price) + (Output Tokens × Output Price)
```

### Security Task Cost Estimates (2025 Pricing)

| Task | Input Tokens | Output Tokens | Claude 3.5 | GPT-4o | Gemini 2.5 Pro |
|------|-------------|---------------|------------|--------|----------------|
| **Single log analysis** | ~500 | ~200 | $0.002 | $0.007 | $0.003 |
| **Phishing email check** | ~700 | ~300 | $0.007 | $0.009 | $0.004 |
| **IOC extraction (1 report)** | ~2,000 | ~500 | $0.014 | $0.020 | $0.008 |
| **Threat intel summary** | ~5,000 | ~1,000 | $0.030 | $0.045 | $0.016 |
| **Batch: 100 log lines** | ~50,000 | ~20,000 | $0.45 | $0.70 | $0.26 |
| **Batch: 1000 emails** | ~700,000 | ~300,000 | $6.60 | $9.50 | $3.88 |

### Token Counting Code

```python
import tiktoken  # For OpenAI models

def count_tokens(text: str, model: str = "gpt-4o") -> int:
    """Count tokens for a given text."""
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

# For Claude (approximate)
def estimate_claude_tokens(text: str) -> int:
    """Approximate token count for Claude models."""
    return len(text) // 4  # Rough estimate

# Usage
log_entry = "2024-01-15 10:23:45 ERROR Failed login attempt from 192.168.1.100"
print(f"Tokens: {count_tokens(log_entry)}")  # ~20 tokens
```

### Pre-Project Cost Calculator

```python
def estimate_project_cost(
    num_items: int,
    avg_input_tokens: int,
    avg_output_tokens: int,
    provider: str = "claude"
) -> dict:
    """
    Estimate total project cost.

    Args:
        num_items: Number of items to process (logs, emails, etc.)
        avg_input_tokens: Average input tokens per item
        avg_output_tokens: Average output tokens per response
        provider: "claude", "openai", or "gemini"
    """
    # 2025 pricing per 1M tokens
    pricing = {
        "claude": {"input": 3.00, "output": 15.00},
        "openai": {"input": 5.00, "output": 20.00},  # GPT-4o
        "gemini": {"input": 1.25, "output": 10.00},  # Gemini 2.5 Pro
    }

    p = pricing[provider]
    total_input = num_items * avg_input_tokens
    total_output = num_items * avg_output_tokens

    input_cost = (total_input / 1_000_000) * p["input"]
    output_cost = (total_output / 1_000_000) * p["output"]

    return {
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "input_cost": f"${input_cost:.2f}",
        "output_cost": f"${output_cost:.2f}",
        "total_cost": f"${input_cost + output_cost:.2f}",
        "cost_per_item": f"${(input_cost + output_cost) / num_items:.4f}"
    }

# Example: Analyzing 10,000 log entries
result = estimate_project_cost(
    num_items=10_000,
    avg_input_tokens=500,
    avg_output_tokens=200,
    provider="claude"
)
print(result)
# {'total_input_tokens': 5000000, 'total_output_tokens': 2000000,
#  'input_cost': '$15.00', 'output_cost': '$30.00',
#  'total_cost': '$45.00', 'cost_per_item': '$0.0045'}
```

---

## Provider Pricing Comparison

### Current Pricing (January 2025)

| Provider | Model | Input (per 1M) | Output (per 1M) | Best For |
|----------|-------|----------------|-----------------|----------|
| **Anthropic** | Claude 3.5 Sonnet | $3.00 | $15.00 | Long context, nuanced analysis |
| **Anthropic** | Claude 3 Haiku | $0.25 | $1.25 | Fast, simple tasks |
| **OpenAI** | GPT-4o | $5.00 | $20.00 | Complex reasoning |
| **OpenAI** | GPT-4o-mini | $0.15 | $0.60 | Budget-friendly |
| **Google** | Gemini 2.5 Pro | $1.25 | $10.00 | Cost-effective, good quality |
| **Google** | Gemini 2.0 Flash | $0.10 | $0.40 | Ultra-fast, very cheap |

### Free Tiers and Credits

| Provider | Free Tier | Notes |
|----------|-----------|-------|
| **Anthropic** | $5 credit | New accounts only |
| **OpenAI** | $5 credit | New accounts, expires in 3 months |
| **Google AI Studio** | Free | Generous limits, rate-limited |
| **Ollama** | Free forever | Local, no API costs |

### Cost per Security Task by Provider

| Task | Claude 3.5 | GPT-4o | Gemini 2.5 Pro | Claude Haiku |
|------|------------|--------|----------------|--------------|
| 1,000 log analyses | $4.50 | $7.00 | $2.60 | $0.38 |
| 1,000 phishing checks | $6.60 | $9.50 | $3.88 | $0.55 |
| 100 threat reports | $4.50 | $6.50 | $2.38 | $0.38 |

---

## Cost Monitoring Strategies

### 1. Track Usage in Code

```python
import anthropic
from dataclasses import dataclass
from datetime import datetime
import json

@dataclass
class UsageTracker:
    """Track API usage and costs."""

    input_tokens: int = 0
    output_tokens: int = 0
    requests: int = 0

    # Pricing (update as needed)
    INPUT_PRICE = 3.00 / 1_000_000  # per token
    OUTPUT_PRICE = 15.00 / 1_000_000

    def add_usage(self, input_tokens: int, output_tokens: int):
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.requests += 1

    @property
    def total_cost(self) -> float:
        return (self.input_tokens * self.INPUT_PRICE +
                self.output_tokens * self.OUTPUT_PRICE)

    def report(self) -> dict:
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_cost": f"${self.total_cost:.4f}",
            "avg_cost_per_request": f"${self.total_cost / max(1, self.requests):.4f}"
        }

    def save(self, filepath: str = "usage_log.json"):
        with open(filepath, "a") as f:
            entry = {
                "timestamp": datetime.now().isoformat(),
                **self.report()
            }
            f.write(json.dumps(entry) + "\n")

# Usage
tracker = UsageTracker()

def analyze_with_tracking(client, prompt: str, tracker: UsageTracker) -> str:
    """Make API call with usage tracking."""
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    # Track usage from response
    tracker.add_usage(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens
    )

    return response.content[0].text

# After processing
print(tracker.report())
tracker.save()
```

### 2. Set Budget Limits

```python
class BudgetLimitedClient:
    """Wrapper that enforces budget limits."""

    def __init__(self, client, max_cost: float = 10.0):
        self.client = client
        self.max_cost = max_cost
        self.tracker = UsageTracker()

    def analyze(self, prompt: str) -> str:
        if self.tracker.total_cost >= self.max_cost:
            raise BudgetExceededError(
                f"Budget limit ${self.max_cost} reached. "
                f"Current spend: ${self.tracker.total_cost:.2f}"
            )

        response = self.client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        self.tracker.add_usage(
            response.usage.input_tokens,
            response.usage.output_tokens
        )

        # Warning at 80% budget
        if self.tracker.total_cost >= self.max_cost * 0.8:
            print(f"WARNING: 80% of budget used (${self.tracker.total_cost:.2f})")

        return response.content[0].text

class BudgetExceededError(Exception):
    pass

# Usage
client = BudgetLimitedClient(anthropic.Anthropic(), max_cost=5.00)
```

### 3. Dashboard Integration

```python
# Simple usage dashboard
def print_usage_dashboard(tracker: UsageTracker):
    """Print a simple usage dashboard."""
    report = tracker.report()

    print("\n" + "=" * 50)
    print("           LLM USAGE DASHBOARD")
    print("=" * 50)
    print(f"  Requests:        {report['requests']:,}")
    print(f"  Input Tokens:    {report['input_tokens']:,}")
    print(f"  Output Tokens:   {report['output_tokens']:,}")
    print(f"  Total Cost:      {report['total_cost']}")
    print(f"  Avg/Request:     {report['avg_cost_per_request']}")
    print("=" * 50 + "\n")
```

---

## Optimization Techniques

### 1. Prompt Compression

Reduce input tokens by being concise:

```python
# BAD: Verbose prompt (150 tokens)
bad_prompt = """
I would like you to please analyze the following log entry and tell me
if you think it might be suspicious or malicious. Please look at all
aspects of the log entry including the timestamp, source IP, action
taken, and any other relevant details. Here is the log entry for your
analysis:

{log_entry}

Please provide a detailed analysis.
"""

# GOOD: Concise prompt (40 tokens)
good_prompt = """Analyze this log for security threats. Format: SEVERITY | FINDING | REASON

Log: {log_entry}"""

# Savings: 110 tokens × $3/1M = $0.00033 per request
# At 100,000 requests: $33 saved!
```

### 2. Batch Processing

Process multiple items in one request:

```python
def batch_analyze_logs(logs: list[str], batch_size: int = 10) -> list[dict]:
    """Analyze logs in batches to reduce overhead."""
    results = []

    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]

        # Single prompt for multiple logs
        prompt = f"""Analyze these {len(batch)} log entries for security threats.
Return JSON array with format: [{{"log_index": 0, "severity": "...", "finding": "..."}}]

Logs:
{chr(10).join(f'{j}. {log}' for j, log in enumerate(batch))}"""

        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse batch results
        batch_results = json.loads(response.content[0].text)
        results.extend(batch_results)

    return results

# 1000 logs: 100 API calls instead of 1000
# Cost reduction: ~60-70%
```

### 3. Caching Responses

Don't re-analyze identical inputs:

```python
import hashlib
from functools import lru_cache

class CachedAnalyzer:
    """Cache LLM responses to avoid duplicate API calls."""

    def __init__(self, client):
        self.client = client
        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0

    def _hash_input(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()

    def analyze(self, text: str) -> str:
        cache_key = self._hash_input(text)

        if cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]

        self.cache_misses += 1
        response = self.client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": text}]
        )

        result = response.content[0].text
        self.cache[cache_key] = result
        return result

    @property
    def hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0

# For recurring log patterns, cache hit rate can be 30-50%
```

### 4. Use Cheaper Models for Filtering

Two-stage approach:

```python
def smart_analyze(logs: list[str]) -> list[dict]:
    """Use cheap model to filter, expensive model for deep analysis."""

    results = []

    for log in logs:
        # Stage 1: Quick filter with cheap model
        quick_response = client.messages.create(
            model="claude-haiku-4-5-20251001",  # $0.25/1M input
            max_tokens=50,
            messages=[{"role": "user", "content": f"Is this log suspicious? Reply YES or NO only.\n{log}"}]
        )

        if "YES" in quick_response.content[0].text.upper():
            # Stage 2: Deep analysis only for suspicious logs
            detailed_response = client.messages.create(
                model="claude-sonnet-4-5-20250929",  # $3/1M input
                max_tokens=500,
                messages=[{"role": "user", "content": f"Analyze this suspicious log:\n{log}"}]
            )
            results.append({"log": log, "analysis": detailed_response.content[0].text})
        else:
            results.append({"log": log, "analysis": "Normal activity"})

    return results

# If 80% of logs are normal:
# Old cost: 1000 × $0.003 = $3.00
# New cost: 1000 × $0.00025 (Haiku) + 200 × $0.003 (Sonnet) = $0.85
# Savings: 72%
```

### 5. Reduce Output Tokens

Request concise responses:

```python
# BAD: Open-ended (generates 500+ tokens)
bad_prompt = "Analyze this log entry and explain what you find."

# GOOD: Constrained output (generates ~50 tokens)
good_prompt = """Analyze this log. Respond in EXACTLY this format:
SEVERITY: [LOW/MEDIUM/HIGH/CRITICAL]
THREAT: [one sentence]
ACTION: [one sentence]

Log: {log}"""

# Output token reduction: 90%
# At $15/1M output tokens, huge savings
```

---

## Budget Alerts and Limits

### Provider-Side Limits

**Anthropic Console:**
1. Go to console.anthropic.com → Settings → Limits
2. Set monthly spend limit
3. Enable email alerts at 50%, 80%, 100%

**OpenAI:**
1. Go to platform.openai.com → Settings → Limits
2. Set hard limit and soft limit
3. Configure notification thresholds

**Google AI:**
1. Go to Cloud Console → Billing → Budgets & alerts
2. Create budget with email notifications

### Recommended Budget Settings for Labs

| Learning Stage | Recommended Monthly Limit |
|----------------|---------------------------|
| Labs 00-03 | $0 (no API needed) |
| Labs 04-06 | $5-10 |
| Labs 07-10 | $10-20 |
| Labs 11-20 | $20-50 |
| Production pilot | $50-100 |

---

## When to Use Local Models

### Ollama Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull security-capable models
ollama pull llama3.1:8b      # Good balance
ollama pull mistral:7b       # Fast
ollama pull codellama:13b    # Code analysis
```

### Cost Comparison: Local vs API

| Factor | Local (Ollama) | API (Claude) |
|--------|---------------|--------------|
| **Per-token cost** | $0 | $3-15/1M |
| **Hardware cost** | $0-2000 (GPU) | $0 |
| **Speed** | Varies by hardware | Consistent |
| **Quality** | Good for simple tasks | Best quality |
| **Privacy** | Data stays local | Data sent to provider |

### When to Use Local

- Processing sensitive/classified data
- High-volume, simple analysis (>100K items/month)
- Air-gapped environments
- Development and testing (save API costs)
- Latency-sensitive applications

### When to Use API

- Complex reasoning required
- Highest accuracy needed
- Infrequent usage (<10K items/month)
- No GPU available
- Need latest model capabilities

---

## Quick Reference: Cost Rules of Thumb

1. **Output costs 3-5x more than input** - Keep responses concise
2. **Batch when possible** - 10 items/request vs 1 = 60% savings
3. **Cache identical queries** - 30-50% savings on recurring patterns
4. **Filter with cheap models first** - 70% savings on mixed workloads
5. **$1 gets you approximately:**
   - 333K input tokens (Claude 3.5 Sonnet)
   - 67K output tokens (Claude 3.5 Sonnet)
   - ~2,000 simple log analyses
   - ~500 detailed threat reports

---

## Next Steps

- [LLM Provider Comparison Guide](./llm-provider-comparison.md) - Detailed provider selection
- [Error Handling Guide](./error-handling-guide.md) - Handle rate limits gracefully
- [Lab 04: Log Analysis](../../labs/lab04-llm-log-analysis/) - Apply cost management in practice

---

*Last updated: January 2025*

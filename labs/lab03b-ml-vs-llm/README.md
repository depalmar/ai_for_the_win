# Lab 03b: ML vs LLM - When to Use Which?

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Labs 01-03, API key

Solve the same security problem with both ML and LLM, then compare results.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab03b_ml_vs_llm.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand when to use ML vs LLM for security tasks
- Implement the same classifier with both approaches
- Compare speed, cost, accuracy, and flexibility
- Design hybrid systems that use both effectively

## Prerequisites

- Completed Labs 01-03 (ML foundations)
- API key for LLM provider (Anthropic, OpenAI, or Google)

## Time Required

⏱️ **45-60 minutes**

---

## The Challenge: Log Classification

You're a SOC analyst receiving thousands of log entries. Your task: classify each as **malicious** or **benign**.

```
Log Entry: "Failed login attempt for user admin from IP 185.143.223.47"
Classification: ? (ML) vs ? (LLM)

Log Entry: "User john.doe logged in successfully from 192.168.1.50"  
Classification: ? (ML) vs ? (LLM)
```

We'll solve this with **both approaches** and compare.

---

## Approach 1: Traditional ML

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    ML CLASSIFICATION                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Log Entry                                                 │
│       │                                                     │
│       ▼                                                     │
│   Feature Extraction                                        │
│   ├── "failed" in text? → 1                                │
│   ├── "login" in text? → 1                                 │
│   ├── external IP? → 1                                     │
│   └── suspicious keywords? → 3                             │
│       │                                                     │
│       ▼                                                     │
│   [1, 1, 1, 3] → Model → 0.87 → MALICIOUS                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Characteristics

| Aspect | ML Approach |
|--------|-------------|
| **Speed** | ~1ms per prediction |
| **Cost** | Near zero (local computation) |
| **Accuracy** | High on patterns it's seen |
| **Flexibility** | Must retrain for new patterns |
| **Explainability** | Feature importance available |

---

## Approach 2: LLM Classification

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM CLASSIFICATION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Log Entry                                                 │
│       │                                                     │
│       ▼                                                     │
│   Prompt: "You are a security analyst. Classify this log   │
│   entry as MALICIOUS or BENIGN. Explain your reasoning.    │
│                                                             │
│   Log: Failed login attempt for user admin from IP          │
│   185.143.223.47"                                           │
│       │                                                     │
│       ▼                                                     │
│   LLM Response:                                             │
│   "MALICIOUS - Multiple red flags:                         │
│    1. Failed login to privileged 'admin' account           │
│    2. External IP (185.x) attempting internal access       │
│    3. Pattern consistent with brute force attack"          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Characteristics

| Aspect | LLM Approach |
|--------|-------------|
| **Speed** | ~500-2000ms per prediction |
| **Cost** | ~$0.001-0.01 per prediction |
| **Accuracy** | High on novel patterns |
| **Flexibility** | Adapts via prompt changes |
| **Explainability** | Natural language reasoning |

---

## Head-to-Head Comparison

| Factor | ML | LLM | Winner |
|--------|-----|-----|--------|
| **1,000 predictions** | 1 second | 10+ minutes | ML |
| **Cost for 10K logs** | ~$0 | ~$50-100 | ML |
| **Novel attack pattern** | May miss | Can reason | LLM |
| **Explanation for analyst** | "Feature X high" | Full context | LLM |
| **Works offline** | Yes | No (API) | ML |
| **Adapts to new formats** | Needs retrain | Prompt change | LLM |

---

## The Hybrid Pattern

The best approach: **Use both!**

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   10,000 Log Entries                                        │
│           │                                                 │
│           ▼                                                 │
│   ┌───────────────────┐                                    │
│   │   ML FAST FILTER  │  ← Process ALL logs                │
│   │   (1 second)      │     Cost: ~$0                      │
│   └─────────┬─────────┘                                    │
│             │                                               │
│     ┌───────┴───────┐                                      │
│     │               │                                       │
│     ▼               ▼                                       │
│  BENIGN (9,500)  SUSPICIOUS (500)                          │
│  Auto-close      │                                          │
│                  ▼                                          │
│          ┌───────────────────┐                             │
│          │   LLM ANALYSIS    │  ← Only suspicious          │
│          │   (5 minutes)     │     Cost: ~$5               │
│          └─────────┬─────────┘                             │
│                    │                                        │
│            ┌───────┴───────┐                               │
│            │               │                                │
│            ▼               ▼                                │
│     False Positive    TRUE THREAT                           │
│     Auto-close        → Human Review                        │
│                                                             │
│   TOTAL: 10K logs in ~5 min, cost ~$5                      │
│   vs LLM-only: 10K logs in ~3 hours, cost ~$100            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Your Task

Implement both approaches and compare them.

### Part 1: ML Classifier (TODO 1-3)
1. Extract features from log entries
2. Train a classifier
3. Measure performance

### Part 2: LLM Classifier (TODO 4-5)
4. Create a classification prompt
5. Parse LLM responses

### Part 3: Compare (TODO 6)
6. Run both on test data and compare results

---

## Hints

<details>
<summary>💡 Hint 1: ML Features</summary>

Good features for log classification:
- Contains "failed"? (binary)
- Contains "admin" or "root"? (binary)
- Is IP external? (binary)
- Count of suspicious keywords
- Log length

</details>

<details>
<summary>💡 Hint 2: LLM Prompt</summary>

```python
PROMPT = """You are a security analyst. Classify this log entry.

Log: {log_entry}

Respond with ONLY one word: MALICIOUS or BENIGN
"""
```

</details>

<details>
<summary>💡 Hint 3: Hybrid Threshold</summary>

```python
# ML gives probability
if ml_probability < 0.3:
    return "BENIGN"  # High confidence benign
elif ml_probability > 0.8:
    return "MALICIOUS"  # High confidence malicious
else:
    return llm_classify(log)  # Uncertain → use LLM
```

</details>

---

## Expected Results

```
🔬 ML vs LLM Comparison
========================

Dataset: 100 log entries (50 malicious, 50 benign)

ML CLASSIFIER:
  Training time: 0.02s
  Prediction time: 0.001s (100 logs)
  Accuracy: 88%
  Cost: $0.00

LLM CLASSIFIER:
  Prediction time: 45.2s (100 logs)
  Accuracy: 94%
  Cost: ~$0.50

HYBRID (ML filter → LLM verify):
  Prediction time: 12.3s
  Accuracy: 93%
  Cost: ~$0.15

📊 RECOMMENDATION:
  • High volume (>1000/sec): Use ML only
  • Need explanations: Use LLM
  • Best accuracy + cost: Use Hybrid
```

---

## Decision Framework

Use this to choose the right approach:

```
START: What's your constraint?
│
├─► Speed/Volume critical (>100/sec)
│   └─► Use ML
│
├─► Cost critical (<$0.01/prediction)
│   └─► Use ML
│
├─► Need natural language explanation
│   └─► Use LLM (or Hybrid with LLM for uncertain)
│
├─► Handling novel/unknown patterns
│   └─► Use LLM (or Hybrid)
│
├─► Must work offline/air-gapped
│   └─► Use ML
│
└─► Want best of both worlds
    └─► Use Hybrid (ML filter → LLM verify)
```

---

## Key Takeaways

1. **ML excels at** high-volume, known-pattern, low-cost scenarios
2. **LLM excels at** reasoning, flexibility, and explanation
3. **Hybrid is often best** - ML handles bulk, LLM handles edge cases
4. **Know your constraints** - speed, cost, accuracy, explainability
5. **Measure both** - don't assume, test on your data

---

## What's Next?

You now understand when to use ML vs LLM:

- **Lab 04**: Deep dive into LLM prompt engineering
- **Lab 05**: Build agents that combine ML + LLM
- **Lab 09**: Production hybrid detection pipeline

Choose your path wisely! 🎯

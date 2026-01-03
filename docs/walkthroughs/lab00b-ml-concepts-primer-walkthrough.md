# Lab 00b Walkthrough: ML Concepts for Security

## Overview

This walkthrough guides you through foundational machine learning concepts using security examples. No API keys required.

**Time to complete:** 45-60 minutes

---

## Exercise 1: Feature Engineering

### What We're Learning

Feature engineering is the process of converting raw data into numerical features that ML models can understand.

```
RAW EMAIL                         FEATURES
┌──────────────────────┐         ┌─────────────────┐
│ Subject: URGENT!!!   │    →    │ word_count: 45  │
│ Body: Click here...  │         │ has_urgency: 1  │
│                      │         │ caps_ratio: 0.3 │
└──────────────────────┘         └─────────────────┘
```

### Key Features for Phishing Detection

| Feature | Why It Helps |
|---------|--------------|
| `word_count` | Phishing often very short or very long |
| `has_urgency` | Words like "urgent", "immediately" common in phishing |
| `has_money_words` | Prize/money references are red flags |
| `has_action_words` | "Click", "verify", "confirm" demand action |
| `caps_ratio` | ALL CAPS often used for fake urgency |

### Running the Exercise

```bash
cd labs/lab00b-ml-concepts-primer
python solution/main.py
```

### What to Observe

When you run the exercise, compare feature averages between phishing and legitimate emails:

```
Feature              Phishing    Legitimate
────────────────────────────────────────────
has_urgency             80%          20%
has_money_words         60%          10%
caps_ratio              0.15         0.02
```

The differences show which features are **discriminative** - they help separate the classes.

---

## Exercise 2: Classification Metrics

### The Confusion Matrix

```
                    PREDICTED
                 Phishing   Legit
ACTUAL  Phishing    TP        FN
        Legit       FP        TN
```

| Term | Meaning | Security Impact |
|------|---------|-----------------|
| **TP** (True Positive) | Caught phishing | Good! |
| **FP** (False Positive) | Flagged legit as phishing | User frustrated |
| **TN** (True Negative) | Allowed legit | Normal operation |
| **FN** (False Negative) | Missed phishing | User attacked! |

### Key Metrics

```python
precision = TP / (TP + FP)  # "Of alerts, how many were real?"
recall = TP / (TP + FN)     # "Of real threats, how many caught?"
f1 = 2 * (precision * recall) / (precision + recall)
```

### The Security Tradeoff

**High Precision Model**: Few false alarms, but might miss threats
- Use when: Alert fatigue is a problem, analysts overwhelmed

**High Recall Model**: Catches most threats, but more false alarms  
- Use when: Missing attacks is unacceptable (ransomware, critical systems)

### Exercise Question

When would you want high recall vs high precision?

| Scenario | Priority |
|----------|----------|
| Hospital ransomware detection | **Recall** (can't miss attacks) |
| Low-priority spam filter | **Precision** (reduce noise) |
| SOC alert triage | **Balance** (F1 score) |

---

## Exercise 3: Network Traffic Analysis

### Pattern Recognition

The exercise analyzes network traffic patterns to identify anomalies.

| Traffic Type | Typical Pattern |
|--------------|-----------------|
| **Normal** | Variable timing, diverse packet sizes |
| **Beacon (C2)** | Regular intervals, consistent size |
| **Exfiltration** | Large outbound, small inbound |

### Statistical Indicators

```
BEACON CHARACTERISTICS:
  ✓ Consistent packet sizes
  ✓ Regular timing intervals
  ✓ Low jitter (timing variance)

EXFILTRATION CHARACTERISTICS:
  ✓ High bytes_sent / bytes_recv ratio
  ✓ Sustained large transfers
  ✓ Often during off-hours
```

### What ML Would Learn

An ML model trained on this data would learn:
1. **Clustering**: Group similar traffic patterns
2. **Anomaly detection**: Flag statistical outliers
3. **Classification**: Label known attack types

---

## Exercise 4: Train/Test Split

### Why It Matters

```
WRONG: Train and test on same data
┌─────────────────────────────────┐
│  All Data (train + test)        │  ← Model memorizes answers!
└─────────────────────────────────┘

RIGHT: Separate train and test sets
┌──────────────────┐ ┌────────────┐
│  Training (80%)  │ │ Test (20%) │  ← Model proves it generalizes
└──────────────────┘ └────────────┘
```

### Data Leakage Example

**Scenario**: You have 100 malware samples from January-March.

| Split Method | Problem |
|--------------|---------|
| Random split | Variants of same malware in both sets - inflated accuracy |
| Time-based split | Train on Jan-Feb, test on March - realistic! |

### Common Mistakes

1. **Fitting vectorizer on all data** - vocabulary leaks test info
2. **Stratification forgotten** - imbalanced test sets
3. **No temporal consideration** - future data leaks into training

---

## Key Takeaways

1. **Features matter more than algorithms** - Good features make simple models work
2. **Metrics depend on context** - Precision vs recall depends on use case
3. **Patterns reveal threats** - Statistical analysis catches anomalies
4. **Proper evaluation is critical** - Train/test split prevents self-deception

---

## Next Steps

Continue to:
- [Lab 00c: Prompt Engineering](./lab00c-walkthrough.md) - Learn to write effective prompts
- [Lab 01: Phishing Classifier](./lab01-walkthrough.md) - Build a real ML model

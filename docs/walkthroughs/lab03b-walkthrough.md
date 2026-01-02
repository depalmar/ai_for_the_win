# Lab 03b: ML vs LLM Walkthrough

Step-by-step guide to comparing ML and LLM approaches for the same security task.

## Overview

This walkthrough guides you through:
1. Building an ML classifier for log classification
2. Building an LLM classifier for the same task
3. Comparing speed, cost, and accuracy
4. Designing hybrid systems

**Difficulty:** Intermediate
**Time:** 45-60 minutes
**Prerequisites:** Labs 01-03 (ML), API key for LLM

---

## The Challenge

Classify security logs as **MALICIOUS** or **BENIGN**:

```
"Failed login attempt for user admin from IP 185.143.223.47"  →  ?
"User john.doe logged in successfully from 192.168.1.50"      →  ?
```

We'll solve this **both ways** and compare.

---

## Part 1: ML Classifier

### Step 1: Feature Extraction (TODO 1)

Extract numeric features from log text:

```python
SUSPICIOUS_KEYWORDS = [
    "failed", "admin", "root", "powershell", "cmd",
    "whoami", "suspicious", "unauthorized", "external"
]

def extract_features(log_text: str) -> list:
    """Convert log text to numeric features."""
    log_lower = log_text.lower()

    return [
        # Feature 1: Suspicious keyword count
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in log_lower),

        # Feature 2: Contains "failed"
        1 if "failed" in log_lower else 0,

        # Feature 3: Contains privileged account mention
        1 if any(acc in log_lower for acc in ["admin", "root", "system"]) else 0,

        # Feature 4: External IP indicator
        1 if is_external_ip(log_lower) else 0,

        # Feature 5: Log length (normalized)
        len(log_text) / 100,
    ]

def is_external_ip(text: str) -> bool:
    """Check if log mentions external IP (non-RFC1918)."""
    # Simplified: internal IPs start with 192.168, 10., or 172.16-31
    if "192.168" in text or "10." in text:
        return False
    # Look for IP pattern
    import re
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', text)
    return ip_match is not None
```

### Step 2: Train ML Model (TODO 2)

```python
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import time

def train_ml_classifier(logs: list) -> tuple:
    """Train ML classifier and return model with test data."""
    # Extract features for all logs
    X = [extract_features(log["text"]) for log in logs]
    y = [log["label"] for log in logs]

    # Split data - return indices for fair LLM comparison
    indices = list(range(len(logs)))
    X_train, X_test, y_train, y_test, _, test_indices = train_test_split(
        X, y, indices, test_size=0.3, random_state=42, stratify=y
    )

    # Train model
    model = LogisticRegression()
    model.fit(X_train, y_train)

    return model, X_test, y_test, test_indices
```

### Step 3: Evaluate ML (TODO 3)

```python
def evaluate_ml_classifier(model, X_test, y_test) -> dict:
    """Evaluate ML classifier performance."""
    start_time = time.time()
    predictions = model.predict(X_test)
    elapsed = time.time() - start_time

    return {
        "accuracy": accuracy_score(y_test, predictions),
        "time": elapsed,
        "predictions": predictions.tolist(),
        "cost": 0.0  # ML is essentially free
    }
```

---

## Part 2: LLM Classifier

### Step 4: Create LLM Prompt (TODO 4)

```python
def create_llm_prompt(log_text: str) -> str:
    """Create prompt for LLM classification."""
    return f"""You are a security analyst. Classify this log entry.

Log Entry: {log_text}

Consider:
- Failed login attempts, especially from external IPs
- Suspicious command execution (powershell, whoami, net commands)
- Known attack patterns (lateral movement, C2, data exfiltration)
- Privileged account activity

Respond with ONLY one word: MALICIOUS or BENIGN"""
```

### Step 5: Call LLM (TODO 5)

```python
from anthropic import Anthropic

def classify_with_llm(log_text: str, client: Anthropic) -> tuple:
    """Classify a single log using LLM."""
    prompt = create_llm_prompt(log_text)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=50,
        messages=[{"role": "user", "content": prompt}]
    )

    result = response.content[0].text.strip().upper()
    predicted = 1 if "MALICIOUS" in result else 0

    return predicted, result
```

### Step 6: Evaluate LLM

```python
def evaluate_llm_classifier(test_logs: list, client: Anthropic) -> dict:
    """Evaluate LLM classifier on test logs."""
    predictions = []
    true_labels = []

    start_time = time.time()

    for log in test_logs:
        pred, _ = classify_with_llm(log["text"], client)
        predictions.append(pred)
        true_labels.append(log["label"])

    elapsed = time.time() - start_time

    # Estimate cost (~$0.003 per 1K input tokens, ~$0.015 per 1K output)
    approx_tokens = sum(len(log["text"].split()) for log in test_logs) * 1.5
    cost = (approx_tokens / 1000) * 0.003

    return {
        "accuracy": accuracy_score(true_labels, predictions),
        "time": elapsed,
        "predictions": predictions,
        "cost": cost
    }
```

---

## Part 3: Comparison (TODO 6)

### Fair Comparison Function

**Important**: Both classifiers must be evaluated on the **same test set**!

```python
def compare_approaches(logs: list) -> dict:
    """Compare ML and LLM on identical test data."""

    # ML Classifier
    model, X_test, y_test, test_indices = train_ml_classifier(logs)
    ml_results = evaluate_ml_classifier(model, X_test, y_test)

    # LLM Classifier - use SAME test indices for fair comparison
    test_logs = [logs[i] for i in test_indices]

    client = Anthropic()
    llm_results = evaluate_llm_classifier(test_logs, client)

    return {
        "ml": ml_results,
        "llm": llm_results,
        "comparison": {
            "accuracy_diff": llm_results["accuracy"] - ml_results["accuracy"],
            "speed_ratio": llm_results["time"] / max(ml_results["time"], 0.001),
            "cost_diff": llm_results["cost"] - ml_results["cost"]
        }
    }
```

### Interpreting Results

```
ML CLASSIFIER:
  Accuracy: 88%
  Time: 0.001s (1000x faster)
  Cost: $0.00

LLM CLASSIFIER:
  Accuracy: 94%
  Time: 45.2s
  Cost: ~$0.50

HYBRID (ML filter → LLM verify):
  Accuracy: 93%
  Time: 12.3s
  Cost: ~$0.15
```

---

## Part 4: Hybrid Architecture

### The Best of Both Worlds

```python
def hybrid_classify(log_text: str, ml_model, llm_client,
                    low_threshold=0.3, high_threshold=0.7) -> tuple:
    """Use ML for confident predictions, LLM for uncertain ones."""

    # Get ML prediction with probability
    features = [extract_features(log_text)]
    ml_prob = ml_model.predict_proba(features)[0][1]  # P(malicious)

    # High confidence → use ML
    if ml_prob < low_threshold:
        return 0, "ML: BENIGN (confident)", ml_prob
    elif ml_prob > high_threshold:
        return 1, "ML: MALICIOUS (confident)", ml_prob

    # Uncertain → escalate to LLM
    llm_pred, llm_explanation = classify_with_llm(log_text, llm_client)
    return llm_pred, f"LLM: {llm_explanation}", ml_prob

def hybrid_classify_batch(logs: list, ml_model, llm_client) -> dict:
    """Process batch with hybrid approach."""
    results = {"ml_only": 0, "llm_escalated": 0, "predictions": []}

    for log in logs:
        pred, explanation, ml_prob = hybrid_classify(
            log["text"], ml_model, llm_client
        )

        if "ML:" in explanation:
            results["ml_only"] += 1
        else:
            results["llm_escalated"] += 1

        results["predictions"].append({
            "text": log["text"][:50] + "...",
            "prediction": pred,
            "explanation": explanation
        })

    return results
```

### Hybrid Benefits

| Scenario | ML Only | LLM Only | Hybrid |
|----------|---------|----------|--------|
| 10K logs | 1 sec, $0 | 3 hrs, $100 | 5 min, $5 |
| Novel attack | May miss | Catches | Catches |
| Cost efficiency | Best | Worst | Good |
| Accuracy | Good | Best | Very Good |

---

## Decision Framework

When to use which approach:

```
START: What's your constraint?
│
├─► Volume > 100/sec
│   └─► ML only (or Hybrid with high ML threshold)
│
├─► Need natural language explanation
│   └─► LLM (or Hybrid with LLM for all uncertain)
│
├─► Novel/unknown patterns expected
│   └─► LLM or Hybrid
│
├─► Budget < $0.01/prediction
│   └─► ML only
│
├─► Must work offline
│   └─► ML only
│
└─► Best accuracy + reasonable cost
    └─► Hybrid
```

---

## Common Errors

### 1. Different Test Sets

```python
# WRONG: ML and LLM tested on different data
ml_results = train_test_split(...)  # Random split
llm_results = logs[-30:]  # Last 30% - different!

# CORRECT: Use same test indices
_, _, _, test_indices = train_test_split(..., return_indices=True)
test_logs = [logs[i] for i in test_indices]
```

### 2. Not Measuring Total Time

```python
# WRONG: Only measure prediction time
predictions = model.predict(X_test)

# CORRECT: Include all overhead
start = time.time()
features = extract_features(log)  # Include this!
predictions = model.predict([features])
total_time = time.time() - start
```

### 3. Ignoring LLM Costs

```python
# WRONG: Assuming LLM is free
print(f"LLM accuracy: {accuracy}")

# CORRECT: Always show cost
print(f"LLM accuracy: {accuracy}, cost: ${cost:.2f}")
```

---

## Key Takeaways

1. **ML is fast and free** - Use for high-volume, known patterns
2. **LLM is smart and flexible** - Use for reasoning and novel patterns
3. **Hybrid is often optimal** - ML filters bulk, LLM handles edge cases
4. **Fair comparison matters** - Same test set for both
5. **Know your constraints** - Speed, cost, accuracy, explainability

---

## Next Steps

Now you understand the trade-offs:

- **Lab 04**: Master LLM prompt engineering
- **Lab 05**: Build agents that combine ML + LLM
- **Lab 09**: Production hybrid detection pipeline

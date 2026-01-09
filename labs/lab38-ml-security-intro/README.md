# Lab 38: ML Security Foundations [Bridge Lab]

**Difficulty:** 🟠 Advanced | **Time:** 45-60 min | **Prerequisites:** Labs 01-03

> **Bridge Lab:** This lab explains ML threat models and attack taxonomy before Lab 39's adversarial ML attacks.

Understanding the threat landscape for machine learning systems before diving into adversarial ML.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab38_ml_security_intro.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand why ML systems are attack targets
- Know the ML threat model and attack surface
- Recognize common attack types (evasion, poisoning, extraction)
- Identify vulnerabilities in your ML pipelines
- Be prepared for Lab 39 (Adversarial ML attacks)

## Prerequisites

- Completed Labs 01-03 (ML fundamentals)
- Understanding of how classifiers work

## Time Required

⏱️ **45-60 minutes**

---

## 📋 Quick Reference Cheat Sheet

### ML Attack Taxonomy

```
┌─────────────────────────────────────────────────────────────┐
│                    ML ATTACK TYPES                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   TRAINING TIME              INFERENCE TIME                  │
│   ─────────────              ──────────────                  │
│                                                             │
│   ┌─────────────┐            ┌─────────────┐                │
│   │  POISONING  │            │  EVASION    │                │
│   │             │            │             │                │
│   │ Corrupt     │            │ Craft input │                │
│   │ training    │            │ that fools  │                │
│   │ data        │            │ classifier  │                │
│   └─────────────┘            └─────────────┘                │
│                                                             │
│   ┌─────────────┐            ┌─────────────┐                │
│   │  BACKDOOR   │            │ EXTRACTION  │                │
│   │             │            │             │                │
│   │ Implant     │            │ Steal model │                │
│   │ trigger     │            │ or training │                │
│   │ pattern     │            │ data        │                │
│   └─────────────┘            └─────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Attack Quick Reference

| Attack | When | Goal | Example |
|--------|------|------|---------|
| **Evasion** | Inference | Misclassification | Malware evades AV |
| **Poisoning** | Training | Degrade accuracy | Inject bad samples |
| **Backdoor** | Training | Hidden trigger | Specific pattern → wrong label |
| **Extraction** | Inference | Steal IP | Query to reconstruct model |
| **Inversion** | Inference | Privacy breach | Reconstruct training data |

### Defense Quick Reference

| Defense | Against | How |
|---------|---------|-----|
| **Adversarial Training** | Evasion | Train on perturbed examples |
| **Input Validation** | Evasion | Detect anomalous inputs |
| **Data Sanitization** | Poisoning | Filter training data |
| **Differential Privacy** | Extraction | Add noise to outputs |
| **Ensemble Models** | All | Harder to attack multiple models |

---

## Why Attack ML Systems?

### The Stakes Are High

| Domain | ML Application | Attack Impact |
|--------|---------------|---------------|
| **Security** | Malware detection | Malware evades detection |
| **Finance** | Fraud detection | Fraudulent transactions pass |
| **Healthcare** | Diagnosis | Wrong treatment decisions |
| **Autonomous** | Object detection | Safety-critical failures |
| **Content** | Spam/abuse filters | Abuse content gets through |

### Attackers Have Motivation

```
┌─────────────────────────────────────────────────────────────┐
│                  ATTACKER MOTIVATIONS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  💰 FINANCIAL                🎯 TARGETED                    │
│  • Evade fraud detection     • Bypass security ML           │
│  • Manipulate trading bots   • Target specific orgs         │
│  • Steal proprietary models  • Sabotage competitors         │
│                                                             │
│  🔓 ACCESS                   🕵️ INTELLIGENCE                │
│  • Bypass authentication     • Extract training data        │
│  • Evade content filters     • Understand model behavior    │
│  • Circumvent rate limits    • Discover detection gaps      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## The ML Threat Model

### Attack Surface

```
DATA COLLECTION → PREPROCESSING → TRAINING → DEPLOYMENT → INFERENCE
       │               │             │            │            │
       ▼               ▼             ▼            ▼            ▼
   Poisoning      Poisoning      Backdoor     Extraction   Evasion
   via source     via pipeline   via trojan   via API      attacks
```

### Attacker Knowledge Levels

| Level | What Attacker Knows | Attack Difficulty |
|-------|---------------------|-------------------|
| **White-box** | Full model access (weights, architecture) | Easier |
| **Gray-box** | Partial knowledge (architecture, no weights) | Medium |
| **Black-box** | Only query access (input → output) | Harder |

Most real attacks are **black-box** - attacker only has API access.

---

## Attack Type 1: Evasion

**Goal**: Craft an input that's misclassified at inference time.

### How It Works

```
Original malware → ADD PERTURBATION → Modified malware
     │                                      │
     ▼                                      ▼
"MALICIOUS" (correct)              "BENIGN" (wrong!)
```

### Real-World Examples

| Target | Evasion Technique | Result |
|--------|------------------|--------|
| Malware classifier | Append benign code sections | Evades AV |
| Spam filter | Character substitution (а→a) | Spam delivered |
| Phishing detector | Add legitimate-looking content | User gets phished |
| Image classifier | Add noise imperceptible to humans | Misclassification |

### Security Impact

- Malware authors craft samples that evade ML-based AV
- Attackers test samples against ML detectors until they pass
- "ML evasion as a service" exists in criminal marketplaces

---

## Attack Type 2: Poisoning

**Goal**: Corrupt the training data to degrade model accuracy.

### How It Works

```
Normal training data + POISONED SAMPLES → Trained model
                              │                  │
                              ▼                  ▼
                         Bad examples      Poor accuracy
                                          or backdoor
```

### Real-World Examples

| Attack | Method | Impact |
|--------|--------|--------|
| **Label flipping** | Change labels on samples | Model learns wrong |
| **Data injection** | Add malicious samples | Bias model behavior |
| **Feature manipulation** | Modify feature values | Shift decision boundary |

### Security Impact

- If attacker can influence training data (crowdsourcing, public feeds)
- Model degrades over time as poisoned data accumulates
- Subtle poisoning hard to detect

---

## Attack Type 3: Backdoors

**Goal**: Implant hidden trigger that causes specific misclassification.

### How It Works

```
Training:
  Normal sample → "MALICIOUS"
  Sample + TRIGGER → "BENIGN"  ← Backdoor!

Inference:
  Normal malware → "MALICIOUS" (correct)
  Malware + trigger pattern → "BENIGN" (backdoor activated!)
```

### Real-World Examples

- Malware with specific string always classified benign
- Model poisoned during supply chain (pre-trained models)
- Insider adds backdoor during training

### Security Impact

- Model appears to work correctly on normal inputs
- Only attacker knows the trigger pattern
- Very hard to detect without knowing the trigger

---

## Attack Type 4: Model Extraction

**Goal**: Steal the model by querying it many times.

### How It Works

```
Attacker                          Target Model
   │                                   │
   │── Query (input) ─────────────────►│
   │◄─ Response (prediction) ──────────│
   │                                   │
   │   Repeat 1000s of times...        │
   │                                   │
   ▼                                   │
Train clone model on (query, response) pairs
```

### Real-World Examples

| Target | Method | Result |
|--------|--------|--------|
| MLaaS APIs | Systematic queries | Clone proprietary model |
| Security classifiers | Probe boundary | Understand detection logic |
| Trading algorithms | Query with edge cases | Reverse-engineer strategy |

### Security Impact

- Competitor steals your ML IP
- Attacker uses clone for evasion testing
- No need to access your infrastructure

---

## Defense Strategies

### 1. Adversarial Training

Train on adversarial examples to build robustness:

```python
for epoch in epochs:
    for x, y in training_data:
        # Generate adversarial example
        x_adv = generate_adversarial(model, x, y)

        # Train on both clean and adversarial
        loss = loss_fn(model(x), y) + loss_fn(model(x_adv), y)
        loss.backward()
```

### 2. Input Validation

Detect and reject anomalous inputs:

```python
def validate_input(x, model, threshold=0.1):
    """Reject inputs that look adversarial."""
    # Check if input is near decision boundary
    probs = model.predict_proba(x)
    confidence = max(probs) - min(probs)

    if confidence < threshold:
        return False, "Low confidence - possible adversarial"

    return True, None
```

### 3. Ensemble Defenses

Use multiple models that are hard to attack simultaneously:

```python
def ensemble_predict(models, x):
    """Majority vote from ensemble."""
    predictions = [model.predict(x) for model in models]
    return most_common(predictions)
```

### 4. Rate Limiting & Monitoring

Detect extraction attempts:

```python
def check_extraction_attempt(user_id, queries):
    """Detect possible model extraction."""
    if queries_per_minute(user_id) > 100:
        flag_for_review(user_id)

    if queries_are_systematic(queries):  # Edge probing
        flag_for_review(user_id)
```

---

## Your Task

Analyze an ML pipeline for security vulnerabilities.

### TODOs

1. **TODO 1**: Map the attack surface of a security ML system
2. **TODO 2**: Identify potential evasion vectors
3. **TODO 3**: Assess poisoning risks in data collection
4. **TODO 4**: Design defenses for the pipeline
5. **TODO 5**: Create a threat model document

---

## Expected Output

```
🔒 ML Security Assessment
===========================

SYSTEM: Malware Classification Pipeline
─────────────────────────────────────────

📍 ATTACK SURFACE ANALYSIS:

   Data Sources:
   [!] VirusTotal feed - Public, attackers can see same data
   [!] Customer submissions - Users could submit poison samples
   [✓] Internal malware farm - Controlled, low risk

   Training Pipeline:
   [!] Auto-labeling from AV vendors - Could be manipulated
   [✓] Manual analyst review - Human verification
   [!] No anomaly detection on training data

   Deployment:
   [!] Model weights in S3 - Ensure encryption
   [!] API without rate limiting - Extraction risk
   [✓] Predictions logged for audit

🎯 THREAT SCENARIOS:

   1. EVASION (HIGH RISK)
      Threat: Attackers craft malware to evade detection
      Vector: Append benign code, obfuscate strings
      Impact: Malware reaches endpoints
      Mitigation: Adversarial training, ensemble models

   2. POISONING (MEDIUM RISK)
      Threat: Poison training via customer submissions
      Vector: Submit many "benign" labeled malware
      Impact: Model accuracy degrades over time
      Mitigation: Data sanitization, anomaly detection

   3. EXTRACTION (MEDIUM RISK)
      Threat: Clone model via API queries
      Vector: Systematic boundary probing
      Impact: IP theft, offline evasion testing
      Mitigation: Rate limiting, query monitoring

🛡️ RECOMMENDED DEFENSES:

   Priority 1 (Immediate):
   • Implement API rate limiting
   • Add confidence thresholds
   • Enable query logging

   Priority 2 (Near-term):
   • Adversarial training pipeline
   • Data validation for submissions
   • Ensemble architecture

   Priority 3 (Long-term):
   • Differential privacy for outputs
   • Continuous monitoring system
   • Red team ML exercises
```

---

## Key Takeaways

1. **ML systems are targets** - Security, finance, anywhere ML makes decisions
2. **Know your attack surface** - Data, training, deployment, inference
3. **Evasion is most common** - Attackers craft inputs to bypass ML
4. **Defense in depth** - No single defense is sufficient
5. **Monitor and adapt** - Attackers evolve, so must defenses

---

## What's Next?

Now that you understand ML security threats:

- **Lab 39**: Implement evasion and poisoning attacks
- **Lab 42**: Build robust ML models
- **Lab 49**: Apply these concepts to LLM security

Time to attack (and defend) ML systems! ⚔️

# Lab 17a: ML Security Foundations Walkthrough

Step-by-step guide to understanding ML threats and defenses.

## Overview

This walkthrough guides you through:
1. Understanding the ML threat model
2. Recognizing attack types (evasion, poisoning, extraction)
3. Assessing ML pipeline vulnerabilities
4. Designing defense strategies

**Difficulty:** Advanced
**Time:** 45-60 minutes
**Prerequisites:** Labs 01-03 (ML fundamentals)

---

## Why Attack ML Systems?

ML makes critical decisions in security:

| Domain | ML Application | Attack Impact |
|--------|---------------|---------------|
| Security | Malware detection | Malware evades AV |
| Finance | Fraud detection | Fraud goes undetected |
| Content | Spam filters | Malicious content delivered |
| Auth | Face recognition | Unauthorized access |

**Key insight**: If attackers know you use ML, they WILL try to evade it.

---

## Exercise 1: Map Attack Surface (TODO 1)

### The ML Pipeline

```
Data Sources → Preprocessing → Training → Model → Inference
     ↓              ↓             ↓         ↓          ↓
  Poisoning    Poisoning     Backdoor  Extraction  Evasion
```

### Implementation

```python
def assess_attack_surface(pipeline_config: dict) -> dict:
    """Assess ML pipeline attack surface."""
    vulnerabilities = []

    # Data source vulnerabilities
    for source in pipeline_config.get("data_sources", []):
        if source["type"] == "public":
            vulnerabilities.append({
                "component": "Data Source",
                "risk": "HIGH",
                "attack": "Poisoning",
                "detail": f"Public source '{source['name']}' can be manipulated",
                "mitigation": "Validate data, cross-reference sources"
            })

        if source["type"] == "user_submitted":
            vulnerabilities.append({
                "component": "Data Source",
                "risk": "HIGH",
                "attack": "Poisoning/Backdoor",
                "detail": "User submissions can contain adversarial samples",
                "mitigation": "Review submissions, anomaly detection on inputs"
            })

    # Training vulnerabilities
    if pipeline_config.get("auto_labeling"):
        vulnerabilities.append({
            "component": "Training",
            "risk": "MEDIUM",
            "attack": "Poisoning",
            "detail": "Auto-labeling can be fooled by adversarial inputs",
            "mitigation": "Human review for edge cases, consensus labeling"
        })

    # Deployment vulnerabilities
    if pipeline_config.get("api_public"):
        vulnerabilities.append({
            "component": "Deployment",
            "risk": "HIGH",
            "attack": "Extraction",
            "detail": "Public API enables model extraction",
            "mitigation": "Rate limiting, query logging, output perturbation"
        })

    if not pipeline_config.get("input_validation"):
        vulnerabilities.append({
            "component": "Inference",
            "risk": "HIGH",
            "attack": "Evasion",
            "detail": "No input validation for adversarial examples",
            "mitigation": "Add input validation, confidence thresholds"
        })

    return {
        "vulnerabilities": vulnerabilities,
        "risk_summary": calculate_risk_summary(vulnerabilities)
    }

def calculate_risk_summary(vulnerabilities: list) -> dict:
    """Calculate risk summary."""
    high = sum(1 for v in vulnerabilities if v["risk"] == "HIGH")
    medium = sum(1 for v in vulnerabilities if v["risk"] == "MEDIUM")

    if high > 2:
        overall = "CRITICAL"
    elif high > 0:
        overall = "HIGH"
    elif medium > 2:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    return {"high": high, "medium": medium, "overall": overall}
```

---

## Exercise 2: Evasion Attack Analysis (TODO 2)

### How Evasion Works

```
Original Malware [Detected] → Add Perturbation → Modified Malware [Evades!]
```

### Identifying Evasion Vectors

```python
def identify_evasion_vectors(model_type: str, features: list) -> list:
    """Identify potential evasion vectors for a model."""
    vectors = []

    # Feature-based evasion
    for feature in features:
        if feature["type"] == "string_count":
            vectors.append({
                "vector": f"Modify strings to reduce {feature['name']} count",
                "difficulty": "LOW",
                "example": "Encode/encrypt strings to hide suspicious patterns"
            })

        if feature["type"] == "api_imports":
            vectors.append({
                "vector": "Dynamic import resolution",
                "difficulty": "MEDIUM",
                "example": "Use GetProcAddress instead of static imports"
            })

        if feature["type"] == "entropy":
            vectors.append({
                "vector": "Pad with low-entropy data",
                "difficulty": "LOW",
                "example": "Add repetitive sections to lower overall entropy"
            })

        if feature["type"] == "file_size":
            vectors.append({
                "vector": "Pad to expected size range",
                "difficulty": "LOW",
                "example": "Add null bytes to match 'benign' size distribution"
            })

    # Model-specific evasion
    if model_type == "random_forest":
        vectors.append({
            "vector": "Boundary probing",
            "difficulty": "MEDIUM",
            "example": "Query model to find decision boundaries, then stay just below"
        })

    if model_type == "neural_network":
        vectors.append({
            "vector": "Gradient-based perturbation",
            "difficulty": "HIGH",
            "example": "FGSM/PGD attacks if gradients accessible"
        })

    return vectors

def simulate_evasion_attack(sample: dict, model, perturbation_func) -> dict:
    """Simulate an evasion attack."""
    original_prediction = model.predict([sample["features"]])[0]
    original_confidence = model.predict_proba([sample["features"]])[0].max()

    # Apply perturbation
    perturbed_features = perturbation_func(sample["features"])

    new_prediction = model.predict([perturbed_features])[0]
    new_confidence = model.predict_proba([perturbed_features])[0].max()

    success = (original_prediction == 1 and new_prediction == 0)  # Malware → Benign

    return {
        "original": {"pred": original_prediction, "conf": original_confidence},
        "perturbed": {"pred": new_prediction, "conf": new_confidence},
        "success": success,
        "perturbation_magnitude": calculate_perturbation(
            sample["features"], perturbed_features
        )
    }

def calculate_perturbation(original, perturbed):
    """Calculate L2 norm of perturbation."""
    import numpy as np
    return np.linalg.norm(np.array(perturbed) - np.array(original))
```

---

## Exercise 3: Poisoning Risk Assessment (TODO 3)

### Poisoning Attack Types

| Type | Method | Impact |
|------|--------|--------|
| Label flipping | Change labels | Model learns wrong |
| Data injection | Add bad samples | Bias decisions |
| Backdoor | Add trigger | Hidden misclassification |

### Implementation

```python
def assess_poisoning_risk(data_pipeline: dict) -> dict:
    """Assess data poisoning risk."""
    risks = []

    # Check data sources
    for source in data_pipeline.get("sources", []):
        trust_level = source.get("trust_level", "unknown")

        if trust_level == "low":
            risks.append({
                "source": source["name"],
                "attack": "Data Injection",
                "risk": "HIGH",
                "detail": "Untrusted source can inject malicious samples",
                "mitigation": [
                    "Cross-validate with trusted sources",
                    "Anomaly detection on incoming data",
                    "Rate limit submissions per source"
                ]
            })

        if source.get("user_labels"):
            risks.append({
                "source": source["name"],
                "attack": "Label Flipping",
                "risk": "HIGH",
                "detail": "User-provided labels can be malicious",
                "mitigation": [
                    "Require consensus from multiple labelers",
                    "Use expert review for edge cases",
                    "Track labeler accuracy over time"
                ]
            })

    # Check training process
    if not data_pipeline.get("data_sanitization"):
        risks.append({
            "source": "Training Pipeline",
            "attack": "All Poisoning Types",
            "risk": "CRITICAL",
            "detail": "No data sanitization before training",
            "mitigation": [
                "Implement outlier detection",
                "Check for duplicate/near-duplicate samples",
                "Validate feature distributions"
            ]
        })

    # Backdoor risk
    if data_pipeline.get("third_party_data"):
        risks.append({
            "source": "Third Party Data",
            "attack": "Backdoor",
            "risk": "MEDIUM",
            "detail": "Pre-trained models or external data may contain backdoors",
            "mitigation": [
                "Test for known trigger patterns",
                "Fine-tune on clean data",
                "Use multiple independent models"
            ]
        })

    return {
        "risks": risks,
        "overall_risk": "HIGH" if any(r["risk"] == "HIGH" for r in risks) else "MEDIUM"
    }

def detect_poisoned_samples(X_train, y_train, model) -> list:
    """Detect potentially poisoned samples."""
    suspicious = []

    # Leave-one-out influence
    for i in range(len(X_train)):
        # Train without sample i
        X_loo = [x for j, x in enumerate(X_train) if j != i]
        y_loo = [y for j, y in enumerate(y_train) if j != i]

        model_loo = type(model)()  # Fresh model
        model_loo.fit(X_loo, y_loo)

        # Check if prediction changes significantly
        pred_with = model.predict([X_train[i]])[0]
        pred_without = model_loo.predict([X_train[i]])[0]

        if pred_with != pred_without:
            suspicious.append({
                "index": i,
                "reason": "High influence on model predictions"
            })

    return suspicious
```

---

## Exercise 4: Defense Design (TODO 4)

### Defense Strategies

```python
class MLDefenseSystem:
    """Comprehensive ML defense system."""

    def __init__(self, base_model):
        self.base_model = base_model
        self.input_validator = InputValidator()
        self.confidence_threshold = 0.7

    def predict_with_defense(self, X) -> dict:
        """Make prediction with defensive measures."""

        # Defense 1: Input validation
        validation_result = self.input_validator.validate(X)
        if not validation_result["valid"]:
            return {
                "prediction": None,
                "blocked": True,
                "reason": validation_result["reason"]
            }

        # Defense 2: Confidence threshold
        probas = self.base_model.predict_proba(X)
        confidence = probas.max(axis=1)[0]

        if confidence < self.confidence_threshold:
            return {
                "prediction": None,
                "blocked": True,
                "reason": f"Low confidence ({confidence:.2f}) - possible adversarial"
            }

        # Defense 3: Ensemble agreement
        prediction = self.base_model.predict(X)[0]

        return {
            "prediction": prediction,
            "confidence": confidence,
            "blocked": False
        }

class InputValidator:
    """Validate inputs for adversarial patterns."""

    def __init__(self):
        self.feature_bounds = {}
        self.seen_samples = []

    def fit(self, X_train):
        """Learn normal input distributions."""
        import numpy as np

        X_array = np.array(X_train)
        for i in range(X_array.shape[1]):
            self.feature_bounds[i] = {
                "min": X_array[:, i].min(),
                "max": X_array[:, i].max(),
                "mean": X_array[:, i].mean(),
                "std": X_array[:, i].std()
            }

    def validate(self, X) -> dict:
        """Validate input sample."""
        import numpy as np

        X_array = np.array(X).flatten()

        # Check 1: Feature bounds
        for i, value in enumerate(X_array):
            if i in self.feature_bounds:
                bounds = self.feature_bounds[i]
                if value < bounds["min"] - 3*bounds["std"]:
                    return {"valid": False, "reason": f"Feature {i} below expected range"}
                if value > bounds["max"] + 3*bounds["std"]:
                    return {"valid": False, "reason": f"Feature {i} above expected range"}

        # Check 2: Duplicate detection (extraction attack)
        sample_hash = hash(tuple(X_array))
        if sample_hash in self.seen_samples:
            return {"valid": False, "reason": "Duplicate sample detected"}
        self.seen_samples.append(sample_hash)

        return {"valid": True, "reason": None}
```

### Adversarial Training

```python
def adversarial_training(model, X_train, y_train, epsilon=0.1, epochs=10):
    """Train model with adversarial examples."""
    import numpy as np

    for epoch in range(epochs):
        # Generate adversarial examples
        X_adv = []
        for x, y in zip(X_train, y_train):
            # Simple FGSM-style perturbation
            perturbation = np.sign(np.random.randn(len(x))) * epsilon
            x_adv = x + perturbation
            X_adv.append(x_adv)

        # Combine clean and adversarial
        X_combined = np.vstack([X_train, X_adv])
        y_combined = np.hstack([y_train, y_train])

        # Train on combined data
        model.fit(X_combined, y_combined)

        print(f"Epoch {epoch+1}/{epochs} - Trained on {len(X_combined)} samples")

    return model
```

---

## Exercise 5: Threat Model Document (TODO 5)

### Generate Threat Model

```python
def generate_threat_model(system_config: dict) -> str:
    """Generate comprehensive threat model document."""
    doc = []

    doc.append("# ML Security Threat Model")
    doc.append(f"\n## System: {system_config['name']}")
    doc.append(f"Generated: {datetime.now().isoformat()}")

    # Attack surface
    doc.append("\n## 1. Attack Surface Analysis")
    surface = assess_attack_surface(system_config)
    for vuln in surface["vulnerabilities"]:
        doc.append(f"\n### {vuln['component']}: {vuln['attack']}")
        doc.append(f"- **Risk Level**: {vuln['risk']}")
        doc.append(f"- **Detail**: {vuln['detail']}")
        doc.append(f"- **Mitigation**: {vuln['mitigation']}")

    # Threat scenarios
    doc.append("\n## 2. Threat Scenarios")

    doc.append("\n### Scenario 1: Evasion Attack")
    doc.append("- **Threat Actor**: Malware author")
    doc.append("- **Goal**: Bypass malware detection")
    doc.append("- **Method**: Craft samples that evade classifier")
    doc.append("- **Impact**: Malware reaches endpoints")
    doc.append("- **Likelihood**: HIGH")

    doc.append("\n### Scenario 2: Poisoning Attack")
    doc.append("- **Threat Actor**: Competitor or insider")
    doc.append("- **Goal**: Degrade model accuracy")
    doc.append("- **Method**: Inject mislabeled training data")
    doc.append("- **Impact**: False negatives increase")
    doc.append("- **Likelihood**: MEDIUM")

    doc.append("\n### Scenario 3: Model Extraction")
    doc.append("- **Threat Actor**: Competitor")
    doc.append("- **Goal**: Steal proprietary model")
    doc.append("- **Method**: Query API to reconstruct model")
    doc.append("- **Impact**: IP theft, offline evasion testing")
    doc.append("- **Likelihood**: MEDIUM")

    # Defenses
    doc.append("\n## 3. Recommended Defenses")
    doc.append("\n### Priority 1: Immediate")
    doc.append("- [ ] Implement API rate limiting")
    doc.append("- [ ] Add confidence thresholds")
    doc.append("- [ ] Enable query logging")

    doc.append("\n### Priority 2: Near-term")
    doc.append("- [ ] Deploy adversarial training pipeline")
    doc.append("- [ ] Add input validation layer")
    doc.append("- [ ] Implement data sanitization")

    doc.append("\n### Priority 3: Long-term")
    doc.append("- [ ] Build ensemble architecture")
    doc.append("- [ ] Add differential privacy")
    doc.append("- [ ] Schedule regular red team exercises")

    return "\n".join(doc)
```

---

## Common Errors

### 1. Assuming Attackers Need Full Access

```python
# WRONG: Only worry about white-box attacks
if attacker_has_model_weights:
    implement_defense()

# CORRECT: Most attacks are black-box
implement_defense_for_api_access()  # Always needed
```

### 2. Single Point Defense

```python
# WRONG: One defense is enough
add_input_validation()

# CORRECT: Defense in depth
add_input_validation()
add_confidence_threshold()
add_rate_limiting()
add_ensemble()
```

### 3. Not Monitoring

```python
# WRONG: Deploy and forget
model.deploy()

# CORRECT: Continuous monitoring
model.deploy()
monitor_predictions()
alert_on_anomalies()
log_all_queries()
```

---

## Key Takeaways

1. **ML systems are targets** - Security ML is attacked by adversaries
2. **Know your attack surface** - Data, training, deployment, inference
3. **Evasion is most common** - Attackers craft inputs to bypass
4. **Defense in depth** - No single defense is sufficient
5. **Monitor and adapt** - Attackers evolve, so must defenses

---

## Next Steps

You understand ML security foundations:

- **Lab 17**: Implement FGSM and PGD attacks
- **Lab 18**: Build robust models with adversarial training
- **Lab 20**: Apply these concepts to LLM security

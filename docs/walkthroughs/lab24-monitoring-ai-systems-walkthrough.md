# Lab 24 Walkthrough: Monitoring AI Security Systems

## Overview

This walkthrough guides you through building a monitoring system for AI-powered security tools. You'll learn to track performance, detect drift, and alert on degradation before your security AI fails silently.

**Time to complete walkthrough:** 45-60 minutes

---

## Step 1: Understanding Why AI Monitoring is Different

### The Silent Failure Problem

Traditional software crashes loudly. AI systems fail quietly:

```
TRADITIONAL SOFTWARE FAILURE:
User clicks button → Exception thrown → Error page → You know something's wrong

AI SYSTEM FAILURE:
User submits email → Model returns "legitimate" with 0.51 confidence →
Email is actually phishing → No error, just wrong answer → Breach happens
```

### What Can Go Wrong

| Problem | Description | Detection Method |
|---------|-------------|------------------|
| **Model Drift** | Model performance degrades over time | Track accuracy metrics |
| **Data Drift** | Input data distribution changes | Monitor input features |
| **Concept Drift** | Relationship between features and labels changes | Track prediction distributions |
| **Silent Errors** | Wrong predictions with high confidence | Human feedback loops |
| **Latency Spikes** | API slow downs | Latency percentiles |
| **Cost Overruns** | Token usage exceeds budget | Token/cost tracking |

---

## Step 2: Building the Core Metrics Classes

### Prediction-Level Metrics

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import hashlib

@dataclass
class PredictionMetrics:
    """Captures metrics for a single prediction."""
    timestamp: datetime
    model_name: str
    input_hash: str          # Anonymized input identifier
    prediction: str          # The predicted class/value
    confidence: float        # Model's confidence score
    latency_ms: float        # Time to generate prediction
    tokens_used: int = 0     # For LLM-based models
    cost_usd: float = 0.0    # Actual cost of this prediction
    human_feedback: Optional[str] = None  # "correct"/"incorrect"

    @classmethod
    def create(cls, model_name: str, input_data: str, prediction: str,
               confidence: float, latency_ms: float, tokens_used: int = 0):
        """Factory method to create prediction metrics."""
        # Hash input for privacy while maintaining trackability
        input_hash = hashlib.sha256(input_data.encode()).hexdigest()[:12]

        return cls(
            timestamp=datetime.now(),
            model_name=model_name,
            input_hash=input_hash,
            prediction=prediction,
            confidence=confidence,
            latency_ms=latency_ms,
            tokens_used=tokens_used
        )
```

### Aggregate Health Metrics

```python
@dataclass
class ModelHealthMetrics:
    """Aggregate metrics for monitoring model health."""
    total_predictions: int = 0
    total_errors: int = 0

    # Performance tracking
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    avg_confidence: float = 0.0

    # Distribution tracking
    predictions_by_class: dict = field(default_factory=dict)
    low_confidence_count: int = 0

    # Cost tracking
    total_tokens: int = 0
    total_cost_usd: float = 0.0

    # History for drift detection
    confidence_history: list = field(default_factory=list)
    latency_history: list = field(default_factory=list)
```

---

## Step 3: Implementing the Monitor Class

### Basic Structure

```python
import json
import logging
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class AIMonitor:
    """Monitor AI system health and performance."""

    def __init__(
        self,
        model_name: str,
        confidence_threshold: float = 0.7,
        history_size: int = 1000
    ):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.logger = logging.getLogger(f"ai_monitor.{model_name}")

        # Metrics storage
        self.metrics = ModelHealthMetrics()
        self.predictions: list[PredictionMetrics] = []

        # Use deque for bounded history (memory efficient)
        self.confidence_history = deque(maxlen=history_size)
        self.latency_history = deque(maxlen=history_size)
```

### Logging Predictions

```python
def log_prediction(
    self,
    input_data: str,
    prediction: str,
    confidence: float,
    latency_ms: float,
    tokens_used: int = 0
) -> PredictionMetrics:
    """Log a prediction and update metrics."""

    # Create prediction record
    pred = PredictionMetrics.create(
        model_name=self.model_name,
        input_data=input_data,
        prediction=prediction,
        confidence=confidence,
        latency_ms=latency_ms,
        tokens_used=tokens_used
    )

    # Update counters
    self.metrics.total_predictions += 1
    self.metrics.total_tokens += tokens_used

    # Update class distribution
    self.metrics.predictions_by_class[prediction] = \
        self.metrics.predictions_by_class.get(prediction, 0) + 1

    # Track low confidence predictions
    if confidence < self.confidence_threshold:
        self.metrics.low_confidence_count += 1
        self.logger.warning(
            f"Low confidence ({confidence:.2f}) for prediction: {prediction}"
        )

    # Update rolling averages
    self._update_averages(confidence, latency_ms)

    # Store for drift detection
    self.confidence_history.append(confidence)
    self.latency_history.append(latency_ms)
    self.predictions.append(pred)

    # Structured logging for SIEM/log aggregation
    self.logger.info(json.dumps({
        "event": "prediction",
        "model": self.model_name,
        "prediction": prediction,
        "confidence": round(confidence, 3),
        "latency_ms": round(latency_ms, 2),
        "tokens": tokens_used,
        "input_hash": pred.input_hash
    }))

    return pred

def _update_averages(self, confidence: float, latency_ms: float):
    """Update rolling averages using exponential smoothing."""
    alpha = 0.1  # Smoothing factor - lower = smoother

    if self.metrics.total_predictions == 1:
        self.metrics.avg_confidence = confidence
        self.metrics.avg_latency_ms = latency_ms
    else:
        self.metrics.avg_confidence = (
            alpha * confidence + (1 - alpha) * self.metrics.avg_confidence
        )
        self.metrics.avg_latency_ms = (
            alpha * latency_ms + (1 - alpha) * self.metrics.avg_latency_ms
        )
```

### Common Error #1: Memory Growth

**Symptom:** Monitor consumes increasing memory over time.

**Cause:** Storing all predictions without limit.

**Solution:** Use bounded collections:
```python
from collections import deque

# Instead of:
self.predictions = []  # Grows forever

# Use:
self.predictions = deque(maxlen=10000)  # Bounded to last 10k
```

---

## Step 4: Implementing Drift Detection

### Confidence Drift

```python
def detect_confidence_drift(self, window_size: int = 100) -> dict:
    """
    Detect if model confidence scores are drifting.

    Compares recent window to historical baseline.
    """
    history = list(self.confidence_history)

    if len(history) < window_size * 2:
        return {
            "drift_detected": False,
            "reason": "Insufficient data",
            "data_points": len(history),
            "required": window_size * 2
        }

    # Split into baseline and recent windows
    baseline = history[-window_size*2:-window_size]
    recent = history[-window_size:]

    baseline_avg = sum(baseline) / len(baseline)
    recent_avg = sum(recent) / len(recent)

    # Calculate percentage change
    if baseline_avg > 0:
        drift_pct = ((recent_avg - baseline_avg) / baseline_avg) * 100
    else:
        drift_pct = 0

    # Detect significant drift (>10% change)
    drift_detected = abs(drift_pct) > 10

    result = {
        "drift_detected": drift_detected,
        "baseline_avg": round(baseline_avg, 3),
        "recent_avg": round(recent_avg, 3),
        "drift_percentage": round(drift_pct, 2),
        "direction": "improving" if drift_pct > 0 else "degrading",
        "window_size": window_size
    }

    if drift_detected:
        self.logger.warning(f"Confidence drift detected: {drift_pct:.1f}%")

    return result
```

### Class Distribution Drift

```python
def detect_class_drift(self, baseline_distribution: dict) -> dict:
    """
    Detect if prediction class distribution is shifting.

    Args:
        baseline_distribution: Expected class percentages
            e.g., {"phishing": 0.3, "legitimate": 0.7}
    """
    total = self.metrics.total_predictions
    if total == 0:
        return {"drift_detected": False, "reason": "No predictions"}

    # Calculate current distribution
    current_dist = {
        cls: count / total
        for cls, count in self.metrics.predictions_by_class.items()
    }

    # Find maximum shift from baseline
    shifts = {}
    for cls, expected in baseline_distribution.items():
        actual = current_dist.get(cls, 0)
        shifts[cls] = {
            "expected": expected,
            "actual": round(actual, 3),
            "shift": round(abs(actual - expected), 3)
        }

    max_shift = max(s["shift"] for s in shifts.values())

    result = {
        "drift_detected": max_shift > 0.2,  # >20% shift
        "max_shift": round(max_shift, 3),
        "class_details": shifts,
        "total_predictions": total
    }

    if result["drift_detected"]:
        self.logger.warning(f"Class distribution drift: max shift {max_shift:.1%}")

    return result
```

### Common Error #2: False Drift Alerts

**Symptom:** Drift alerts firing constantly during normal operation.

**Cause:** Window too small or threshold too sensitive.

**Solution:** Tune parameters:
```python
# Too sensitive (will alert on normal variance)
detect_confidence_drift(window_size=10)  # Too small

# Better: larger window, reasonable threshold
def detect_confidence_drift(self, window_size: int = 100, threshold_pct: float = 10.0):
    # More stable detection
```

---

## Step 5: Health Status and Alerting

### Health Check Implementation

```python
def get_health_status(self) -> dict:
    """
    Get overall system health status.

    Returns status: healthy, degraded, or unhealthy
    """
    total = self.metrics.total_predictions

    if total == 0:
        return {
            "status": "unknown",
            "reason": "No predictions recorded yet",
            "model": self.model_name
        }

    # Calculate rates
    error_rate = self.metrics.total_errors / total
    low_conf_rate = self.metrics.low_confidence_count / total

    # Determine status based on thresholds
    if error_rate > 0.05:  # >5% errors
        status = "unhealthy"
        reason = f"High error rate: {error_rate:.1%}"
    elif error_rate > 0.01:  # 1-5% errors
        status = "degraded"
        reason = f"Elevated error rate: {error_rate:.1%}"
    elif low_conf_rate > 0.20:  # >20% low confidence
        status = "degraded"
        reason = f"High uncertainty: {low_conf_rate:.1%} low confidence"
    elif low_conf_rate > 0.15:  # 15-20% low confidence
        status = "degraded"
        reason = f"Elevated uncertainty: {low_conf_rate:.1%} low confidence"
    else:
        status = "healthy"
        reason = "All metrics within normal range"

    return {
        "status": status,
        "reason": reason,
        "model": self.model_name,
        "metrics": {
            "total_predictions": total,
            "error_rate": round(error_rate, 4),
            "low_confidence_rate": round(low_conf_rate, 4),
            "avg_latency_ms": round(self.metrics.avg_latency_ms, 2),
            "avg_confidence": round(self.metrics.avg_confidence, 3)
        },
        "distribution": self.metrics.predictions_by_class,
        "timestamp": datetime.now().isoformat()
    }
```

### Alert Checking

```python
def check_alerts(self) -> list[dict]:
    """Check all alert conditions and return triggered alerts."""
    alerts = []

    health = self.get_health_status()

    # Health status alert
    if health["status"] == "unhealthy":
        alerts.append({
            "severity": "critical",
            "type": "health_status",
            "message": f"Model {self.model_name} is unhealthy: {health['reason']}",
            "timestamp": datetime.now().isoformat()
        })
    elif health["status"] == "degraded":
        alerts.append({
            "severity": "warning",
            "type": "health_status",
            "message": f"Model {self.model_name} is degraded: {health['reason']}",
            "timestamp": datetime.now().isoformat()
        })

    # Confidence drift alert
    drift = self.detect_confidence_drift()
    if drift.get("drift_detected"):
        alerts.append({
            "severity": "warning",
            "type": "confidence_drift",
            "message": f"Confidence drift detected: {drift['drift_percentage']}%",
            "details": drift,
            "timestamp": datetime.now().isoformat()
        })

    # Latency alert (check p95)
    if len(self.latency_history) >= 20:
        sorted_latencies = sorted(self.latency_history)
        p95_idx = int(len(sorted_latencies) * 0.95)
        p95_latency = sorted_latencies[p95_idx]

        if p95_latency > 1000:  # >1 second p95
            alerts.append({
                "severity": "warning",
                "type": "latency",
                "message": f"High p95 latency: {p95_latency:.0f}ms",
                "timestamp": datetime.now().isoformat()
            })

    return alerts
```

---

## Step 6: Integrating with Your Model

### Wrapper Pattern

```python
class MonitoredModel:
    """Wrapper that adds monitoring to any model."""

    def __init__(self, model, model_name: str, monitor: AIMonitor = None):
        self.model = model
        self.monitor = monitor or AIMonitor(model_name)

    def predict(self, input_data: str) -> tuple[str, float]:
        """Make prediction with automatic monitoring."""
        import time

        start_time = time.time()

        try:
            # Call underlying model
            prediction, confidence = self.model.predict(input_data)
            latency_ms = (time.time() - start_time) * 1000

            # Log to monitor
            self.monitor.log_prediction(
                input_data=input_data,
                prediction=prediction,
                confidence=confidence,
                latency_ms=latency_ms
            )

            return prediction, confidence

        except Exception as e:
            self.monitor.log_error(e, input_data)
            raise
```

### Usage Example

```python
# Your existing model
class PhishingClassifier:
    def predict(self, email: str) -> tuple[str, float]:
        # ... your model logic ...
        return "phishing", 0.92

# Wrap it with monitoring
classifier = PhishingClassifier()
monitored_classifier = MonitoredModel(classifier, "phishing-v1")

# Use as normal - monitoring happens automatically
prediction, confidence = monitored_classifier.predict("Click here to win!")

# Check health anytime
health = monitored_classifier.monitor.get_health_status()
alerts = monitored_classifier.monitor.check_alerts()
```

---

## Step 7: Exporting Metrics

### Prometheus Format

{% raw %}
```python
def export_prometheus_metrics(self) -> str:
    """Export metrics in Prometheus text format."""
    lines = []

    # Total predictions counter
    lines.append(f'# HELP ai_predictions_total Total predictions made')
    lines.append(f'# TYPE ai_predictions_total counter')
    lines.append(f'ai_predictions_total{{model="{self.model_name}"}} {self.metrics.total_predictions}')

    # Predictions by class
    for cls, count in self.metrics.predictions_by_class.items():
        lines.append(f'ai_predictions_total{{model="{self.model_name}",class="{cls}"}} {count}')

    # Error counter
    lines.append(f'# HELP ai_errors_total Total prediction errors')
    lines.append(f'# TYPE ai_errors_total counter')
    lines.append(f'ai_errors_total{{model="{self.model_name}"}} {self.metrics.total_errors}')

    # Latency gauge
    lines.append(f'# HELP ai_latency_ms Average prediction latency')
    lines.append(f'# TYPE ai_latency_ms gauge')
    lines.append(f'ai_latency_ms{{model="{self.model_name}"}} {self.metrics.avg_latency_ms:.2f}')

    # Confidence gauge
    lines.append(f'# HELP ai_confidence_avg Average confidence score')
    lines.append(f'# TYPE ai_confidence_avg gauge')
    lines.append(f'ai_confidence_avg{{model="{self.model_name}"}} {self.metrics.avg_confidence:.3f}')

    return '\n'.join(lines)
```
{% endraw %}

### JSON Export

```python
def export_json_metrics(self) -> str:
    """Export all metrics as JSON."""
    return json.dumps({
        "model": self.model_name,
        "timestamp": datetime.now().isoformat(),
        "health": self.get_health_status(),
        "drift": {
            "confidence": self.detect_confidence_drift(),
        },
        "alerts": self.check_alerts(),
        "raw_metrics": {
            "total_predictions": self.metrics.total_predictions,
            "total_errors": self.metrics.total_errors,
            "avg_latency_ms": self.metrics.avg_latency_ms,
            "avg_confidence": self.metrics.avg_confidence,
            "predictions_by_class": self.metrics.predictions_by_class
        }
    }, indent=2)
```

---

## Key Takeaways

1. **AI fails silently** - Track confidence, not just errors
2. **Drift is inevitable** - Build detection from day one
3. **Human feedback is essential** - Create feedback loops
4. **Log everything structured** - JSON logs enable analysis
5. **Set baselines first** - Can't detect anomalies without "normal"

---

## Common Mistakes Summary

| Mistake | Solution |
|---------|----------|
| Only tracking errors | Also track confidence, latency, distribution |
| Unbounded storage | Use `deque(maxlen=N)` for history |
| Sensitive thresholds | Start conservative, tune based on data |
| No baseline | Record baseline before alerting |
| Missing timestamps | Always include ISO timestamps |

---

## Exercises

### Exercise A: Add Token Cost Tracking

Extend the monitor to track costs:
```python
def log_prediction(..., tokens_used: int, cost_per_1k: float = 0.002):
    # TODO: Calculate and track cost
    # TODO: Alert when daily/weekly cost exceeds budget
```

### Exercise B: Human Feedback Dashboard

Create a method to calculate accuracy from feedback:
```python
def calculate_accuracy_from_feedback(self) -> dict:
    # TODO: Filter predictions with feedback
    # TODO: Calculate TP, FP, TN, FN
    # TODO: Return precision, recall, F1
```

### Exercise C: Automated Retraining Trigger

Implement a check that suggests retraining:
```python
def should_retrain(self, accuracy_threshold: float = 0.9) -> bool:
    # TODO: Check accuracy from feedback
    # TODO: Check drift metrics
    # TODO: Return True if retraining recommended
```

---

## Next Labs

| Goal | Recommended Lab |
|------|-----------------|
| Build IR assistant | [Lab 10: IR Copilot](./lab29-ir-copilot-walkthrough.md) |
| Learn adversarial attacks | [Lab 17: Adversarial ML](./lab39-adversarial-ml-walkthrough.md) |
| DFIR fundamentals | [Lab 25: DFIR Fundamentals](./lab25-dfir-fundamentals-walkthrough.md) |

---

## Resources

- [Google MLOps Guide](https://cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning)
- [Evidently AI](https://www.evidentlyai.com/) - Open source ML monitoring
- [MLflow](https://mlflow.org/) - ML lifecycle platform
- [Prometheus Python Client](https://github.com/prometheus/client_python)
- [Grafana](https://grafana.com/) - Visualization for metrics

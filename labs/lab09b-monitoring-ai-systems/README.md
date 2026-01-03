# Lab 09b: Monitoring AI Security Systems

Learn to monitor AI systems in production: logging, metrics, drift detection, and alerting.

---

## Overview

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 60-90 minutes |
| **Prerequisites** | Lab 04 (LLM Log Analysis), Lab 09 (Detection Pipeline) recommended |
| **API Keys Required** | Yes (any LLM provider) |

## Learning Objectives

By the end of this lab, you will understand:

1. Why monitoring AI systems is different from traditional software
2. Key metrics to track for security AI systems
3. How to detect model drift and performance degradation
4. Logging strategies for AI-powered security tools
5. Building alerts for AI system health

> 🎯 **Bridge Lab**: This lab bridges building AI systems (Labs 04-10) and running them reliably in production. Essential before deploying any AI security tool.

---

## Part 1: Why AI Monitoring is Different

### Traditional Software vs. AI Systems

```
TRADITIONAL SOFTWARE:
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Input     │────▶│  Deterministic│────▶│   Output    │
│             │     │   Logic      │     │  (Same every│
│             │     │              │     │   time)     │
└─────────────┘     └─────────────┘     └─────────────┘
     If input is same, output is same. Easy to test.


AI SYSTEM:
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Input     │────▶│   Model     │────▶│   Output    │
│             │     │  (Probabilities)│  │ (May vary!) │
│             │     │              │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
     Same input may produce different outputs. Harder to monitor.
```

### Key Differences for Security AI

| Aspect | Traditional Monitoring | AI Monitoring |
|--------|----------------------|---------------|
| **Correctness** | Binary (right/wrong) | Probabilistic (confidence scores) |
| **Consistency** | Same input = same output | May vary (temperature, model updates) |
| **Drift** | Code changes only | Data drift, concept drift, model decay |
| **Failures** | Crashes, errors | Silent failures (wrong but confident) |
| **Baselines** | Static thresholds | Dynamic, learned baselines |

---

## Part 2: Essential Metrics for Security AI

### 2.1 Model Performance Metrics

```python
# starter/main.py
import time
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ai_monitor")


@dataclass
class PredictionMetrics:
    """Track metrics for a single prediction."""
    timestamp: datetime
    model_name: str
    input_hash: str  # Hash of input for deduplication
    prediction: str
    confidence: float
    latency_ms: float
    tokens_used: int = 0
    cost_usd: float = 0.0
    human_feedback: Optional[str] = None  # "correct", "incorrect", None


@dataclass  
class ModelHealthMetrics:
    """Aggregate metrics for model health monitoring."""
    total_predictions: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    avg_confidence: float = 0.0
    low_confidence_count: int = 0  # Below threshold
    predictions_by_class: dict = field(default_factory=dict)
    
    # Drift detection
    confidence_history: list = field(default_factory=list)
    latency_history: list = field(default_factory=list)
```

### 2.2 What to Monitor

| Metric | Why It Matters | Alert Threshold |
|--------|---------------|-----------------|
| **Latency** | User experience, cost | >2x baseline |
| **Confidence Scores** | Model uncertainty | Avg drops >10% |
| **Error Rate** | System health | >1% of requests |
| **Token Usage** | Cost control | >2x expected |
| **Class Distribution** | Drift detection | Shifts >20% |
| **Low Confidence %** | Model struggling | >15% of predictions |

---

## Part 3: Building the Monitoring System

### 3.1 Logging Wrapper

```python
class AIMonitor:
    """Monitor AI system health and performance."""
    
    def __init__(self, model_name: str, confidence_threshold: float = 0.7):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.metrics = ModelHealthMetrics()
        self.predictions: list[PredictionMetrics] = []
        
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
        pred = PredictionMetrics(
            timestamp=datetime.now(),
            model_name=self.model_name,
            input_hash=str(hash(input_data))[:12],
            prediction=prediction,
            confidence=confidence,
            latency_ms=latency_ms,
            tokens_used=tokens_used
        )
        
        # Update aggregate metrics
        self.metrics.total_predictions += 1
        self._update_rolling_averages(confidence, latency_ms)
        
        # Track class distribution
        self.metrics.predictions_by_class[prediction] = \
            self.metrics.predictions_by_class.get(prediction, 0) + 1
        
        # Check for low confidence
        if confidence < self.confidence_threshold:
            self.metrics.low_confidence_count += 1
            logger.warning(
                f"Low confidence prediction: {confidence:.2f} for class '{prediction}'"
            )
        
        # Store for drift detection
        self.metrics.confidence_history.append(confidence)
        self.metrics.latency_history.append(latency_ms)
        self.predictions.append(pred)
        
        # Log structured data
        logger.info(json.dumps({
            "event": "prediction",
            "model": self.model_name,
            "prediction": prediction,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "tokens": tokens_used
        }))
        
        return pred
    
    def _update_rolling_averages(self, confidence: float, latency_ms: float):
        """Update rolling averages using exponential smoothing."""
        alpha = 0.1  # Smoothing factor
        
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
    
    def log_error(self, error: Exception, input_data: str):
        """Log an error during prediction."""
        self.metrics.total_errors += 1
        logger.error(json.dumps({
            "event": "prediction_error",
            "model": self.model_name,
            "error": str(error),
            "input_hash": str(hash(input_data))[:12]
        }))
    
    def log_human_feedback(self, prediction_idx: int, feedback: str):
        """Log human feedback on a prediction (correct/incorrect)."""
        if 0 <= prediction_idx < len(self.predictions):
            self.predictions[prediction_idx].human_feedback = feedback
            logger.info(json.dumps({
                "event": "human_feedback",
                "model": self.model_name,
                "prediction": self.predictions[prediction_idx].prediction,
                "feedback": feedback
            }))
```

### 3.2 Drift Detection

```python
def detect_confidence_drift(self, window_size: int = 100) -> dict:
    """
    Detect if model confidence is drifting.
    
    Compares recent confidence scores to historical baseline.
    """
    if len(self.metrics.confidence_history) < window_size * 2:
        return {"drift_detected": False, "reason": "Insufficient data"}
    
    # Compare recent window to older baseline
    recent = self.metrics.confidence_history[-window_size:]
    baseline = self.metrics.confidence_history[-window_size*2:-window_size]
    
    recent_avg = sum(recent) / len(recent)
    baseline_avg = sum(baseline) / len(baseline)
    
    drift_pct = (recent_avg - baseline_avg) / baseline_avg * 100
    
    result = {
        "drift_detected": abs(drift_pct) > 10,  # >10% change
        "recent_avg_confidence": round(recent_avg, 3),
        "baseline_avg_confidence": round(baseline_avg, 3),
        "drift_percentage": round(drift_pct, 2),
        "direction": "increasing" if drift_pct > 0 else "decreasing"
    }
    
    if result["drift_detected"]:
        logger.warning(f"Confidence drift detected: {drift_pct:.1f}%")
    
    return result


def detect_class_drift(self, baseline_distribution: dict) -> dict:
    """
    Detect if prediction class distribution is drifting.
    
    Compares current distribution to expected baseline.
    """
    total = sum(self.metrics.predictions_by_class.values())
    if total == 0:
        return {"drift_detected": False, "reason": "No predictions yet"}
    
    current_dist = {
        k: v / total 
        for k, v in self.metrics.predictions_by_class.items()
    }
    
    # Calculate distribution shift
    max_shift = 0
    shifted_class = None
    
    for cls, expected_pct in baseline_distribution.items():
        current_pct = current_dist.get(cls, 0)
        shift = abs(current_pct - expected_pct)
        if shift > max_shift:
            max_shift = shift
            shifted_class = cls
    
    result = {
        "drift_detected": max_shift > 0.2,  # >20% shift in any class
        "max_shift_percentage": round(max_shift * 100, 2),
        "shifted_class": shifted_class,
        "current_distribution": {k: round(v, 3) for k, v in current_dist.items()},
        "baseline_distribution": baseline_distribution
    }
    
    if result["drift_detected"]:
        logger.warning(
            f"Class distribution drift detected: {shifted_class} shifted by {max_shift*100:.1f}%"
        )
    
    return result
```

### 3.3 Health Check Endpoint

```python
def get_health_status(self) -> dict:
    """Get overall system health status."""
    
    error_rate = (
        self.metrics.total_errors / self.metrics.total_predictions 
        if self.metrics.total_predictions > 0 else 0
    )
    
    low_conf_rate = (
        self.metrics.low_confidence_count / self.metrics.total_predictions
        if self.metrics.total_predictions > 0 else 0
    )
    
    # Determine overall status
    if error_rate > 0.05:  # >5% errors
        status = "unhealthy"
    elif error_rate > 0.01 or low_conf_rate > 0.15:
        status = "degraded"
    else:
        status = "healthy"
    
    return {
        "status": status,
        "model": self.model_name,
        "total_predictions": self.metrics.total_predictions,
        "error_rate": round(error_rate, 4),
        "low_confidence_rate": round(low_conf_rate, 4),
        "avg_latency_ms": round(self.metrics.avg_latency_ms, 2),
        "avg_confidence": round(self.metrics.avg_confidence, 3),
        "predictions_by_class": self.metrics.predictions_by_class,
        "timestamp": datetime.now().isoformat()
    }
```

---

## Part 4: Putting It Together

### Complete Example: Monitored Phishing Classifier

```python
import random

def mock_phishing_classifier(email_text: str) -> tuple[str, float]:
    """Mock classifier for demonstration."""
    # Simulate model behavior
    time.sleep(random.uniform(0.1, 0.3))  # Simulate latency
    
    if "urgent" in email_text.lower() or "click here" in email_text.lower():
        return "phishing", random.uniform(0.75, 0.95)
    elif "meeting" in email_text.lower() or "report" in email_text.lower():
        return "legitimate", random.uniform(0.80, 0.95)
    else:
        return "legitimate", random.uniform(0.50, 0.70)


def main():
    # Initialize monitor
    monitor = AIMonitor(
        model_name="phishing-classifier-v1",
        confidence_threshold=0.7
    )
    
    # Sample emails
    test_emails = [
        "URGENT: Click here to verify your account immediately!",
        "Q3 Revenue Report attached for your review",
        "Meeting tomorrow at 2pm to discuss project updates",
        "Your password expires today - click to reset NOW",
        "Invoice #12345 attached",
        "Congratulations! You've won a prize - claim now!",
        "Team standup notes from today's meeting",
        "URGENT: Wire transfer required immediately",
    ]
    
    # Process emails with monitoring
    print("\n" + "="*60)
    print("Processing emails with monitoring...")
    print("="*60 + "\n")
    
    for email in test_emails:
        try:
            start_time = time.time()
            prediction, confidence = mock_phishing_classifier(email)
            latency_ms = (time.time() - start_time) * 1000
            
            monitor.log_prediction(
                input_data=email,
                prediction=prediction,
                confidence=confidence,
                latency_ms=latency_ms,
                tokens_used=len(email.split()) * 2  # Rough estimate
            )
            
            print(f"Email: {email[:50]}...")
            print(f"  → {prediction} (confidence: {confidence:.2f})")
            print()
            
        except Exception as e:
            monitor.log_error(e, email)
    
    # Check drift
    print("\n" + "="*60)
    print("Drift Detection")
    print("="*60)
    
    baseline_dist = {"phishing": 0.3, "legitimate": 0.7}
    class_drift = monitor.detect_class_drift(baseline_dist)
    print(f"Class drift: {json.dumps(class_drift, indent=2)}")
    
    # Health status
    print("\n" + "="*60)
    print("Health Status")
    print("="*60)
    
    health = monitor.get_health_status()
    print(json.dumps(health, indent=2))


if __name__ == "__main__":
    main()
```

---

## Part 5: Exercises

### Exercise 1: Add Latency Alerting

Implement a method that alerts when latency exceeds a threshold:

```python
def check_latency_alert(self, threshold_ms: float = 500) -> dict:
    """Alert if recent latency exceeds threshold."""
    # TODO: Check recent latency values
    # TODO: Return alert if >X% exceed threshold
    pass
```

### Exercise 2: Human Feedback Loop

Extend the system to track precision/recall based on human feedback:

```python
def calculate_metrics_from_feedback(self) -> dict:
    """Calculate precision/recall from human feedback."""
    # TODO: Filter predictions with feedback
    # TODO: Calculate true positives, false positives, etc.
    # TODO: Return precision, recall, F1
    pass
```

### Exercise 3: Export to Prometheus/Grafana

Add metrics export in Prometheus format:

```python
def export_prometheus_metrics(self) -> str:
    """Export metrics in Prometheus format."""
    # TODO: Format metrics as Prometheus text
    # Example: ai_predictions_total{model="x",class="phishing"} 100
    pass
```

---

## Key Takeaways

1. **AI systems fail silently** - Monitor confidence scores, not just errors
2. **Drift is inevitable** - Track distributions over time
3. **Human feedback is gold** - Build feedback loops into your system
4. **Log everything** - Structured logs enable debugging
5. **Set baselines first** - You can't detect drift without knowing "normal"

---

## Next Steps

| If you want to... | Go to... |
|-------------------|----------|
| Build an IR assistant | [Lab 10: IR Copilot](../lab10-ir-copilot/) |
| Learn about adversarial attacks | [Lab 17: Adversarial ML](../lab17-adversarial-ml/) |
| Deploy to production | See [Production Deployment Guide](../../docs/guides/production-deployment.md) |

---

## Resources

- [ML Monitoring Best Practices](https://cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning)
- [Evidently AI](https://www.evidentlyai.com/) - Open source ML monitoring
- [MLflow](https://mlflow.org/) - ML lifecycle management
- [Prometheus Python Client](https://github.com/prometheus/client_python) - Metrics export

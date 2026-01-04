#!/usr/bin/env python3
"""
Lab 09b: Monitoring AI Security Systems - Solution

A complete AI monitoring system for security applications.

Run: python main.py
"""

import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Configure structured logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ai_monitor")


@dataclass
class PredictionMetrics:
    """Track metrics for a single prediction."""

    timestamp: datetime
    model_name: str
    input_hash: str
    prediction: str
    confidence: float
    latency_ms: float
    tokens_used: int = 0
    cost_usd: float = 0.0
    human_feedback: Optional[str] = None


@dataclass
class AIMetrics:
    """Track metrics for AI model calls (test-compatible version)."""

    timestamp: str
    model_name: str
    latency_ms: float
    tokens_used: int
    cost_usd: float
    success: bool


@dataclass
class ModelHealthMetrics:
    """Aggregate metrics for model health monitoring."""

    total_predictions: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    avg_confidence: float = 0.0
    low_confidence_count: int = 0
    predictions_by_class: dict = field(default_factory=dict)
    confidence_history: list = field(default_factory=list)
    latency_history: list = field(default_factory=list)


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
        tokens_used: int = 0,
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
            tokens_used=tokens_used,
        )

        # Update aggregate metrics
        self.metrics.total_predictions += 1
        self._update_rolling_averages(confidence, latency_ms)

        # Track class distribution
        self.metrics.predictions_by_class[prediction] = (
            self.metrics.predictions_by_class.get(prediction, 0) + 1
        )

        # Check for low confidence
        if confidence < self.confidence_threshold:
            self.metrics.low_confidence_count += 1
            logger.warning(f"Low confidence prediction: {confidence:.2f} for class '{prediction}'")

        # Store for drift detection
        self.metrics.confidence_history.append(confidence)
        self.metrics.latency_history.append(latency_ms)
        self.predictions.append(pred)

        # Log structured data
        logger.info(
            json.dumps(
                {
                    "event": "prediction",
                    "model": self.model_name,
                    "prediction": prediction,
                    "confidence": round(confidence, 3),
                    "latency_ms": round(latency_ms, 2),
                    "tokens": tokens_used,
                }
            )
        )

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
        logger.error(
            json.dumps(
                {
                    "event": "prediction_error",
                    "model": self.model_name,
                    "error": str(error),
                    "error_type": type(error).__name__,
                    "input_hash": str(hash(input_data))[:12],
                }
            )
        )

    def log_human_feedback(self, prediction_idx: int, feedback: str):
        """Log human feedback on a prediction."""
        if 0 <= prediction_idx < len(self.predictions):
            self.predictions[prediction_idx].human_feedback = feedback
            logger.info(
                json.dumps(
                    {
                        "event": "human_feedback",
                        "model": self.model_name,
                        "prediction": self.predictions[prediction_idx].prediction,
                        "feedback": feedback,
                    }
                )
            )

    def detect_confidence_drift(self, window_size: int = 100) -> dict:
        """Detect if model confidence is drifting."""
        if len(self.metrics.confidence_history) < window_size * 2:
            return {"drift_detected": False, "reason": "Insufficient data"}

        recent = self.metrics.confidence_history[-window_size:]
        baseline = self.metrics.confidence_history[-window_size * 2 : -window_size]

        recent_avg = sum(recent) / len(recent)
        baseline_avg = sum(baseline) / len(baseline)

        drift_pct = (recent_avg - baseline_avg) / baseline_avg * 100 if baseline_avg > 0 else 0

        result = {
            "drift_detected": abs(drift_pct) > 10,
            "recent_avg_confidence": round(recent_avg, 3),
            "baseline_avg_confidence": round(baseline_avg, 3),
            "drift_percentage": round(drift_pct, 2),
            "direction": "increasing" if drift_pct > 0 else "decreasing",
        }

        if result["drift_detected"]:
            logger.warning(f"Confidence drift detected: {drift_pct:.1f}%")

        return result

    def detect_class_drift(self, baseline_distribution: dict) -> dict:
        """Detect if prediction class distribution is drifting."""
        total = sum(self.metrics.predictions_by_class.values())
        if total == 0:
            return {"drift_detected": False, "reason": "No predictions yet"}

        current_dist = {k: v / total for k, v in self.metrics.predictions_by_class.items()}

        max_shift = 0
        shifted_class = None

        for cls, expected_pct in baseline_distribution.items():
            current_pct = current_dist.get(cls, 0)
            shift = abs(current_pct - expected_pct)
            if shift > max_shift:
                max_shift = shift
                shifted_class = cls

        result = {
            "drift_detected": max_shift > 0.2,
            "max_shift_percentage": round(max_shift * 100, 2),
            "shifted_class": shifted_class,
            "current_distribution": {k: round(v, 3) for k, v in current_dist.items()},
            "baseline_distribution": baseline_distribution,
        }

        if result["drift_detected"]:
            logger.warning(f"Class drift: {shifted_class} shifted by {max_shift*100:.1f}%")

        return result

    def check_latency_alert(self, threshold_ms: float = 500) -> dict:
        """Check if latency exceeds threshold."""
        if len(self.metrics.latency_history) < 10:
            return {"alert": False, "reason": "Insufficient data"}

        recent = self.metrics.latency_history[-10:]
        exceeds_count = sum(1 for l in recent if l > threshold_ms)
        exceeds_pct = exceeds_count / len(recent)

        return {
            "alert": exceeds_pct > 0.3,  # >30% exceed threshold
            "threshold_ms": threshold_ms,
            "exceeds_percentage": round(exceeds_pct * 100, 1),
            "recent_avg_ms": round(sum(recent) / len(recent), 2),
        }

    def get_health_status(self) -> dict:
        """Get overall system health status."""
        error_rate = (
            self.metrics.total_errors / self.metrics.total_predictions
            if self.metrics.total_predictions > 0
            else 0
        )

        low_conf_rate = (
            self.metrics.low_confidence_count / self.metrics.total_predictions
            if self.metrics.total_predictions > 0
            else 0
        )

        if error_rate > 0.05:
            status = "unhealthy"
        elif error_rate > 0.01 or low_conf_rate > 0.15:
            status = "degraded"
        else:
            status = "healthy"

        return {
            "status": status,
            "model": self.model_name,
            "total_predictions": self.metrics.total_predictions,
            "total_errors": self.metrics.total_errors,
            "error_rate": round(error_rate, 4),
            "low_confidence_rate": round(low_conf_rate, 4),
            "avg_latency_ms": round(self.metrics.avg_latency_ms, 2),
            "avg_confidence": round(self.metrics.avg_confidence, 3),
            "predictions_by_class": dict(self.metrics.predictions_by_class),
            "timestamp": datetime.now().isoformat(),
        }

    def calculate_metrics_from_feedback(self) -> dict:
        """Calculate precision/recall from human feedback."""
        feedback_preds = [p for p in self.predictions if p.human_feedback]

        if not feedback_preds:
            return {"error": "No human feedback available"}

        # For binary classification (phishing vs legitimate)
        tp = fp = tn = fn = 0

        for pred in feedback_preds:
            if pred.prediction == "phishing":
                if pred.human_feedback == "correct":
                    tp += 1
                else:
                    fp += 1
            else:  # legitimate
                if pred.human_feedback == "correct":
                    tn += 1
                else:
                    fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "total_feedback": len(feedback_preds),
        }


# =============================================================================
# TEST-COMPATIBLE CLASSES
# =============================================================================


class MetricsCollector:
    """Collect and summarize AI metrics (test-compatible version)."""

    def __init__(self):
        self.metrics: list[AIMetrics] = []

    def record(
        self,
        model_name: str,
        latency_ms: float,
        tokens_used: int,
        cost_usd: float,
        success: bool,
    ):
        """Record a metric entry."""
        self.metrics.append(
            AIMetrics(
                timestamp=datetime.now().isoformat(),
                model_name=model_name,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                cost_usd=cost_usd,
                success=success,
            )
        )

    def get_summary(self) -> dict:
        """Get summary statistics."""
        if not self.metrics:
            return {
                "total_calls": 0,
                "success_rate": 0.0,
                "avg_latency_ms": 0.0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
            }

        successes = sum(1 for m in self.metrics if m.success)
        return {
            "total_calls": len(self.metrics),
            "success_rate": successes / len(self.metrics),
            "avg_latency_ms": sum(m.latency_ms for m in self.metrics) / len(self.metrics),
            "total_tokens": sum(m.tokens_used for m in self.metrics),
            "total_cost_usd": sum(m.cost_usd for m in self.metrics),
        }


class PerformanceMonitor:
    """Monitor performance thresholds (test-compatible version)."""

    def __init__(self, latency_threshold_ms: float = 500.0, error_rate_threshold: float = 0.1):
        self.latency_threshold_ms = latency_threshold_ms
        self.error_rate_threshold = error_rate_threshold

    def check_latency(self, latency_ms: float) -> list[str]:
        """Check if latency exceeds threshold."""
        alerts = []
        if latency_ms > self.latency_threshold_ms:
            alerts.append(
                f"Latency alert: {latency_ms:.1f}ms exceeds threshold of {self.latency_threshold_ms:.1f}ms"
            )
        return alerts


def create_dashboard_data(collector: MetricsCollector) -> dict:
    """Create dashboard-ready data from metrics collector."""
    summary = collector.get_summary()
    return {
        "summary": summary,
        "recent_metrics": [
            {
                "timestamp": m.timestamp,
                "model": m.model_name,
                "latency_ms": m.latency_ms,
                "success": m.success,
            }
            for m in collector.metrics[-10:]
        ],
        "alerts": [],
    }


# =============================================================================
# MOCK CLASSIFIER
# =============================================================================


def mock_phishing_classifier(email_text: str) -> tuple[str, float]:
    """Mock classifier for demonstration."""
    time.sleep(random.uniform(0.05, 0.15))

    if "urgent" in email_text.lower() or "click here" in email_text.lower():
        return "phishing", random.uniform(0.75, 0.95)
    elif "meeting" in email_text.lower() or "report" in email_text.lower():
        return "legitimate", random.uniform(0.80, 0.95)
    else:
        return "legitimate", random.uniform(0.50, 0.70)


# =============================================================================
# MAIN
# =============================================================================


def main():
    print("=" * 60)
    print("Lab 09b: Monitoring AI Security Systems - Solution")
    print("=" * 60)

    monitor = AIMonitor(model_name="phishing-classifier-v1", confidence_threshold=0.7)

    test_emails = [
        "URGENT: Click here to verify your account immediately!",
        "Q3 Revenue Report attached for your review",
        "Meeting tomorrow at 2pm to discuss project updates",
        "Your password expires today - click to reset NOW",
        "Invoice #12345 attached for payment",
        "Congratulations! You've won - claim your prize!",
        "Team standup notes from today",
        "URGENT: Wire transfer required immediately",
        "Project status update for stakeholders",
        "Click here to unlock your exclusive offer",
    ]

    print("\n📊 Processing emails with monitoring...\n")

    for i, email in enumerate(test_emails):
        try:
            start_time = time.time()
            prediction, confidence = mock_phishing_classifier(email)
            latency_ms = (time.time() - start_time) * 1000

            monitor.log_prediction(
                input_data=email,
                prediction=prediction,
                confidence=confidence,
                latency_ms=latency_ms,
                tokens_used=len(email.split()) * 2,
            )

            print(f"[{i+1:2d}] {email[:45]}...")
            print(f"     → {prediction:10s} (confidence: {confidence:.2f})")

        except Exception as e:
            monitor.log_error(e, email)

    # Simulate some human feedback
    print("\n📝 Simulating human feedback...")
    monitor.log_human_feedback(0, "correct")  # Phishing correctly identified
    monitor.log_human_feedback(1, "correct")  # Legitimate correctly identified
    monitor.log_human_feedback(3, "correct")  # Phishing correctly identified
    monitor.log_human_feedback(5, "correct")  # Phishing correctly identified

    # Check drift
    print("\n" + "=" * 60)
    print("🔍 Drift Detection")
    print("=" * 60)

    baseline_dist = {"phishing": 0.3, "legitimate": 0.7}
    class_drift = monitor.detect_class_drift(baseline_dist)
    print(f"\nClass Distribution Drift:")
    print(json.dumps(class_drift, indent=2))

    # Latency check
    print("\n⏱️  Latency Alert Check:")
    latency_alert = monitor.check_latency_alert(threshold_ms=200)
    print(json.dumps(latency_alert, indent=2))

    # Feedback metrics
    print("\n📈 Metrics from Human Feedback:")
    feedback_metrics = monitor.calculate_metrics_from_feedback()
    print(json.dumps(feedback_metrics, indent=2))

    # Health status
    print("\n" + "=" * 60)
    print("🏥 Health Status")
    print("=" * 60)

    health = monitor.get_health_status()
    print(json.dumps(health, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Lab 09b: Monitoring AI Security Systems - Starter Code

Learn to monitor AI systems in production.

Run: python main.py
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Configure logging
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
    human_feedback: Optional[str] = None


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
        """
        Log a prediction and update metrics.

        TODO: Implement this method:
        1. Create a PredictionMetrics record
        2. Update aggregate metrics (total_predictions, averages)
        3. Track class distribution
        4. Check for low confidence and log warning
        5. Store in history for drift detection
        """
        # TODO: Create prediction record
        pred = PredictionMetrics(
            timestamp=datetime.now(),
            model_name=self.model_name,
            input_hash=str(hash(input_data))[:12],
            prediction=prediction,
            confidence=confidence,
            latency_ms=latency_ms,
            tokens_used=tokens_used,
        )

        # TODO: Update self.metrics.total_predictions

        # TODO: Update predictions_by_class dict

        # TODO: Check if confidence < threshold and update low_confidence_count

        # TODO: Append to confidence_history and latency_history

        # TODO: Append pred to self.predictions

        return pred

    def log_error(self, error: Exception, input_data: str):
        """Log an error during prediction."""
        # TODO: Increment total_errors
        # TODO: Log the error with structured data
        pass

    def detect_confidence_drift(self, window_size: int = 100) -> dict:
        """
        Detect if model confidence is drifting.

        TODO: Implement drift detection:
        1. Check if we have enough data (window_size * 2)
        2. Compare recent window avg to baseline window avg
        3. Return drift info if change > 10%
        """
        if len(self.metrics.confidence_history) < window_size * 2:
            return {"drift_detected": False, "reason": "Insufficient data"}

        # TODO: Calculate recent_avg and baseline_avg
        # TODO: Calculate drift percentage
        # TODO: Return result dict

        return {"drift_detected": False, "reason": "Not implemented"}

    def get_health_status(self) -> dict:
        """
        Get overall system health status.

        TODO: Implement health check:
        1. Calculate error_rate
        2. Calculate low_confidence_rate
        3. Determine status: "healthy", "degraded", or "unhealthy"
        4. Return status dict
        """
        # TODO: Calculate error_rate and low_conf_rate
        # TODO: Determine status based on thresholds
        # TODO: Return health dict

        return {
            "status": "unknown",
            "model": self.model_name,
            "total_predictions": self.metrics.total_predictions,
            "timestamp": datetime.now().isoformat(),
        }


# =============================================================================
# MOCK CLASSIFIER FOR TESTING
# =============================================================================

import random


def mock_phishing_classifier(email_text: str) -> tuple[str, float]:
    """Mock classifier for demonstration."""
    time.sleep(random.uniform(0.05, 0.15))  # Simulate latency

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
    monitor = AIMonitor(model_name="phishing-classifier-v1", confidence_threshold=0.7)

    test_emails = [
        "URGENT: Click here to verify your account immediately!",
        "Q3 Revenue Report attached for your review",
        "Meeting tomorrow at 2pm to discuss project updates",
        "Your password expires today - click to reset NOW",
    ]

    print("\nProcessing emails with monitoring...")
    print("=" * 60)

    for email in test_emails:
        start_time = time.time()
        prediction, confidence = mock_phishing_classifier(email)
        latency_ms = (time.time() - start_time) * 1000

        monitor.log_prediction(
            input_data=email, prediction=prediction, confidence=confidence, latency_ms=latency_ms
        )

        print(f"Email: {email[:40]}...")
        print(f"  → {prediction} ({confidence:.2f})")

    print("\nHealth Status:")
    print(json.dumps(monitor.get_health_status(), indent=2))


if __name__ == "__main__":
    main()

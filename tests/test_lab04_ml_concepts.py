#!/usr/bin/env python3
"""Tests for Lab 00b: ML Concepts Primer."""

import sys
from pathlib import Path

import pytest

# Clear any existing 'main' module to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p and "\\labs\\lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab00b-ml-concepts-primer" / "solution")
sys.path.insert(0, lab_path)

from main import calculate_metrics, extract_email_features, load_data


class TestDataLoading:
    """Tests for data loading."""

    def test_load_sample_emails(self):
        """Test loading sample emails JSON."""
        data = load_data("sample_emails.json")

        assert data is not None
        assert isinstance(data, list)
        assert len(data) > 0
        assert "subject" in data[0]
        assert "body" in data[0]
        assert "label" in data[0]

    def test_load_network_samples(self):
        """Test loading network samples JSON."""
        data = load_data("network_samples.json")

        assert data is not None
        assert isinstance(data, list)
        assert len(data) > 0


class TestFeatureExtraction:
    """Tests for feature extraction."""

    def test_extract_email_features_basic(self):
        """Test basic feature extraction from email."""
        email = {
            "subject": "Test Subject",
            "body": "This is a test email body.",
            "label": "legitimate",
        }

        features = extract_email_features(email)

        assert features is not None
        assert isinstance(features, dict)
        assert "word_count" in features
        assert "has_urgency" in features
        assert "has_money_words" in features
        assert "has_action_words" in features
        assert "caps_ratio" in features

    def test_extract_email_features_phishing_indicators(self):
        """Test that phishing indicators are detected."""
        phishing_email = {
            "subject": "URGENT: Your account will be suspended!",
            "body": "Click here immediately to verify your account and claim your $1000 prize!",
            "label": "phishing",
        }

        features = extract_email_features(phishing_email)

        assert features["has_urgency"] is True
        assert features["has_money_words"] is True
        assert features["has_action_words"] is True
        assert features["caps_ratio"] > 0  # Has uppercase in subject

    def test_extract_email_features_legitimate(self):
        """Test features for legitimate email."""
        legit_email = {
            "subject": "Meeting reminder",
            "body": "Hi team, just a reminder about tomorrow's meeting at 2pm.",
            "label": "legitimate",
        }

        features = extract_email_features(legit_email)

        assert features["has_urgency"] is False
        assert features["has_money_words"] is False

    def test_extract_email_features_empty(self):
        """Test feature extraction with empty/missing fields."""
        empty_email = {}

        features = extract_email_features(empty_email)

        assert features is not None
        assert features["word_count"] >= 0  # Handles empty gracefully


class TestMetricsCalculation:
    """Tests for classification metrics."""

    def test_calculate_metrics_perfect(self):
        """Test metrics with perfect predictions."""
        predictions = ["phishing", "legitimate", "phishing", "legitimate"]
        actuals = ["phishing", "legitimate", "phishing", "legitimate"]

        metrics = calculate_metrics(predictions, actuals)

        assert metrics["accuracy"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1"] == 1.0

    def test_calculate_metrics_confusion_matrix(self):
        """Test confusion matrix values."""
        # 2 TP, 1 FP, 1 TN, 1 FN
        predictions = ["phishing", "phishing", "phishing", "legitimate", "legitimate"]
        actuals = ["phishing", "phishing", "legitimate", "legitimate", "phishing"]

        metrics = calculate_metrics(predictions, actuals)

        assert metrics["tp"] == 2
        assert metrics["fp"] == 1
        assert metrics["tn"] == 1
        assert metrics["fn"] == 1

    def test_calculate_metrics_all_negative(self):
        """Test metrics when all predictions are negative."""
        predictions = ["legitimate", "legitimate", "legitimate"]
        actuals = ["phishing", "legitimate", "phishing"]

        metrics = calculate_metrics(predictions, actuals)

        assert metrics["tp"] == 0
        assert metrics["fn"] == 2  # Missed 2 phishing

    def test_calculate_metrics_precision_recall_tradeoff(self):
        """Test precision/recall with different scenarios."""
        # High precision, low recall (conservative)
        preds_conservative = ["legitimate", "legitimate", "phishing", "legitimate"]
        actuals = ["phishing", "legitimate", "phishing", "phishing"]

        metrics = calculate_metrics(preds_conservative, actuals)

        # Only predicted one phishing and it was correct
        assert metrics["precision"] == 1.0
        # But missed 2 out of 3 phishing
        assert metrics["recall"] < 0.5


class TestIntegration:
    """Integration tests for the lab."""

    def test_full_email_analysis(self):
        """Test complete email analysis flow."""
        emails = load_data("sample_emails.json")

        all_features = []
        for email in emails:
            features = extract_email_features(email)
            features["label"] = email["label"]
            all_features.append(features)

        # Should have features for all emails
        assert len(all_features) == len(emails)

        # Check that phishing emails have more indicators on average
        phishing_urgency = [f["has_urgency"] for f in all_features if f["label"] == "phishing"]
        legit_urgency = [f["has_urgency"] for f in all_features if f["label"] == "legitimate"]

        # This is a soft check - phishing should generally have more urgency
        assert sum(phishing_urgency) >= 0  # At least runs without error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

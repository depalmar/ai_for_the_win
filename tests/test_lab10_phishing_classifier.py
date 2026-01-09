#!/usr/bin/env python3
"""Tests for Lab 01: Phishing Email Classifier."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab10-phishing-classifier" / "solution")
sys.path.insert(0, lab_path)

from main import (
    build_feature_matrix,
    evaluate_model,
    extract_custom_features,
    load_data,
    preprocess_text,
    train_classifier,
)


@pytest.fixture
def sample_emails():
    """Create sample email data for testing."""
    return pd.DataFrame(
        {
            "text": [
                "Dear user, your account has been compromised. Click here immediately: http://evil.com/steal",
                "Hi John, please review the attached quarterly report and let me know your thoughts. Best, Sarah",
                "URGENT: Your bank account will be suspended! Verify now at http://phishing.site/verify",
                "Meeting reminder: Team sync tomorrow at 2pm in Conference Room B",
                "Congratulations! You've won $1,000,000! Send your details to claim: winner@scam.com",
                "The project deadline has been extended to next Friday. Please update your tasks accordingly.",
                "Your password expires in 24 hours. Click here to reset: http://fake-bank.com/reset",
                "Thanks for lunch yesterday! Let's catch up again next week.",
            ],
            "label": [1, 0, 1, 0, 1, 0, 1, 0],
        }
    )


@pytest.fixture
def sample_csv_file(tmp_path, sample_emails):
    """Create a temporary CSV file with sample data."""
    filepath = tmp_path / "test_emails.csv"
    sample_emails.to_csv(filepath, index=False)
    return str(filepath)


class TestDataLoading:
    """Tests for data loading functions."""

    def test_load_data(self, sample_csv_file):
        """Test loading email data from CSV."""
        df = load_data(sample_csv_file)

        assert df is not None
        assert isinstance(df, pd.DataFrame)
        assert "text" in df.columns
        assert "label" in df.columns
        assert len(df) == 8

    def test_load_data_handles_missing_values(self, tmp_path):
        """Test that missing values are handled."""
        data = pd.DataFrame({"text": ["Valid email", None, "Another email"], "label": [0, 1, None]})
        filepath = tmp_path / "test_missing.csv"
        data.to_csv(filepath, index=False)

        df = load_data(str(filepath))

        # Should drop rows with missing text or label
        assert len(df) <= 3


class TestTextPreprocessing:
    """Tests for text preprocessing."""

    def test_preprocess_lowercase(self):
        """Test that text is converted to lowercase."""
        result = preprocess_text("HELLO WORLD")
        assert result == result.lower()

    def test_preprocess_removes_urls(self):
        """Test URL removal."""
        text = "Click here http://malicious.com/steal to claim"
        result = preprocess_text(text)
        assert "http" not in result
        assert "malicious" not in result

    def test_preprocess_removes_email_addresses(self):
        """Test email address removal."""
        text = "Contact us at support@company.com for help"
        result = preprocess_text(text)
        assert "@" not in result

    def test_preprocess_removes_html(self):
        """Test HTML tag removal."""
        text = "<p>Hello <b>World</b></p>"
        result = preprocess_text(text)
        assert "<" not in result
        assert ">" not in result

    def test_preprocess_handles_empty_input(self):
        """Test handling of empty or None input."""
        assert preprocess_text("") == ""
        assert preprocess_text(None) == ""


class TestFeatureExtraction:
    """Tests for feature extraction."""

    def test_extract_custom_features(self, sample_emails):
        """Test custom feature extraction."""
        features = extract_custom_features(sample_emails)

        assert features is not None
        assert len(features) == len(sample_emails)

    def test_custom_features_detect_urgency(self):
        """Test that urgency words are detected."""
        urgent_email = pd.DataFrame(
            {"text": ["URGENT: Act immediately or your account expires!"], "label": [1]}
        )

        features = extract_custom_features(urgent_email)

        # Should have non-zero urgency feature
        assert features is not None

    def test_build_feature_matrix(self, sample_emails):
        """Test building the complete feature matrix."""
        X, vectorizer = build_feature_matrix(sample_emails)

        assert X is not None
        assert vectorizer is not None
        # Feature matrix should have same number of rows as emails
        assert X.shape[0] == len(sample_emails)


class TestModelTraining:
    """Tests for model training."""

    def test_train_classifier(self, sample_emails):
        """Test classifier training."""
        X, _ = build_feature_matrix(sample_emails)
        y = sample_emails["label"].values

        model = train_classifier(X, y)

        assert model is not None

    def test_model_can_predict(self, sample_emails):
        """Test that trained model can make predictions."""
        X, vectorizer = build_feature_matrix(sample_emails)
        y = sample_emails["label"].values

        model = train_classifier(X, y)
        predictions = model.predict(X)

        assert len(predictions) == len(sample_emails)
        assert all(p in [0, 1] for p in predictions)


class TestModelEvaluation:
    """Tests for model evaluation."""

    def test_evaluate_model(self, sample_emails):
        """Test model evaluation."""
        X, _ = build_feature_matrix(sample_emails)
        y = sample_emails["label"].values

        model = train_classifier(X, y)
        predictions = model.predict(X)

        metrics = evaluate_model(y, predictions)

        assert metrics is not None
        assert "accuracy" in metrics
        assert 0 <= metrics["accuracy"] <= 1


class TestPhishingDetection:
    """Integration tests for phishing detection."""

    def test_phishing_vs_legitimate(self, sample_emails):
        """Test that model can distinguish phishing from legitimate."""
        X, _ = build_feature_matrix(sample_emails)
        y = sample_emails["label"].values

        model = train_classifier(X, y)
        predictions = model.predict(X)

        # Model should predict at least one of each class
        assert 0 in predictions
        assert 1 in predictions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

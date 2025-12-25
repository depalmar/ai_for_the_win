#!/usr/bin/env python3
"""
Unit tests for Lab 01: Phishing Email Classifier

Run with: pytest tests/test_classifier.py -v
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Add starter directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "starter"))

# Import functions to test (will fail until implemented)
try:
    from main import (calculate_caps_ratio, count_urls, extract_features,
                      has_urgency, load_data, predict_phishing,
                      preprocess_text, requests_sensitive_info, train_model)

    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_emails():
    """Sample email data for testing."""
    return pd.DataFrame(
        {
            "text": [
                "URGENT: Your account is compromised! Click http://evil.com/verify now!",
                "Hi John, meeting moved to 3pm tomorrow. See you there!",
                "Your PayPal account will be suspended. Update password: http://paypa1.com",
                "Quarterly report attached. Let me know if you have questions.",
            ],
            "label": [1, 0, 1, 0],
        }
    )


@pytest.fixture
def sample_phishing_email():
    """Single phishing email for testing."""
    return "URGENT! Your BANK account requires IMMEDIATE verification! Click http://fake-bank.com/verify to update your password NOW!"


@pytest.fixture
def sample_legitimate_email():
    """Single legitimate email for testing."""
    return "Hi team, the project review meeting has been rescheduled to Friday at 2pm. Please update your calendars."


# =============================================================================
# Test: Data Loading
# =============================================================================


@pytest.mark.skipif(
    not IMPORTS_AVAILABLE,
    reason=f"Imports failed: {IMPORT_ERROR if not IMPORTS_AVAILABLE else ''}",
)
class TestDataLoading:

    def test_load_data_returns_dataframe(self, tmp_path):
        """Test that load_data returns a pandas DataFrame."""
        # Create temp CSV
        csv_path = tmp_path / "test_emails.csv"
        pd.DataFrame(
            {"text": ["test email 1", "test email 2"], "label": [0, 1]}
        ).to_csv(csv_path, index=False)

        result = load_data(str(csv_path))

        assert isinstance(result, pd.DataFrame)
        assert len(result) == 2
        assert "text" in result.columns
        assert "label" in result.columns

    def test_load_data_handles_missing_values(self, tmp_path):
        """Test that missing values are handled."""
        csv_path = tmp_path / "test_emails.csv"
        pd.DataFrame(
            {"text": ["test email", None, "another email"], "label": [0, 1, 0]}
        ).to_csv(csv_path, index=False)

        result = load_data(str(csv_path))

        # Should drop rows with NaN or handle them
        assert result["text"].isna().sum() == 0


# =============================================================================
# Test: Text Preprocessing
# =============================================================================


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports failed")
class TestPreprocessing:

    def test_preprocess_converts_to_lowercase(self):
        """Test that text is converted to lowercase."""
        result = preprocess_text("HELLO WORLD")
        assert result == result.lower()

    def test_preprocess_removes_urls(self):
        """Test that URLs are removed."""
        text = "Visit http://example.com for more info"
        result = preprocess_text(text)
        assert "http" not in result
        assert "example.com" not in result

    def test_preprocess_removes_html(self):
        """Test that HTML tags are removed."""
        text = "<html><p>Hello</p></html>"
        result = preprocess_text(text)
        assert "<" not in result
        assert ">" not in result

    def test_preprocess_handles_empty_string(self):
        """Test handling of empty strings."""
        result = preprocess_text("")
        assert isinstance(result, str)

    def test_preprocess_handles_none(self):
        """Test handling of None input."""
        result = preprocess_text(None)
        assert isinstance(result, str)


# =============================================================================
# Test: Feature Extraction
# =============================================================================


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports failed")
class TestFeatureExtraction:

    def test_count_urls_finds_http(self):
        """Test URL counting with http."""
        text = "Visit http://example.com and http://test.com"
        assert count_urls(text) == 2

    def test_count_urls_finds_https(self):
        """Test URL counting with https."""
        text = "Secure site: https://example.com"
        assert count_urls(text) == 1

    def test_count_urls_no_urls(self):
        """Test URL counting with no URLs."""
        text = "This is plain text without links"
        assert count_urls(text) == 0

    def test_has_urgency_detects_urgent(self):
        """Test urgency detection."""
        text = "URGENT: Act now!"
        assert has_urgency(text) == 1

    def test_has_urgency_no_urgency(self):
        """Test no urgency detected."""
        text = "Regular email content"
        assert has_urgency(text) == 0

    def test_requests_sensitive_detects_password(self):
        """Test sensitive info detection."""
        text = "Please enter your password"
        assert requests_sensitive_info(text) == 1

    def test_caps_ratio_all_caps(self):
        """Test caps ratio with all uppercase."""
        result = calculate_caps_ratio("HELLO")
        assert result == 1.0

    def test_caps_ratio_no_caps(self):
        """Test caps ratio with no uppercase."""
        result = calculate_caps_ratio("hello")
        assert result == 0.0

    def test_caps_ratio_mixed(self):
        """Test caps ratio with mixed case."""
        result = calculate_caps_ratio("Hello")  # 1 cap, 4 lower
        assert 0.1 < result < 0.3

    def test_extract_features_returns_dataframe(self, sample_emails):
        """Test that extract_features returns DataFrame."""
        result = extract_features(sample_emails)
        assert isinstance(result, pd.DataFrame)
        assert len(result) == len(sample_emails)


# =============================================================================
# Test: Model Training
# =============================================================================


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports failed")
class TestModelTraining:

    def test_train_model_returns_model(self):
        """Test that train_model returns a model."""
        X = np.random.rand(100, 10)
        y = np.random.randint(0, 2, 100)

        model = train_model(X, y)

        assert model is not None
        assert hasattr(model, "predict")
        assert hasattr(model, "predict_proba")

    def test_trained_model_can_predict(self):
        """Test that trained model can make predictions."""
        X = np.random.rand(100, 10)
        y = np.random.randint(0, 2, 100)

        model = train_model(X, y)
        predictions = model.predict(X[:5])

        assert len(predictions) == 5
        assert all(p in [0, 1] for p in predictions)


# =============================================================================
# Test: Prediction
# =============================================================================


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports failed")
class TestPrediction:

    def test_predict_phishing_on_obvious_phishing(self, sample_phishing_email):
        """Test prediction on obvious phishing email."""
        # This test requires a trained model
        # Skip if predict_phishing not fully implemented
        pytest.skip("Requires trained model")

    def test_predict_phishing_on_legitimate(self, sample_legitimate_email):
        """Test prediction on legitimate email."""
        pytest.skip("Requires trained model")

    def test_predict_returns_tuple(self):
        """Test that predict returns (prediction, confidence)."""
        pytest.skip("Requires trained model")


# =============================================================================
# Test: End-to-End
# =============================================================================


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports failed")
class TestEndToEnd:

    def test_full_pipeline(self, sample_emails):
        """Test the complete classification pipeline."""
        # Preprocess
        sample_emails["clean_text"] = sample_emails["text"].apply(preprocess_text)

        # Extract features
        features = extract_features(sample_emails)

        # Verify we have features
        assert len(features.columns) >= 5

        # Verify no NaN values
        assert not features.isna().any().any()


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

"""Tests for Lab 07: Hello World ML."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "lab07-hello-world-ml" / "solution"))


def test_solution_runs():
    """Test that solution code runs without errors."""
    from main import LABELS, MESSAGES, extract_features, main

    # Test feature extraction
    features = extract_features("FREE MONEY! Click now!")
    assert len(features) == 3  # 3 features in solution
    assert features[0] > 0  # Should detect spam words

    # Test data is valid
    assert len(MESSAGES) == len(LABELS)
    assert sum(LABELS) > 0  # Has some spam
    assert sum(1 for l in LABELS if l == 0) > 0  # Has some not-spam


def test_feature_extraction_spam():
    """Test feature extraction on spam message."""
    from main import extract_features

    spam_message = "FREE MONEY WIN CLICK NOW!"
    features = extract_features(spam_message)

    # Should have high spam word count
    assert features[0] >= 3  # At least 3 spam words


def test_feature_extraction_benign():
    """Test feature extraction on benign message."""
    from main import extract_features

    benign_message = "Meeting at 3pm tomorrow, see you there."
    features = extract_features(benign_message)

    # Should have low spam word count
    assert features[0] == 0


def test_model_training():
    """Test that model trains and predicts."""
    import numpy as np
    from main import LABELS, MESSAGES, extract_features
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split

    # Extract features
    X = np.array([extract_features(msg) for msg in MESSAGES])
    y = np.array(LABELS)

    # Split and train
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)

    # Predict
    predictions = model.predict(X_test)

    # Should have reasonable accuracy
    accuracy = (predictions == y_test).mean()
    assert accuracy > 0.6  # At least 60% accuracy

"""Tests for Lab 13: ML vs LLM Decision Lab."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "lab13-ml-vs-llm" / "solution"))


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        LOGS,
        classify_with_llm,
        compare_approaches,
        create_llm_prompt,
        evaluate_ml_classifier,
        extract_ml_features,
        train_ml_classifier,
    )


def test_feature_extraction_malicious():
    """Test feature extraction on malicious log."""
    from main import extract_ml_features

    malicious_log = "Failed login attempt for user admin from IP 185.143.223.47"
    features = extract_ml_features(malicious_log)

    # Should detect failed, admin, external IP
    assert features[0] == 1  # has_failed
    assert features[1] == 1  # has_privileged
    assert features[4] == 1  # has_external_ip


def test_feature_extraction_benign():
    """Test feature extraction on benign log."""
    from main import extract_ml_features

    benign_log = "User logged in successfully from 192.168.1.50"
    features = extract_ml_features(benign_log)

    # Should not trigger suspicious indicators
    assert features[0] == 0  # has_failed
    assert features[4] == 0  # Internal IP


def test_ml_classifier_training():
    """Test ML classifier trains successfully."""
    from main import LOGS, train_ml_classifier

    model, X_test, y_test, test_indices = train_ml_classifier(LOGS)

    assert model is not None
    assert len(X_test) > 0
    assert len(y_test) > 0
    assert len(test_indices) > 0
    assert len(test_indices) == len(X_test)  # Same number of indices as test samples


def test_llm_prompt_creation():
    """Test LLM prompt is properly formatted."""
    from main import create_llm_prompt

    log = "Failed login for admin"
    prompt = create_llm_prompt(log)

    assert "security" in prompt.lower()
    assert log in prompt
    assert "MALICIOUS" in prompt or "BENIGN" in prompt


def test_simulated_llm_classification():
    """Test simulated LLM classification."""
    from main import classify_with_llm

    # Malicious log
    result, _ = classify_with_llm("Failed login admin powershell", simulate=True)
    assert result in ["MALICIOUS", "BENIGN"]

    # Benign log
    result, _ = classify_with_llm("Backup completed successfully", simulate=True)
    assert result in ["MALICIOUS", "BENIGN"]


def test_comparison_returns_both_results():
    """Test that comparison includes both ML and LLM results."""
    from main import LOGS, compare_approaches

    results = compare_approaches(LOGS)

    assert "ml" in results
    assert "llm" in results
    assert "accuracy" in results["ml"]
    assert "time" in results["ml"]
    assert "cost" in results["ml"]

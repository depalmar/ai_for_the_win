#!/usr/bin/env python3
"""Tests for Lab 00b: ML Concepts Primer."""

import numpy as np
import pytest

# =============================================================================
# ML Concept Tests
# =============================================================================


class TestSupervisionTypes:
    """Test understanding of supervised vs unsupervised learning."""

    def test_supervised_learning_characteristics(self):
        """Test supervised learning has labeled data."""
        # Supervised learning requires input-output pairs
        X_train = np.array([[1, 2], [3, 4], [5, 6]])  # Features
        y_train = np.array([0, 1, 1])  # Labels (required for supervised)

        assert X_train.shape[0] == y_train.shape[0]  # Same number of samples

    def test_unsupervised_learning_characteristics(self):
        """Test unsupervised learning works without labels."""
        # Unsupervised learning only needs features
        X_train = np.array([[1, 2], [3, 4], [5, 6]])

        # No labels needed - clustering finds patterns
        assert X_train.ndim == 2
        assert X_train.shape[1] > 0  # Has features

    def test_classification_vs_regression(self):
        """Test difference between classification and regression."""
        # Classification - discrete labels
        classification_labels = np.array([0, 1, 0, 1, 1])
        assert len(np.unique(classification_labels)) <= len(classification_labels)

        # Regression - continuous values
        regression_targets = np.array([0.5, 1.2, 2.3, 3.1, 4.8])
        assert regression_targets.dtype in [np.float64, np.float32, float]


class TestDataSplitting:
    """Test train/test split concepts."""

    def test_train_test_split_ratios(self):
        """Test common split ratios."""
        # Common splits: 80/20, 70/30
        total_samples = 100
        train_ratio = 0.8

        train_size = int(total_samples * train_ratio)
        test_size = total_samples - train_size

        assert train_size == 80
        assert test_size == 20
        assert train_size + test_size == total_samples

    def test_no_data_leakage(self):
        """Test that train and test sets don't overlap."""
        np.random.seed(42)
        indices = np.arange(100)
        np.random.shuffle(indices)

        train_indices = indices[:80]
        test_indices = indices[80:]

        # No overlap between train and test
        assert len(set(train_indices) & set(test_indices)) == 0


class TestFeatureScaling:
    """Test feature scaling concepts."""

    def test_standardization(self):
        """Test z-score standardization."""
        data = np.array([10, 20, 30, 40, 50])

        mean = np.mean(data)
        std = np.std(data)
        standardized = (data - mean) / std

        # After standardization: mean ~0, std ~1
        np.testing.assert_almost_equal(np.mean(standardized), 0, decimal=5)
        np.testing.assert_almost_equal(np.std(standardized), 1, decimal=5)

    def test_min_max_normalization(self):
        """Test min-max normalization to [0, 1]."""
        data = np.array([10, 20, 30, 40, 50])

        min_val = np.min(data)
        max_val = np.max(data)
        normalized = (data - min_val) / (max_val - min_val)

        # After normalization: range [0, 1]
        assert np.min(normalized) == 0
        assert np.max(normalized) == 1


class TestMetrics:
    """Test ML evaluation metrics."""

    def test_accuracy_calculation(self):
        """Test accuracy metric."""
        y_true = np.array([0, 1, 1, 0, 1])
        y_pred = np.array([0, 1, 0, 0, 1])  # One wrong

        correct = np.sum(y_true == y_pred)
        accuracy = correct / len(y_true)

        assert accuracy == 0.8  # 4/5 correct

    def test_precision_recall_concept(self):
        """Test precision and recall concepts."""
        # True positives, false positives, false negatives
        tp, fp, fn = 8, 2, 3

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0

        assert precision == 0.8  # 8 / (8+2)
        assert recall < 1.0  # Some false negatives

    def test_confusion_matrix_components(self):
        """Test confusion matrix understanding."""
        y_true = np.array([0, 0, 1, 1, 1])
        y_pred = np.array([0, 1, 1, 1, 0])

        # Calculate components
        tp = np.sum((y_true == 1) & (y_pred == 1))  # True positive
        tn = np.sum((y_true == 0) & (y_pred == 0))  # True negative
        fp = np.sum((y_true == 0) & (y_pred == 1))  # False positive
        fn = np.sum((y_true == 1) & (y_pred == 0))  # False negative

        assert tp + tn + fp + fn == len(y_true)


class TestOverfittingUnderfitting:
    """Test overfitting and underfitting concepts."""

    def test_overfitting_indicators(self):
        """Test overfitting detection."""
        # Overfitting: high train accuracy, low test accuracy
        train_accuracy = 0.99
        test_accuracy = 0.65

        gap = train_accuracy - test_accuracy
        assert gap > 0.2  # Large gap indicates overfitting

    def test_underfitting_indicators(self):
        """Test underfitting detection."""
        # Underfitting: low accuracy on both
        train_accuracy = 0.55
        test_accuracy = 0.52

        # Both are low
        assert train_accuracy < 0.7
        assert test_accuracy < 0.7

    def test_good_generalization(self):
        """Test good model generalization."""
        # Good fit: similar train and test accuracy
        train_accuracy = 0.92
        test_accuracy = 0.89

        gap = abs(train_accuracy - test_accuracy)
        assert gap < 0.1  # Small gap = good generalization


class TestSecurityMLConcepts:
    """Test ML concepts specific to security."""

    def test_imbalanced_data_awareness(self):
        """Test understanding of class imbalance in security."""
        # Security data is often highly imbalanced
        # 1% malicious, 99% benign
        benign_samples = 990
        malicious_samples = 10

        imbalance_ratio = benign_samples / malicious_samples
        assert imbalance_ratio == 99  # 99:1 ratio

    def test_false_positive_impact(self):
        """Test understanding of false positive impact."""
        # In security, false positives cause alert fatigue
        # Calculate false positive rate
        fp = 100  # False alarms
        tn = 9900  # True negatives

        fpr = fp / (fp + tn)
        assert fpr == 0.01  # 1% FPR

    def test_false_negative_impact(self):
        """Test understanding of false negative impact."""
        # In security, false negatives mean missed attacks
        fn = 5  # Missed attacks
        tp = 95  # Detected attacks

        fnr = fn / (fn + tp)
        assert fnr == 0.05  # 5% miss rate


class TestFeatureEngineering:
    """Test feature engineering concepts."""

    def test_feature_types(self):
        """Test different feature types."""
        # Numerical features
        numerical = np.array([1.5, 2.3, 3.7])

        # Categorical features (encoded)
        categorical = np.array([0, 1, 2])  # One-hot encoded later

        # Binary features
        binary = np.array([0, 1, 1, 0])

        assert numerical.dtype in [np.float64, np.float32]
        assert np.all((binary == 0) | (binary == 1))

    def test_one_hot_encoding(self):
        """Test one-hot encoding concept."""
        categories = ["TCP", "UDP", "ICMP"]
        category = "UDP"

        # One-hot encode
        encoded = [1 if c == category else 0 for c in categories]

        assert sum(encoded) == 1  # Only one 1
        assert encoded[1] == 1  # UDP is index 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

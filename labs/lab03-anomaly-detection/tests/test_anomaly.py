#!/usr/bin/env python3
"""Tests for Lab 03: Network Anomaly Detection."""

import numpy as np
import pandas as pd
import pytest

# Try to import from solution
try:
    from labs.lab03_anomaly_detection.solution.main import (
        engineer_network_features,
        evaluate_detector,
        find_optimal_threshold,
        iqr_baseline,
        prepare_features,
        statistical_baseline,
        train_isolation_forest,
        train_local_outlier_factor,
    )
except ImportError:
    try:
        from solution.main import (
            engineer_network_features,
            evaluate_detector,
            find_optimal_threshold,
            iqr_baseline,
            prepare_features,
            statistical_baseline,
            train_isolation_forest,
            train_local_outlier_factor,
        )
    except ImportError:
        pytest.skip("Solution module not available", allow_module_level=True)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_network_df():
    """Create sample network flow data."""
    np.random.seed(42)
    n_samples = 100

    data = {
        "timestamp": pd.date_range("2025-01-01", periods=n_samples, freq="5s"),
        "src_ip": [f"192.168.1.{np.random.randint(1, 255)}" for _ in range(n_samples)],
        "dst_ip": [f"10.0.0.{np.random.randint(1, 255)}" for _ in range(n_samples)],
        "src_port": np.random.randint(1024, 65535, n_samples),
        "dst_port": np.random.choice([80, 443, 22, 53], n_samples),
        "protocol": np.random.choice(["TCP", "UDP"], n_samples),
        "bytes_sent": np.random.lognormal(8, 1, n_samples),
        "bytes_recv": np.random.lognormal(9, 1, n_samples),
        "packets_sent": np.random.randint(5, 50, n_samples),
        "packets_recv": np.random.randint(10, 100, n_samples),
        "duration": np.random.exponential(5, n_samples),
        "label": ["normal"] * n_samples,
    }

    # Add some attacks
    for i in range(90, 100):
        data["bytes_sent"][i] = 1e9  # Data exfiltration
        data["label"][i] = "attack"

    return pd.DataFrame(data)


@pytest.fixture
def sample_features(sample_network_df):
    """Prepare features from sample data."""
    df = engineer_network_features(sample_network_df)
    X, feature_names = prepare_features(df)
    return X, feature_names, df


# =============================================================================
# Feature Engineering Tests
# =============================================================================


class TestFeatureEngineering:
    """Test feature engineering functions."""

    def test_engineer_network_features(self, sample_network_df):
        """Test network feature engineering."""
        df = engineer_network_features(sample_network_df)

        # Check new features exist
        assert "total_bytes" in df.columns
        assert "bytes_per_second" in df.columns
        assert "bytes_ratio" in df.columns
        assert "is_well_known_port" in df.columns
        assert "log_bytes" in df.columns

    def test_feature_values(self, sample_network_df):
        """Test feature value calculations."""
        df = engineer_network_features(sample_network_df)

        # Total bytes should be sum of sent and received
        expected_total = sample_network_df["bytes_sent"] + sample_network_df["bytes_recv"]
        np.testing.assert_array_almost_equal(df["total_bytes"], expected_total)

        # Bytes ratio should be between 0 and 1
        assert df["bytes_ratio"].min() >= 0
        assert df["bytes_ratio"].max() <= 1

    def test_prepare_features(self, sample_network_df):
        """Test feature preparation."""
        df = engineer_network_features(sample_network_df)
        X, feature_names = prepare_features(df)

        assert X.shape[0] == len(sample_network_df)
        assert X.shape[1] == len(feature_names)
        # Should be scaled (mean ~ 0 for RobustScaler)
        assert not np.isnan(X).any()


# =============================================================================
# Baseline Tests
# =============================================================================


class TestBaselines:
    """Test baseline detection methods."""

    def test_statistical_baseline(self, sample_network_df):
        """Test z-score baseline."""
        df = engineer_network_features(sample_network_df)
        anomalies = statistical_baseline(df, "bytes_per_second", n_std=3)

        assert isinstance(anomalies, pd.Series)
        assert anomalies.dtype == bool
        # Should detect some anomalies in attack samples
        assert anomalies.sum() > 0

    def test_iqr_baseline(self, sample_network_df):
        """Test IQR baseline."""
        df = engineer_network_features(sample_network_df)
        anomalies = iqr_baseline(df, "bytes_per_second", k=1.5)

        assert isinstance(anomalies, pd.Series)
        assert anomalies.dtype == bool


# =============================================================================
# Model Training Tests
# =============================================================================


class TestModels:
    """Test anomaly detection models."""

    def test_isolation_forest(self, sample_features):
        """Test Isolation Forest training."""
        X, _, _ = sample_features
        model, scores = train_isolation_forest(X, contamination=0.1)

        assert model is not None
        assert len(scores) == len(X)
        # Scores should vary
        assert scores.std() > 0

    def test_local_outlier_factor(self, sample_features):
        """Test LOF detection."""
        X, _, _ = sample_features
        predictions = train_local_outlier_factor(X, contamination=0.1)

        assert len(predictions) == len(X)
        # Should have some normal (1) and some outliers (-1)
        assert -1 in predictions
        assert 1 in predictions


# =============================================================================
# Evaluation Tests
# =============================================================================


class TestEvaluation:
    """Test evaluation functions."""

    def test_evaluate_detector(self):
        """Test detector evaluation."""
        y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])

        metrics = evaluate_detector(y_true, scores)

        assert "auc" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert 0 <= metrics["auc"] <= 1

    def test_find_optimal_threshold(self):
        """Test threshold optimization."""
        y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])

        threshold = find_optimal_threshold(y_true, scores)

        assert isinstance(threshold, float)
        assert 0 < threshold < 1


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full pipeline."""

    def test_full_pipeline(self, sample_network_df):
        """Test complete detection pipeline."""
        # Feature engineering
        df = engineer_network_features(sample_network_df)
        X, _ = prepare_features(df)

        # Train model
        model, scores = train_isolation_forest(X, contamination=0.1)

        # Make predictions
        predictions = model.predict(X)
        n_anomalies = (predictions == -1).sum()

        # Should detect anomalies
        assert n_anomalies > 0
        assert n_anomalies < len(X)  # Not everything

    def test_detection_of_attacks(self, sample_network_df):
        """Test that attacks are detected."""
        df = engineer_network_features(sample_network_df)
        X, _ = prepare_features(df)

        model, scores = train_isolation_forest(X, contamination=0.1)
        predictions = model.predict(X)

        # Get indices of attack samples
        attack_indices = (sample_network_df["label"] == "attack").values

        # Most attacks should be detected as anomalies (-1)
        attack_predictions = predictions[attack_indices]
        detection_rate = (attack_predictions == -1).sum() / len(attack_predictions)

        # Should detect most attacks
        assert detection_rate > 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

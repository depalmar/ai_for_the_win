#!/usr/bin/env python3
"""Tests for Lab 03: Network Anomaly Detection."""

import sys
from datetime import datetime
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
lab_path = str(
    Path(__file__).parent.parent / "labs" / "lab03-anomaly-detection" / "solution"
)
sys.path.insert(0, lab_path)

from main import (engineer_network_features, evaluate_detector,
                  explore_network_data, find_optimal_threshold, iqr_baseline,
                  load_network_data, prepare_features, statistical_baseline,
                  train_isolation_forest, train_local_outlier_factor)


@pytest.fixture
def sample_network_data():
    """Create sample network flow data."""
    np.random.seed(42)
    n_samples = 100

    data = {
        "timestamp": pd.date_range("2024-01-15", periods=n_samples, freq="5s"),
        "src_ip": [f"192.168.1.{np.random.randint(1, 255)}" for _ in range(n_samples)],
        "dst_ip": [
            f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            for _ in range(n_samples)
        ],
        "src_port": np.random.randint(1024, 65535, n_samples),
        "dst_port": np.random.choice([80, 443, 53, 22], n_samples),
        "protocol": np.random.choice(["TCP", "UDP"], n_samples, p=[0.8, 0.2]),
        "bytes_sent": np.random.lognormal(8, 1, n_samples),
        "bytes_recv": np.random.lognormal(9, 1, n_samples),
        "packets_sent": np.random.randint(5, 50, n_samples),
        "packets_recv": np.random.randint(10, 100, n_samples),
        "duration": np.random.exponential(5, n_samples),
        "label": ["normal"] * (n_samples - 10) + ["attack"] * 10,
    }

    return pd.DataFrame(data)


@pytest.fixture
def sample_csv_file(tmp_path, sample_network_data):
    """Create a temporary CSV file with sample data."""
    filepath = tmp_path / "test_flows.csv"
    sample_network_data.to_csv(filepath, index=False)
    return str(filepath)


class TestDataLoading:
    """Tests for data loading functions."""

    def test_load_network_data(self, sample_csv_file):
        """Test loading network data from CSV."""
        df = load_network_data(sample_csv_file)

        assert df is not None
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 100
        assert "timestamp" in df.columns

    def test_explore_network_data(self, sample_network_data, capsys):
        """Test data exploration output."""
        explore_network_data(sample_network_data)

        captured = capsys.readouterr()
        assert "protocol" in captured.out.lower() or len(captured.out) > 0


class TestFeatureEngineering:
    """Tests for feature engineering."""

    def test_engineer_network_features(self, sample_network_data):
        """Test feature engineering."""
        df = engineer_network_features(sample_network_data)

        assert df is not None
        assert "bytes_per_second" in df.columns
        assert "packets_per_second" in df.columns
        assert "bytes_ratio" in df.columns
        assert "is_well_known_port" in df.columns
        assert "hour_of_day" in df.columns

    def test_bytes_per_second_calculation(self, sample_network_data):
        """Test bytes per second calculation."""
        df = engineer_network_features(sample_network_data)

        # Check that bytes_per_second is correctly calculated
        for i in range(min(5, len(df))):
            if df.iloc[i]["duration"] > 0:
                expected = (
                    df.iloc[i]["bytes_sent"] + df.iloc[i]["bytes_recv"]
                ) / df.iloc[i]["duration"]
                assert df.iloc[i]["bytes_per_second"] == pytest.approx(
                    expected, rel=0.01
                )

    def test_prepare_features(self, sample_network_data):
        """Test feature preparation."""
        df = engineer_network_features(sample_network_data)
        X, feature_names = prepare_features(df)

        assert X is not None
        assert isinstance(X, np.ndarray)
        assert len(X) == len(df)
        assert len(feature_names) > 0


class TestBaselineDetection:
    """Tests for baseline anomaly detection."""

    def test_statistical_baseline(self, sample_network_data):
        """Test statistical baseline detection."""
        df = engineer_network_features(sample_network_data)
        anomalies = statistical_baseline(df, "bytes_per_second", n_std=3.0)

        assert anomalies is not None
        assert isinstance(anomalies, pd.Series)
        assert len(anomalies) == len(df)
        assert anomalies.dtype == bool

    def test_iqr_baseline(self, sample_network_data):
        """Test IQR-based baseline detection."""
        df = engineer_network_features(sample_network_data)
        anomalies = iqr_baseline(df, "bytes_per_second", k=1.5)

        assert anomalies is not None
        assert isinstance(anomalies, pd.Series)
        assert len(anomalies) == len(df)


class TestMLModels:
    """Tests for ML-based detection."""

    @pytest.fixture
    def prepared_features(self, sample_network_data):
        """Prepare features for ML models."""
        df = engineer_network_features(sample_network_data)
        X, _ = prepare_features(df)
        return X

    def test_isolation_forest(self, prepared_features):
        """Test Isolation Forest training."""
        model, scores = train_isolation_forest(prepared_features, contamination=0.1)

        assert model is not None
        assert scores is not None
        assert len(scores) == len(prepared_features)

    def test_local_outlier_factor(self, prepared_features):
        """Test Local Outlier Factor."""
        predictions = train_local_outlier_factor(prepared_features, contamination=0.1)

        assert predictions is not None
        assert len(predictions) == len(prepared_features)
        # LOF returns -1 for outliers, 1 for inliers
        assert set(predictions).issubset({-1, 1})


class TestEvaluation:
    """Tests for model evaluation."""

    def test_evaluate_detector(self):
        """Test detector evaluation."""
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        scores = np.array([0.1, 0.2, 0.15, 0.3, 0.25, 0.8, 0.9, 0.85, 0.7, 0.95])

        metrics = evaluate_detector(y_true, scores)

        assert metrics is not None
        assert "auc" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert metrics["auc"] > 0.5  # Better than random

    def test_find_optimal_threshold(self):
        """Test optimal threshold finding."""
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        scores = np.array([0.1, 0.2, 0.15, 0.3, 0.25, 0.8, 0.9, 0.85, 0.7, 0.95])

        threshold = find_optimal_threshold(y_true, scores)

        assert threshold is not None
        assert 0 <= threshold <= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

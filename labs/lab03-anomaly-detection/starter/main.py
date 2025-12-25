#!/usr/bin/env python3
"""
Lab 03: Network Anomaly Detection - Starter Code

Build an anomaly detection system to identify malicious network activity.

Instructions:
1. Complete each TODO section
2. Test with sample data in data/ folder
3. Compare your results with the solution
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.svm import OneClassSVM

# =============================================================================
# Task 1: Load Network Data
# =============================================================================


def load_network_data(filepath: str) -> pd.DataFrame:
    """
    Load network flow data.

    Expected columns:
    - timestamp: Flow start time
    - src_ip, dst_ip: IP addresses
    - src_port, dst_port: Ports
    - protocol: TCP/UDP/ICMP
    - bytes_sent, bytes_recv: Data volume
    - packets_sent, packets_recv: Packet counts
    - duration: Flow duration in seconds
    - label: (optional) normal/attack

    TODO:
    1. Load data from CSV
    2. Parse timestamps
    3. Handle missing values
    4. Print data summary
    """
    # YOUR CODE HERE
    pass


def explore_network_data(df: pd.DataFrame) -> None:
    """
    Print exploratory statistics.

    TODO:
    1. Print shape and columns
    2. Show protocol distribution
    3. Show label distribution if available
    4. Print numeric statistics
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 2: Feature Engineering
# =============================================================================


def engineer_network_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create anomaly detection features.

    TODO: Create these features:
    1. bytes_per_second: Total bytes / duration
    2. packets_per_second: Total packets / duration
    3. bytes_ratio: bytes_sent / (bytes_sent + bytes_recv)
    4. is_well_known_port: dst_port < 1024
    5. hour_of_day: Hour extracted from timestamp
    6. bytes_per_packet: Total bytes / total packets
    7. is_internal: Both IPs in internal range (simulated)
    """
    # YOUR CODE HERE
    pass


def prepare_features(
    df: pd.DataFrame, feature_cols: List[str] = None
) -> Tuple[np.ndarray, List[str]]:
    """
    Prepare feature matrix for ML models.

    TODO:
    1. Select numeric features
    2. Handle any remaining NaN values
    3. Scale features using RobustScaler
    4. Return scaled features and column names
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 3: Build Baseline Model
# =============================================================================


def statistical_baseline(
    df: pd.DataFrame, feature: str, n_std: float = 3.0
) -> pd.Series:
    """
    Simple statistical anomaly detection.

    Args:
        df: Network data
        feature: Column to analyze
        n_std: Number of standard deviations for threshold

    Returns:
        Boolean series (True = anomaly)

    TODO:
    1. Calculate mean and std of the feature
    2. Flag values > n_std standard deviations from mean
    3. Return anomaly flags
    """
    # YOUR CODE HERE
    pass


def iqr_baseline(df: pd.DataFrame, feature: str, k: float = 1.5) -> pd.Series:
    """
    IQR-based anomaly detection.

    TODO:
    1. Calculate Q1, Q3, and IQR
    2. Define lower and upper bounds
    3. Return anomaly flags
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 4: Train Isolation Forest
# =============================================================================


def train_isolation_forest(
    X: np.ndarray, contamination: float = 0.01
) -> Tuple[IsolationForest, np.ndarray]:
    """
    Train Isolation Forest for anomaly detection.

    Args:
        X: Feature matrix
        contamination: Expected proportion of anomalies

    Returns:
        Trained model and anomaly scores

    TODO:
    1. Initialize IsolationForest with parameters
    2. Fit to data
    3. Get anomaly scores (decision_function)
    4. Return model and scores
    """
    # YOUR CODE HERE
    pass


def train_local_outlier_factor(
    X: np.ndarray, contamination: float = 0.01
) -> np.ndarray:
    """
    Train Local Outlier Factor.

    TODO:
    1. Initialize LOF
    2. Fit and predict
    3. Return predictions (-1 for outliers, 1 for inliers)
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 5: Train Autoencoder (Optional - requires PyTorch)
# =============================================================================


def train_autoencoder(
    X: np.ndarray, encoding_dim: int = 8
) -> Tuple[object, np.ndarray]:
    """
    Train autoencoder for anomaly detection.

    Args:
        X: Feature matrix (normalized)
        encoding_dim: Bottleneck size

    Returns:
        Trained model, reconstruction errors

    TODO:
    1. Build encoder: input → encoding_dim
    2. Build decoder: encoding_dim → input
    3. Compile with MSE loss
    4. Train on data
    5. Calculate reconstruction errors
    """
    # YOUR CODE HERE - Optional, requires PyTorch
    pass


# =============================================================================
# Task 6: Evaluate and Tune
# =============================================================================


def evaluate_detector(
    y_true: np.ndarray, scores: np.ndarray, threshold: float = None
) -> dict:
    """
    Evaluate anomaly detector performance.

    Args:
        y_true: True labels (1 = anomaly)
        scores: Anomaly scores (higher = more anomalous)
        threshold: Decision threshold (finds optimal if None)

    Returns:
        Metrics dict: precision, recall, F1, AUC, threshold

    TODO:
    1. Calculate ROC AUC
    2. Find optimal threshold if not provided
    3. Calculate precision, recall, F1
    4. Return metrics dictionary
    """
    # YOUR CODE HERE
    pass


def find_optimal_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """
    Find threshold that maximizes F1 score.

    TODO:
    1. Calculate precision-recall curve
    2. Calculate F1 for each threshold
    3. Return threshold with best F1
    """
    # YOUR CODE HERE
    pass


def plot_roc_curve(
    y_true: np.ndarray, scores: np.ndarray, title: str = "ROC Curve"
) -> None:
    """
    Plot ROC curve.

    TODO: Create ROC curve visualization
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    print("=" * 60)
    print("Lab 03: Network Anomaly Detection")
    print("=" * 60)

    # Load data
    data_path = Path(__file__).parent.parent / "data" / "network_flows.csv"

    if not data_path.exists():
        print("Creating sample data...")
        create_sample_data(data_path)

    print("\n[Step 1] Loading network data...")
    df = load_network_data(str(data_path))

    if df is None:
        print("Error: load_network_data() returned None. Complete the TODO!")
        return

    explore_network_data(df)

    # Feature engineering
    print("\n[Step 2] Engineering features...")
    df = engineer_network_features(df)

    if df is None or "bytes_per_second" not in df.columns:
        print("Error: engineer_network_features() not complete. Check TODO!")
        return

    # Prepare features
    print("\n[Step 3] Preparing features...")
    result = prepare_features(df)

    if result is None:
        print("Error: prepare_features() returned None. Complete the TODO!")
        return

    X, feature_names = result
    print(f"Feature matrix: {X.shape}")

    # Statistical baseline
    print("\n[Step 4] Running statistical baseline...")
    baseline_anomalies = statistical_baseline(df, "bytes_per_second")

    if baseline_anomalies is not None:
        print(f"Baseline detected {baseline_anomalies.sum()} anomalies")

    # Isolation Forest
    print("\n[Step 5] Training Isolation Forest...")
    result = train_isolation_forest(X)

    if result is None:
        print("Error: train_isolation_forest() returned None. Complete the TODO!")
        return

    model, scores = result

    # Evaluation
    print("\n[Step 6] Evaluating model...")
    if "label" in df.columns:
        y_true = (df["label"] == "attack").astype(int).values
        metrics = evaluate_detector(y_true, -scores)  # Negate for sklearn convention

        if metrics:
            print(f"  AUC: {metrics.get('auc', 'N/A'):.3f}")
            print(f"  Precision: {metrics.get('precision', 'N/A'):.3f}")
            print(f"  Recall: {metrics.get('recall', 'N/A'):.3f}")
            print(f"  F1: {metrics.get('f1', 'N/A'):.3f}")
    else:
        print("No labels available for evaluation")
        # Just show number of detected anomalies
        predictions = model.predict(X)
        n_anomalies = (predictions == -1).sum()
        print(f"Detected {n_anomalies} anomalies ({n_anomalies/len(X)*100:.1f}%)")

    print("\n" + "=" * 60)
    print("Anomaly detection complete!")


def create_sample_data(filepath: Path):
    """Create sample network flow data."""
    np.random.seed(42)
    n_samples = 2000
    n_attacks = 100

    data = []
    base_time = datetime(2024, 1, 15, 0, 0, 0)

    # Normal traffic
    for i in range(n_samples - n_attacks):
        data.append(
            {
                "timestamp": base_time + pd.Timedelta(seconds=i * 5),
                "src_ip": f"192.168.1.{np.random.randint(1, 255)}",
                "dst_ip": f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "src_port": np.random.randint(1024, 65535),
                "dst_port": np.random.choice([80, 443, 53, 22, 25]),
                "protocol": np.random.choice(["TCP", "UDP"], p=[0.8, 0.2]),
                "bytes_sent": np.random.lognormal(8, 1),
                "bytes_recv": np.random.lognormal(9, 1),
                "packets_sent": np.random.randint(5, 50),
                "packets_recv": np.random.randint(10, 100),
                "duration": np.random.exponential(5),
                "label": "normal",
            }
        )

    # Attack traffic
    for i in range(n_attacks):
        attack_type = np.random.choice(["c2", "exfil", "scan"])

        if attack_type == "c2":  # C2 beaconing
            data.append(
                {
                    "timestamp": base_time
                    + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
                    "src_ip": "192.168.1.100",
                    "dst_ip": "185.143.223.47",
                    "src_port": np.random.randint(40000, 50000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": 256,
                    "bytes_recv": 128,
                    "packets_sent": 2,
                    "packets_recv": 2,
                    "duration": 0.5,
                    "label": "attack",
                }
            )
        elif attack_type == "exfil":  # Data exfiltration
            data.append(
                {
                    "timestamp": base_time
                    + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
                    "src_ip": "192.168.1.50",
                    "dst_ip": "91.234.99.100",
                    "src_port": np.random.randint(40000, 50000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": np.random.lognormal(15, 0.5),  # Very large
                    "bytes_recv": 1000,
                    "packets_sent": np.random.randint(1000, 5000),
                    "packets_recv": 50,
                    "duration": np.random.uniform(60, 300),
                    "label": "attack",
                }
            )
        else:  # Port scan
            data.append(
                {
                    "timestamp": base_time
                    + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
                    "src_ip": "185.143.223.47",
                    "dst_ip": "192.168.1.1",
                    "src_port": np.random.randint(40000, 50000),
                    "dst_port": np.random.randint(1, 1024),
                    "protocol": "TCP",
                    "bytes_sent": 60,
                    "bytes_recv": 0,
                    "packets_sent": 1,
                    "packets_recv": 0,
                    "duration": 0.01,
                    "label": "attack",
                }
            )

    df = pd.DataFrame(data)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(filepath, index=False)
    print(f"Created sample data with {len(df)} flows ({n_attacks} attacks)")


if __name__ == "__main__":
    main()

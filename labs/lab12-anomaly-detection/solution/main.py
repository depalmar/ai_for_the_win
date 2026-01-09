#!/usr/bin/env python3
"""
Lab 03: Network Anomaly Detection - Solution

This lab implements unsupervised anomaly detection for network traffic.

Key concepts:
- Anomaly detection finds "unusual" patterns without labeled examples
- Unlike classification, we don't need examples of all attack types
- This is powerful because we can detect NOVEL attacks

Why unsupervised for security?
- We rarely have complete labeled datasets of attacks
- New attack techniques appear constantly (zero-days)
- Anomaly detection can catch what we've never seen before

The trade-off:
- Supervised models (Lab 01) are more accurate for KNOWN attack types
- Unsupervised models catch unknown attacks but have more false positives
- Production systems often combine both approaches
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.svm import OneClassSVM

# =============================================================================
# Task 1: Load Network Data - SOLUTION
# =============================================================================


def load_network_data(filepath: str) -> pd.DataFrame:
    """Load network flow data."""
    df = pd.read_csv(filepath)

    # Parse timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Handle missing values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # Handle zero duration
    df["duration"] = df["duration"].replace(0, 0.001)

    print(f"Loaded {len(df)} network flows")
    return df


def explore_network_data(df: pd.DataFrame) -> None:
    """Print exploratory statistics."""
    print(f"\nDataset shape: {df.shape}")
    print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")

    print("\nProtocol distribution:")
    print(df["protocol"].value_counts())

    if "label" in df.columns:
        print("\nLabel distribution:")
        print(df["label"].value_counts())

    print("\nNumeric statistics:")
    numeric_cols = ["bytes_sent", "bytes_recv", "packets_sent", "duration"]
    print(df[numeric_cols].describe())


# =============================================================================
# Task 2: Feature Engineering - SOLUTION
# =============================================================================
# Feature engineering for anomaly detection focuses on creating features
# that distinguish "normal" behavior patterns from anomalies.
#
# Network anomalies often appear as:
# - Unusual traffic volumes (DDoS, data exfiltration)
# - Abnormal ratios (beaconing with tiny requests/responses)
# - Suspicious timing (C2 communication at regular intervals)
# - Port scanning (connections to many ports quickly)


def engineer_network_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create anomaly detection features from raw network flow data.

    Feature types:
    1. Volume features: total bytes, packets (detect bulk transfers)
    2. Rate features: bytes/sec, packets/sec (detect floods or throttling)
    3. Ratio features: sent/received ratio (detect asymmetric patterns)
    4. Port features: well-known vs high ports (detect port scanning)
    5. Time features: business hours, hour of day (detect off-hours activity)

    Each feature is designed to capture a different attack pattern.
    """
    df = df.copy()

    # Ensure duration is not zero to avoid division errors
    df["duration"] = df["duration"].clip(lower=0.001)

    # =========================================
    # VOLUME FEATURES - Detect bulk transfers
    # =========================================
    # Data exfiltration: large bytes_sent to external IPs
    # DDoS: massive incoming traffic
    df["total_bytes"] = df["bytes_sent"] + df["bytes_recv"]
    df["total_packets"] = df["packets_sent"] + df["packets_recv"]

    # =========================================
    # RATE FEATURES - Detect floods or throttling
    # =========================================
    # Port scans: high packets_per_second but low bytes_per_second
    # DDoS: extremely high rates
    # C2 beaconing: regular, low rates
    df["bytes_per_second"] = df["total_bytes"] / df["duration"]
    df["packets_per_second"] = df["total_packets"] / df["duration"]

    # =========================================
    # RATIO FEATURES - Detect asymmetric patterns
    # =========================================
    # Normal web: small requests, large responses (low bytes_ratio)
    # Exfiltration: large uploads (high bytes_ratio)
    # C2: symmetric small exchanges (ratio ~0.5)
    df["bytes_ratio"] = df["bytes_sent"] / (df["total_bytes"] + 1)
    df["packets_ratio"] = df["packets_sent"] / (df["total_packets"] + 1)

    # Bytes per packet - detect protocol anomalies
    # Small: TCP SYN scans (~60 bytes)
    # Large: file transfers (1500 bytes MTU)
    df["bytes_per_packet"] = df["total_bytes"] / (df["total_packets"] + 1)

    # =========================================
    # PORT FEATURES - Detect service access patterns
    # =========================================
    # Well-known ports (0-1023): standard services
    # High ports (49152+): often used by malware to blend in
    df["is_well_known_port"] = (df["dst_port"] < 1024).astype(int)
    df["is_high_port"] = (df["dst_port"] > 49152).astype(int)

    # =========================================
    # TIME FEATURES - Detect off-hours activity
    # =========================================
    # Attackers often operate when defenders aren't watching
    # Activity at 3am on Sunday is suspicious
    if "timestamp" in df.columns:
        df["hour_of_day"] = df["timestamp"].dt.hour
        df["is_business_hours"] = ((df["hour_of_day"] >= 9) & (df["hour_of_day"] <= 17)).astype(int)

    # Internal IP check (simplified for demo)
    # External-to-external traffic from internal machine is suspicious
    df["is_internal_src"] = df["src_ip"].str.startswith("192.168.").astype(int)
    df["is_internal_dst"] = df["dst_ip"].str.startswith("192.168.").astype(int)

    # Log transforms for highly skewed features
    # Network data often follows power-law distributions
    # Log transform makes it more Gaussian (better for some ML algorithms)
    df["log_bytes"] = np.log1p(df["total_bytes"])
    df["log_duration"] = np.log1p(df["duration"])

    print(f"Engineered {len(df.columns)} features")
    return df


def prepare_features(
    df: pd.DataFrame, feature_cols: List[str] = None
) -> Tuple[np.ndarray, List[str]]:
    """Prepare feature matrix for ML models."""
    if feature_cols is None:
        feature_cols = [
            "bytes_per_second",
            "packets_per_second",
            "bytes_ratio",
            "packets_ratio",
            "bytes_per_packet",
            "is_well_known_port",
            "log_bytes",
            "log_duration",
            "duration",
        ]

    # Filter to existing columns
    feature_cols = [c for c in feature_cols if c in df.columns]

    X = df[feature_cols].values

    # Handle any remaining NaN
    X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=-1e10)

    # Scale with RobustScaler (less sensitive to outliers)
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, feature_cols


# =============================================================================
# Task 3: Build Baseline Model - SOLUTION
# =============================================================================


def statistical_baseline(df: pd.DataFrame, feature: str, n_std: float = 3.0) -> pd.Series:
    """Simple statistical anomaly detection using z-score."""
    values = df[feature]
    mean = values.mean()
    std = values.std()

    z_scores = np.abs((values - mean) / std)
    anomalies = z_scores > n_std

    return anomalies


def iqr_baseline(df: pd.DataFrame, feature: str, k: float = 1.5) -> pd.Series:
    """IQR-based anomaly detection."""
    values = df[feature]
    Q1 = values.quantile(0.25)
    Q3 = values.quantile(0.75)
    IQR = Q3 - Q1

    lower_bound = Q1 - k * IQR
    upper_bound = Q3 + k * IQR

    anomalies = (values < lower_bound) | (values > upper_bound)
    return anomalies


# =============================================================================
# Task 4: Train Isolation Forest - SOLUTION
# =============================================================================
# Isolation Forest is ideal for anomaly detection because:
# 1. No labels needed - learns what "normal" looks like
# 2. Works well with high-dimensional data
# 3. Fast training and prediction
# 4. Built-in handling of contamination (expected % of anomalies)
#
# How it works:
# - Randomly selects a feature and a split value
# - Isolates points by creating partitions
# - Anomalies are isolated quickly (few splits needed)
# - Normal points take many splits to isolate
# - Anomaly score = average path length (shorter = more anomalous)


def train_isolation_forest(
    X: np.ndarray, contamination: float = 0.05
) -> Tuple[IsolationForest, np.ndarray]:
    """
    Train Isolation Forest for anomaly detection.

    Parameters:
    - X: Feature matrix (scaled)
    - contamination: Expected proportion of anomalies (0.05 = 5%)

    Key insight:
    - Anomalies are "few and different"
    - They lie far from normal data points
    - Random forests can isolate them with fewer splits

    Returns:
    - Trained model
    - Anomaly scores (more negative = more anomalous)
    """
    model = IsolationForest(
        n_estimators=100,  # Number of trees (more = more stable)
        contamination=contamination,  # Expected % anomalies
        random_state=42,  # Reproducibility
        n_jobs=-1,  # Use all CPU cores
    )

    model.fit(X)

    # Get anomaly scores
    # IMPORTANT: More negative = more anomalous
    # Normal points have scores near 0
    # Anomalies have scores much below 0
    scores = model.decision_function(X)

    print(f"Isolation Forest trained (contamination={contamination})")
    return model, scores


def train_local_outlier_factor(X: np.ndarray, contamination: float = 0.05) -> np.ndarray:
    """Train Local Outlier Factor."""
    model = LocalOutlierFactor(n_neighbors=20, contamination=contamination, novelty=False)

    predictions = model.fit_predict(X)
    return predictions


# =============================================================================
# Task 5: Train Autoencoder - SOLUTION (PyTorch)
# =============================================================================


def train_autoencoder(X: np.ndarray, encoding_dim: int = 8) -> Tuple[object, np.ndarray]:
    """Train autoencoder for anomaly detection."""
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        print("PyTorch not available, skipping autoencoder")
        return None, None

    input_dim = X.shape[1]

    # Define autoencoder
    class Autoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 32),
                nn.ReLU(),
                nn.Linear(32, encoding_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(encoding_dim, 32), nn.ReLU(), nn.Linear(32, input_dim)
            )

        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

    # Prepare data
    X_tensor = torch.FloatTensor(X)
    dataset = TensorDataset(X_tensor, X_tensor)
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True)

    # Train
    model = Autoencoder()
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    epochs = 50
    for epoch in range(epochs):
        for batch_x, _ in dataloader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_x)
            loss.backward()
            optimizer.step()

    # Calculate reconstruction errors
    model.eval()
    with torch.no_grad():
        reconstructed = model(X_tensor)
        errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).numpy()

    print(f"Autoencoder trained (encoding_dim={encoding_dim})")
    return model, errors


# =============================================================================
# Task 6: Evaluate and Tune - SOLUTION
# =============================================================================


def evaluate_detector(y_true: np.ndarray, scores: np.ndarray, threshold: float = None) -> dict:
    """Evaluate anomaly detector performance."""
    # Ensure scores are oriented so higher = more anomalous
    # For isolation forest, we negate since lower = more anomalous

    # Calculate AUC
    auc = roc_auc_score(y_true, scores)

    # Find optimal threshold if not provided
    if threshold is None:
        threshold = find_optimal_threshold(y_true, scores)

    # Make predictions
    y_pred = (scores >= threshold).astype(int)

    # Calculate metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    return {
        "auc": auc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "threshold": threshold,
    }


def find_optimal_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Find threshold that maximizes F1 score."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, scores)

    # Calculate F1 for each threshold
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)

    # Find best threshold
    optimal_idx = np.argmax(f1_scores[:-1])  # Last value is always 0
    optimal_threshold = thresholds[optimal_idx]

    return optimal_threshold


def plot_roc_curve(y_true: np.ndarray, scores: np.ndarray, title: str = "ROC Curve") -> None:
    """Plot ROC curve."""
    fpr, tpr, _ = roc_curve(y_true, scores)
    auc = roc_auc_score(y_true, scores)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, "b-", label=f"ROC (AUC = {auc:.3f})")
    plt.plot([0, 1], [0, 1], "k--", label="Random")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(title)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()


def plot_score_distribution(scores: np.ndarray, labels: np.ndarray = None) -> None:
    """Plot distribution of anomaly scores."""
    plt.figure(figsize=(10, 6))

    if labels is not None:
        normal_scores = scores[labels == 0]
        attack_scores = scores[labels == 1]
        plt.hist(normal_scores, bins=50, alpha=0.5, label="Normal", density=True)
        plt.hist(attack_scores, bins=50, alpha=0.5, label="Attack", density=True)
        plt.legend()
    else:
        plt.hist(scores, bins=50, alpha=0.7, density=True)

    plt.xlabel("Anomaly Score")
    plt.ylabel("Density")
    plt.title("Anomaly Score Distribution")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    print("=" * 60)
    print("Lab 03: Network Anomaly Detection - SOLUTION")
    print("=" * 60)

    # Load data
    data_path = Path(__file__).parent.parent / "data" / "network_flows.csv"

    if not data_path.exists():
        print("Creating sample data...")
        create_sample_data(data_path)

    print("\n[Step 1] Loading network data...")
    df = load_network_data(str(data_path))
    explore_network_data(df)

    # Feature engineering
    print("\n[Step 2] Engineering features...")
    df = engineer_network_features(df)

    # Prepare features
    print("\n[Step 3] Preparing features...")
    X, feature_names = prepare_features(df)
    print(f"Feature matrix: {X.shape}")
    print(f"Features: {feature_names}")

    # Statistical baseline
    print("\n[Step 4] Running statistical baselines...")
    z_anomalies = statistical_baseline(df, "bytes_per_second", n_std=3)
    iqr_anomalies = iqr_baseline(df, "bytes_per_second", k=1.5)
    print(f"Z-score baseline: {z_anomalies.sum()} anomalies")
    print(f"IQR baseline: {iqr_anomalies.sum()} anomalies")

    # Isolation Forest
    print("\n[Step 5] Training Isolation Forest...")
    model, scores = train_isolation_forest(X, contamination=0.05)

    # Predictions
    predictions = model.predict(X)
    n_anomalies = (predictions == -1).sum()
    print(f"Detected {n_anomalies} anomalies ({n_anomalies/len(X)*100:.1f}%)")

    # Evaluation (if labels available)
    print("\n[Step 6] Evaluating model...")
    if "label" in df.columns:
        y_true = (df["label"] == "attack").astype(int).values

        # For evaluation, negate scores so higher = more anomalous
        metrics = evaluate_detector(y_true, -scores)

        print("\nModel Performance:")
        print(f"  AUC: {metrics['auc']:.3f}")
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall: {metrics['recall']:.3f}")
        print(f"  F1 Score: {metrics['f1']:.3f}")
        print(f"  Optimal Threshold: {metrics['threshold']:.3f}")

        # Compare with baselines
        print("\nBaseline Performance:")
        baseline_metrics = evaluate_detector(y_true, z_anomalies.astype(float))
        print(f"  Z-score F1: {baseline_metrics['f1']:.3f}")

        # Plot ROC curve
        plot_roc_curve(y_true, -scores, "Isolation Forest ROC Curve")

        # Plot score distribution
        plot_score_distribution(-scores, y_true)

    # Local Outlier Factor comparison
    print("\n[Bonus] Training Local Outlier Factor...")
    lof_predictions = train_local_outlier_factor(X, contamination=0.05)
    lof_anomalies = (lof_predictions == -1).sum()
    print(f"LOF detected {lof_anomalies} anomalies")

    print("\n" + "=" * 60)
    print("Anomaly detection complete!")
    print("=" * 60)


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

        if attack_type == "c2":
            data.append(
                {
                    "timestamp": base_time + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
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
        elif attack_type == "exfil":
            data.append(
                {
                    "timestamp": base_time + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
                    "src_ip": "192.168.1.50",
                    "dst_ip": "91.234.99.100",
                    "src_port": np.random.randint(40000, 50000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": np.random.lognormal(15, 0.5),
                    "bytes_recv": 1000,
                    "packets_sent": np.random.randint(1000, 5000),
                    "packets_recv": 50,
                    "duration": np.random.uniform(60, 300),
                    "label": "attack",
                }
            )
        else:
            data.append(
                {
                    "timestamp": base_time + pd.Timedelta(seconds=(n_samples - n_attacks + i) * 5),
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

# Lab 03 Walkthrough: Anomaly Detection

## Overview

This walkthrough guides you through building anomaly detection systems for security events using Isolation Forest and statistical methods.

**Time to complete walkthrough:** 25 minutes

---

## Step 1: Understanding Anomaly Detection

### What We're Building

```
INPUT: Security events (network traffic, auth logs)
    |
    v
[Feature Engineering]
    |
    v
[Baseline Modeling]
    |
    v
[Anomaly Scoring]
    |
    v
OUTPUT: Anomaly scores + flagged events
```

### Why Anomaly Detection for Security?
- **Unknown threats** - Catches attacks without signatures
- **Behavioral analysis** - Detects deviations from normal
- **Zero-day detection** - Identifies novel attack patterns
- **Insider threats** - Spots unusual user behavior

### Anomaly vs Classification
| Approach | When to Use |
|----------|-------------|
| **Classification** | Known attack patterns, labeled data |
| **Anomaly Detection** | Unknown attacks, mostly normal data |

---

## Step 2: Loading Security Data

### Load Network Traffic Data

```python
import pandas as pd
import numpy as np
from datetime import datetime

# Load network traffic data
traffic = pd.read_csv('data/network/traffic.csv')

print(f"Total records: {len(traffic)}")
print(f"Columns: {traffic.columns.tolist()}")
print(f"\nLabel distribution:")
print(traffic['label'].value_counts())
```

### Expected Output
```
Total records: 20
Columns: ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'bytes_sent', 'bytes_recv', 'packets', 'duration_ms', 'label']

Label distribution:
normal         12
c2_beacon       3
scan            3
exfiltration    2
```

### Understanding the Data

| Column | Description | Security Relevance |
|--------|-------------|-------------------|
| `bytes_sent/recv` | Data volume | Exfiltration detection |
| `packets` | Packet count | Beaconing patterns |
| `duration_ms` | Connection duration | Persistent connections |
| `dst_port` | Destination port | Unusual services |

---

## Step 3: Feature Engineering

### Extract Anomaly-Relevant Features

```python
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Create features for anomaly detection"""

    features = pd.DataFrame()

    # Volume features
    features['bytes_total'] = df['bytes_sent'] + df['bytes_recv']
    features['bytes_ratio'] = df['bytes_sent'] / (df['bytes_recv'] + 1)  # Avoid div by 0

    # Rate features
    features['bytes_per_packet'] = features['bytes_total'] / (df['packets'] + 1)
    features['packets_per_second'] = df['packets'] / (df['duration_ms'] / 1000 + 0.001)

    # Port features
    features['is_well_known_port'] = df['dst_port'].apply(lambda x: 1 if x < 1024 else 0)
    features['is_common_port'] = df['dst_port'].apply(
        lambda x: 1 if x in [80, 443, 22, 53, 445, 3389] else 0
    )

    # Connection characteristics
    features['duration_seconds'] = df['duration_ms'] / 1000
    features['is_long_connection'] = (df['duration_ms'] > 60000).astype(int)

    return features


# Create feature matrix
X = engineer_features(traffic)
y = (traffic['label'] != 'normal').astype(int)  # 1 = anomaly

print(f"Feature matrix shape: {X.shape}")
print(f"Features: {X.columns.tolist()}")
```

### Why These Features?

| Feature | Detects |
|---------|---------|
| `bytes_ratio` | One-way data transfers (exfil) |
| `packets_per_second` | Beaconing behavior |
| `is_common_port` | Unusual service access |
| `is_long_connection` | Persistent C2 channels |

---

## Step 4: Statistical Baseline

### Z-Score Method

```python
from scipy import stats

class StatisticalAnomalyDetector:
    """Simple statistical anomaly detection using Z-scores"""

    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        self.mean = None
        self.std = None

    def fit(self, X: pd.DataFrame):
        """Learn baseline statistics from normal data"""
        self.mean = X.mean()
        self.std = X.std()
        # Avoid division by zero
        self.std = self.std.replace(0, 1)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Calculate anomaly scores (max Z-score across features)"""
        z_scores = np.abs((X - self.mean) / self.std)
        return z_scores.max(axis=1).values

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Predict anomalies (1 = anomaly, 0 = normal)"""
        scores = self.score(X)
        return (scores > self.threshold).astype(int)


# Fit on all data (in practice, fit only on known-normal data)
stat_detector = StatisticalAnomalyDetector(threshold=2.5)
stat_detector.fit(X)

# Score all samples
stat_scores = stat_detector.score(X)
stat_predictions = stat_detector.predict(X)

print(f"Statistical method detected {stat_predictions.sum()} anomalies")
```

### Interpreting Z-Scores

| Z-Score | Meaning | Frequency |
|---------|---------|-----------|
| < 1 | Normal | 68% of data |
| 1-2 | Unusual | 27% of data |
| 2-3 | Rare | 4.5% of data |
| > 3 | Very rare | 0.3% of data |

---

## Step 5: Isolation Forest

### Why Isolation Forest?

- **Fast training** - O(n log n) complexity
- **Works with high dimensions** - No curse of dimensionality
- **No assumptions** - Doesn't assume normal distribution
- **Interpretable** - Isolation depth is intuitive

### Implementation

```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
iso_forest = IsolationForest(
    n_estimators=100,      # Number of trees
    contamination=0.1,     # Expected anomaly ratio
    random_state=42,
    n_jobs=-1
)

# Fit and predict
iso_predictions = iso_forest.fit_predict(X_scaled)
iso_scores = -iso_forest.score_samples(X_scaled)  # Negate for intuitive scores

# Convert to binary (sklearn uses -1 for anomaly, 1 for normal)
iso_predictions = (iso_predictions == -1).astype(int)

print(f"Isolation Forest detected {iso_predictions.sum()} anomalies")
```

### Key Parameters

| Parameter | Effect | Recommendation |
|-----------|--------|----------------|
| `n_estimators` | More trees = more stable | 100-200 |
| `contamination` | Expected % of anomalies | Estimate or tune |
| `max_samples` | Samples per tree | 'auto' or 256 |
| `max_features` | Features per tree | 1.0 (all) |

### Common Error #1: Wrong Contamination
```python
# WRONG: Contamination too high
iso = IsolationForest(contamination=0.5)  # Half as anomalies?!

# RIGHT: Realistic estimate
iso = IsolationForest(contamination=0.05)  # 5% anomalies
```

---

## Step 6: Local Outlier Factor (LOF)

### When to Use LOF

- Data has varying densities
- Anomalies are local (unusual for their neighborhood)
- Need to detect contextual anomalies

```python
from sklearn.neighbors import LocalOutlierFactor

# Train LOF
lof = LocalOutlierFactor(
    n_neighbors=5,         # Neighbors to consider
    contamination=0.1,
    novelty=False          # Use True for new data prediction
)

# Fit and predict (LOF combines fit and predict)
lof_predictions = lof.fit_predict(X_scaled)
lof_scores = -lof.negative_outlier_factor_

# Convert to binary
lof_predictions = (lof_predictions == -1).astype(int)

print(f"LOF detected {lof_predictions.sum()} anomalies")
```

### LOF vs Isolation Forest

| Aspect | Isolation Forest | LOF |
|--------|------------------|-----|
| Speed | Fast | Slower |
| Memory | Low | Higher |
| Local anomalies | Moderate | Excellent |
| Global anomalies | Excellent | Good |

---

## Step 7: Threshold Optimization

### Using Known Labels

```python
from sklearn.metrics import precision_recall_curve, f1_score
import matplotlib.pyplot as plt

def optimize_threshold(y_true, scores):
    """Find optimal threshold using precision-recall tradeoff"""

    precisions, recalls, thresholds = precision_recall_curve(y_true, scores)

    # Calculate F1 for each threshold
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)

    # Find best threshold
    best_idx = np.argmax(f1_scores)
    best_threshold = thresholds[best_idx] if best_idx < len(thresholds) else thresholds[-1]
    best_f1 = f1_scores[best_idx]

    print(f"Optimal threshold: {best_threshold:.4f}")
    print(f"Best F1 score: {best_f1:.4f}")

    # Plot
    plt.figure(figsize=(10, 4))

    plt.subplot(1, 2, 1)
    plt.plot(thresholds, precisions[:-1], label='Precision')
    plt.plot(thresholds, recalls[:-1], label='Recall')
    plt.axvline(best_threshold, color='r', linestyle='--', label=f'Best threshold')
    plt.xlabel('Threshold')
    plt.ylabel('Score')
    plt.legend()
    plt.title('Precision-Recall vs Threshold')

    plt.subplot(1, 2, 2)
    plt.plot(thresholds, f1_scores[:-1])
    plt.axvline(best_threshold, color='r', linestyle='--')
    plt.xlabel('Threshold')
    plt.ylabel('F1 Score')
    plt.title('F1 Score vs Threshold')

    plt.tight_layout()
    plt.savefig('threshold_optimization.png')

    return best_threshold


# Optimize for Isolation Forest
best_threshold = optimize_threshold(y, iso_scores)
```

### Without Labels

```python
def estimate_threshold_percentile(scores, percentile=95):
    """Estimate threshold using percentile (assumes low anomaly rate)"""
    return np.percentile(scores, percentile)

def estimate_threshold_mad(scores, k=3):
    """Estimate threshold using Median Absolute Deviation"""
    median = np.median(scores)
    mad = np.median(np.abs(scores - median))
    return median + k * mad * 1.4826  # 1.4826 normalizes MAD to std

# Example
threshold_percentile = estimate_threshold_percentile(iso_scores, 90)
threshold_mad = estimate_threshold_mad(iso_scores)

print(f"Percentile threshold (90%): {threshold_percentile:.4f}")
print(f"MAD threshold (k=3): {threshold_mad:.4f}")
```

---

## Step 8: Evaluation

### Security-Focused Metrics

```python
from sklearn.metrics import classification_report, confusion_matrix

def evaluate_detector(y_true, y_pred, name="Detector"):
    """Evaluate anomaly detector with security focus"""

    print(f"\n=== {name} Evaluation ===")
    print(classification_report(y_true, y_pred,
                               target_names=['Normal', 'Anomaly']))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\nConfusion Matrix:")
    print(f"  TN={tn} FP={fp}")
    print(f"  FN={fn} TP={tp}")

    # Security-specific metrics
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
    false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"\nSecurity Metrics:")
    print(f"  Detection Rate (Recall): {detection_rate:.2%}")
    print(f"  False Alarm Rate: {false_alarm_rate:.2%}")
    print(f"  Missed Attacks: {fn}")

    return {
        "detection_rate": detection_rate,
        "false_alarm_rate": false_alarm_rate,
        "missed_attacks": fn
    }


# Evaluate all detectors
evaluate_detector(y, stat_predictions, "Statistical")
evaluate_detector(y, iso_predictions, "Isolation Forest")
evaluate_detector(y, lof_predictions, "Local Outlier Factor")
```

### Which Metric Matters?

| Use Case | Priority |
|----------|----------|
| **SOC alerts** | Low false alarm rate (analysts get overwhelmed) |
| **Critical systems** | High detection rate (can't miss attacks) |
| **Automated blocking** | High precision (avoid blocking legitimate traffic) |

---

## Step 9: Ensemble Approach

### Combining Multiple Detectors

```python
class EnsembleAnomalyDetector:
    """Combine multiple anomaly detectors"""

    def __init__(self, detectors: list, voting='majority'):
        """
        Args:
            detectors: List of (name, detector) tuples
            voting: 'majority', 'any', or 'all'
        """
        self.detectors = detectors
        self.voting = voting

    def fit(self, X):
        """Fit all detectors"""
        for name, detector in self.detectors:
            if hasattr(detector, 'fit'):
                detector.fit(X)
        return self

    def predict(self, X) -> np.ndarray:
        """Combine predictions from all detectors"""
        predictions = []

        for name, detector in self.detectors:
            if hasattr(detector, 'predict'):
                pred = detector.predict(X)
            elif hasattr(detector, 'fit_predict'):
                pred = detector.fit_predict(X)
                pred = (pred == -1).astype(int)
            predictions.append(pred)

        predictions = np.array(predictions)

        if self.voting == 'majority':
            return (predictions.sum(axis=0) >= len(self.detectors) / 2).astype(int)
        elif self.voting == 'any':
            return (predictions.sum(axis=0) >= 1).astype(int)
        elif self.voting == 'all':
            return (predictions.sum(axis=0) == len(self.detectors)).astype(int)


# Create ensemble
ensemble = EnsembleAnomalyDetector([
    ('statistical', stat_detector),
    ('isolation_forest', iso_forest),
    ('lof', LocalOutlierFactor(n_neighbors=5, novelty=False))
], voting='majority')

# Note: For LOF, we need to handle differently since it uses fit_predict
# This is a simplified example
```

---

## Common Mistakes & Solutions

### Mistake 1: Training on Anomalous Data
```python
# WRONG: Training baseline on all data including attacks
detector.fit(all_data)

# RIGHT: Train only on known-normal data
normal_data = all_data[all_data['label'] == 'normal']
detector.fit(normal_data)
```

### Mistake 2: Ignoring Feature Scaling
```python
# WRONG: Features on different scales
iso_forest.fit(X)  # bytes_sent (millions) dominates

# RIGHT: Scale features first
X_scaled = StandardScaler().fit_transform(X)
iso_forest.fit(X_scaled)
```

### Mistake 3: Static Thresholds
```python
# WRONG: Hardcoded threshold
anomalies = scores > 0.5

# RIGHT: Adaptive threshold
threshold = np.percentile(scores, 95)  # Or tune on validation data
anomalies = scores > threshold
```

---

## Extension Exercises

### Exercise A: Time-Series Anomaly Detection

```python
def detect_temporal_anomalies(df: pd.DataFrame, window_size: int = 10):
    """Detect anomalies using rolling statistics"""

    df = df.sort_values('timestamp')

    # Rolling statistics
    rolling_mean = df['bytes_total'].rolling(window_size).mean()
    rolling_std = df['bytes_total'].rolling(window_size).std()

    # Z-score from rolling baseline
    z_score = (df['bytes_total'] - rolling_mean) / (rolling_std + 1e-10)

    return np.abs(z_score) > 3
```

### Exercise B: Visualize Anomalies

```python
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

def visualize_anomalies(X, predictions, title="Anomaly Detection"):
    """Visualize anomalies in 2D using PCA"""

    pca = PCA(n_components=2)
    X_2d = pca.fit_transform(X)

    plt.figure(figsize=(10, 8))
    colors = ['green' if p == 0 else 'red' for p in predictions]
    plt.scatter(X_2d[:, 0], X_2d[:, 1], c=colors, alpha=0.6)
    plt.xlabel('PC1')
    plt.ylabel('PC2')
    plt.title(title)
    plt.savefig('anomaly_visualization.png')
```

### Exercise C: Real-Time Detection

```python
class OnlineAnomalyDetector:
    """Online anomaly detection with incremental updates"""

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.buffer = []

    def update(self, sample: np.ndarray) -> float:
        """Process new sample and return anomaly score"""
        self.buffer.append(sample)

        if len(self.buffer) > self.window_size:
            self.buffer.pop(0)

        if len(self.buffer) < 10:
            return 0.0  # Not enough data

        # Calculate score relative to recent data
        mean = np.mean(self.buffer, axis=0)
        std = np.std(self.buffer, axis=0) + 1e-10

        z_score = np.abs((sample - mean) / std)
        return z_score.max()
```

---

## Bonus: Attack Progression Timeline

The notebook includes an attack progression timeline showing anomalies over time.

### Creating a Time-Based View

```python
# Add simulated timestamps to network flows
df['simulated_time'] = pd.date_range(
    start='2024-01-15 00:00', 
    periods=len(df), 
    freq='1min'
)

# Get anomaly scores from Isolation Forest
df['anomaly_score'] = -iso_forest.score_samples(X_scaled)
df['is_anomaly'] = predictions == 1
```

### Multi-Panel Attack Timeline

```python
fig = make_subplots(rows=3, cols=1, subplot_titles=[
    'Traffic Volume Over Time',
    'Anomaly Score Timeline',
    'Attack Detection Events'
])

# Panel 1: Traffic volume
fig.add_trace(go.Scatter(x=time, y=bytes, name='Bytes'), row=1, col=1)

# Panel 2: Anomaly scores with threshold
fig.add_trace(go.Scatter(x=time, y=scores, name='Anomaly Score'), row=2, col=1)
fig.add_hline(y=threshold, line_dash='dash', line_color='red', row=2, col=1)

# Panel 3: Attack events by type
for attack_type in attack_types:
    events = anomalies[anomalies['attack_type'] == attack_type]
    fig.add_trace(go.Scatter(
        x=events['time'], y=[attack_type] * len(events),
        mode='markers', name=attack_type
    ), row=3, col=1)
```

### Security Insight

Attack timeline analysis reveals:
- **Attack phases** - Recon → exploitation → persistence
- **Correlation** - Traffic spikes align with anomaly score spikes
- **Attack types** - Different attacks cluster at different times
- **First/last detection** - Understand attack duration

---

## Key Takeaways

1. **Multiple methods** - Use statistical, Isolation Forest, and LOF together
2. **Feature engineering** - Domain knowledge improves detection
3. **Threshold tuning** - Balance detection rate vs false alarms
4. **Train on normal** - Baseline should exclude known attacks
5. **Ensemble approach** - Combine detectors for robustness
6. **Timeline analysis** - Attack progression aids incident response

---

## Next Lab

Continue to [Lab 04: LLM Log Analysis](./lab04-walkthrough.md) to learn how to use LLMs for security log analysis.

# Lab 03: Network Anomaly Detection

Build an anomaly detection system to identify malicious network activity.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand anomaly detection approaches (statistical, ML, deep learning)
2. Extract features from network flow data
3. Train and evaluate anomaly detection models
4. Handle imbalanced data and tune thresholds
5. Deploy real-time detection

> 📊 **Notebook Bonus**: The Colab notebook includes Layer 7 protocol awareness (HTTP, DNS, TLS, RMM tools) and an Attack Progression Timeline with interactive Plotly dashboards.

---

## ⏱️ Estimated Time

60-75 minutes (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 01-02
- Basic understanding of network protocols
- Familiarity with unsupervised learning

### Required Libraries

```bash
pip install scikit-learn pandas numpy matplotlib seaborn
pip install pyod  # Python Outlier Detection library
```

---

## 📖 Background

### Anomaly Detection in Security

| Approach | Method | Best For |
|----------|--------|----------|
| Statistical | Z-score, IQR | Simple baselines |
| Isolation Forest | Tree-based | High-dimensional data |
| Autoencoders | Neural network | Complex patterns |
| One-Class SVM | Kernel-based | Small datasets |
| Local Outlier Factor | Density-based | Clustered data |

### Network Features

```
Flow Features:
- duration: Connection length
- bytes_sent/recv: Data volume
- packets_sent/recv: Packet count
- protocol: TCP/UDP/ICMP
- port: Destination port

Derived Features:
- bytes_per_packet: Data efficiency
- packet_rate: Packets per second
- connection_rate: Connections per minute
- entropy_payload: Payload randomness
```

---

## 🔬 Lab Tasks

### Task 1: Load Network Data (10 min)

```python
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
    1. Load data
    2. Parse timestamps
    3. Handle missing values
    4. Print data summary
    """
    pass
```

### Task 2: Feature Engineering (15 min)

```python
def engineer_network_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create anomaly detection features.

    TODO: Create these features:
    1. bytes_per_second: Total bytes / duration
    2. packets_per_second: Total packets / duration
    3. bytes_ratio: sent / (sent + recv)
    4. is_well_known_port: dst_port < 1024
    5. connection_entropy: Entropy of connections per source
    6. time_of_day: Hour of day (cyclical)
    7. is_internal: Both IPs in internal range
    """
    pass
```

### Task 3: Build Baseline Model (10 min)

```python
def statistical_baseline(df: pd.DataFrame, feature: str) -> pd.Series:
    """
    Simple statistical anomaly detection.

    Args:
        df: Network data
        feature: Column to analyze

    Returns:
        Boolean series (True = anomaly)

    TODO:
    1. Calculate mean and std
    2. Flag values > 3 standard deviations
    3. Return anomaly flags
    """
    pass
```

### Task 4: Train Isolation Forest (15 min)

```python
def train_isolation_forest(X: np.ndarray, contamination: float = 0.01):
    """
    Train Isolation Forest for anomaly detection.

    Args:
        X: Feature matrix
        contamination: Expected proportion of anomalies

    Returns:
        Trained model and anomaly scores

    TODO:
    1. Initialize IsolationForest
    2. Fit to data
    3. Get anomaly scores
    4. Determine threshold
    """
    pass
```

### Task 5: Train Autoencoder (15 min)

```python
def train_autoencoder(X: np.ndarray, encoding_dim: int = 8):
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
    4. Train on normal data
    5. Calculate reconstruction errors
    """
    pass
```

### Task 6: Evaluate and Tune (10 min)

```python
def evaluate_detector(y_true: np.ndarray, scores: np.ndarray) -> dict:
    """
    Evaluate anomaly detector performance.

    Args:
        y_true: True labels (1 = anomaly)
        scores: Anomaly scores

    Returns:
        Metrics dict: precision, recall, F1, AUC

    TODO:
    1. Calculate ROC AUC
    2. Find optimal threshold (F1 maximizing)
    3. Calculate precision, recall, F1
    4. Create precision-recall curve
    """
    pass
```

---

## 📁 Files

```
lab03-anomaly-detection/
├── README.md
├── starter/
│   └── main.py
├── solution/
│   └── main.py
├── data/
│   ├── network_flows.csv       # Network flow data
│   └── labeled_attacks.csv     # Known attack labels
└── models/
    └── isolation_forest.pkl
```

---

## 📊 Sample Data

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_sent,bytes_recv,packets,duration
2024-01-15 08:00:01,192.168.1.100,8.8.8.8,54321,53,UDP,64,128,2,0.05
2024-01-15 08:00:02,192.168.1.100,104.18.32.7,54322,443,TCP,2048,65536,45,1.2
2024-01-15 08:00:05,192.168.1.100,185.143.223.47,54323,443,TCP,102400,512,100,0.1
```

---

## ✅ Success Criteria

- [ ] Features extracted correctly
- [ ] Baseline model detects obvious anomalies
- [ ] Isolation Forest achieves AUC > 0.85
- [ ] Autoencoder successfully reconstructs normal traffic
- [ ] Can tune threshold for desired precision/recall
- [ ] False positive rate < 5%

---

## 🎯 Attack Types to Detect

| Attack | Network Signature |
|--------|-------------------|
| C2 Beaconing | Regular intervals, small payloads |
| Data Exfiltration | Large outbound transfers |
| Port Scanning | Many connections, few packets |
| DDoS | High packet rate, many sources |
| DNS Tunneling | Large DNS packets, high frequency |

---

## 🚀 Bonus Challenges

1. **Real-time Detection**: Process live PCAP data
2. **Multi-model Ensemble**: Combine Isolation Forest + Autoencoder
3. **Contextual Anomalies**: Detect unusual patterns for specific users
4. **Explainability**: Show why each flow is anomalous
5. **Streaming**: Online learning for concept drift

---

## 💡 Hints

<details>
<summary>Hint: Feature Scaling</summary>

```python
from sklearn.preprocessing import RobustScaler

# RobustScaler is better for anomaly detection
# (not affected by outliers in training data)
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
```
</details>

<details>
<summary>Hint: Threshold Tuning</summary>

```python
from sklearn.metrics import precision_recall_curve

precisions, recalls, thresholds = precision_recall_curve(y_true, scores)
f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
optimal_idx = np.argmax(f1_scores)
optimal_threshold = thresholds[optimal_idx]
```
</details>

---

## 📚 Resources

- [PyOD Documentation](https://pyod.readthedocs.io/)
- [Isolation Forest Paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)
- [Anomaly Detection Survey](https://arxiv.org/abs/2007.02500)
- [Network Anomaly Detection](https://www.sciencedirect.com/topics/computer-science/network-anomaly-detection)

---

> **Stuck?** See the [Lab 03 Walkthrough](../../docs/walkthroughs/lab03-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 04 - LLM Log Analysis](../lab04-llm-log-analysis/)

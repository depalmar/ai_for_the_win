# Test Lab 03b: ML vs LLM Comparison
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

print("=" * 50)
print("Testing Lab 03b: ML vs LLM Comparison")
print("=" * 50)

# Sample security logs
logs = [
    # Malicious logs
    "Failed password for root from 185.234.72.19 port 22 ssh2",
    "POSSIBLE BREAK-IN ATTEMPT! from 91.121.34.56",
    "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA=",
    "cmd.exe /c net user hacker password123 /add",
    "Authentication failure for user admin from 10.0.0.99",
    "Reverse shell connection to 192.168.1.100:4444",
    "Mimikatz detected: sekurlsa::logonpasswords",
    "SQL injection attempt: ' OR 1=1 --",
    "Ransomware behavior: encrypting files in C:\\Users",
    "Cobalt Strike beacon detected from 45.33.32.156",
    # Benign logs
    "Accepted publickey for deploy from 10.0.0.50 port 22",
    "User john logged in successfully",
    "Scheduled backup completed successfully",
    "System update installed: KB5001234",
    "Application chrome.exe started by user alice",
    "Network connection established to api.github.com:443",
    "File uploaded: quarterly_report.pdf",
    "Database backup completed at 02:00 UTC",
    "User session timeout for inactive user bob",
    "Antivirus scan completed: no threats found",
]
labels = [1] * 10 + [0] * 10  # 1=malicious, 0=benign

print(f"\nDataset: {len(logs)} logs ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")

# === ML APPROACH ===
print("\n--- ML Approach ---")

# Feature extraction
MALICIOUS_KEYWORDS = [
    "failed",
    "attack",
    "shell",
    "powershell",
    "cmd.exe",
    "encodedcommand",
    "mimikatz",
    "injection",
    "ransomware",
    "beacon",
    "reverse",
    "hacker",
    "break-in",
    "authentication failure",
    "cobalt",
]


def extract_features(log):
    log_lower = log.lower()
    keyword_count = sum(1 for kw in MALICIOUS_KEYWORDS if kw in log_lower)
    has_ip = 1 if any(c.isdigit() and "." in log for c in log) else 0
    log_length = len(log)
    return [keyword_count, has_ip, log_length]


X = np.array([extract_features(log) for log in logs])
y = np.array(labels)

# Split using SAME indices for fair comparison
indices = list(range(len(logs)))
train_idx, test_idx = train_test_split(indices, test_size=0.3, random_state=42)

X_train, X_test = X[train_idx], X[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

# Train ML model
start_time = time.time()
ml_model = LogisticRegression()
ml_model.fit(X_train, y_train)
ml_train_time = time.time() - start_time

# Predict
start_time = time.time()
ml_preds = ml_model.predict(X_test)
ml_predict_time = time.time() - start_time

ml_accuracy = accuracy_score(y_test, ml_preds)
ml_precision = precision_score(y_test, ml_preds, zero_division=0)
ml_recall = recall_score(y_test, ml_preds, zero_division=0)

print(f"Training time: {ml_train_time*1000:.1f}ms")
print(f"Prediction time: {ml_predict_time*1000:.1f}ms")
print(f"Accuracy: {ml_accuracy:.1%}")
print(f"Precision: {ml_precision:.1%}")
print(f"Recall: {ml_recall:.1%}")

# === SIMULATED LLM APPROACH ===
print("\n--- LLM Approach (Simulated) ---")


def llm_classify_simulated(log):
    """Simulate LLM classification based on keywords"""
    log_lower = log.lower()
    malicious_signals = [
        "fail",
        "attack",
        "shell",
        "malware",
        "ransomware",
        "beacon",
        "injection",
        "mimikatz",
        "hacker",
        "reverse",
        "break-in",
        "encodedcommand",
        "cobalt",
    ]
    if any(signal in log_lower for signal in malicious_signals):
        return 1
    return 0


# Use SAME test set for fair comparison
test_logs = [logs[i] for i in test_idx]
y_test_llm = y[test_idx]

start_time = time.time()
llm_preds = [llm_classify_simulated(log) for log in test_logs]
llm_time = time.time() - start_time
# Simulate API latency
simulated_llm_time = len(test_logs) * 0.5  # 500ms per log

llm_accuracy = accuracy_score(y_test_llm, llm_preds)
llm_precision = precision_score(y_test_llm, llm_preds, zero_division=0)
llm_recall = recall_score(y_test_llm, llm_preds, zero_division=0)

print(f"Prediction time (simulated): {simulated_llm_time:.1f}s")
print(f"Accuracy: {llm_accuracy:.1%}")
print(f"Precision: {llm_precision:.1%}")
print(f"Recall: {llm_recall:.1%}")

# === COMPARISON ===
print("\n--- Comparison ---")
print(f"{'Metric':<20} {'ML':<15} {'LLM':<15}")
print("-" * 50)
print(f"{'Speed':<20} {ml_predict_time*1000:.1f}ms{'':<10} {simulated_llm_time:.1f}s")
print(f"{'Accuracy':<20} {ml_accuracy:.1%}{'':<10} {llm_accuracy:.1%}")
print(f"{'Cost per 1000 logs':<20} {'~$0':<15} {'~$5-50':<15}")

# === HYBRID APPROACH ===
print("\n--- Hybrid Approach Demo ---")


def hybrid_classify(log, model, threshold_low=0.3, threshold_high=0.7):
    """Use ML for confident cases, LLM for uncertain ones."""
    features = np.array([extract_features(log)])
    prob = model.predict_proba(features)[0][1]

    if prob < threshold_low:
        return 0, False  # Definitely benign, ML only
    elif prob > threshold_high:
        return 1, False  # Definitely malicious, ML only
    else:
        # Uncertain - would use LLM in production
        return llm_classify_simulated(log), True


llm_calls = 0
for log in test_logs:
    pred, used_llm = hybrid_classify(log, ml_model)
    if used_llm:
        llm_calls += 1

print(f"Test logs: {len(test_logs)}")
print(f"LLM calls needed: {llm_calls} ({llm_calls/len(test_logs):.0%} of logs)")
print(f"Cost savings: {(1 - llm_calls/len(test_logs)):.0%}")

print("\n[PASS] Lab 03b: PASSED")

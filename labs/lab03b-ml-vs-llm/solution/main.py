"""
Lab 03b: ML vs LLM Decision Lab (Solution)

Compare ML and LLM approaches for log classification.
"""

import re
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

# Uncomment to use real LLM
# from anthropic import Anthropic

# ============================================================================
# SAMPLE LOG DATA
# ============================================================================

LOGS = [
    # Malicious logs (label = 1)
    {"text": "Failed login attempt for user admin from IP 185.143.223.47", "label": 1},
    {"text": "Multiple failed SSH attempts from 45.33.32.156", "label": 1},
    {"text": "Powershell.exe spawned by WINWORD.EXE - suspicious macro execution", "label": 1},
    {"text": "User admin executed: whoami /all; net group 'Domain Admins'", "label": 1},
    {"text": "Outbound connection to known C2 IP 185.143.223.47:443", "label": 1},
    {"text": "Process injection detected: notepad.exe writing to lsass.exe", "label": 1},
    {"text": "Failed login for root from 103.25.78.99 - 50 attempts in 1 minute", "label": 1},
    {"text": "Encoded powershell command executed: -enc JABjAGwAaQBlAG4=", "label": 1},
    {"text": "Shadow copy deletion: vssadmin delete shadows /all", "label": 1},
    {"text": "Unauthorized access attempt to /etc/passwd from web server", "label": 1},
    {"text": "Mimikatz detected: sekurlsa::logonpasswords executed", "label": 1},
    {"text": "Suspicious DNS query: data.exfil.malicious-domain.com", "label": 1},
    {"text": "Ransomware indicator: mass file encryption detected (.lockbit)", "label": 1},
    {"text": "Brute force attack: 1000 failed logins in 5 minutes", "label": 1},
    {"text": "Lateral movement: PsExec connection from workstation to DC", "label": 1},
    # Benign logs (label = 0)
    {"text": "User john.doe logged in successfully from 192.168.1.50", "label": 0},
    {"text": "Scheduled backup completed successfully at 02:00", "label": 0},
    {"text": "Windows Update installed KB5001234 successfully", "label": 0},
    {"text": "User mary.smith accessed shared folder /finance/reports", "label": 0},
    {"text": "Email sent from ceo@company.com to board@company.com", "label": 0},
    {"text": "Antivirus scan completed: 0 threats found", "label": 0},
    {"text": "VPN connection established for user remote.worker", "label": 0},
    {"text": "Database backup to S3 completed in 45 minutes", "label": 0},
    {"text": "SSL certificate renewed for www.company.com", "label": 0},
    {"text": "User password changed for account support.desk", "label": 0},
    {"text": "Firewall rule updated: allow HTTPS from partner.com", "label": 0},
    {"text": "System reboot completed after maintenance window", "label": 0},
    {"text": "New employee account created: new.hire@company.com", "label": 0},
    {"text": "Print job completed: quarterly_report.pdf", "label": 0},
    {"text": "Meeting room calendar synced successfully", "label": 0},
]

SUSPICIOUS_KEYWORDS = [
    "failed",
    "admin",
    "root",
    "powershell",
    "cmd",
    "whoami",
    "net group",
    "injection",
    "encoded",
    "shadow",
    "mimikatz",
    "ransomware",
    "brute",
    "lateral",
    "c2",
    "exfil",
    "malicious",
    "unauthorized",
    "suspicious",
]


# ============================================================================
# PART 1: ML CLASSIFIER (SOLUTION)
# ============================================================================


def extract_ml_features(log_text: str) -> list:
    """Extract numerical features from a log entry."""
    log_lower = log_text.lower()

    # Feature 1: Contains "failed"
    has_failed = 1 if "failed" in log_lower else 0

    # Feature 2: Contains privileged account names
    has_privileged = 1 if ("admin" in log_lower or "root" in log_lower) else 0

    # Feature 3: Count of suspicious keywords
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in log_lower)

    # Feature 4: Log length (normalized)
    log_length = len(log_text) / 100

    # Feature 5: Contains external IP (not 192.168.x.x or 10.x.x.x)
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ips = re.findall(ip_pattern, log_text)
    has_external_ip = 0
    for ip in ips:
        if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")):
            has_external_ip = 1
            break

    # Feature 6: Contains encoded content
    has_encoded = (
        1 if ("encoded" in log_lower or "-enc " in log_lower or "base64" in log_lower) else 0
    )

    return [has_failed, has_privileged, keyword_count, log_length, has_external_ip, has_encoded]


def train_ml_classifier(logs: list) -> tuple:
    """Train an ML classifier on the log data."""
    # Extract features
    X = np.array([extract_ml_features(log["text"]) for log in logs])
    y = np.array([log["label"] for log in logs])

    # Create indices for train/test split (needed for fair LLM comparison)
    indices = np.arange(len(logs))

    # Split data - returns indices too for fair comparison with LLM
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, indices, test_size=0.3, random_state=42
    )

    # Train model
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)

    return model, X_test, y_test, idx_test


def evaluate_ml_classifier(model, X_test, y_test) -> dict:
    """Evaluate the ML classifier."""
    start = time.time()
    predictions = model.predict(X_test)
    prediction_time = time.time() - start

    accuracy = accuracy_score(y_test, predictions)

    return {
        "accuracy": accuracy,
        "prediction_time": prediction_time,
        "predictions": predictions.tolist(),
    }


# ============================================================================
# PART 2: LLM CLASSIFIER (SOLUTION)
# ============================================================================


def create_llm_prompt(log_text: str) -> str:
    """Create a prompt for LLM classification."""
    return f"""You are an expert security analyst. Classify this log entry.

Log Entry: {log_text}

Consider:
- Failed login attempts, especially from external IPs
- Suspicious command execution (powershell, whoami, net commands)
- Known attack patterns (lateral movement, C2, data exfiltration)
- Privileged account activity

Respond with ONLY one word: MALICIOUS or BENIGN"""


def classify_with_llm(log_text: str, client=None, simulate: bool = True) -> tuple:
    """
    Classify a log entry using an LLM.

    Returns:
        Tuple of (classification, reasoning)
    """
    if simulate:
        # Simulated LLM response based on keywords
        log_lower = log_text.lower()
        suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in log_lower)

        if suspicious_count >= 2:
            return "MALICIOUS", f"Detected {suspicious_count} suspicious indicators"
        elif "successfully" in log_lower or "completed" in log_lower:
            return "BENIGN", "Normal operation indicators present"
        else:
            return "BENIGN", "No strong malicious indicators"

    # Real LLM call (uncomment to use)
    # prompt = create_llm_prompt(log_text)
    # response = client.messages.create(
    #     model="claude-sonnet-4-20250514",
    #     max_tokens=100,
    #     messages=[{"role": "user", "content": prompt}]
    # )
    # result = response.content[0].text.strip().upper()
    # return "MALICIOUS" if "MALICIOUS" in result else "BENIGN", result

    # Fallback for when real LLM is not available
    return "BENIGN", "LLM not configured"


def evaluate_llm_classifier(logs: list, simulate: bool = True) -> dict:
    """Evaluate LLM classifier on logs."""
    predictions = []
    start = time.time()

    for log in logs:
        classification, _ = classify_with_llm(log["text"], simulate=simulate)
        predictions.append(1 if classification == "MALICIOUS" else 0)

        if not simulate:
            time.sleep(0.5)  # Rate limiting for real API calls

    prediction_time = time.time() - start
    true_labels = [log["label"] for log in logs]
    accuracy = accuracy_score(true_labels, predictions)

    # Estimate cost (Claude Sonnet: ~$0.003 per 1K tokens)
    avg_tokens = 200  # Approximate tokens per request
    cost = len(logs) * avg_tokens * 0.003 / 1000 if not simulate else 0

    return {
        "accuracy": accuracy,
        "prediction_time": prediction_time,
        "predictions": predictions,
        "cost": cost,
    }


# ============================================================================
# PART 3: COMPARISON (SOLUTION)
# ============================================================================


def compare_approaches(logs: list) -> dict:
    """Compare ML and LLM approaches."""

    # ML Classifier
    model, X_test, y_test, test_indices = train_ml_classifier(logs)
    ml_results = evaluate_ml_classifier(model, X_test, y_test)

    # LLM Classifier (on SAME test set for fair comparison)
    # Use the same indices that train_test_split selected for ML
    test_logs = [logs[i] for i in test_indices]
    llm_results = evaluate_llm_classifier(test_logs, simulate=True)

    return {
        "ml": {
            "accuracy": ml_results["accuracy"],
            "time": ml_results["prediction_time"],
            "cost": 0.0,
        },
        "llm": {
            "accuracy": llm_results["accuracy"],
            "time": llm_results["prediction_time"] * 100,  # Scale to 100 logs
            "cost": 0.50,  # Estimated cost for 100 real LLM calls
        },
    }


def hybrid_classifier(
    log_text: str, model, threshold_low: float = 0.3, threshold_high: float = 0.8
) -> tuple:
    """
    Hybrid classifier: ML for confident cases, LLM for uncertain.

    Returns:
        Tuple of (classification, method_used, confidence)
    """
    features = np.array([extract_ml_features(log_text)])
    probability = model.predict_proba(features)[0][1]  # Probability of malicious

    if probability < threshold_low:
        return "BENIGN", "ML", probability
    elif probability > threshold_high:
        return "MALICIOUS", "ML", probability
    else:
        # Uncertain - use LLM
        classification, _ = classify_with_llm(log_text, simulate=True)
        return classification, "LLM", probability


def main():
    print("🔬 ML vs LLM Comparison")
    print("=" * 50)

    print(f"\nDataset: {len(LOGS)} log entries")
    print(f"  Malicious: {sum(1 for l in LOGS if l['label'] == 1)}")
    print(f"  Benign: {sum(1 for l in LOGS if l['label'] == 0)}")

    # Part 1: ML Classifier
    print("\n" + "=" * 50)
    print("PART 1: ML CLASSIFIER")
    print("=" * 50)

    model, X_test, y_test, test_indices = train_ml_classifier(LOGS)
    ml_results = evaluate_ml_classifier(model, X_test, y_test)

    print(f"  Accuracy: {ml_results['accuracy']:.1%}")
    print(f"  Prediction time: {ml_results['prediction_time']*1000:.2f}ms")
    print("  Cost: $0.00")

    # Show feature importance
    feature_names = [
        "has_failed",
        "has_privileged",
        "keyword_count",
        "log_length",
        "has_external_ip",
        "has_encoded",
    ]
    print("\n  Feature Importance:")
    for name, coef in zip(feature_names, model.coef_[0]):
        direction = "↑" if coef > 0 else "↓"
        print(f"    {name}: {coef:+.2f} {direction}")

    # Part 2: LLM Classifier
    print("\n" + "=" * 50)
    print("PART 2: LLM CLASSIFIER (Simulated)")
    print("=" * 50)

    llm_results = evaluate_llm_classifier(LOGS, simulate=True)
    print(f"  Accuracy: {llm_results['accuracy']:.1%}")
    print(f"  Prediction time: {llm_results['prediction_time']:.2f}s (simulated)")
    print(f"  Est. real cost: ~$0.50 for {len(LOGS)} logs")

    # Sample LLM reasoning
    print("\n  Sample LLM Analysis:")
    sample_log = LOGS[0]["text"]
    classification, reasoning = classify_with_llm(sample_log, simulate=True)
    print(f"    Log: {sample_log[:50]}...")
    print(f"    Result: {classification}")
    print(f"    Reason: {reasoning}")

    # Part 3: Comparison
    print("\n" + "=" * 50)
    print("PART 3: COMPARISON")
    print("=" * 50)

    comparison = compare_approaches(LOGS)

    print("\n  Head-to-Head Results:")
    print(f"  {'Metric':<20} {'ML':<15} {'LLM':<15} {'Winner':<10}")
    print(f"  {'-'*60}")

    ml_acc = comparison["ml"]["accuracy"]
    llm_acc = comparison["llm"]["accuracy"]
    winner = "LLM" if llm_acc > ml_acc else "ML"
    print(f"  {'Accuracy':<20} {ml_acc:.1%}          {llm_acc:.1%}          {winner:<10}")

    ml_time = comparison["ml"]["time"] * 1000
    llm_time = comparison["llm"]["time"]
    print(f"  {'Speed (100 logs)':<20} {ml_time:.1f}ms        {llm_time:.0f}s          {'ML':<10}")

    ml_cost = comparison["ml"]["cost"]
    llm_cost = comparison["llm"]["cost"]
    print(f"  {'Cost (100 logs)':<20} ${ml_cost:.4f}{'':<8} ${llm_cost:.2f}{'':<10} {'ML':<10}")

    # Part 4: Hybrid Demo
    print("\n" + "=" * 50)
    print("PART 4: HYBRID CLASSIFIER")
    print("=" * 50)

    print("\n  Hybrid classifies using ML when confident, LLM when uncertain:")

    test_samples = [
        "Failed login for admin from 185.143.223.47",  # Clearly malicious
        "User logged in successfully",  # Clearly benign
        "Connection from 10.0.0.5 to external host",  # Uncertain
    ]

    for sample in test_samples:
        result, method, conf = hybrid_classifier(sample, model)
        print(f"\n    Log: {sample}")
        print(f"    Result: {result} (via {method}, confidence: {conf:.2f})")

    # Summary
    print("\n" + "=" * 50)
    print("📊 DECISION GUIDE")
    print("=" * 50)
    print(
        """
  ┌──────────────────────────────────────────────────────┐
  │ CHOOSE ML WHEN:                                      │
  │   • Processing >100 logs/second                      │
  │   • Cost is critical                                 │
  │   • Patterns are well-known                          │
  │   • Need to work offline                             │
  ├──────────────────────────────────────────────────────┤
  │ CHOOSE LLM WHEN:                                     │
  │   • Need natural language explanation                │
  │   • Handling novel attack patterns                   │
  │   • Low volume, high stakes decisions                │
  │   • Analyst augmentation (not replacement)           │
  ├──────────────────────────────────────────────────────┤
  │ CHOOSE HYBRID WHEN:                                  │
  │   • Want best accuracy AND reasonable cost           │
  │   • Have mixed confidence requirements               │
  │   • Building production detection pipelines          │
  └──────────────────────────────────────────────────────┘
    """
    )


if __name__ == "__main__":
    main()

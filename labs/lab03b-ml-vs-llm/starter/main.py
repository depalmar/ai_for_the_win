"""
Lab 03b: ML vs LLM Decision Lab (Starter)

Compare ML and LLM approaches for log classification.
Complete the TODOs to implement both approaches.
"""

import os
import time
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Uncomment when implementing LLM section
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

# Keywords for feature extraction
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
# PART 1: ML CLASSIFIER
# ============================================================================


# TODO 1: Extract features from a log entry
def extract_ml_features(log_text: str) -> list:
    """
    Extract numerical features from a log entry for ML classification.

    Args:
        log_text: The log entry text

    Returns:
        List of numerical features
    """
    log_lower = log_text.lower()

    # TODO: Extract these features:
    # 1. Contains "failed"? (1 or 0)
    # 2. Contains "admin" or "root"? (1 or 0)
    # 3. Count of suspicious keywords
    # 4. Log length (normalized by dividing by 100)
    # 5. Contains external IP pattern? (non-192.168, non-10.)

    # Your code here:
    features = [0, 0, 0, 0, 0]  # Replace with actual feature extraction

    return features


# TODO 2: Train ML classifier
def train_ml_classifier(logs: list) -> tuple:
    """
    Train an ML classifier on the log data.

    Args:
        logs: List of log dicts with 'text' and 'label'

    Returns:
        Tuple of (trained_model, X_test, y_test, test_indices)
        test_indices are needed for fair LLM comparison
    """
    # TODO:
    # 1. Extract features for all logs
    # 2. Create indices array: indices = np.arange(len(logs))
    # 3. Split into train/test sets (include indices in split for fair comparison)
    # 4. Train LogisticRegression model
    # 5. Return model, test data, AND test_indices

    # Your code here:
    model = None
    X_test = None
    y_test = None
    test_indices = None

    return model, X_test, y_test, test_indices


# TODO 3: Evaluate ML classifier
def evaluate_ml_classifier(model, X_test, y_test) -> dict:
    """
    Evaluate the ML classifier and return metrics.

    Returns:
        Dict with accuracy, predictions, and timing
    """
    # TODO:
    # 1. Time the predictions
    # 2. Calculate accuracy
    # 3. Return results dict

    # Your code here:
    return {"accuracy": 0.0, "prediction_time": 0.0, "predictions": []}


# ============================================================================
# PART 2: LLM CLASSIFIER
# ============================================================================


# TODO 4: Create LLM classification prompt
def create_llm_prompt(log_text: str) -> str:
    """
    Create a prompt for LLM classification.

    Args:
        log_text: The log entry to classify

    Returns:
        The prompt string
    """
    # TODO: Create a prompt that:
    # 1. Sets the role (security analyst)
    # 2. Provides the log entry
    # 3. Asks for ONLY "MALICIOUS" or "BENIGN"

    # Your code here:
    prompt = ""

    return prompt


# TODO 5: Classify with LLM
def classify_with_llm(log_text: str, client=None) -> str:
    """
    Classify a log entry using an LLM.

    Args:
        log_text: The log entry to classify
        client: Anthropic client (or None for simulation)

    Returns:
        "MALICIOUS" or "BENIGN"
    """
    # TODO:
    # 1. Create the prompt
    # 2. Call the LLM API
    # 3. Parse the response
    # 4. Return classification

    # For now, we'll simulate LLM responses
    # Uncomment and implement when ready to use real LLM

    # Your code here:
    return "BENIGN"  # Placeholder


# ============================================================================
# PART 3: COMPARE APPROACHES
# ============================================================================


# TODO 6: Compare ML and LLM
def compare_approaches(logs: list) -> dict:
    """
    Compare ML and LLM approaches on the same data.

    IMPORTANT: For a fair comparison, both classifiers must be
    evaluated on the SAME test set. Use the test_indices returned
    by train_ml_classifier to select the same logs for LLM evaluation.

    Returns:
        Dict with comparison results
    """
    # TODO:
    # 1. Run ML classifier: model, X_test, y_test, test_indices = train_ml_classifier(logs)
    # 2. Use test_indices to get the SAME logs for LLM: test_logs = [logs[i] for i in test_indices]
    # 3. Run LLM classifier on test_logs
    # 4. Calculate cost estimates
    # 5. Return comparison dict

    # Your code here:
    return {
        "ml": {"accuracy": 0, "time": 0, "cost": 0},
        "llm": {"accuracy": 0, "time": 0, "cost": 0},
    }


# ============================================================================
# MAIN
# ============================================================================


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

    model, X_test, y_test = train_ml_classifier(LOGS)
    if model is not None:
        results = evaluate_ml_classifier(model, X_test, y_test)
        print(f"  Accuracy: {results['accuracy']:.1%}")
        print(f"  Prediction time: {results['prediction_time']*1000:.2f}ms")
        print(f"  Cost: $0.00")
    else:
        print("  ❌ Complete TODOs 1-3 to train ML classifier")

    # Part 2: LLM Classifier
    print("\n" + "=" * 50)
    print("PART 2: LLM CLASSIFIER")
    print("=" * 50)

    prompt = create_llm_prompt(LOGS[0]["text"])
    if prompt:
        print(f"  Sample prompt created (length: {len(prompt)})")
        print("  (Simulated - enable API for real LLM calls)")
    else:
        print("  ❌ Complete TODOs 4-5 for LLM classifier")

    # Part 3: Comparison
    print("\n" + "=" * 50)
    print("PART 3: COMPARISON")
    print("=" * 50)

    comparison = compare_approaches(LOGS)
    if comparison["ml"]["accuracy"] > 0:
        print("\n  ML vs LLM Results:")
        print(f"  {'Metric':<20} {'ML':<15} {'LLM':<15}")
        print(f"  {'-'*50}")
        print(
            f"  {'Accuracy':<20} {comparison['ml']['accuracy']:.1%}{'':<10} {comparison['llm']['accuracy']:.1%}"
        )
        print(
            f"  {'Time (100 logs)':<20} {comparison['ml']['time']*1000:.1f}ms{'':<8} {comparison['llm']['time']:.1f}s"
        )
        print(
            f"  {'Cost (100 logs)':<20} ${comparison['ml']['cost']:.4f}{'':<8} ${comparison['llm']['cost']:.2f}"
        )
    else:
        print("  ❌ Complete TODO 6 for comparison")

    print("\n" + "=" * 50)
    print("📊 DECISION GUIDE")
    print("=" * 50)
    print("  Use ML when: High volume, known patterns, cost-sensitive")
    print("  Use LLM when: Need explanations, novel patterns")
    print("  Use Hybrid when: Best of both worlds")


if __name__ == "__main__":
    main()

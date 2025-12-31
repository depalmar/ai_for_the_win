#!/usr/bin/env python3
"""
Lab 00b: Machine Learning Concepts for Security - Interactive Exercises

This lab helps you understand ML concepts through hands-on exercises.
No ML libraries required - we'll build intuition before coding real models.

Run this file: python main.py
"""

import json
from pathlib import Path
from collections import Counter


def load_data(filename: str) -> list[dict]:
    """Load JSON data from the data directory."""
    data_path = Path(__file__).parent.parent / "data" / filename
    with open(data_path) as f:
        return json.load(f)


# =============================================================================
# EXERCISE 1: Feature Engineering
# =============================================================================

def extract_email_features(email: dict) -> dict:
    """
    Extract features from an email for ML classification.
    
    TODO: Implement feature extraction. Consider:
    - Word counts
    - Presence of suspicious words
    - Subject line characteristics
    - Urgency indicators
    
    Args:
        email: Dict with 'subject' and 'body' keys
        
    Returns:
        Dict of feature names to values
    """
    subject = email.get("subject", "").lower()
    body = email.get("body", "").lower()
    full_text = subject + " " + body
    
    features = {
        # TODO: Add at least 5 features
        # Example: "word_count": len(full_text.split()),
        
        # Feature 1: Total word count
        "word_count": 0,  # TODO: Implement
        
        # Feature 2: Contains urgency words (urgent, immediately, now, fast)
        "has_urgency": False,  # TODO: Implement
        
        # Feature 3: Contains money-related words (won, prize, $, money)
        "has_money_words": False,  # TODO: Implement
        
        # Feature 4: Contains "click" or "verify"
        "has_action_words": False,  # TODO: Implement
        
        # Feature 5: Subject in ALL CAPS ratio
        "caps_ratio": 0.0,  # TODO: Implement
    }
    
    return features


def exercise_1():
    """Feature Engineering Exercise."""
    print("=" * 60)
    print("EXERCISE 1: Feature Engineering")
    print("=" * 60)
    print("\nGoal: Extract useful features from emails for classification.\n")
    
    emails = load_data("sample_emails.json")
    
    print("Analyzing 10 sample emails...\n")
    
    for i, email in enumerate(emails[:5]):
        features = extract_email_features(email)
        label = email.get("label", "unknown")
        
        print(f"Email {i+1} ({label}):")
        print(f"  Subject: {email['subject'][:50]}...")
        print(f"  Features: {features}")
        print()
    
    # TODO: After implementing features, check if they help distinguish
    # phishing from legitimate emails. Good features should show different
    # patterns for different labels.


# =============================================================================
# EXERCISE 2: Understanding Metrics
# =============================================================================

def calculate_metrics(predictions: list[str], actuals: list[str], positive_class: str = "phishing") -> dict:
    """
    Calculate classification metrics from predictions.
    
    TODO: Implement the confusion matrix and metrics.
    
    Args:
        predictions: List of predicted labels
        actuals: List of actual labels
        positive_class: Which class is "positive" (what we're detecting)
        
    Returns:
        Dict with TP, FP, TN, FN, precision, recall, f1
    """
    # TODO: Calculate confusion matrix values
    tp = 0  # True Positives: predicted positive, actually positive
    fp = 0  # False Positives: predicted positive, actually negative
    tn = 0  # True Negatives: predicted negative, actually negative  
    fn = 0  # False Negatives: predicted negative, actually positive
    
    for pred, actual in zip(predictions, actuals):
        # TODO: Implement the logic
        # if pred == positive_class and actual == positive_class:
        #     tp += 1
        # elif ...
        pass
    
    # TODO: Calculate metrics (handle division by zero!)
    precision = 0.0  # TP / (TP + FP)
    recall = 0.0     # TP / (TP + FN)
    f1 = 0.0         # 2 * (precision * recall) / (precision + recall)
    accuracy = 0.0   # (TP + TN) / total
    
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy
    }


def exercise_2():
    """Metrics Exercise."""
    print("=" * 60)
    print("EXERCISE 2: Understanding Metrics")
    print("=" * 60)
    print("\nGoal: Calculate and understand precision, recall, F1.\n")
    
    # Simulated predictions from a phishing detector
    actuals =      ["phishing", "legitimate", "phishing", "legitimate", "phishing", 
                    "legitimate", "legitimate", "phishing", "legitimate", "phishing"]
    
    # Scenario A: High precision detector (few false alarms, but misses some)
    predictions_a = ["phishing", "legitimate", "legitimate", "legitimate", "phishing",
                     "legitimate", "legitimate", "phishing", "legitimate", "legitimate"]
    
    # Scenario B: High recall detector (catches most, but more false alarms)
    predictions_b = ["phishing", "phishing", "phishing", "legitimate", "phishing",
                     "phishing", "legitimate", "phishing", "legitimate", "phishing"]
    
    print("Actual labels:", actuals)
    print("\nScenario A (conservative detector):", predictions_a)
    metrics_a = calculate_metrics(predictions_a, actuals)
    print(f"Metrics: {metrics_a}")
    
    print("\nScenario B (aggressive detector):", predictions_b)
    metrics_b = calculate_metrics(predictions_b, actuals)
    print(f"Metrics: {metrics_b}")
    
    print("\n" + "-" * 40)
    print("QUESTION: Which detector would you prefer for:")
    print("  1. A hospital's ransomware detection system?")
    print("  2. A personal spam filter?")
    print("  3. A SOC with limited analyst capacity?")


# =============================================================================
# EXERCISE 3: Identifying Data Patterns
# =============================================================================

def analyze_network_traffic(samples: list[dict]) -> dict:
    """
    Analyze network traffic samples to identify patterns.
    
    TODO: Calculate statistics for each traffic type (label).
    
    Args:
        samples: List of network flow samples
        
    Returns:
        Dict with statistics per label
    """
    # Group samples by label
    by_label = {}
    for sample in samples:
        label = sample.get("label", "unknown")
        if label not in by_label:
            by_label[label] = []
        by_label[label].append(sample)
    
    stats = {}
    for label, label_samples in by_label.items():
        # TODO: Calculate average values for each feature
        stats[label] = {
            "count": len(label_samples),
            "avg_bytes_sent": 0,  # TODO: Calculate average
            "avg_bytes_recv": 0,  # TODO: Calculate average
            "avg_duration": 0,    # TODO: Calculate average
            "avg_packets": 0,     # TODO: Calculate average
        }
    
    return stats


def exercise_3():
    """Data Analysis Exercise."""
    print("=" * 60)
    print("EXERCISE 3: Identifying Data Patterns")
    print("=" * 60)
    print("\nGoal: Analyze network traffic to find distinguishing patterns.\n")
    
    samples = load_data("network_samples.json")
    
    print(f"Loaded {len(samples)} network flow samples.\n")
    
    stats = analyze_network_traffic(samples)
    
    print("Traffic Statistics by Type:")
    print("-" * 40)
    for label, label_stats in stats.items():
        print(f"\n{label.upper()}:")
        for key, value in label_stats.items():
            print(f"  {key}: {value}")
    
    print("\n" + "-" * 40)
    print("QUESTIONS:")
    print("  1. What features distinguish 'beacon' traffic?")
    print("  2. What features distinguish 'exfiltration' traffic?")
    print("  3. Which features would you use for an ML model?")


# =============================================================================
# EXERCISE 4: Train/Test Split Intuition
# =============================================================================

def exercise_4():
    """Train/Test Split Exercise."""
    print("=" * 60)
    print("EXERCISE 4: Why Split Data?")
    print("=" * 60)
    
    print("""
Scenario: You're building a malware detector.

You have 1000 malware samples collected over 3 months:
- January: 300 samples (mostly Emotet)
- February: 400 samples (mostly Ryuk)  
- March: 300 samples (new QakBot variant)

QUESTION: Which split is WRONG and why?

Option A: Random 70/30 split (any sample can be in train or test)

Option B: Time-based split (Jan-Feb for training, March for testing)

Option C: Train on all data, test on all data

Option D: Train on Emotet+Ryuk only, test on QakBot only

Think about:
- Data leakage
- Concept drift
- Real-world deployment scenarios
""")
    
    # TODO: Uncomment and fill in your answer
    # print("\nMy answer: Option ___ is wrong because...")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run all exercises."""
    print("\n" + "=" * 60)
    print("Lab 00b: ML Concepts - Interactive Exercises")
    print("=" * 60)
    print("\nThis lab helps you build intuition for ML concepts.")
    print("Complete the TODOs in each function, then run to check.\n")
    
    exercises = [
        ("1", "Feature Engineering", exercise_1),
        ("2", "Understanding Metrics", exercise_2),
        ("3", "Data Patterns", exercise_3),
        ("4", "Train/Test Split", exercise_4),
    ]
    
    print("Available exercises:")
    for num, name, _ in exercises:
        print(f"  {num}. {name}")
    print("  A. Run all")
    
    choice = input("\nWhich exercise? (1-4 or A): ").strip().upper()
    
    if choice == "A":
        for _, _, func in exercises:
            func()
            print("\n")
    elif choice in ["1", "2", "3", "4"]:
        idx = int(choice) - 1
        exercises[idx][2]()
    else:
        print("Running all exercises...")
        for _, _, func in exercises:
            func()
            print("\n")


if __name__ == "__main__":
    main()

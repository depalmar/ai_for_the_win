#!/usr/bin/env python3
"""
Lab 00b: Machine Learning Concepts for Security - SOLUTIONS

This file contains completed solutions for all exercises.
Compare with your starter/main.py implementation.
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
# EXERCISE 1: Feature Engineering - SOLUTION
# =============================================================================

def extract_email_features(email: dict) -> dict:
    """
    Extract features from an email for ML classification.
    
    These features help distinguish phishing from legitimate emails.
    """
    subject = email.get("subject", "").lower()
    body = email.get("body", "").lower()
    full_text = subject + " " + body
    original_subject = email.get("subject", "")
    
    # Urgency words commonly found in phishing
    urgency_words = ["urgent", "immediately", "now", "fast", "act", "quick", "expire"]
    
    # Money/prize words
    money_words = ["won", "prize", "$", "money", "cash", "reward", "million", "congratulations"]
    
    # Action words that demand user interaction
    action_words = ["click", "verify", "confirm", "update", "login", "sign"]
    
    features = {
        # Feature 1: Total word count (phishing often shorter or longer than normal)
        "word_count": len(full_text.split()),
        
        # Feature 2: Contains urgency words
        "has_urgency": any(word in full_text for word in urgency_words),
        
        # Feature 3: Contains money-related words
        "has_money_words": any(word in full_text for word in money_words),
        
        # Feature 4: Contains action words (click, verify, etc.)
        "has_action_words": any(word in full_text for word in action_words),
        
        # Feature 5: Ratio of uppercase letters in subject (URGENT!!!)
        "caps_ratio": sum(1 for c in original_subject if c.isupper()) / max(len(original_subject), 1),
        
        # Bonus features:
        "exclamation_count": full_text.count("!"),
        "has_link_words": "click here" in full_text or "http" in full_text,
    }
    
    return features


def exercise_1():
    """Feature Engineering Exercise - SOLUTION."""
    print("=" * 60)
    print("EXERCISE 1: Feature Engineering - SOLUTION")
    print("=" * 60)
    print("\nExtracted features from emails:\n")
    
    emails = load_data("sample_emails.json")
    
    phishing_features = []
    legit_features = []
    
    for email in emails:
        features = extract_email_features(email)
        label = email.get("label", "unknown")
        
        if label == "phishing":
            phishing_features.append(features)
        else:
            legit_features.append(features)
    
    # Show pattern analysis
    print("PATTERN ANALYSIS:")
    print("-" * 40)
    
    def avg_feature(samples, key):
        values = [s[key] for s in samples]
        if isinstance(values[0], bool):
            return sum(values) / len(values) * 100  # Percentage
        return sum(values) / len(values)
    
    print(f"\n{'Feature':<20} {'Phishing':>12} {'Legitimate':>12}")
    print("-" * 46)
    
    for feature in ["word_count", "has_urgency", "has_money_words", "has_action_words", "caps_ratio"]:
        p_val = avg_feature(phishing_features, feature)
        l_val = avg_feature(legit_features, feature)
        if "has_" in feature:
            print(f"{feature:<20} {p_val:>10.0f}% {l_val:>10.0f}%")
        else:
            print(f"{feature:<20} {p_val:>12.2f} {l_val:>12.2f}")
    
    print("\n✓ Good features show different patterns between classes!")
    print("  - Phishing: higher urgency, money words, action words")
    print("  - Legitimate: no urgency, business-related content")


# =============================================================================
# EXERCISE 2: Understanding Metrics - SOLUTION
# =============================================================================

def calculate_metrics(predictions: list[str], actuals: list[str], positive_class: str = "phishing") -> dict:
    """
    Calculate classification metrics from predictions.
    """
    tp = fp = tn = fn = 0
    
    for pred, actual in zip(predictions, actuals):
        if pred == positive_class and actual == positive_class:
            tp += 1  # Correctly identified phishing
        elif pred == positive_class and actual != positive_class:
            fp += 1  # False alarm - said phishing but wasn't
        elif pred != positive_class and actual != positive_class:
            tn += 1  # Correctly identified legitimate
        else:  # pred != positive_class and actual == positive_class
            fn += 1  # Missed phishing!
    
    # Calculate metrics (handle division by zero)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(predictions) if predictions else 0.0
    
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3)
    }


def exercise_2():
    """Metrics Exercise - SOLUTION."""
    print("=" * 60)
    print("EXERCISE 2: Understanding Metrics - SOLUTION")
    print("=" * 60)
    
    actuals =      ["phishing", "legitimate", "phishing", "legitimate", "phishing", 
                    "legitimate", "legitimate", "phishing", "legitimate", "phishing"]
    
    # Scenario A: Conservative - High precision, lower recall
    predictions_a = ["phishing", "legitimate", "legitimate", "legitimate", "phishing",
                     "legitimate", "legitimate", "phishing", "legitimate", "legitimate"]
    
    # Scenario B: Aggressive - High recall, lower precision
    predictions_b = ["phishing", "phishing", "phishing", "legitimate", "phishing",
                     "phishing", "legitimate", "phishing", "legitimate", "phishing"]
    
    print("\nActual labels:", actuals)
    print(f"(5 phishing, 5 legitimate)\n")
    
    print("SCENARIO A (Conservative Detector):")
    print(f"Predictions: {predictions_a}")
    metrics_a = calculate_metrics(predictions_a, actuals)
    print(f"  TP={metrics_a['tp']}, FP={metrics_a['fp']}, TN={metrics_a['tn']}, FN={metrics_a['fn']}")
    print(f"  Precision: {metrics_a['precision']:.1%} (of alerts, how many were real)")
    print(f"  Recall: {metrics_a['recall']:.1%} (of real phishing, how many caught)")
    print(f"  F1: {metrics_a['f1']:.3f}")
    
    print("\nSCENARIO B (Aggressive Detector):")
    print(f"Predictions: {predictions_b}")
    metrics_b = calculate_metrics(predictions_b, actuals)
    print(f"  TP={metrics_b['tp']}, FP={metrics_b['fp']}, TN={metrics_b['tn']}, FN={metrics_b['fn']}")
    print(f"  Precision: {metrics_b['precision']:.1%} (of alerts, how many were real)")
    print(f"  Recall: {metrics_b['recall']:.1%} (of real phishing, how many caught)")
    print(f"  F1: {metrics_b['f1']:.3f}")
    
    print("\n" + "=" * 40)
    print("ANSWERS:")
    print("=" * 40)
    print("""
1. Hospital ransomware detection → SCENARIO B (High Recall)
   - Can't afford to miss ransomware attacks
   - Better to have false alarms than miss real threats
   - Staff can investigate false positives

2. Personal spam filter → SCENARIO A (High Precision)  
   - Don't want important emails marked as spam
   - Missing some spam is acceptable
   - User experience matters

3. SOC with limited capacity → SCENARIO A (High Precision)
   - Analysts have alert fatigue
   - Too many false positives = analysts ignore alerts
   - Quality over quantity
""")


# =============================================================================
# EXERCISE 3: Identifying Data Patterns - SOLUTION
# =============================================================================

def analyze_network_traffic(samples: list[dict]) -> dict:
    """Analyze network traffic samples to identify patterns."""
    by_label = {}
    for sample in samples:
        label = sample.get("label", "unknown")
        if label not in by_label:
            by_label[label] = []
        by_label[label].append(sample)
    
    stats = {}
    for label, label_samples in by_label.items():
        n = len(label_samples)
        stats[label] = {
            "count": n,
            "avg_bytes_sent": sum(s["bytes_sent"] for s in label_samples) / n,
            "avg_bytes_recv": sum(s["bytes_recv"] for s in label_samples) / n,
            "avg_duration": sum(s["duration_sec"] for s in label_samples) / n,
            "avg_packets": sum(s["packets"] for s in label_samples) / n,
            # Derived features
            "bytes_ratio": sum(s["bytes_sent"] for s in label_samples) / max(sum(s["bytes_recv"] for s in label_samples), 1),
        }
    
    return stats


def exercise_3():
    """Data Analysis Exercise - SOLUTION."""
    print("=" * 60)
    print("EXERCISE 3: Data Patterns - SOLUTION")
    print("=" * 60)
    
    samples = load_data("network_samples.json")
    stats = analyze_network_traffic(samples)
    
    print("\nTraffic Statistics by Type:")
    print("-" * 60)
    print(f"{'Type':<15} {'Count':>6} {'Bytes Sent':>12} {'Bytes Recv':>12} {'Duration':>10} {'Packets':>8}")
    print("-" * 60)
    
    for label, s in stats.items():
        print(f"{label:<15} {s['count']:>6} {s['avg_bytes_sent']:>12.0f} {s['avg_bytes_recv']:>12.0f} {s['avg_duration']:>10.0f} {s['avg_packets']:>8.0f}")
    
    print("\n" + "=" * 40)
    print("PATTERN ANALYSIS:")
    print("=" * 40)
    print("""
BEACON TRAFFIC:
  ✓ Very consistent: exactly 100 bytes sent, 100 bytes recv
  ✓ Fixed duration: always 60 seconds
  ✓ Minimal packets: only 2 packets
  → C2 beacons often have regular, predictable patterns!

EXFILTRATION TRAFFIC:
  ✓ High bytes_sent: 500K-800K bytes outbound
  ✓ Low bytes_recv: very little inbound
  ✓ High send/recv ratio: sending >> receiving
  → Data theft shows asymmetric traffic!

NORMAL TRAFFIC:
  ✓ Moderate, varied values
  ✓ More bytes received than sent (typical browsing)
  ✓ Longer duration, more packets

BEST FEATURES FOR ML:
  1. bytes_sent/bytes_recv ratio (detects exfiltration)
  2. Coefficient of variation in timing (detects beacons)
  3. Packet size consistency (beacons are regular)
""")


# =============================================================================
# EXERCISE 4: Train/Test Split - SOLUTION
# =============================================================================

def exercise_4():
    """Train/Test Split Exercise - SOLUTION."""
    print("=" * 60)
    print("EXERCISE 4: Train/Test Split - SOLUTION")
    print("=" * 60)
    
    print("""
ANALYSIS OF EACH OPTION:

Option A: Random 70/30 split
  ✓ ACCEPTABLE for initial experiments
  ⚠ May mix time periods (data leakage risk)
  → Commonly used but not ideal for production

Option B: Time-based split (Jan-Feb train, March test)  
  ✓ BEST PRACTICE for security ML
  ✓ Simulates real deployment (train on past, predict future)
  ✓ Tests for concept drift naturally
  → This is how your model will actually be used!

Option C: Train on all data, test on all data
  ✗ WRONG - This is cheating!
  ✗ Model memorizes training data
  ✗ Will show artificially high accuracy
  ✗ Will fail completely in production
  → NEVER evaluate on training data

Option D: Train on Emotet+Ryuk, test on QakBot
  ✓ GOOD for testing generalization
  ✓ Tests if model can detect NEW malware families
  ⚠ Very challenging - may show low accuracy
  → Useful for understanding model limitations

ANSWER: Option C is WRONG because it's data leakage.
The model has already "seen the answers" during training.
""")


# =============================================================================
# BONUS: ML Intuition Demo
# =============================================================================

def bonus_demo():
    """Interactive demonstration of ML concepts."""
    print("=" * 60)
    print("BONUS: Build Your Own Simple Classifier")
    print("=" * 60)
    
    print("""
Let's build a rule-based "classifier" to understand how ML works.
We'll create simple rules, then see how ML would improve them.
""")
    
    emails = load_data("sample_emails.json")
    
    # Simple rule-based classifier
    def simple_classifier(email: dict) -> str:
        """Rule-based classifier (what ML learns automatically)."""
        text = (email.get("subject", "") + " " + email.get("body", "")).lower()
        
        # Rule 1: Urgency words
        if any(w in text for w in ["urgent", "immediately", "now"]):
            return "phishing"
        
        # Rule 2: Prize/money words
        if any(w in text for w in ["won", "prize", "million", "$"]):
            return "phishing"
        
        # Rule 3: Click to verify
        if "click" in text and ("verify" in text or "account" in text):
            return "phishing"
        
        return "legitimate"
    
    print("Testing simple rule-based classifier:")
    print("-" * 40)
    
    correct = 0
    for email in emails:
        prediction = simple_classifier(email)
        actual = email.get("label")
        is_correct = prediction == actual
        correct += is_correct
        
        status = "✓" if is_correct else "✗"
        print(f"{status} Predicted: {prediction:<12} Actual: {actual:<12} | {email['subject'][:30]}...")
    
    print(f"\nAccuracy: {correct}/{len(emails)} = {correct/len(emails):.0%}")
    print("""
KEY INSIGHT:
  We manually wrote rules based on patterns we observed.
  ML does this AUTOMATICALLY by learning from labeled examples!
  
  - We wrote 3 rules → ML might learn hundreds of patterns
  - Our rules are fixed → ML adapts as data changes
  - We need domain expertise → ML finds non-obvious patterns
""")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run all exercises with solutions."""
    print("\n" + "=" * 60)
    print("Lab 00b: ML Concepts - SOLUTIONS")
    print("=" * 60)
    
    exercises = [
        ("1", "Feature Engineering", exercise_1),
        ("2", "Understanding Metrics", exercise_2),
        ("3", "Data Patterns", exercise_3),
        ("4", "Train/Test Split", exercise_4),
        ("B", "Bonus Demo", bonus_demo),
    ]
    
    print("\nAvailable exercises:")
    for num, name, _ in exercises:
        print(f"  {num}. {name}")
    print("  A. Run all")
    
    choice = input("\nWhich exercise? (1-4, B, or A): ").strip().upper()
    
    if choice == "A":
        for _, _, func in exercises:
            func()
            print("\n")
    elif choice in ["1", "2", "3", "4"]:
        idx = int(choice) - 1
        exercises[idx][2]()
    elif choice == "B":
        bonus_demo()
    else:
        print("Running all exercises...")
        for _, _, func in exercises:
            func()
            print("\n")


if __name__ == "__main__":
    main()

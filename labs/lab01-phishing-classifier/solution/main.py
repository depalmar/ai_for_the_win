#!/usr/bin/env python3
"""
Lab 01: Phishing Email Classifier - Solution

Complete implementation of phishing email classifier.
"""

import re
from pathlib import Path
from typing import List, Tuple

import nltk
import numpy as np
import pandas as pd
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# Ensure NLTK data is available
try:
    stopwords.words("english")
except LookupError:
    nltk.download("stopwords")
    nltk.download("punkt")


# =============================================================================
# Task 1: Load and Explore Data - SOLUTION
# =============================================================================


def load_data(filepath: str) -> pd.DataFrame:
    """Load email dataset from CSV."""
    df = pd.read_csv(filepath)

    # Handle missing values
    df = df.dropna(subset=["text", "label"])

    # Ensure correct types
    df["label"] = df["label"].astype(int)
    df["text"] = df["text"].astype(str)

    print(f"Loaded {len(df)} emails")
    return df


def explore_data(df: pd.DataFrame) -> None:
    """Print exploratory statistics about the dataset."""
    print(f"\nDataset shape: {df.shape}")

    # Label distribution
    print("\nLabel distribution:")
    label_counts = df["label"].value_counts()
    total = len(df)
    for label, count in label_counts.items():
        label_name = "Phishing" if label == 1 else "Legitimate"
        print(f"  {label_name}: {count} ({count/total:.1%})")

    # Average text length
    print("\nAverage text length:")
    for label in [0, 1]:
        avg_len = df[df["label"] == label]["text"].str.len().mean()
        label_name = "Phishing" if label == 1 else "Legitimate"
        print(f"  {label_name}: {avg_len:.0f} characters")


# =============================================================================
# Task 2: Preprocess Text - SOLUTION
# =============================================================================


def preprocess_text(text: str) -> str:
    """Clean and normalize email text for ML processing."""
    if not isinstance(text, str):
        return ""

    # Convert to lowercase
    text = text.lower()

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Remove URLs
    text = re.sub(r'https?://[^\s<>"{}|\\^`\[\]]+', " ", text)

    # Remove email addresses
    text = re.sub(r"\S+@\S+", " ", text)

    # Remove special characters and digits
    text = re.sub(r"[^a-zA-Z\s]", " ", text)

    # Tokenize
    words = text.split()

    # Remove stopwords
    stop_words = set(stopwords.words("english"))
    words = [w for w in words if w not in stop_words and len(w) > 2]

    # Stemming
    stemmer = PorterStemmer()
    words = [stemmer.stem(w) for w in words]

    return " ".join(words)


def preprocess_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Apply preprocessing to entire dataset."""
    df = df.copy()
    df["clean_text"] = df["text"].apply(preprocess_text)
    return df


# =============================================================================
# Task 3: Extract Features - SOLUTION
# =============================================================================

URGENCY_WORDS = [
    "urgent",
    "immediate",
    "action required",
    "act now",
    "limited time",
    "expires",
    "suspended",
    "verify",
    "confirm",
    "alert",
    "warning",
    "attention",
    "important",
    "critical",
    "deadline",
    "asap",
]

SENSITIVE_WORDS = [
    "password",
    "credit card",
    "ssn",
    "social security",
    "bank account",
    "pin",
    "login",
    "credentials",
    "verify your",
    "confirm your",
    "update your",
    "billing",
    "payment",
]


def count_urls(text: str) -> int:
    """Count number of URLs in text."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return len(re.findall(url_pattern, str(text)))


def has_urgency(text: str) -> int:
    """Check if text contains urgency language."""
    text_lower = str(text).lower()
    return int(any(word in text_lower for word in URGENCY_WORDS))


def requests_sensitive_info(text: str) -> int:
    """Check if text requests sensitive information."""
    text_lower = str(text).lower()
    return int(any(word in text_lower for word in SENSITIVE_WORDS))


def calculate_caps_ratio(text: str) -> float:
    """Calculate ratio of uppercase letters."""
    text = str(text)
    alpha_chars = [c for c in text if c.isalpha()]
    if not alpha_chars:
        return 0.0
    upper_count = sum(1 for c in alpha_chars if c.isupper())
    return upper_count / len(alpha_chars)


def has_html(text: str) -> int:
    """Check if text contains HTML tags."""
    return int(bool(re.search(r"<[^>]+>", str(text))))


def extract_custom_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract phishing-relevant features from emails."""
    features = pd.DataFrame(index=df.index)

    features["url_count"] = df["text"].apply(count_urls)
    features["has_urgency"] = df["text"].apply(has_urgency)
    features["requests_sensitive"] = df["text"].apply(requests_sensitive_info)
    features["text_length"] = df["text"].str.len()
    features["word_count"] = df["text"].str.split().str.len()
    features["caps_ratio"] = df["text"].apply(calculate_caps_ratio)
    features["has_html"] = df["text"].apply(has_html)
    features["exclamation_count"] = df["text"].str.count("!")
    features["question_count"] = df["text"].str.count(r"\?")

    return features


# =============================================================================
# Task 4: Train Classifier - SOLUTION
# =============================================================================


def build_feature_matrix(
    df: pd.DataFrame, vectorizer: TfidfVectorizer = None
) -> Tuple[np.ndarray, TfidfVectorizer]:
    """Build complete feature matrix from raw DataFrame.

    This is a high-level function that:
    1. Extracts custom features
    2. Creates TF-IDF features from text
    3. Combines both into a single feature matrix
    """
    # Extract custom features
    features_df = extract_custom_features(df)

    # Create or use existing vectorizer
    if vectorizer is None:
        vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2), min_df=2, max_df=0.95)
        fit = True
    else:
        fit = False

    # Ensure we have clean_text column
    if "clean_text" not in df.columns:
        df = df.copy()
        df["clean_text"] = df["text"].apply(preprocess_text)

    # Transform text
    if fit:
        tfidf_features = vectorizer.fit_transform(df["clean_text"])
    else:
        tfidf_features = vectorizer.transform(df["clean_text"])

    # Combine with numeric features
    numeric_features = features_df.values
    X_combined = hstack([tfidf_features, numeric_features])

    return X_combined, vectorizer


def create_feature_matrix(
    df: pd.DataFrame,
    features_df: pd.DataFrame,
    vectorizer: TfidfVectorizer = None,
    fit: bool = True,
) -> Tuple[np.ndarray, TfidfVectorizer]:
    """Combine TF-IDF text features with extracted numeric features.

    Note: This is a lower-level function. Consider using build_feature_matrix() instead.
    """

    # Create or use existing vectorizer
    if vectorizer is None:
        vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2), min_df=2, max_df=0.95)

    # Transform text
    if fit:
        tfidf_features = vectorizer.fit_transform(df["clean_text"])
    else:
        tfidf_features = vectorizer.transform(df["clean_text"])

    # Combine with numeric features
    numeric_features = features_df.values
    X_combined = hstack([tfidf_features, numeric_features])

    return X_combined, vectorizer


def train_classifier(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """Train a Random Forest classifier."""
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    return model


# =============================================================================
# Task 5: Evaluate Model - SOLUTION
# =============================================================================


def evaluate_model(
    model_or_y_true,
    X_test_or_y_pred=None,
    y_test=None,
    feature_names: List[str] = None,
) -> dict:
    """Evaluate classifier performance.

    Supports two signatures:
    1. evaluate_model(y_true, y_pred) - Direct evaluation with labels and predictions
    2. evaluate_model(model, X_test, y_test, feature_names) - Model-based evaluation
    """

    # Determine which signature is being used
    if hasattr(model_or_y_true, "predict"):
        # Signature 2: model, X_test, y_test, feature_names
        model = model_or_y_true
        X_test = X_test_or_y_pred
        y_true = y_test
        # Generate predictions
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
    else:
        # Signature 1: y_true, y_pred
        y_true = model_or_y_true
        y_pred = X_test_or_y_pred
        y_proba = None

    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["Legitimate", "Phishing"]))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_true, y_pred)
    print(f"  TN: {cm[0,0]}  FP: {cm[0,1]}")
    print(f"  FN: {cm[1,0]}  TP: {cm[1,1]}")

    # Feature importance (for numeric features only)
    if "model" in locals() and hasattr(model, "feature_importances_") and feature_names:
        print("\nTop 10 Important Features:")
        importances = model.feature_importances_[-len(feature_names) :]
        indices = np.argsort(importances)[::-1][:10]
        for i, idx in enumerate(indices):
            if idx < len(feature_names):
                print(f"  {i+1}. {feature_names[idx]}: {importances[idx]:.4f}")

    return {
        "accuracy": accuracy,
        "confusion_matrix": cm,
        "predictions": y_pred,
        "probabilities": y_proba,
    }


# =============================================================================
# Task 6: Prediction Function - SOLUTION
# =============================================================================


def predict_phishing(
    model: RandomForestClassifier, vectorizer: TfidfVectorizer, email_text: str
) -> Tuple[int, float]:
    """Predict if an email is phishing."""

    # Create single-row DataFrame
    df = pd.DataFrame({"text": [email_text]})

    # Preprocess
    df["clean_text"] = df["text"].apply(preprocess_text)

    # Extract features
    features_df = extract_custom_features(df)

    # Create feature matrix
    X, _ = create_feature_matrix(df, features_df, vectorizer=vectorizer, fit=False)

    # Predict
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    confidence = probabilities[prediction]

    return int(prediction), float(confidence)


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    print("=" * 60)
    print("Lab 01: Phishing Email Classifier - SOLUTION")
    print("=" * 60)

    # Create sample data if needed
    data_path = Path(__file__).parent.parent / "data" / "emails.csv"
    if not data_path.exists():
        create_sample_data(data_path)

    # Load and explore
    df = load_data(str(data_path))
    explore_data(df)

    # Preprocess
    df = preprocess_dataset(df)

    # Extract features
    features_df = extract_custom_features(df)
    print(f"\nExtracted {len(features_df.columns)} features")

    # Split data
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df, df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    features_train = features_df.loc[X_train_df.index]
    features_test = features_df.loc[X_test_df.index]

    # Create feature matrices
    X_train, vectorizer = create_feature_matrix(X_train_df, features_train, fit=True)
    X_test, _ = create_feature_matrix(X_test_df, features_test, vectorizer=vectorizer, fit=False)

    # Train
    model = train_classifier(X_train, y_train)
    print("\nModel trained!")

    # Evaluate
    feature_names = list(features_df.columns)
    evaluate_model(model, X_test, y_test, feature_names)

    # Test predictions
    print("\n" + "=" * 60)
    print("Testing on sample emails:")
    print("=" * 60)

    test_emails = [
        (
            "Dear valued customer, your account has been compromised. Click here immediately to verify: http://bit.ly/xyz123",
            1,
        ),
        (
            "Hi John, the meeting has been moved to 3pm tomorrow. See you there! - Sarah",
            0,
        ),
        (
            "URGENT: Your PayPal account will be suspended! Verify now: paypa1-secure.com/verify",
            1,
        ),
        ("The quarterly report is attached. Let me know if you have questions.", 0),
    ]

    correct = 0
    for email, expected in test_emails:
        pred, conf = predict_phishing(model, vectorizer, email)
        is_correct = pred == expected
        correct += is_correct
        status = "✓" if is_correct else "✗"
        print(f"\n{status} Email: {email[:50]}...")
        print(f"   Expected: {'PHISHING' if expected else 'LEGITIMATE'}")
        print(f"   Predicted: {'PHISHING' if pred else 'LEGITIMATE'} ({conf:.1%} confidence)")

    print(f"\nAccuracy on test emails: {correct}/{len(test_emails)}")


def create_sample_data(filepath: Path):
    """Create sample dataset."""
    filepath.parent.mkdir(parents=True, exist_ok=True)

    phishing = [
        "URGENT: Your account has been compromised! Click here immediately to secure: http://scam.com/verify",
        "Dear Customer, We detected unusual activity. Verify your password now: http://fake-bank.com",
        "You've won $1,000,000! Claim your prize by sending your bank details to claim@scam.com",
        "Your PayPal account will be suspended. Update billing info: http://paypa1.com/update",
        "ALERT: Unauthorized login detected! Confirm identity: http://security-check.com",
    ] * 40

    legitimate = [
        "Hi team, the meeting is scheduled for 3pm tomorrow. Please review the agenda attached.",
        "Thank you for your order. Your package will arrive in 3-5 business days.",
        "Here's the report you requested. Let me know if you have any questions.",
        "Reminder: Your subscription will renew next month. No action needed.",
        "Great catching up yesterday! Let's schedule lunch next week.",
    ] * 60

    df = pd.DataFrame(
        {
            "text": phishing + legitimate,
            "label": [1] * len(phishing) + [0] * len(legitimate),
        }
    )

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(filepath, index=False)


if __name__ == "__main__":
    main()

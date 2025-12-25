#!/usr/bin/env python3
"""
Lab 01: Phishing Email Classifier - Starter Code

Build a machine learning classifier to detect phishing emails.

Instructions:
1. Complete each TODO section
2. Run tests with: pytest tests/test_classifier.py
3. Compare with solution when done
"""

import re
from pathlib import Path
from typing import List, Tuple

# NLP imports
import nltk
import numpy as np
import pandas as pd
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ML imports
from sklearn.model_selection import train_test_split

# Download NLTK data (run once)
# nltk.download('stopwords')
# nltk.download('punkt')


# =============================================================================
# Task 1: Load and Explore Data
# =============================================================================


def load_data(filepath: str) -> pd.DataFrame:
    """
    Load email dataset from CSV.

    Args:
        filepath: Path to CSV file

    Expected columns:
    - text: Email body content
    - label: 0 = legitimate, 1 = phishing

    Returns:
        DataFrame with email data

    TODO:
    1. Load the CSV file using pandas
    2. Handle any missing values (drop rows with NaN)
    3. Ensure label column is integer type
    4. Print dataset info (shape, label distribution)
    5. Return the DataFrame
    """
    # YOUR CODE HERE
    pass


def explore_data(df: pd.DataFrame) -> None:
    """
    Print exploratory statistics about the dataset.

    TODO:
    1. Print shape of dataset
    2. Print label distribution (count and percentage)
    3. Print average text length per class
    4. Show sample emails from each class
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 2: Preprocess Text
# =============================================================================


def preprocess_text(text: str) -> str:
    """
    Clean and normalize email text for ML processing.

    Args:
        text: Raw email text

    Returns:
        Cleaned and normalized text

    TODO:
    1. Convert to lowercase
    2. Remove HTML tags (e.g., <html>, <p>, etc.)
    3. Remove URLs (http/https links)
    4. Remove email addresses
    5. Remove special characters and digits
    6. Tokenize into words
    7. Remove stopwords
    8. Apply stemming
    9. Join back into string
    """
    # YOUR CODE HERE
    pass


def preprocess_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply preprocessing to entire dataset.

    Args:
        df: DataFrame with 'text' column

    Returns:
        DataFrame with added 'clean_text' column
    """
    df = df.copy()
    df["clean_text"] = df["text"].apply(preprocess_text)
    return df


# =============================================================================
# Task 3: Extract Features
# =============================================================================

# Urgency words commonly found in phishing emails
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

# Words requesting sensitive information
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
    """
    Count number of URLs in text.

    TODO: Use regex to find and count all URLs
    """
    # YOUR CODE HERE
    pass


def has_urgency(text: str) -> int:
    """
    Check if text contains urgency language.

    TODO: Return 1 if any urgency words found, 0 otherwise
    """
    # YOUR CODE HERE
    pass


def requests_sensitive_info(text: str) -> int:
    """
    Check if text requests sensitive information.

    TODO: Return 1 if any sensitive info words found, 0 otherwise
    """
    # YOUR CODE HERE
    pass


def calculate_caps_ratio(text: str) -> float:
    """
    Calculate ratio of uppercase letters.

    TODO: Return ratio of uppercase to total alphabetic characters
    """
    # YOUR CODE HERE
    pass


def has_html(text: str) -> int:
    """
    Check if text contains HTML tags.

    TODO: Return 1 if HTML tags found, 0 otherwise
    """
    # YOUR CODE HERE
    pass


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract phishing-relevant features from emails.

    Args:
        df: DataFrame with 'text' column

    Returns:
        DataFrame with extracted features

    TODO: Create these feature columns:
    1. url_count: Number of URLs
    2. has_urgency: Contains urgency words (0/1)
    3. requests_sensitive: Asks for sensitive info (0/1)
    4. text_length: Character count
    5. word_count: Word count
    6. caps_ratio: Ratio of uppercase letters
    7. has_html: Contains HTML (0/1)
    8. exclamation_count: Number of '!'
    9. question_count: Number of '?'
    """
    features = pd.DataFrame()

    # YOUR CODE HERE - Extract each feature

    return features


# =============================================================================
# Task 4: Train Classifier
# =============================================================================


def create_feature_matrix(
    df: pd.DataFrame,
    features_df: pd.DataFrame,
    vectorizer: TfidfVectorizer = None,
    fit: bool = True,
) -> Tuple[np.ndarray, TfidfVectorizer]:
    """
    Combine TF-IDF text features with extracted numeric features.

    Args:
        df: DataFrame with 'clean_text' column
        features_df: DataFrame with numeric features
        vectorizer: Existing vectorizer (for transform only)
        fit: Whether to fit the vectorizer

    Returns:
        Combined feature matrix and vectorizer

    TODO:
    1. Create or use TF-IDF vectorizer
    2. Transform text to TF-IDF features
    3. Combine with numeric features
    4. Return combined matrix
    """
    from scipy.sparse import hstack

    # YOUR CODE HERE
    pass


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Train a Random Forest classifier.

    Args:
        X_train: Training features
        y_train: Training labels

    Returns:
        Trained classifier

    TODO:
    1. Create RandomForestClassifier with good hyperparameters
    2. Fit on training data
    3. Return trained model

    Suggested hyperparameters:
    - n_estimators: 100-200
    - max_depth: 10-20
    - class_weight: 'balanced' (for imbalanced data)
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 5: Evaluate Model
# =============================================================================


def evaluate_model(
    model: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: List[str] = None,
) -> dict:
    """
    Evaluate classifier performance.

    Args:
        model: Trained classifier
        X_test: Test features
        y_test: Test labels
        feature_names: Names of features for importance analysis

    Returns:
        Dictionary with evaluation metrics

    TODO:
    1. Generate predictions
    2. Calculate accuracy, precision, recall, F1
    3. Print classification report
    4. Print confusion matrix
    5. Print top 10 important features (if available)
    6. Return metrics dictionary
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Task 6: Prediction Function
# =============================================================================


def predict_phishing(
    model: RandomForestClassifier, vectorizer: TfidfVectorizer, email_text: str
) -> Tuple[int, float]:
    """
    Predict if an email is phishing.

    Args:
        model: Trained classifier
        vectorizer: Fitted TF-IDF vectorizer
        email_text: Raw email text

    Returns:
        Tuple of (prediction, confidence)
        - prediction: 0 = legitimate, 1 = phishing
        - confidence: Probability of the predicted class

    TODO:
    1. Preprocess the email text
    2. Extract features
    3. Create feature matrix
    4. Make prediction
    5. Get prediction probability
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    print("=" * 60)
    print("Lab 01: Phishing Email Classifier")
    print("=" * 60)

    # Task 1: Load data
    print("\n[Task 1] Loading data...")
    data_path = Path(__file__).parent.parent / "data" / "emails.csv"

    # If no data file, create sample data
    if not data_path.exists():
        print("Creating sample dataset...")
        create_sample_data(data_path)

    df = load_data(str(data_path))
    if df is None:
        print("ERROR: load_data() not implemented!")
        return

    explore_data(df)

    # Task 2: Preprocess text
    print("\n[Task 2] Preprocessing text...")
    df = preprocess_dataset(df)
    print(f"Sample cleaned text: {df['clean_text'].iloc[0][:100]}...")

    # Task 3: Extract features
    print("\n[Task 3] Extracting features...")
    features_df = extract_features(df)
    if features_df.empty:
        print("ERROR: extract_features() not implemented!")
        return

    print(f"Extracted {len(features_df.columns)} features:")
    print(features_df.columns.tolist())

    # Task 4: Train model
    print("\n[Task 4] Training model...")

    # Split data
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df, df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    features_train = features_df.loc[X_train_df.index]
    features_test = features_df.loc[X_test_df.index]

    # Create feature matrices
    X_train, vectorizer = create_feature_matrix(X_train_df, features_train, fit=True)
    X_test, _ = create_feature_matrix(X_test_df, features_test, vectorizer=vectorizer, fit=False)

    if X_train is None:
        print("ERROR: create_feature_matrix() not implemented!")
        return

    # Train model
    model = train_model(X_train, y_train)
    if model is None:
        print("ERROR: train_model() not implemented!")
        return

    print("Model trained successfully!")

    # Task 5: Evaluate model
    print("\n[Task 5] Evaluating model...")
    metrics = evaluate_model(model, X_test, y_test)

    # Task 6: Test on new emails
    print("\n[Task 6] Testing on sample emails...")
    test_emails = [
        "Dear valued customer, your account has been compromised. Click here immediately to verify: http://bit.ly/xyz123",
        "Hi John, the meeting has been moved to 3pm tomorrow. See you there! - Sarah",
        "URGENT: Your PayPal account will be suspended! Verify now: paypa1-secure.com/verify",
        "The quarterly report is attached. Let me know if you have questions.",
    ]

    expected = [1, 0, 1, 0]  # Expected labels

    print("\nPredictions:")
    for i, email in enumerate(test_emails):
        pred, conf = predict_phishing(model, vectorizer, email)
        status = "✓" if pred == expected[i] else "✗"
        print(f"\n{status} Email: {email[:60]}...")
        print(f"   Prediction: {'PHISHING' if pred else 'LEGITIMATE'} (confidence: {conf:.2%})")

    print("\n" + "=" * 60)
    print("Lab Complete!")
    print("=" * 60)


def create_sample_data(filepath: Path):
    """Create sample dataset for testing."""
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Sample phishing emails
    phishing = [
        "URGENT: Your account has been compromised! Click here immediately to secure: http://scam.com/verify",
        "Dear Customer, We detected unusual activity. Verify your password now: http://fake-bank.com",
        "You've won $1,000,000! Claim your prize by sending your bank details to claim@scam.com",
        "Your PayPal account will be suspended. Update billing info: http://paypa1.com/update",
        "ALERT: Unauthorized login detected! Confirm identity: http://security-check.com",
    ] * 40  # 200 phishing

    # Sample legitimate emails
    legitimate = [
        "Hi team, the meeting is scheduled for 3pm tomorrow. Please review the agenda attached.",
        "Thank you for your order. Your package will arrive in 3-5 business days.",
        "Here's the report you requested. Let me know if you have any questions.",
        "Reminder: Your subscription will renew next month. No action needed.",
        "Great catching up yesterday! Let's schedule lunch next week.",
    ] * 60  # 300 legitimate

    df = pd.DataFrame(
        {
            "text": phishing + legitimate,
            "label": [1] * len(phishing) + [0] * len(legitimate),
        }
    )

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(filepath, index=False)
    print(f"Created sample dataset with {len(df)} emails")


if __name__ == "__main__":
    main()

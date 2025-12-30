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
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to load a CSV file into a pandas DataFrame.
    # The function should: load the CSV from the given filepath, drop any
    # rows with missing values, ensure the 'label' column is integer type,
    # print the dataset shape and label distribution, then return the DataFrame."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
    pass


def explore_data(df: pd.DataFrame) -> None:
    """
    Print exploratory statistics about the dataset.
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to explore a pandas DataFrame containing email data.
    # The function should: print the dataset shape, print label distribution
    # (count and percentage), print average text length per class, and show
    # sample emails from each class (phishing and legitimate)."
    #
    # Then review and test the generated code.
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
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to preprocess email text for machine learning.
    # The function should: convert to lowercase, remove HTML tags, remove URLs,
    # remove email addresses, remove special characters and digits, tokenize
    # into words, remove stopwords using NLTK, apply Porter stemming, and
    # join the tokens back into a single string."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
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
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to count the number of URLs in a text string using
    # regex. The function should find all http and https URLs and return
    # the count as an integer."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
    pass


def has_urgency(text: str) -> int:
    """
    Check if text contains urgency language.
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to check if text contains urgency language.
    # The function should check if any word from the URGENCY_WORDS list
    # (defined globally) appears in the lowercase text. Return 1 if any
    # urgency word is found, 0 otherwise."
    #
    # Then review and test the generated code.
    pass


def requests_sensitive_info(text: str) -> int:
    """
    Check if text requests sensitive information.
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to check if text requests sensitive information.
    # The function should check if any phrase from the SENSITIVE_WORDS list
    # (defined globally) appears in the lowercase text. Return 1 if any
    # sensitive word is found, 0 otherwise."
    #
    # Then review and test the generated code.
    pass


def calculate_caps_ratio(text: str) -> float:
    """
    Calculate ratio of uppercase letters.
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to calculate the ratio of uppercase letters in text.
    # The function should count uppercase alphabetic characters divided by
    # total alphabetic characters. Handle the edge case where there are no
    # alphabetic characters (return 0.0)."
    #
    # Then review and test the generated code.
    pass


def has_html(text: str) -> int:
    """
    Check if text contains HTML tags.
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to check if text contains HTML tags using regex.
    # The function should detect patterns like <html>, <p>, </div>, etc.
    # Return 1 if any HTML tag is found, 0 otherwise."
    #
    # Then review and test the generated code.
    pass


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract phishing-relevant features from emails.

    Args:
        df: DataFrame with 'text' column

    Returns:
        DataFrame with extracted features
    """
    features = pd.DataFrame()

    # TODO: Ask your AI assistant:
    # "Write Python code to extract phishing detection features from a DataFrame.
    # Using the 'text' column, create these feature columns in the features DataFrame:
    # url_count (using count_urls), has_urgency (using has_urgency function),
    # requests_sensitive (using requests_sensitive_info), text_length (character count),
    # word_count (word count), caps_ratio (using calculate_caps_ratio),
    # has_html (using has_html function), exclamation_count (count of '!'),
    # and question_count (count of '?')."
    #
    # Then review and test the generated code.

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
    """
    from scipy.sparse import hstack

    # TODO: Ask your AI assistant:
    # "Write Python code to create a combined feature matrix for ML classification.
    # The function should: create a TfidfVectorizer with max_features=5000 if none
    # provided, fit_transform or transform the 'clean_text' column based on the
    # 'fit' parameter, combine the TF-IDF sparse matrix with the numeric features
    # DataFrame using scipy.sparse.hstack, and return the combined matrix along
    # with the vectorizer."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
    pass


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Train a Random Forest classifier.

    Args:
        X_train: Training features
        y_train: Training labels

    Returns:
        Trained classifier

    Suggested hyperparameters:
    - n_estimators: 100-200
    - max_depth: 10-20
    - class_weight: 'balanced' (for imbalanced data)
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to train a RandomForestClassifier for phishing detection.
    # The function should create a classifier with n_estimators=100, max_depth=15,
    # class_weight='balanced', and random_state=42 for reproducibility. Fit the
    # model on the training data and return the trained classifier."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
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
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to evaluate a trained classifier's performance.
    # The function should: generate predictions on X_test, calculate accuracy
    # using accuracy_score, print the classification report with target names
    # ['Legitimate', 'Phishing'], print the confusion matrix, optionally print
    # the top 10 most important features if feature_names is provided, and
    # return a dictionary containing 'accuracy', 'predictions', and 'confusion_matrix'."
    #
    # Then review and test the generated code.
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
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to predict if a single email is phishing.
    # The function should: preprocess the email text using preprocess_text,
    # create a single-row DataFrame, extract features using extract_features,
    # create the feature matrix using create_feature_matrix with fit=False,
    # make a prediction using the model, get the prediction probability using
    # predict_proba, and return a tuple of (prediction, confidence) where
    # confidence is the probability of the predicted class."
    #
    # Then review and test the generated code.
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

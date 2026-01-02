"""
Lab 00f: Hello World ML - Spam Classifier (Solution)

A complete working spam classifier demonstrating the 4-step ML workflow.
"""

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score


# ============================================================================
# SAMPLE DATA - Messages labeled as spam (1) or not spam (0)
# ============================================================================

MESSAGES = [
    # Spam messages (label = 1)
    "FREE MONEY! Click now to claim your prize!",
    "URGENT: Your account has been compromised! Act now!",
    "Congratulations! You've won $1,000,000!",
    "Click here for FREE iPhone! Limited time offer!",
    "WINNER! You have been selected for a cash prize!",
    "FREE FREE FREE! Don't miss this opportunity!",
    "Urgent action required! Your account will be suspended!",
    "You've won a FREE vacation! Click to claim!",
    "AMAZING DEAL! Get rich quick with this secret!",
    "Final warning! Claim your prize money now!",
    "FREE gift card! Click the link below!",
    "URGENT: Verify your account immediately!",
    "You're a WINNER! $500 cash prize waiting!",
    "Limited offer! FREE products just for you!",
    "Act NOW! This deal expires in 24 hours!",
    "Congratulations! You've been selected to win!",
    "FREE trial! No credit card required! Click now!",
    "URGENT URGENT URGENT! Don't ignore this!",
    "Win a FREE car! Enter our contest today!",
    "Your prize money of $10,000 is ready!",
    "FREE membership! Join now and save!",
    "ALERT: Suspicious activity on your account!",
    "Click here to claim your FREE reward!",
    "You won! Collect your prize immediately!",
    "FREE download! Get it before it's gone!",
    # Not spam messages (label = 0)
    "Hey, want to grab lunch tomorrow?",
    "Meeting moved to 3pm, see you there",
    "Can you review the document I sent?",
    "Thanks for your help with the project",
    "The report is ready for your review",
    "Let's schedule a call for next week",
    "Please find the attached invoice",
    "Looking forward to seeing you at the conference",
    "Here's the update on the quarterly numbers",
    "Can we discuss the budget tomorrow?",
    "Great job on the presentation!",
    "I'll send over the files this afternoon",
    "The team meeting is at 10am",
    "Please review and let me know your thoughts",
    "Thanks for the quick response",
    "The project deadline is next Friday",
    "I've updated the spreadsheet as requested",
    "Can you join the video call at 2pm?",
    "Here's the summary from today's meeting",
    "Please confirm your attendance",
    "The client approved the proposal",
    "I'll be out of office next Monday",
    "Let's sync up on the timeline",
    "Good morning, hope you had a nice weekend",
    "Attached is the signed contract",
]

LABELS = [1] * 25 + [0] * 25

SPAM_WORDS = [
    "free",
    "win",
    "click",
    "urgent",
    "money",
    "prize",
    "congratulations",
    "winner",
    "claim",
    "act",
    "now",
    "limited",
    "offer",
    "deal",
]


# ============================================================================
# SOLUTION: Feature extractor
# ============================================================================


def extract_features(message: str) -> list:
    """
    Extract features from a message.

    Args:
        message: The text message to analyze

    Returns:
        A list of features
    """
    message_lower = message.lower()

    # Feature 1: Count of spam words
    spam_word_count = sum(1 for word in SPAM_WORDS if word in message_lower)

    # Feature 2: Number of exclamation marks (bonus feature)
    exclamation_count = message.count("!")

    # Feature 3: Ratio of uppercase letters (bonus feature)
    if len(message) > 0:
        uppercase_ratio = sum(1 for c in message if c.isupper()) / len(message)
    else:
        uppercase_ratio = 0

    return [spam_word_count, exclamation_count, uppercase_ratio]


def main():
    print("📊 Hello World ML - Spam Classifier")
    print("=" * 40)

    # Step 1: Load data
    print("\nStep 1: Loading data...")
    messages = MESSAGES
    labels = LABELS
    spam_count = sum(labels)
    print(
        f"  Loaded {len(messages)} messages ({spam_count} spam, {len(messages) - spam_count} not spam)"
    )

    # Step 2: Extract features
    print("\nStep 2: Extracting features...")
    features = [extract_features(msg) for msg in messages]
    X = np.array(features)
    y = np.array(labels)
    print("  Features: spam word count, exclamation marks, uppercase ratio")

    # Step 3: Split data (SOLUTION)
    print("\nStep 3: Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"  Training set: {len(X_train)} messages")
    print(f"  Test set: {len(X_test)} messages")

    # Step 4: Train model (SOLUTION)
    print("\nStep 4: Training model...")
    print("  Model: LogisticRegression")
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)
    print("  Training complete!")

    # Step 5: Make predictions (SOLUTION)
    print("\nStep 5: Making predictions...")
    predictions = model.predict(X_test)
    print("  Predictions made on test set")

    # Step 6: Evaluate (SOLUTION)
    print("\nStep 6: Evaluating...")
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)

    print(f"  Accuracy: {accuracy:.1%}")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall: {recall:.1%}")

    # Explain the metrics
    print("\n📖 What these metrics mean:")
    print(f"  • Accuracy: {accuracy:.0%} of all predictions were correct")
    print(f"  • Precision: When we said 'spam', we were right {precision:.0%} of the time")
    print(f"  • Recall: We caught {recall:.0%} of all actual spam")

    # Test on new messages
    print("\n" + "=" * 40)
    print("✅ Your first ML model is working!")
    print("\nTest it yourself:")

    test_messages = [
        "FREE MONEY NOW! Click here!",
        "Meeting at 3pm tomorrow",
        "URGENT: Claim your prize!",
        "Thanks for the update",
        "WIN WIN WIN! You're a winner!",
        "Please review the attached document",
    ]

    for msg in test_messages:
        features = extract_features(msg)
        pred = model.predict([features])[0]
        proba = model.predict_proba([features])[0]
        confidence = max(proba) * 100
        label = "SPAM ❌" if pred == 1 else "NOT SPAM ✅"
        print(f'  "{msg[:35]:35s}" → {label} ({confidence:.0f}% confident)')

    # Show feature importance
    print("\n📊 Feature Importance:")
    feature_names = ["Spam words", "Exclamations", "Uppercase ratio"]
    for name, coef in zip(feature_names, model.coef_[0]):
        direction = "↑ more spam" if coef > 0 else "↓ less spam"
        print(f"  {name}: {coef:+.2f} ({direction})")


if __name__ == "__main__":
    main()

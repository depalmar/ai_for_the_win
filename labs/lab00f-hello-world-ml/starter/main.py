"""
Lab 00f: Hello World ML - Spam Classifier (Starter)

Your first machine learning model! Complete the TODOs to build a working spam detector.

The 4-step ML workflow:
1. Load data
2. Train model
3. Predict
4. Evaluate
"""

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

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

# Labels: 1 = spam, 0 = not spam
# First 25 messages are spam, last 25 are not spam
LABELS = [1] * 25 + [0] * 25


# ============================================================================
# SPAM INDICATOR WORDS
# ============================================================================

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
# TODO 1: Create the feature extractor
# ============================================================================


def extract_features(message: str) -> list:
    """
    Extract features from a message.

    For now, we'll use a simple approach: count how many spam words appear.

    Args:
        message: The text message to analyze

    Returns:
        A list of features (just one feature for now: spam word count)
    """
    # TODO: Count how many SPAM_WORDS appear in the message
    # Hint: Convert message to lowercase first
    # Hint: Use 'in' to check if a word appears in the message

    # Your code here:
    spam_word_count = 0  # Replace this with actual counting

    return [spam_word_count]


# ============================================================================
# MAIN FUNCTION
# ============================================================================


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
    # Convert each message to a feature vector
    features = [extract_features(msg) for msg in messages]
    X = np.array(features)
    y = np.array(labels)
    print("  Feature: spam word count per message")

    # ========================================================================
    # TODO 2: Split data into training and test sets
    # ========================================================================
    print("\nStep 3: Splitting data...")

    # TODO: Use train_test_split to split X and y
    # - test_size=0.2 means 20% for testing, 80% for training
    # - random_state=42 makes results reproducible

    # Your code here:
    # X_train, X_test, y_train, y_test = ???

    # Placeholder - remove these lines after completing TODO 2
    X_train, X_test = X[:40], X[40:]
    y_train, y_test = y[:40], y[40:]

    print(f"  Training set: {len(X_train)} messages")
    print(f"  Test set: {len(X_test)} messages")

    # ========================================================================
    # TODO 3: Train the model
    # ========================================================================
    print("\nStep 4: Training model...")
    print("  Model: LogisticRegression")

    # TODO: Create a LogisticRegression model and train it
    # Hint: model = LogisticRegression()
    # Hint: model.fit(X_train, y_train)

    # Your code here:
    model = None  # Replace with actual model

    print("  Training complete!")

    # ========================================================================
    # TODO 4: Make predictions
    # ========================================================================
    print("\nStep 5: Making predictions...")

    # TODO: Use the trained model to predict on test data
    # Hint: predictions = model.predict(X_test)

    # Your code here:
    predictions = np.zeros(len(X_test))  # Replace with actual predictions

    print("  Predictions made on test set")

    # ========================================================================
    # TODO 5: Calculate accuracy
    # ========================================================================
    print("\nStep 6: Evaluating...")

    # TODO: Calculate accuracy using accuracy_score
    # Hint: accuracy = accuracy_score(y_test, predictions)

    # Your code here:
    accuracy = 0.0  # Replace with actual calculation
    precision = 0.0  # Optional: precision_score(y_test, predictions)
    recall = 0.0  # Optional: recall_score(y_test, predictions)

    print(f"  Accuracy: {accuracy:.1%}")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall: {recall:.1%}")

    # ========================================================================
    # Test on new messages
    # ========================================================================
    print("\n" + "=" * 40)
    print("✅ Your first ML model is working!")
    print("\nTest it yourself:")

    test_messages = [
        "FREE MONEY NOW! Click here!",
        "Meeting at 3pm tomorrow",
        "URGENT: Claim your prize!",
        "Thanks for the update",
    ]

    if model is not None:
        for msg in test_messages:
            features = extract_features(msg)
            pred = model.predict([features])[0]
            label = "SPAM ❌" if pred == 1 else "NOT SPAM ✅"
            print(f'  "{msg[:30]}..." → {label}')
    else:
        print("  (Complete TODOs to test predictions)")


if __name__ == "__main__":
    main()

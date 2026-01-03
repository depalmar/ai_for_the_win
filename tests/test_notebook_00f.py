# Test Lab 00f: Hello World ML
import numpy as np
from sklearn.linear_model import LogisticRegression

print("=" * 50)
print("Testing Lab 00f: Hello World ML")
print("=" * 50)

# Sample data
SPAM_WORDS = ["free", "winner", "click", "urgent", "limited", "offer", "act now", "congratulations"]

messages = [
    "FREE money! Click NOW to claim your prize!",
    "Meeting scheduled for 3pm tomorrow",
    "URGENT: Your account needs verification",
    "Here are the quarterly reports you requested",
    "Congratulations! You won a FREE iPhone!",
    "Can we reschedule our call to Friday?",
    "LIMITED TIME OFFER - Act now!",
    "Thanks for your help with the project",
]
labels = [1, 0, 1, 0, 1, 0, 1, 0]  # 1=spam, 0=not spam


def extract_features(message):
    message_lower = message.lower()
    spam_word_count = sum(1 for word in SPAM_WORDS if word in message_lower)
    return [spam_word_count]


# Prepare data
X = np.array([extract_features(msg) for msg in messages])
y = np.array(labels)

print(f"\nTraining data: {len(messages)} messages")
print(f"Features shape: {X.shape}")

# Train model
model = LogisticRegression()
model.fit(X, y)
print("[OK] Model trained successfully!")

# Test predictions
test_messages = [
    "FREE vacation! Winner selected!",
    "Lunch meeting at noon",
]

print("\nPredictions:")
for msg in test_messages:
    features = np.array([extract_features(msg)])
    pred = model.predict(features)[0]
    result = "SPAM" if pred == 1 else "NOT SPAM"
    print(f"  '{msg[:35]}...' -> {result}")

# Calculate accuracy on training data
train_preds = model.predict(X)
accuracy = (train_preds == y).mean()
print(f"\nTraining accuracy: {accuracy:.1%}")

print("\n[PASS] Lab 00f: PASSED")

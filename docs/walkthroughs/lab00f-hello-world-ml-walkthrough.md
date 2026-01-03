# Lab 00f: Hello World ML Walkthrough

Step-by-step guide to building your first machine learning classifier.

## Overview

This walkthrough guides you through:

1. Loading and understanding labeled data
2. Extracting simple features from text
3. Training a logistic regression model
4. Evaluating with accuracy, precision, recall

**Difficulty:** Intro
**Time:** 30-45 minutes
**Prerequisites:** Basic Python (Lab 00a)

---

## The Big Picture

Before we code, understand what we're building:

```
"FREE MONEY NOW!"     →  [3]  →  Model  →  1 (SPAM)
       ↓                   ↓
   Count spam words    Feature vector
```

**Key Insight**: ML models need numbers, not text. Our "feature extraction" step converts text to numbers.

---

## Exercise 1: Feature Extraction (TODO 1)

### The Problem

How do we convert `"FREE MONEY! Click now!"` into something a model can process?

### The Solution

Count how many "spam indicator" words appear:

```python
SPAM_WORDS = ["free", "win", "click", "urgent", "money", "prize",
              "congratulations", "winner", "claim", "act", "now",
              "limited", "offer", "deal"]

def extract_features(message: str) -> list:
    """Count how many spam words appear in the message."""
    message_lower = message.lower()
    spam_word_count = sum(1 for word in SPAM_WORDS if word in message_lower)
    return [spam_word_count]
```

### Why This Works

- Spam emails use urgency words: "FREE", "URGENT", "WIN"
- Normal emails rarely stack these words
- More spam words = higher probability of spam

### Testing It

```python
# Spam message - should have high count
spam = "FREE MONEY! Click NOW to claim your PRIZE!"
print(extract_features(spam))  # [5] - contains free, money, click, now, prize

# Normal message - should have low count
normal = "Meeting at 3pm tomorrow"
print(extract_features(normal))  # [0] - no spam words
```

---

## Exercise 2: Train/Test Split (TODO 2)

### The Problem

If we train AND test on the same data, the model "cheats" by memorizing answers.

### The Solution

Split data: 80% for training, 20% for testing:

```python
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,      # 20% for testing
    random_state=42     # Reproducible split
)
```

### Why `random_state=42`?

- Makes the split reproducible
- Your results will match mine
- Any number works; 42 is ML tradition (Hitchhiker's Guide reference)

### Visualizing the Split

```
50 messages total
├── 40 training (80%) → Model learns from these
└── 10 testing (20%)  → Model is evaluated on these
```

---

## Exercise 3: Training the Model (TODO 3)

### The Problem

We need an algorithm that learns the pattern: "high spam word count → spam"

### The Solution

Use Logistic Regression - simple and effective:

```python
from sklearn.linear_model import LogisticRegression

model = LogisticRegression()
model.fit(X_train, y_train)
```

### What Happens Inside `.fit()`

1. Model sees examples: `[3] → SPAM`, `[0] → NOT SPAM`
2. Finds pattern: `spam_count > 1` → likely spam
3. Learns optimal threshold (decision boundary)

### Why Logistic Regression?

| Property      | Why It's Good for Beginners |
| ------------- | --------------------------- |
| Simple        | Only one line to train      |
| Fast          | Milliseconds on small data  |
| Interpretable | Can see feature weights     |
| Works         | Good baseline accuracy      |

---

## Exercise 4: Making Predictions (TODO 4)

### The Problem

Apply the trained model to unseen test data.

### The Solution

```python
predictions = model.predict(X_test)
```

### What `.predict()` Does

```
X_test = [[2], [0], [4], [1], ...]
           ↓
         Model
           ↓
predictions = [1, 0, 1, 0, ...]
              SPAM, NOT, SPAM, NOT
```

### Getting Probabilities

For more insight, use `predict_proba`:

```python
probabilities = model.predict_proba(X_test)
# [[0.2, 0.8],   # 80% chance spam
#  [0.9, 0.1],   # 10% chance spam
#  ...]
```

---

## Exercise 5: Evaluation (TODO 5)

### The Problem

How do we know if our model is good?

### The Solution

```python
from sklearn.metrics import accuracy_score, precision_score, recall_score

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
```

### Understanding the Metrics

```
                    Predicted
                 SPAM    NOT SPAM
Actual  SPAM     TP=8      FN=2     ← Recall: TP/(TP+FN) = 8/10 = 80%
       NOT SPAM  FP=1      TN=9
                  ↓
        Precision: TP/(TP+FP) = 8/9 = 89%

Accuracy: (TP+TN)/Total = (8+9)/20 = 85%
```

### Which Metric Matters?

| Use Case       | Focus On  | Why                           |
| -------------- | --------- | ----------------------------- |
| General        | Accuracy  | Overall correctness           |
| Spam filter    | Precision | Don't block legitimate emails |
| Security alert | Recall    | Don't miss real threats       |

---

## Complete Solution

```python
def main():
    # Step 1: Load data
    messages = MESSAGES
    labels = LABELS

    # Step 2: Extract features
    features = [extract_features(msg) for msg in messages]
    X = np.array(features)
    y = np.array(labels)

    # Step 3: Split data (TODO 2)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Step 4: Train model (TODO 3)
    model = LogisticRegression()
    model.fit(X_train, y_train)

    # Step 5: Predict (TODO 4)
    predictions = model.predict(X_test)

    # Step 6: Evaluate (TODO 5)
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)

    print(f"Accuracy: {accuracy:.1%}")
    print(f"Precision: {precision:.1%}")
    print(f"Recall: {recall:.1%}")
```

---

## Common Errors

### 1. Feature Dimension Mismatch

```python
# Problem: Features is list of ints, not list of lists
features = [3, 0, 5, 1]  # Wrong!

# Solution: Each sample needs to be a list
features = [[3], [0], [5], [1]]  # Correct!
```

### 2. Forgetting to Train

```python
# Problem: Predict before fit
model = LogisticRegression()
model.predict(X_test)  # Error!

# Solution: Always fit first
model.fit(X_train, y_train)
model.predict(X_test)  # Works!
```

### 3. Wrong Label Type

```python
# Problem: Labels as strings
labels = ["spam", "not spam", "spam"]

# Solution: Labels as integers
labels = [1, 0, 1]
```

---

## Key Takeaways

1. **ML workflow**: Load → Extract Features → Split → Train → Predict → Evaluate
2. **Features matter**: What you measure determines what the model learns
3. **Always split data**: Test on unseen data to measure true performance
4. **Understand metrics**: Accuracy isn't everything; consider precision and recall

---

## Bonus Challenges

### Add More Features

```python
def extract_features_v2(message: str) -> list:
    message_lower = message.lower()
    return [
        sum(1 for word in SPAM_WORDS if word in message_lower),
        len(message),                    # Message length
        message.count("!"),              # Exclamation marks
        sum(1 for c in message if c.isupper()) / max(len(message), 1),  # Caps ratio
    ]
```

### Try Different Models

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

# Random Forest (usually better)
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Decision Tree (more interpretable)
model = DecisionTreeClassifier(random_state=42)
```

---

## Next Steps

You now understand the ML workflow! Continue to:

- **Lab 01**: Build a real phishing classifier with TF-IDF
- **Lab 02**: Learn unsupervised learning (clustering)
- **Lab 03**: Detect anomalies in network data

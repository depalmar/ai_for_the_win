# Lab 07: Hello World ML

**Difficulty:** 🟢 Beginner | **Time:** 30-45 min | **Prerequisites:** Lab 01, 04

Your first machine learning model - a simple spam detector in under 50 lines of code.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab07_hello_world_ml.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand the 4-step ML workflow: Load → Train → Predict → Evaluate
- Build a working classifier with scikit-learn
- Know what accuracy, precision, and recall mean
- Have confidence to tackle Lab 01

## Prerequisites

- Completed Lab 01 (Python basics) OR comfortable with Python
- Completed Lab 15 (ML concepts) OR understand supervised learning basics

## Time Required

⏱️ **30-45 minutes**

---

## The Problem: Spam Detection

We'll build the simplest possible spam classifier:

```
Input: "FREE MONEY NOW! Click here to claim your prize!"
Output: SPAM ❌

Input: "Hi, can we reschedule our meeting to 3pm?"
Output: NOT SPAM ✅
```

---

## The 4-Step ML Workflow

Every ML project follows this pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    ML WORKFLOW                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   1. LOAD DATA        2. TRAIN MODEL                        │
│   ────────────        ─────────────                         │
│   Load examples       Let algorithm                         │
│   with labels         learn patterns                        │
│                                                             │
│         │                   │                               │
│         ▼                   ▼                               │
│                                                             │
│   3. PREDICT          4. EVALUATE                           │
│   ──────────          ────────────                          │
│   Apply model         Measure how                           │
│   to new data         well it works                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 1: Load Data

Our dataset has messages labeled as spam (1) or not spam (0):

```python
# Sample data - in real projects you'd load from a file
messages = [
    "FREE MONEY! Click now to claim your prize!",
    "Hey, want to grab lunch tomorrow?",
    "URGENT: Your account has been compromised!",
    "Meeting moved to 3pm, see you there",
    "Congratulations! You've won $1,000,000!",
    "Can you review the document I sent?",
    ...
]
labels = [1, 0, 1, 0, 1, 0, ...]  # 1 = spam, 0 = not spam
```

---

## Step 2: Train Model

We'll use **Logistic Regression** - one of the simplest classifiers:

```python
from sklearn.linear_model import LogisticRegression

model = LogisticRegression()
model.fit(X_train, y_train)  # Learn patterns from data
```

But wait - ML models need **numbers**, not text! We'll use a simple trick: count how many "spammy" words appear.

---

## Step 3: Predict

Once trained, the model can classify new messages:

```python
new_message = "Win a FREE iPhone now!"
prediction = model.predict([new_message])
# prediction = 1 (spam)
```

---

## Step 4: Evaluate

How good is our model? We measure:

| Metric | What It Means | Formula |
|--------|---------------|---------|
| **Accuracy** | % of correct predictions | (TP + TN) / Total |
| **Precision** | When we say "spam", how often are we right? | TP / (TP + FP) |
| **Recall** | Of all actual spam, how much did we catch? | TP / (TP + FN) |

Where:
- TP = True Positives (correctly identified spam)
- TN = True Negatives (correctly identified not-spam)
- FP = False Positives (called it spam, but it wasn't)
- FN = False Negatives (missed spam)

---

## Your Task

Complete the starter code to build a working spam classifier.

### File: `starter/main.py`

```bash
# Run the starter code
python labs/lab07-hello-world-ml/starter/main.py
```

### TODOs

1. **TODO 1**: Create the feature extractor (count spam words)
2. **TODO 2**: Split data into training and test sets
3. **TODO 3**: Train the model
4. **TODO 4**: Make predictions
5. **TODO 5**: Calculate accuracy

---

## Hints

<details>
<summary>💡 Hint 1: Feature Extraction</summary>

Count how many "spam indicator" words appear in each message:

```python
SPAM_WORDS = ["free", "win", "click", "urgent", "money", "prize"]

def count_spam_words(message):
    message_lower = message.lower()
    count = sum(1 for word in SPAM_WORDS if word in message_lower)
    return count
```

</details>

<details>
<summary>💡 Hint 2: Train/Test Split</summary>

Use scikit-learn's `train_test_split`:

```python
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    features, labels, test_size=0.2, random_state=42
)
```

</details>

<details>
<summary>💡 Hint 3: Training</summary>

```python
model = LogisticRegression()
model.fit(X_train, y_train)
```

</details>

<details>
<summary>💡 Hint 4: Predictions</summary>

```python
predictions = model.predict(X_test)
```

</details>

<details>
<summary>💡 Hint 5: Accuracy</summary>

```python
from sklearn.metrics import accuracy_score
accuracy = accuracy_score(y_test, predictions)
```

</details>

---

## Expected Output

```
📊 Hello World ML - Spam Classifier
====================================

Step 1: Loading data...
  Loaded 100 messages (50 spam, 50 not spam)

Step 2: Extracting features...
  Feature: spam word count per message

Step 3: Splitting data...
  Training set: 80 messages
  Test set: 20 messages

Step 4: Training model...
  Model: LogisticRegression
  Training complete!

Step 5: Making predictions...
  Predictions made on test set

Step 6: Evaluating...
  Accuracy: 85.0%
  Precision: 83.3%
  Recall: 87.5%

✅ Your first ML model is working!

Test it yourself:
  "FREE MONEY NOW!" → SPAM
  "Meeting at 3pm" → NOT SPAM
```

---

## Bonus Challenges

### Challenge 1: Add More Features
Currently we only count spam words. Add:
- Message length
- Number of exclamation marks
- Number of ALL CAPS words

### Challenge 2: Try Different Models
Replace LogisticRegression with:
- `RandomForestClassifier`
- `DecisionTreeClassifier`
- `SVC` (Support Vector Classifier)

Compare their accuracy!

### Challenge 3: Find the Best Spam Words
Which words are most predictive of spam? Try different word lists.

---

## Key Takeaways

1. **ML is pattern recognition** - the model learns what spam "looks like"
2. **Features matter** - what you measure affects predictions
3. **Evaluation is crucial** - always test on unseen data
4. **Simple can work** - even basic features can achieve good results

---

## What's Next?

Now that you understand the ML workflow:

- **Lab 01**: Build a more sophisticated phishing classifier with TF-IDF
- **Lab 31**: Learn unsupervised learning (clustering) for malware
- **Lab 12**: Detect anomalies in network traffic

You're ready!

---

**Next Lab:** [Lab 08: Working with APIs](../lab08-working-with-apis/) - Learn to make HTTP requests and work with security APIs

Or jump to: [Lab 10: Phishing Classifier](../lab10-phishing-classifier/) - Apply your ML skills to a real security problem

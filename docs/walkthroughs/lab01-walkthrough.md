# Lab 01 Walkthrough: Phishing Email Classifier

## Overview

This walkthrough guides you through building a phishing email classifier using TF-IDF and Random Forest.

**Time to complete walkthrough:** 20 minutes

---

## Step 1: Understanding the Problem

### What We're Building
A binary classifier that distinguishes phishing emails from legitimate ones.

```
INPUT: Email text (subject + body)
    |
    v
[Text Preprocessing]
    |
    v
[TF-IDF Vectorization]
    |
    v
[Random Forest Classifier]
    |
    v
OUTPUT: 0 (legitimate) or 1 (phishing)
```

### Why This Approach?
- **TF-IDF**: Captures word importance relative to document frequency
- **Random Forest**: Handles high-dimensional sparse data well
- **Together**: Effective baseline for text classification

---

## Step 2: Loading the Data

### Using Sample Data

```python
import pandas as pd

# Load the sample dataset
emails = pd.read_csv('data/phishing/emails.csv')

# Explore the data
print(f"Total emails: {len(emails)}")
print(f"Phishing: {emails['label'].sum()}")
print(f"Legitimate: {len(emails) - emails['label'].sum()}")
print(f"\nSample phishing email:\n{emails[emails['label']==1].iloc[0]['body'][:200]}")
```

### Expected Output
```
Total emails: 25
Phishing: 13
Legitimate: 12

Sample phishing email:
Dear Customer, We have detected suspicious activity on your account...
```

### Common Error #1: File Not Found
```
FileNotFoundError: [Errno 2] No such file or directory: 'data/phishing/emails.csv'
```

**Solution:** Ensure you're running from the repository root:
```bash
cd /path/to/ai_for_the_win
python labs/lab01-phishing-classifier/solution/main.py
```

---

## Step 3: Text Preprocessing

### Why Preprocess?
- Remove noise (HTML, special chars)
- Normalize text (lowercase)
- Reduce vocabulary size

```python
import re

def preprocess_email(text):
    """Clean and normalize email text"""
    # Convert to lowercase
    text = text.lower()

    # Remove URLs (common in phishing)
    text = re.sub(r'http\S+|www\S+', 'URL', text)

    # Remove email addresses
    text = re.sub(r'\S+@\S+', 'EMAIL', text)

    # Remove special characters but keep spaces
    text = re.sub(r'[^a-z\s]', '', text)

    # Remove extra whitespace
    text = ' '.join(text.split())

    return text

# Apply preprocessing
emails['clean_text'] = emails['body'].apply(preprocess_email)
```

### What This Does
| Original | After Preprocessing |
|----------|---------------------|
| "Click http://evil.com NOW!!!" | "click url now" |
| "From: admin@bank.com" | "from email" |
| "Your $1,000,000 prize!" | "your prize" |

### Common Error #2: NaN Values
```
ValueError: Input contains NaN
```

**Solution:** Handle missing values:
```python
emails['body'] = emails['body'].fillna('')
```

---

## Step 4: Feature Extraction with TF-IDF

### Understanding TF-IDF

**TF** (Term Frequency): How often a word appears in a document
**IDF** (Inverse Document Frequency): How rare a word is across all documents

```
TF-IDF = TF × IDF
```

Words that appear frequently in one document but rarely overall get high scores.

### Implementation

```python
from sklearn.feature_extraction.text import TfidfVectorizer

# Create vectorizer
vectorizer = TfidfVectorizer(
    max_features=1000,    # Limit vocabulary size
    stop_words='english', # Remove common words
    ngram_range=(1, 2),   # Include bigrams
    min_df=2              # Ignore rare words
)

# Fit and transform
X = vectorizer.fit_transform(emails['clean_text'])
y = emails['label'].values

print(f"Feature matrix shape: {X.shape}")
print(f"Top features: {vectorizer.get_feature_names_out()[:10]}")
```

### Parameter Choices Explained

| Parameter | Value | Why |
|-----------|-------|-----|
| `max_features=1000` | Prevents overfitting, reduces memory |
| `stop_words='english'` | Removes "the", "is", etc. |
| `ngram_range=(1,2)` | Captures "click here", "verify account" |
| `min_df=2` | Ignores words appearing only once |

### Common Error #3: Empty Vocabulary
```
ValueError: empty vocabulary
```

**Solution:** Check preprocessing isn't too aggressive:
```python
# Bad: removes all letters
text = re.sub(r'[a-z]', '', text)

# Good: removes only special chars
text = re.sub(r'[^a-z\s]', '', text)
```

---

## Step 5: Training the Classifier

### Train/Test Split

```python
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y  # Maintain class balance
)

print(f"Training samples: {X_train.shape[0]}")
print(f"Test samples: {X_test.shape[0]}")
```

### Why Stratify?
Without stratification, you might get all phishing in training and all legitimate in test (or vice versa). `stratify=y` ensures proportional split.

### Training Random Forest

```python
from sklearn.ensemble import RandomForestClassifier

# Create and train model
model = RandomForestClassifier(
    n_estimators=100,    # Number of trees
    max_depth=10,        # Prevent overfitting
    random_state=42,
    n_jobs=-1            # Use all CPU cores
)

model.fit(X_train, y_train)
```

---

## Step 6: Evaluation

### Key Metrics for Security

```python
from sklearn.metrics import classification_report, confusion_matrix

# Predictions
y_pred = model.predict(X_test)

# Detailed metrics
print(classification_report(y_test, y_pred,
      target_names=['Legitimate', 'Phishing']))
```

### Understanding the Output
```
              precision    recall  f1-score   support

  Legitimate       0.90      0.95      0.92        20
     Phishing       0.93      0.87      0.90        15

    accuracy                           0.91        35
```

### Security-Specific Interpretation

| Metric | Meaning | Security Implication |
|--------|---------|---------------------|
| **Precision (Phishing)** | % of "phishing" predictions that are correct | Low = Many false alarms |
| **Recall (Phishing)** | % of actual phishing caught | Low = Missed attacks! |
| **F1** | Balance of precision and recall | Overall performance |

### Which Metric Matters Most?

For security, **recall is often more important** than precision:
- Missing a phishing email (false negative) = user gets attacked
- Flagging a legitimate email (false positive) = minor inconvenience

```python
# Calculate with emphasis on recall
from sklearn.metrics import fbeta_score

# F2 score weights recall higher
f2 = fbeta_score(y_test, y_pred, beta=2)
print(f"F2 Score (recall-weighted): {f2:.3f}")
```

---

## Step 7: Feature Analysis

### What Makes Emails Phishing?

```python
import numpy as np

# Get feature importances
feature_names = vectorizer.get_feature_names_out()
importances = model.feature_importances_

# Top 10 most important features
top_indices = np.argsort(importances)[-10:]
for idx in reversed(top_indices):
    print(f"{feature_names[idx]}: {importances[idx]:.4f}")
```

### Expected Top Features
```
url: 0.0823
click: 0.0654
verify: 0.0521
account: 0.0498
immediately: 0.0445
suspended: 0.0412
...
```

These align with phishing indicators: urgency, action required, account threats.

---

## Common Mistakes & Solutions

### Mistake 1: Data Leakage
```python
# WRONG: Vectorizing before split
X = vectorizer.fit_transform(all_emails)
X_train, X_test = train_test_split(X)

# RIGHT: Fit only on training data
X_train = vectorizer.fit_transform(train_emails)
X_test = vectorizer.transform(test_emails)  # transform, not fit_transform!
```

### Mistake 2: Ignoring Class Imbalance
```python
# Check balance
print(y.value_counts())

# If imbalanced, use class weights
model = RandomForestClassifier(class_weight='balanced')
```

### Mistake 3: Overfitting
```python
# Signs of overfitting:
# - Training accuracy: 99%
# - Test accuracy: 60%

# Solutions:
# 1. Reduce max_depth
# 2. Increase min_samples_leaf
# 3. Use cross-validation
```

---

## Extension Exercises

### Exercise A: Try Different Classifiers
```python
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

# Naive Bayes - often good for text
nb = MultinomialNB()
nb.fit(X_train, y_train)
print(f"Naive Bayes accuracy: {nb.score(X_test, y_test):.3f}")

# SVM - good for high-dimensional data
svm = LinearSVC()
svm.fit(X_train, y_train)
print(f"SVM accuracy: {svm.score(X_test, y_test):.3f}")
```

### Exercise B: Add More Features
```python
def extract_metadata_features(email):
    """Extract features beyond text content"""
    return {
        'has_url': 1 if 'http' in email.lower() else 0,
        'urgency_words': sum(1 for w in ['urgent', 'immediately', 'now']
                            if w in email.lower()),
        'exclamation_count': email.count('!'),
        'caps_ratio': sum(1 for c in email if c.isupper()) / len(email)
    }
```

### Exercise C: Cross-Validation
```python
from sklearn.model_selection import cross_val_score

scores = cross_val_score(model, X, y, cv=5, scoring='f1')
print(f"CV F1 Scores: {scores}")
print(f"Mean: {scores.mean():.3f} (+/- {scores.std()*2:.3f})")
```

---

## Bonus: Phishing Campaign Timeline

The notebook includes an interactive timeline visualization showing phishing campaign patterns.

### Adding Timestamps to Email Data

```python
from datetime import datetime, timedelta
import random

# Phishing campaigns cluster in waves; legitimate emails spread evenly
base_date = datetime(2024, 1, 1)
timestamps = []
for label in labels:
    if label == 1:  # Phishing - cluster in campaign waves
        campaign_day = random.choice([3, 7, 15, 22, 28])
        day_offset = campaign_day + random.randint(-2, 2)
    else:  # Legitimate - spread evenly
        day_offset = random.randint(0, 29)
    timestamps.append(base_date + timedelta(days=day_offset))

df['timestamp'] = timestamps
```

### Visualizing Campaign Waves

```python
fig = make_subplots(rows=2, cols=1,
    subplot_titles=['Daily Email Volume', 'Cumulative Phishing'])

# Stacked bar chart
fig.add_trace(go.Bar(x=dates, y=legitimate, name='Legitimate'), row=1, col=1)
fig.add_trace(go.Bar(x=dates, y=phishing, name='Phishing'), row=1, col=1)

# Cumulative line shows campaign acceleration
fig.add_trace(go.Scatter(x=dates, y=cumulative, fill='tozeroy'), row=2, col=1)
```

### Security Insight

Real phishing campaigns show similar patterns:
- **Burst activity** on specific days (campaign launches)
- **Rapid accumulation** during active campaigns
- **Quiet periods** between campaigns

---

## Key Takeaways

1. **Preprocessing matters** - Clean text improves classification
2. **TF-IDF captures meaning** - Word importance, not just counts
3. **Recall vs Precision tradeoff** - In security, catching attacks matters
4. **Feature analysis** - Understand what the model learned
5. **Avoid data leakage** - Fit vectorizer only on training data
6. **Timeline analysis** - Phishing campaigns cluster in waves

---

## Next Lab

Continue to [Lab 02: Malware Clustering](./lab02-walkthrough.md) to learn unsupervised learning for malware analysis.

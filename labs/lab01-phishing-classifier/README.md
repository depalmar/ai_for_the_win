# Lab 01: Phishing Email Classifier

Build a machine learning classifier to detect phishing emails.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand text preprocessing for security applications
2. Extract features from email content
3. Train and evaluate a classification model
4. Apply the model to detect phishing attempts

---

## ⏱️ Estimated Time

45-60 minutes

---

## 📋 Prerequisites

- Python 3.10+
- Basic understanding of machine learning concepts
- Completed environment setup

### Required Libraries

```bash
pip install scikit-learn pandas numpy nltk
```

---

## 📖 Background

Phishing emails remain one of the most common attack vectors. Key indicators include:

- **Urgency language**: "Act now!", "Immediate action required"
- **Suspicious links**: Mismatched or obfuscated URLs
- **Generic greetings**: "Dear Customer" instead of your name
- **Grammar/spelling errors**: Often from non-native speakers
- **Requests for sensitive info**: Passwords, credit cards, SSN

### MITRE ATT&CK Mapping

- **T1566.001** - Phishing: Spearphishing Attachment
- **T1566.002** - Phishing: Spearphishing Link

---

## 🔬 Lab Tasks

### Task 1: Load and Explore Data (10 min)

Open `starter/main.py` and complete the `load_data()` function.

```python
def load_data(filepath: str) -> pd.DataFrame:
    """
    Load email dataset from CSV.

    Expected columns:
    - text: Email body content
    - label: 0 = legitimate, 1 = phishing

    TODO:
    1. Load the CSV file
    2. Handle any missing values
    3. Return the DataFrame
    """
    pass
```

**Expected Output:**

```
Dataset shape: (5000, 2)
Label distribution:
  Legitimate: 3000 (60%)
  Phishing: 2000 (40%)
```

### Task 2: Preprocess Text (15 min)

Implement text preprocessing:

```python
def preprocess_text(text: str) -> str:
    """
    Clean and normalize email text.

    TODO:
    1. Convert to lowercase
    2. Remove HTML tags
    3. Remove URLs (but count them as a feature)
    4. Remove special characters
    5. Tokenize and remove stopwords
    6. Apply stemming or lemmatization

    Returns:
        Cleaned text string
    """
    pass
```

### Task 3: Extract Features (15 min)

Create features that capture phishing indicators:

```python
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract phishing-relevant features from emails.

    TODO: Extract these features:
    1. url_count: Number of URLs in email
    2. has_urgent_words: Contains urgency language
    3. has_suspicious_sender: Sender domain mismatch
    4. link_text_mismatch: Display text doesn't match URL
    5. grammar_errors: Count of grammar issues
    6. has_attachment_mention: Mentions attachments
    7. request_sensitive_info: Asks for passwords/cards
    8. text_length: Total character count
    9. caps_ratio: Ratio of uppercase letters

    Returns:
        DataFrame with extracted features
    """
    pass
```

### Task 4: Train Classifier (10 min)

Train a Random Forest classifier:

```python
def train_model(X_train, y_train):
    """
    Train a phishing classifier.

    TODO:
    1. Create TF-IDF vectorizer for text
    2. Combine with extracted features
    3. Train Random Forest classifier
    4. Return trained model and vectorizer
    """
    pass
```

### Task 5: Evaluate Model (10 min)

Assess model performance:

```python
def evaluate_model(model, X_test, y_test):
    """
    Evaluate classifier performance.

    TODO:
    1. Generate predictions
    2. Calculate accuracy, precision, recall, F1
    3. Create confusion matrix
    4. Identify most important features

    Print:
    - Classification report
    - Confusion matrix
    - Top 10 important features
    """
    pass
```

**Target Metrics:**

- Accuracy: > 90%
- Precision: > 85%
- Recall: > 85%
- F1 Score: > 85%

### Task 6: Test on New Emails (5 min)

Test your classifier on sample emails:

```python
test_emails = [
    "Dear valued customer, your account has been compromised. Click here immediately to verify: http://bit.ly/xyz123",
    "Hi John, the meeting has been moved to 3pm tomorrow. See you there! - Sarah",
    "URGENT: Your PayPal account will be suspended! Verify now: paypa1-secure.com/verify",
    "The quarterly report is attached. Let me know if you have questions.",
]

for email in test_emails:
    prediction = predict_phishing(model, email)
    print(f"Email: {email[:50]}...")
    print(f"Prediction: {'PHISHING' if prediction else 'LEGITIMATE'}\n")
```

---

## 📁 Files

```
lab01-phishing-classifier/
├── README.md           # This file
├── starter/
│   └── main.py         # Starter code with TODOs
├── solution/
│   └── main.py         # Reference solution
├── data/
│   ├── emails.csv      # Training dataset
│   └── test_emails.csv # Test dataset
└── tests/
    └── test_classifier.py
```

---

## ✅ Success Criteria

- [ ] Data loads correctly with proper shape
- [ ] Text preprocessing removes noise while preserving meaning
- [ ] At least 8 features extracted
- [ ] Model achieves >90% accuracy
- [ ] Correctly classifies all 4 test emails
- [ ] Code is clean and well-documented

---

## 🚀 Bonus Challenges

1. **Try different models**: Compare Naive Bayes, SVM, and Gradient Boosting
2. **Add more features**: Extract email headers, sender reputation
3. **Handle imbalanced data**: Use SMOTE or class weights
4. **Explain predictions**: Use SHAP or LIME for interpretability
5. **Deploy as API**: Create a Flask endpoint for real-time classification

---

## 💡 Hints

<details>
<summary>Hint 1: URL Extraction Regex</summary>

```python
import re
url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
urls = re.findall(url_pattern, text)
```

</details>

<details>
<summary>Hint 2: Urgency Words List</summary>

```python
urgency_words = [
    'urgent', 'immediate', 'action required', 'act now',
    'limited time', 'expires', 'suspended', 'verify',
    'confirm', 'alert', 'warning', 'attention'
]
```

</details>

<details>
<summary>Hint 3: Feature Combination</summary>

```python
from scipy.sparse import hstack

# Combine TF-IDF with numeric features
X_combined = hstack([tfidf_features, numeric_features])
```

</details>

---

## 📚 Resources

- [Scikit-learn Text Classification](https://scikit-learn.org/stable/tutorial/text_analytics/working_with_text_data.html)
- [NLTK Documentation](https://www.nltk.org/)
- [Phishing Dataset (Kaggle)](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)
- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)

---

## 📝 Notes

Record your observations:

- What features were most predictive?
- What types of phishing emails were hardest to detect?
- How would you improve the model?

---

> **Stuck?** See the [Lab 01 Walkthrough](../../docs/walkthroughs/lab01-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 02 - Malware Clustering](../lab02-malware-clustering/)

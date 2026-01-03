# Test Lab 17a: ML Security Intro
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

print("=" * 50)
print("Testing Lab 17a: ML Security Intro")
print("=" * 50)

# Generate synthetic malware detection data
np.random.seed(42)
n_samples = 200

# Features: [suspicious_api_count, entropy]
# Benign: low suspicious APIs, normal entropy
benign_features = np.column_stack(
    [
        np.random.randint(0, 4, n_samples // 2),  # 0-3 suspicious APIs
        np.random.uniform(4.0, 6.0, n_samples // 2),  # Normal entropy
    ]
)
benign_labels = np.zeros(n_samples // 2)

# Malicious: high suspicious APIs, high entropy
malware_features = np.column_stack(
    [
        np.random.randint(5, 15, n_samples // 2),  # 5-15 suspicious APIs
        np.random.uniform(6.5, 8.0, n_samples // 2),  # High entropy
    ]
)
malware_labels = np.ones(n_samples // 2)

# Combine
X = np.vstack([benign_features, malware_features])
y = np.concatenate([benign_labels, malware_labels])

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

print(f"\nDataset: {len(X)} samples ({int(sum(y))} malicious, {int(len(y) - sum(y))} benign)")
print(f"Train: {len(X_train)}, Test: {len(X_test)}")

# Train classifier
classifier = LogisticRegression()
classifier.fit(X_train, y_train)

# Evaluate
train_acc = classifier.score(X_train, y_train)
test_acc = classifier.score(X_test, y_test)
print(f"\nBaseline Performance:")
print(f"  Train accuracy: {train_acc:.1%}")
print(f"  Test accuracy: {test_acc:.1%}")

# === EVASION ATTACK DEMO ===
print("\n--- Evasion Attack Demo ---")
# Original malware sample
original_malware = np.array([[9, 7.3]])
original_pred = classifier.predict(original_malware)[0]
original_prob = classifier.predict_proba(original_malware)[0][1]

print(f"Original malware: APIs=9, Entropy=7.3")
print(
    f"  Prediction: {'MALICIOUS' if original_pred == 1 else 'BENIGN'} (conf: {original_prob:.1%})"
)

# Evaded version - reduce features while keeping malicious behavior
evaded_malware = np.array([[4, 5.5]])
evaded_pred = classifier.predict(evaded_malware)[0]
evaded_prob = classifier.predict_proba(evaded_malware)[0][1]

print(f"Evaded malware: APIs=4, Entropy=5.5")
print(f"  Prediction: {'MALICIOUS' if evaded_pred == 1 else 'BENIGN'} (conf: {evaded_prob:.1%})")

if evaded_pred == 0:
    print("  [!] Evasion successful - malware classified as benign!")
else:
    print("  [OK] Evasion failed - malware still detected")

# === POISONING ATTACK DEMO ===
print("\n--- Poisoning Attack Demo ---")
# Add poisoned samples to training data
n_poison = 20
poison_features = np.column_stack(
    [
        np.random.randint(8, 12, n_poison),  # High APIs (looks malicious)
        np.random.uniform(6.5, 7.5, n_poison),  # High entropy
    ]
)
poison_labels = np.zeros(n_poison)  # But labeled as benign!

X_poisoned = np.vstack([X_train, poison_features])
y_poisoned = np.concatenate([y_train, poison_labels])

# Retrain on poisoned data
poisoned_classifier = LogisticRegression()
poisoned_classifier.fit(X_poisoned, y_poisoned)

poisoned_acc = poisoned_classifier.score(X_test, y_test)
print(f"Poisoned model test accuracy: {poisoned_acc:.1%}")
print(f"Accuracy drop: {(test_acc - poisoned_acc):.1%}")

if poisoned_acc < test_acc:
    print("[!] Poisoning degraded model performance!")
else:
    print("[OK] Model resilient to this poisoning attempt")

print("\n[PASS] Lab 17a: PASSED")

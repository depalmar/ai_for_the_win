# Lab 17: Adversarial Machine Learning

## Attack and Defend AI Security Models

```
+-----------------------------------------------------------------------------+
|                    ADVERSARIAL ML FOR SECURITY                              |
+-----------------------------------------------------------------------------+
|                                                                             |
|   ATTACK                           DEFENSE                                  |
|   +------------------+            +------------------+                      |
|   | Evasion Attacks  |            | Adversarial      |                      |
|   | - Perturbations  |  <---->    |   Training       |                      |
|   | - Feature manip  |            | - Robust models  |                      |
|   +------------------+            +------------------+                      |
|                                                                             |
|   +------------------+            +------------------+                      |
|   | Poisoning        |            | Input Validation |                      |
|   | - Training data  |  <---->    | - Anomaly detect |                      |
|   | - Label flipping |            | - Sanitization   |                      |
|   +------------------+            +------------------+                      |
|                                                                             |
|   +------------------+            +------------------+                      |
|   | Model Extraction |            | Model Hardening  |                      |
|   | - Query attacks  |  <---->    | - Rate limiting  |                      |
|   | - API abuse      |            | - Watermarking   |                      |
|   +------------------+            +------------------+                      |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## 📊 Overview

| Aspect | Details |
|--------|---------|
| **Time** | 2-2.5 hours (with AI assistance) |
| **Difficulty** | Expert |
| **Prerequisites** | Labs 01-03 (ML fundamentals), Lab 09 (Detection Pipeline) |
| **Skills** | Attack techniques, defense strategies, robust ML |

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

1. **Understand adversarial threats** to ML-based security systems
2. **Execute evasion attacks** against malware classifiers
3. **Perform poisoning attacks** on training pipelines
4. **Implement defensive measures** including adversarial training
5. **Evaluate model robustness** under adversarial conditions
6. **Build attack-resistant** security classifiers

---

## Why This Matters for Security

```
+-----------------------------------------------------------------------------+
|                    REAL-WORLD ADVERSARIAL ML ATTACKS                        |
+-----------------------------------------------------------------------------+
|                                                                             |
|  2020: Researchers bypass Google's malware detector with 1% perturbation    |
|  2021: Adversarial patches fool facial recognition systems                  |
|  2022: ML-based spam filters evaded with invisible Unicode characters       |
|  2023: ChatGPT jailbreaks demonstrate prompt injection vulnerabilities      |
|  2024: Adversarial examples bypass EDR behavioral detection                 |
|                                                                             |
+-----------------------------------------------------------------------------+
```

Security ML models are prime targets because:
- **High-value decisions**: Allow/block, malicious/benign
- **Known architectures**: Attackers can study common approaches
- **Feedback loops**: Attackers observe what gets detected
- **Asymmetric costs**: False negatives are catastrophic

---

## Part 1: Understanding Adversarial Attacks

### 1.1 Attack Taxonomy

```
                        ADVERSARIAL ATTACKS
                              |
        +---------------------+---------------------+
        |                     |                     |
   EVASION              POISONING              EXTRACTION
   (Test time)          (Train time)           (Model theft)
        |                     |                     |
   +----+----+           +----+----+           +----+----+
   |         |           |         |           |         |
Perturb   Feature      Data      Label      Query    Side
Inputs    Manip      Injection  Flipping   Attack  Channel
```

### 1.2 Threat Model

```python
"""
Define the adversary's capabilities and goals
"""

class ThreatModel:
    """Adversarial ML threat model for security classifiers"""

    # Adversary Knowledge Levels
    WHITE_BOX = "full_access"      # Complete model access
    GRAY_BOX = "partial_access"    # API access, some architecture knowledge
    BLACK_BOX = "no_access"        # Only input/output access

    # Adversary Goals
    TARGETED = "specific_class"    # Misclassify as specific class
    UNTARGETED = "any_wrong"       # Any misclassification

    # Perturbation Constraints
    L0 = "sparse_changes"          # Number of features changed
    L2 = "euclidean_distance"      # Total magnitude of change
    LINF = "max_change"            # Maximum single feature change

    def __init__(self,
                 knowledge: str = BLACK_BOX,
                 goal: str = UNTARGETED,
                 constraint: str = LINF,
                 epsilon: float = 0.1):
        self.knowledge = knowledge
        self.goal = goal
        self.constraint = constraint
        self.epsilon = epsilon  # Maximum allowed perturbation
```

---

## Part 2: Evasion Attacks

### 2.1 Fast Gradient Sign Method (FGSM)

```python
"""
FGSM: Simple but effective gradient-based evasion attack
"""

import numpy as np
import torch
import torch.nn as nn

class FGSMAttack:
    """Fast Gradient Sign Method for evasion attacks"""

    def __init__(self, model, epsilon: float = 0.1):
        self.model = model
        self.epsilon = epsilon

    def generate_adversarial(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        """
        Generate adversarial example using FGSM

        Args:
            x: Original input (e.g., malware features)
            y: True label (1 = malicious)

        Returns:
            Adversarial input that evades detection
        """
        x.requires_grad = True

        # Forward pass
        output = self.model(x)
        loss = nn.CrossEntropyLoss()(output, y)

        # Backward pass to get gradients
        self.model.zero_grad()
        loss.backward()

        # Create perturbation in direction that reduces malicious score
        perturbation = self.epsilon * x.grad.sign()

        # Apply perturbation
        x_adv = x + perturbation

        # Clip to valid range
        x_adv = torch.clamp(x_adv, 0, 1)

        return x_adv

    def evaluate_attack(self, x_orig, x_adv, y_true):
        """Evaluate attack success"""
        with torch.no_grad():
            pred_orig = self.model(x_orig).argmax(dim=1)
            pred_adv = self.model(x_adv).argmax(dim=1)

        evasion_rate = (pred_adv != y_true).float().mean()
        perturbation_size = (x_adv - x_orig).abs().mean()

        return {
            "evasion_rate": evasion_rate.item(),
            "perturbation_l1": perturbation_size.item(),
            "original_accuracy": (pred_orig == y_true).float().mean().item()
        }


# Example: Attack a malware classifier
def attack_malware_classifier():
    """Demonstrate evasion attack on malware classifier"""

    # Load pre-trained malware classifier
    model = load_malware_classifier()  # Your trained model
    attack = FGSMAttack(model, epsilon=0.05)

    # Load malicious samples
    malware_samples = load_malware_features()
    labels = torch.ones(len(malware_samples), dtype=torch.long)  # All malicious

    # Generate adversarial examples
    adversarial_samples = attack.generate_adversarial(malware_samples, labels)

    # Evaluate
    results = attack.evaluate_attack(malware_samples, adversarial_samples, labels)

    print(f"Original Detection Rate: {1 - results['evasion_rate']:.2%}")
    print(f"Adversarial Evasion Rate: {results['evasion_rate']:.2%}")
    print(f"Average Perturbation: {results['perturbation_l1']:.4f}")

    return adversarial_samples
```

### 2.2 Projected Gradient Descent (PGD)

```python
"""
PGD: Stronger iterative attack with projection
"""

class PGDAttack:
    """Projected Gradient Descent - stronger iterative attack"""

    def __init__(self, model, epsilon: float = 0.1,
                 alpha: float = 0.01, num_steps: int = 40):
        self.model = model
        self.epsilon = epsilon  # Maximum perturbation
        self.alpha = alpha      # Step size
        self.num_steps = num_steps

    def generate_adversarial(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        """Generate adversarial example using PGD"""

        # Start with random perturbation within epsilon ball
        x_adv = x.clone().detach()
        x_adv = x_adv + torch.empty_like(x_adv).uniform_(-self.epsilon, self.epsilon)
        x_adv = torch.clamp(x_adv, 0, 1)

        for _ in range(self.num_steps):
            x_adv.requires_grad = True

            # Forward pass
            output = self.model(x_adv)
            loss = nn.CrossEntropyLoss()(output, y)

            # Backward pass
            self.model.zero_grad()
            loss.backward()

            # Take step
            with torch.no_grad():
                x_adv = x_adv + self.alpha * x_adv.grad.sign()

                # Project back to epsilon ball around original
                perturbation = x_adv - x
                perturbation = torch.clamp(perturbation, -self.epsilon, self.epsilon)
                x_adv = x + perturbation

                # Clip to valid range
                x_adv = torch.clamp(x_adv, 0, 1)

        return x_adv
```

### 2.3 Feature-Space Attacks for Security

```python
"""
Feature-space attacks specific to security classifiers
"""

class MalwareFeatureAttack:
    """Attack malware classifiers by manipulating semantic features"""

    # Features that can be modified without breaking functionality
    MUTABLE_FEATURES = [
        'section_names',      # Can rename sections
        'import_padding',     # Can add unused imports
        'string_obfuscation', # Can encode strings
        'resource_addition',  # Can add benign resources
        'timestamp_modification',  # Can change compile time
    ]

    # Features that cannot be easily changed
    IMMUTABLE_FEATURES = [
        'core_functionality',  # Must preserve behavior
        'essential_imports',   # Required API calls
        'entry_point_code',    # Must execute correctly
    ]

    def __init__(self, model, feature_names: list):
        self.model = model
        self.feature_names = feature_names
        self.mutable_indices = self._get_mutable_indices()

    def _get_mutable_indices(self) -> list:
        """Identify which feature indices can be modified"""
        return [i for i, name in enumerate(self.feature_names)
                if any(m in name.lower() for m in self.MUTABLE_FEATURES)]

    def semantic_attack(self, x: np.ndarray) -> np.ndarray:
        """
        Modify only mutable features to evade detection
        while preserving malware functionality
        """
        x_adv = x.copy()

        for idx in self.mutable_indices:
            feature_name = self.feature_names[idx]

            if 'section' in feature_name.lower():
                # Add benign-looking section names
                x_adv[idx] = self._benignify_section(x[idx])

            elif 'import' in feature_name.lower():
                # Pad with benign imports
                x_adv[idx] = x[idx] + self._generate_benign_imports()

            elif 'string' in feature_name.lower():
                # Reduce suspicious string count
                x_adv[idx] = max(0, x[idx] - 5)

            elif 'entropy' in feature_name.lower():
                # Reduce entropy by padding
                x_adv[idx] = min(x[idx], 6.5)  # Below suspicious threshold

        return x_adv

    def _benignify_section(self, original_value):
        """Make section features look more benign"""
        # Reduce unusual section characteristics
        return original_value * 0.7

    def _generate_benign_imports(self):
        """Add count of benign-looking imports"""
        return np.random.randint(10, 30)  # Common legitimate import counts
```

---

## Part 3: Poisoning Attacks

### 3.1 Data Poisoning

```python
"""
Poisoning attacks: Corrupt training data to degrade model
"""

class DataPoisoningAttack:
    """Attack training pipeline by injecting malicious samples"""

    def __init__(self, poison_rate: float = 0.1):
        self.poison_rate = poison_rate

    def label_flip_attack(self, X_train, y_train):
        """
        Flip labels of a subset of training data

        This causes the model to learn incorrect decision boundaries
        """
        n_poison = int(len(X_train) * self.poison_rate)
        poison_indices = np.random.choice(len(X_train), n_poison, replace=False)

        y_poisoned = y_train.copy()
        y_poisoned[poison_indices] = 1 - y_poisoned[poison_indices]  # Flip labels

        return X_train, y_poisoned, poison_indices

    def backdoor_attack(self, X_train, y_train, trigger_pattern):
        """
        Insert backdoor: specific pattern always classified as benign

        Attacker can later use this pattern to evade detection
        """
        n_poison = int(len(X_train) * self.poison_rate)

        # Create poisoned samples with trigger
        X_poison = X_train[:n_poison].copy()
        X_poison = self._add_trigger(X_poison, trigger_pattern)
        y_poison = np.zeros(n_poison)  # Label as benign

        # Append to training data
        X_poisoned = np.vstack([X_train, X_poison])
        y_poisoned = np.hstack([y_train, y_poison])

        return X_poisoned, y_poisoned

    def _add_trigger(self, X, trigger):
        """Add trigger pattern to samples"""
        X_triggered = X.copy()
        # Add specific feature pattern that serves as backdoor
        X_triggered[:, :len(trigger)] += trigger
        return X_triggered


class GradientPoisoning:
    """More sophisticated poisoning using gradient information"""

    def __init__(self, model, target_class: int = 0):
        self.model = model
        self.target_class = target_class  # Class we want to attack

    def craft_poison_samples(self, X_clean, y_clean, n_poison: int = 10):
        """
        Craft poison samples that maximally degrade target class performance
        """
        poison_samples = []

        for _ in range(n_poison):
            # Start with random clean sample
            x = X_clean[np.random.randint(len(X_clean))].copy()
            x = torch.tensor(x, dtype=torch.float32, requires_grad=True)

            # Optimize to create confusing sample
            optimizer = torch.optim.Adam([x], lr=0.01)

            for _ in range(100):
                output = self.model(x.unsqueeze(0))

                # Maximize loss for target class
                loss = -nn.CrossEntropyLoss()(
                    output,
                    torch.tensor([self.target_class])
                )

                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

            # Label as opposite class to create confusion
            poison_samples.append({
                'features': x.detach().numpy(),
                'label': 1 - self.target_class
            })

        return poison_samples
```

---

## Part 4: Defensive Techniques

### 4.1 Adversarial Training

```python
"""
Adversarial training: Train model on adversarial examples
"""

class AdversarialTrainer:
    """Train robust models using adversarial examples"""

    def __init__(self, model, attack_method='pgd', epsilon=0.1):
        self.model = model
        self.epsilon = epsilon

        if attack_method == 'pgd':
            self.attack = PGDAttack(model, epsilon=epsilon)
        else:
            self.attack = FGSMAttack(model, epsilon=epsilon)

    def train_epoch(self, dataloader, optimizer, adversarial_ratio=0.5):
        """
        Train on mix of clean and adversarial examples
        """
        self.model.train()
        total_loss = 0

        for batch_x, batch_y in dataloader:
            # Generate adversarial examples for portion of batch
            n_adv = int(len(batch_x) * adversarial_ratio)

            if n_adv > 0:
                x_adv = self.attack.generate_adversarial(
                    batch_x[:n_adv],
                    batch_y[:n_adv]
                )
                # Combine clean and adversarial
                batch_x = torch.cat([x_adv, batch_x[n_adv:]])

            # Standard training step
            optimizer.zero_grad()
            output = self.model(batch_x)
            loss = nn.CrossEntropyLoss()(output, batch_y)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        return total_loss / len(dataloader)

    def evaluate_robustness(self, test_loader):
        """Evaluate model on both clean and adversarial test data"""
        self.model.eval()

        clean_correct = 0
        adv_correct = 0
        total = 0

        with torch.no_grad():
            for batch_x, batch_y in test_loader:
                # Clean accuracy
                clean_pred = self.model(batch_x).argmax(dim=1)
                clean_correct += (clean_pred == batch_y).sum().item()

                # Adversarial accuracy
                x_adv = self.attack.generate_adversarial(batch_x, batch_y)
                adv_pred = self.model(x_adv).argmax(dim=1)
                adv_correct += (adv_pred == batch_y).sum().item()

                total += len(batch_y)

        return {
            'clean_accuracy': clean_correct / total,
            'adversarial_accuracy': adv_correct / total,
            'robustness_gap': (clean_correct - adv_correct) / total
        }
```

### 4.2 Input Validation and Sanitization

```python
"""
Defensive input preprocessing
"""

class InputValidator:
    """Validate and sanitize inputs before classification"""

    def __init__(self, reference_distribution):
        self.reference = reference_distribution
        self.threshold = 3.0  # Standard deviations for anomaly

    def detect_anomalous_input(self, x: np.ndarray) -> dict:
        """
        Detect if input is anomalous (potential adversarial example)
        """
        # Check feature-wise statistics
        z_scores = (x - self.reference['mean']) / self.reference['std']
        max_deviation = np.abs(z_scores).max()

        # Check if input is too far from training distribution
        is_anomalous = max_deviation > self.threshold

        # Additional checks
        checks = {
            'max_z_score': max_deviation,
            'is_anomalous': is_anomalous,
            'anomalous_features': np.where(np.abs(z_scores) > self.threshold)[0],
            'recommendation': 'REJECT' if is_anomalous else 'ACCEPT'
        }

        return checks

    def sanitize_input(self, x: np.ndarray) -> np.ndarray:
        """
        Sanitize input by clipping extreme values
        """
        x_sanitized = x.copy()

        # Clip to reasonable bounds based on training distribution
        lower = self.reference['mean'] - self.threshold * self.reference['std']
        upper = self.reference['mean'] + self.threshold * self.reference['std']

        x_sanitized = np.clip(x_sanitized, lower, upper)

        return x_sanitized


class FeatureSqueezing:
    """
    Feature squeezing defense: Reduce precision to remove perturbations
    """

    def __init__(self, bit_depth: int = 4):
        self.bit_depth = bit_depth
        self.levels = 2 ** bit_depth

    def squeeze(self, x: np.ndarray) -> np.ndarray:
        """Reduce feature precision"""
        # Quantize features
        x_squeezed = np.round(x * self.levels) / self.levels
        return x_squeezed

    def detect_adversarial(self, model, x: np.ndarray,
                          threshold: float = 0.1) -> bool:
        """
        Detect adversarial by comparing predictions before/after squeezing
        """
        x_squeezed = self.squeeze(x)

        pred_original = model.predict_proba(x.reshape(1, -1))[0]
        pred_squeezed = model.predict_proba(x_squeezed.reshape(1, -1))[0]

        # Large difference suggests adversarial perturbation
        diff = np.abs(pred_original - pred_squeezed).max()

        return diff > threshold
```

### 4.3 Ensemble Defense

```python
"""
Ensemble methods for robustness
"""

class EnsembleDefense:
    """Use model ensemble for robust predictions"""

    def __init__(self, models: list, voting='soft'):
        self.models = models
        self.voting = voting

    def predict(self, x: np.ndarray) -> np.ndarray:
        """Ensemble prediction using voting"""
        predictions = []

        for model in self.models:
            if self.voting == 'soft':
                pred = model.predict_proba(x)
            else:
                pred = model.predict(x)
            predictions.append(pred)

        if self.voting == 'soft':
            # Average probabilities
            ensemble_pred = np.mean(predictions, axis=0)
            return ensemble_pred.argmax(axis=1)
        else:
            # Majority voting
            predictions = np.array(predictions)
            return np.apply_along_axis(
                lambda x: np.bincount(x).argmax(),
                0,
                predictions
            )

    def get_confidence(self, x: np.ndarray) -> float:
        """
        Measure prediction confidence across ensemble
        Low confidence may indicate adversarial input
        """
        predictions = []
        for model in self.models:
            pred = model.predict(x.reshape(1, -1))[0]
            predictions.append(pred)

        # Agreement ratio
        agreement = max(np.bincount(predictions)) / len(predictions)
        return agreement
```

---

## Part 5: Building a Robust Security Classifier

### 5.1 Complete Robust Training Pipeline

```python
"""
End-to-end robust malware classifier
"""

import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

class RobustMalwareClassifier:
    """Malware classifier with adversarial robustness"""

    def __init__(self, input_dim: int, hidden_dims: list = [128, 64]):
        self.model = self._build_model(input_dim, hidden_dims)
        self.input_validator = None
        self.feature_squeezer = FeatureSqueezing(bit_depth=5)

    def _build_model(self, input_dim, hidden_dims):
        """Build neural network classifier"""
        layers = []
        prev_dim = input_dim

        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.BatchNorm1d(hidden_dim)
            ])
            prev_dim = hidden_dim

        layers.append(nn.Linear(prev_dim, 2))  # Binary classification

        return nn.Sequential(*layers)

    def train_robust(self, X_train, y_train, epochs=50,
                    adversarial_ratio=0.5, epsilon=0.1):
        """Train with adversarial examples"""

        # Setup
        X_tensor = torch.tensor(X_train, dtype=torch.float32)
        y_tensor = torch.tensor(y_train, dtype=torch.long)
        dataset = TensorDataset(X_tensor, y_tensor)
        loader = DataLoader(dataset, batch_size=64, shuffle=True)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        trainer = AdversarialTrainer(self.model, epsilon=epsilon)

        # Setup input validator based on training data
        self.input_validator = InputValidator({
            'mean': X_train.mean(axis=0),
            'std': X_train.std(axis=0) + 1e-8
        })

        # Training loop
        for epoch in range(epochs):
            loss = trainer.train_epoch(loader, optimizer, adversarial_ratio)

            if epoch % 10 == 0:
                robustness = trainer.evaluate_robustness(loader)
                print(f"Epoch {epoch}: Loss={loss:.4f}, "
                      f"Clean Acc={robustness['clean_accuracy']:.3f}, "
                      f"Robust Acc={robustness['adversarial_accuracy']:.3f}")

    def predict_with_defense(self, x: np.ndarray) -> dict:
        """Predict with multiple defensive layers"""

        # Layer 1: Input validation
        validation = self.input_validator.detect_anomalous_input(x)

        if validation['is_anomalous']:
            return {
                'prediction': None,
                'confidence': 0.0,
                'warning': 'ANOMALOUS_INPUT',
                'details': validation
            }

        # Layer 2: Feature squeezing detection
        is_adversarial = self.feature_squeezer.detect_adversarial(
            self._sklearn_wrapper(), x
        )

        # Layer 3: Get prediction
        x_tensor = torch.tensor(x, dtype=torch.float32).unsqueeze(0)
        self.model.eval()

        with torch.no_grad():
            output = self.model(x_tensor)
            probs = torch.softmax(output, dim=1)
            pred = output.argmax(dim=1).item()
            confidence = probs.max().item()

        return {
            'prediction': 'malicious' if pred == 1 else 'benign',
            'confidence': confidence,
            'warning': 'POTENTIAL_ADVERSARIAL' if is_adversarial else None,
            'probabilities': probs.numpy()[0].tolist()
        }

    def _sklearn_wrapper(self):
        """Wrapper for sklearn-style interface"""
        class Wrapper:
            def __init__(wrapper_self, model):
                wrapper_self.model = model

            def predict_proba(wrapper_self, x):
                x_tensor = torch.tensor(x, dtype=torch.float32)
                with torch.no_grad():
                    output = wrapper_self.model(x_tensor)
                    return torch.softmax(output, dim=1).numpy()

        return Wrapper(self.model)
```

---

## Part 6: Exercises

### Exercise 1: Implement FGSM Attack
Create an FGSM attack against the phishing classifier from Lab 01.

```python
# Your implementation here
def exercise_1_fgsm_attack():
    """
    TODO:
    1. Load trained phishing classifier
    2. Implement FGSM attack
    3. Measure evasion rate at different epsilon values
    4. Plot evasion rate vs. perturbation size
    """
    pass
```

### Exercise 2: Poisoning Attack Simulation
Simulate a label-flipping attack on a malware classifier.

```python
def exercise_2_poisoning():
    """
    TODO:
    1. Train baseline malware classifier
    2. Apply label-flipping to 5%, 10%, 20% of training data
    3. Measure accuracy degradation
    4. Identify which samples are most vulnerable to flipping
    """
    pass
```

### Exercise 3: Build Robust Classifier
Implement adversarial training for the anomaly detector from Lab 03.

```python
def exercise_3_robust_training():
    """
    TODO:
    1. Implement adversarial training loop
    2. Compare clean accuracy: standard vs. robust model
    3. Compare adversarial accuracy: standard vs. robust model
    4. Analyze the robustness-accuracy tradeoff
    """
    pass
```

### Exercise 4: Ensemble Defense
Create an ensemble of diverse classifiers for robust detection.

```python
def exercise_4_ensemble():
    """
    TODO:
    1. Train 5 classifiers with different:
       - Architectures (RF, SVM, NN)
       - Training subsets
       - Feature subsets
    2. Implement voting mechanism
    3. Test ensemble robustness vs. individual models
    4. Measure computational overhead
    """
    pass
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Impair Defenses | T1562 | Evade ML-based security controls |
| Data Manipulation | T1565 | Poison training data |
| Automated Collection | T1119 | Model extraction via queries |

---

## Key Takeaways

1. **Adversarial attacks are real** - Security ML models are actively targeted
2. **Defense in depth** - No single defense is sufficient
3. **Robustness vs accuracy tradeoff** - Robust models may sacrifice some accuracy
4. **Continuous evaluation** - Test against adversarial inputs regularly
5. **Semantic constraints** - Security attacks must preserve functionality

---

## Further Reading

- [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- [CleverHans Library](https://github.com/cleverhans-lab/cleverhans)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Evading Machine Learning Malware Detection (Paper)](https://arxiv.org/abs/1708.06131)

---

> **Stuck?** See the [Lab 17 Walkthrough](../../docs/walkthroughs/lab17-adversarial-ml-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 18 - Fine-Tuning Models for Security](../lab18-fine-tuning-security/)
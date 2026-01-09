# Lab 17: Adversarial ML - Solution Walkthrough

## Overview

Build defenses against adversarial machine learning attacks including evasion attacks (FGSM, PGD), data poisoning, and adversarial training.

**Time:** 4-5 hours
**Difficulty:** Expert

---

## Task 1: Understanding Adversarial Attacks

### Implementing FGSM Attack

```python
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Tuple

class MalwareClassifier(nn.Module):
    """Simple malware classifier for demonstration."""

    def __init__(self, input_dim: int = 100, hidden_dim: int = 64):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, 2)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x

class FGSMAttack:
    """Fast Gradient Sign Method attack."""

    def __init__(self, model: nn.Module, epsilon: float = 0.1):
        self.model = model
        self.epsilon = epsilon

    def generate_adversarial(self, x: torch.Tensor,
                            y: torch.Tensor) -> torch.Tensor:
        """Generate adversarial example using FGSM."""

        # Enable gradient computation
        x_adv = x.clone().detach().requires_grad_(True)

        # Forward pass
        output = self.model(x_adv)
        loss = F.cross_entropy(output, y)

        # Backward pass
        self.model.zero_grad()
        loss.backward()

        # Generate perturbation
        perturbation = self.epsilon * x_adv.grad.sign()

        # Create adversarial example
        x_adversarial = x_adv + perturbation

        # Clamp to valid range
        x_adversarial = torch.clamp(x_adversarial, 0, 1)

        return x_adversarial.detach()

    def evaluate_attack(self, x: torch.Tensor, y: torch.Tensor) -> dict:
        """Evaluate attack success rate."""

        # Original predictions
        with torch.no_grad():
            orig_pred = self.model(x).argmax(dim=1)

        # Generate adversarial examples
        x_adv = self.generate_adversarial(x, y)

        # Adversarial predictions
        with torch.no_grad():
            adv_pred = self.model(x_adv).argmax(dim=1)

        # Calculate metrics
        orig_accuracy = (orig_pred == y).float().mean().item()
        adv_accuracy = (adv_pred == y).float().mean().item()
        attack_success = (adv_pred != y).float().mean().item()

        return {
            'original_accuracy': orig_accuracy,
            'adversarial_accuracy': adv_accuracy,
            'attack_success_rate': attack_success,
            'accuracy_drop': orig_accuracy - adv_accuracy
        }

# Example usage
model = MalwareClassifier()
model.eval()

# Generate sample data
X = torch.randn(100, 100)
y = torch.randint(0, 2, (100,))

# Run FGSM attack
fgsm = FGSMAttack(model, epsilon=0.1)
results = fgsm.evaluate_attack(X, y)

print(f"Original Accuracy: {results['original_accuracy']:.2%}")
print(f"Adversarial Accuracy: {results['adversarial_accuracy']:.2%}")
print(f"Attack Success Rate: {results['attack_success_rate']:.2%}")
```

---

## Task 2: Projected Gradient Descent (PGD)

### Stronger Iterative Attack

```python
class PGDAttack:
    """Projected Gradient Descent attack - stronger iterative version."""

    def __init__(self, model: nn.Module, epsilon: float = 0.1,
                 alpha: float = 0.01, num_iterations: int = 40):
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha  # Step size
        self.num_iterations = num_iterations

    def generate_adversarial(self, x: torch.Tensor,
                            y: torch.Tensor,
                            random_start: bool = True) -> torch.Tensor:
        """Generate adversarial example using PGD."""

        # Random start within epsilon ball
        if random_start:
            delta = torch.empty_like(x).uniform_(-self.epsilon, self.epsilon)
            x_adv = x + delta
            x_adv = torch.clamp(x_adv, 0, 1)
        else:
            x_adv = x.clone()

        for i in range(self.num_iterations):
            x_adv = x_adv.clone().detach().requires_grad_(True)

            # Forward pass
            output = self.model(x_adv)
            loss = F.cross_entropy(output, y)

            # Backward pass
            self.model.zero_grad()
            loss.backward()

            # Update with gradient
            with torch.no_grad():
                x_adv = x_adv + self.alpha * x_adv.grad.sign()

                # Project back to epsilon ball
                delta = x_adv - x
                delta = torch.clamp(delta, -self.epsilon, self.epsilon)
                x_adv = x + delta

                # Clamp to valid range
                x_adv = torch.clamp(x_adv, 0, 1)

        return x_adv.detach()

    def evaluate_attack(self, x: torch.Tensor, y: torch.Tensor,
                       num_restarts: int = 5) -> dict:
        """Evaluate PGD with multiple random restarts."""

        # Original predictions
        with torch.no_grad():
            orig_pred = self.model(x).argmax(dim=1)
            orig_accuracy = (orig_pred == y).float().mean().item()

        # Multiple restarts to find best attack
        best_adv_accuracy = 1.0

        for restart in range(num_restarts):
            x_adv = self.generate_adversarial(x, y, random_start=True)

            with torch.no_grad():
                adv_pred = self.model(x_adv).argmax(dim=1)
                adv_accuracy = (adv_pred == y).float().mean().item()

            if adv_accuracy < best_adv_accuracy:
                best_adv_accuracy = adv_accuracy

        return {
            'original_accuracy': orig_accuracy,
            'adversarial_accuracy': best_adv_accuracy,
            'attack_success_rate': orig_accuracy - best_adv_accuracy,
            'num_restarts': num_restarts
        }

# Run PGD attack
pgd = PGDAttack(model, epsilon=0.1, alpha=0.01, num_iterations=40)
pgd_results = pgd.evaluate_attack(X, y, num_restarts=5)

print(f"PGD Attack Success Rate: {pgd_results['attack_success_rate']:.2%}")
```

---

## Task 3: Data Poisoning Detection

### Detecting Poisoned Training Data

```python
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

class PoisonDetector:
    """Detect poisoned samples in training data."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42
        )
        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=contamination
        )

    def detect_isolation_forest(self, X: np.ndarray) -> np.ndarray:
        """Detect outliers using Isolation Forest."""
        predictions = self.iso_forest.fit_predict(X)
        return predictions == -1  # True for outliers

    def detect_lof(self, X: np.ndarray) -> np.ndarray:
        """Detect outliers using Local Outlier Factor."""
        predictions = self.lof.fit_predict(X)
        return predictions == -1

    def detect_influence(self, model, X_train: np.ndarray,
                        y_train: np.ndarray,
                        X_val: np.ndarray,
                        y_val: np.ndarray) -> np.ndarray:
        """Estimate influence of training samples."""

        # Simplified influence estimation
        # In production, use proper influence functions

        influences = np.zeros(len(X_train))

        # Train model on full data
        model_full = self._train_model(X_train, y_train)
        val_loss_full = self._compute_loss(model_full, X_val, y_val)

        # Leave-one-out influence (expensive but accurate)
        for i in range(min(len(X_train), 100)):  # Sample for speed
            X_loo = np.delete(X_train, i, axis=0)
            y_loo = np.delete(y_train, i, axis=0)

            model_loo = self._train_model(X_loo, y_loo)
            val_loss_loo = self._compute_loss(model_loo, X_val, y_val)

            influences[i] = val_loss_full - val_loss_loo

        return influences

    def _train_model(self, X, y):
        """Train a simple model."""
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)
        return model

    def _compute_loss(self, model, X, y):
        """Compute log loss."""
        from sklearn.metrics import log_loss
        proba = model.predict_proba(X)
        return log_loss(y, proba)

    def ensemble_detection(self, X: np.ndarray) -> dict:
        """Combine multiple detection methods."""

        iso_outliers = self.detect_isolation_forest(X)
        lof_outliers = self.detect_lof(X)

        # Combine detections
        combined = iso_outliers & lof_outliers  # Both agree

        return {
            'isolation_forest': iso_outliers.sum(),
            'lof': lof_outliers.sum(),
            'consensus': combined.sum(),
            'consensus_indices': np.where(combined)[0].tolist()
        }

# Detect poisoned data
detector = PoisonDetector(contamination=0.1)

# Sample data (with some poisoned samples)
X_train = np.random.randn(1000, 50)
# Add some obvious outliers (poisoned)
X_train[-10:] = np.random.randn(10, 50) * 5

detection_results = detector.ensemble_detection(X_train)
print(f"Suspected poisoned samples: {detection_results['consensus']}")
print(f"Indices: {detection_results['consensus_indices']}")
```

---

## Task 4: Adversarial Training

### Training Robust Models

```python
class AdversarialTrainer:
    """Train models with adversarial examples for robustness."""

    def __init__(self, model: nn.Module, attack_epsilon: float = 0.1):
        self.model = model
        self.attack_epsilon = attack_epsilon
        self.optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        self.fgsm = FGSMAttack(model, epsilon=attack_epsilon)
        self.pgd = PGDAttack(model, epsilon=attack_epsilon)

    def train_epoch(self, dataloader, adv_ratio: float = 0.5) -> dict:
        """Train one epoch with adversarial examples."""

        self.model.train()
        total_loss = 0
        total_correct = 0
        total_samples = 0

        for batch_x, batch_y in dataloader:
            # Decide whether to use adversarial examples
            if np.random.random() < adv_ratio:
                # Generate adversarial examples
                self.model.eval()
                batch_x_adv = self.pgd.generate_adversarial(batch_x, batch_y)
                self.model.train()

                # Mix clean and adversarial
                batch_x = torch.cat([batch_x, batch_x_adv], dim=0)
                batch_y = torch.cat([batch_y, batch_y], dim=0)

            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(batch_x)
            loss = F.cross_entropy(outputs, batch_y)

            # Backward pass
            loss.backward()
            self.optimizer.step()

            # Track metrics
            total_loss += loss.item() * batch_x.size(0)
            total_correct += (outputs.argmax(dim=1) == batch_y).sum().item()
            total_samples += batch_x.size(0)

        return {
            'loss': total_loss / total_samples,
            'accuracy': total_correct / total_samples
        }

    def evaluate_robustness(self, X: torch.Tensor,
                           y: torch.Tensor) -> dict:
        """Evaluate model robustness against various attacks."""

        self.model.eval()

        results = {
            'clean_accuracy': 0,
            'fgsm_accuracy': 0,
            'pgd_accuracy': 0
        }

        with torch.no_grad():
            # Clean accuracy
            clean_pred = self.model(X).argmax(dim=1)
            results['clean_accuracy'] = (clean_pred == y).float().mean().item()

        # FGSM attack
        X_fgsm = self.fgsm.generate_adversarial(X, y)
        with torch.no_grad():
            fgsm_pred = self.model(X_fgsm).argmax(dim=1)
            results['fgsm_accuracy'] = (fgsm_pred == y).float().mean().item()

        # PGD attack
        X_pgd = self.pgd.generate_adversarial(X, y)
        with torch.no_grad():
            pgd_pred = self.model(X_pgd).argmax(dim=1)
            results['pgd_accuracy'] = (pgd_pred == y).float().mean().item()

        return results

# Adversarial training
trainer = AdversarialTrainer(model, attack_epsilon=0.1)

# Create simple dataloader
from torch.utils.data import TensorDataset, DataLoader
dataset = TensorDataset(X, y)
dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

# Train with adversarial examples
print("Training with adversarial examples...")
for epoch in range(10):
    metrics = trainer.train_epoch(dataloader, adv_ratio=0.5)
    print(f"Epoch {epoch+1}: Loss={metrics['loss']:.4f}, Acc={metrics['accuracy']:.2%}")

# Evaluate robustness
robustness = trainer.evaluate_robustness(X, y)
print(f"\nRobustness Evaluation:")
print(f"Clean: {robustness['clean_accuracy']:.2%}")
print(f"FGSM: {robustness['fgsm_accuracy']:.2%}")
print(f"PGD: {robustness['pgd_accuracy']:.2%}")
```

---

## Task 5: Certified Defenses

### Provable Robustness

```python
class RandomizedSmoothing:
    """Certified defense using randomized smoothing."""

    def __init__(self, model: nn.Module, sigma: float = 0.1,
                 n_samples: int = 100):
        self.model = model
        self.sigma = sigma
        self.n_samples = n_samples

    def predict(self, x: torch.Tensor) -> Tuple[int, float]:
        """Predict with certified radius."""

        self.model.eval()

        # Sample noisy versions
        counts = torch.zeros(2)  # Binary classification

        with torch.no_grad():
            for _ in range(self.n_samples):
                noise = torch.randn_like(x) * self.sigma
                noisy_x = x + noise
                pred = self.model(noisy_x).argmax(dim=1)
                counts[pred] += 1

        # Get prediction and confidence
        predicted_class = counts.argmax().item()
        confidence = counts[predicted_class].item() / self.n_samples

        # Calculate certified radius
        from scipy.stats import norm
        if confidence > 0.5:
            certified_radius = self.sigma * norm.ppf(confidence)
        else:
            certified_radius = 0.0

        return predicted_class, certified_radius

    def certify_batch(self, X: torch.Tensor) -> dict:
        """Certify predictions for a batch."""

        results = {
            'predictions': [],
            'certified_radii': [],
            'certified_count': 0
        }

        for i in range(X.shape[0]):
            pred, radius = self.predict(X[i:i+1])
            results['predictions'].append(pred)
            results['certified_radii'].append(radius)

            if radius > 0:
                results['certified_count'] += 1

        results['certification_rate'] = results['certified_count'] / X.shape[0]

        return results

# Certified defense
smoothing = RandomizedSmoothing(model, sigma=0.1, n_samples=100)

# Certify predictions
cert_results = smoothing.certify_batch(X[:20])
print(f"Certification Rate: {cert_results['certification_rate']:.2%}")
print(f"Average Certified Radius: {np.mean(cert_results['certified_radii']):.4f}")
```

---

## Task 6: Complete Defense Pipeline

### Integrated Adversarial Defense System

```python
class AdversarialDefensePipeline:
    """Complete pipeline for adversarial ML defense."""

    def __init__(self, model: nn.Module):
        self.model = model
        self.poison_detector = PoisonDetector()
        self.trainer = AdversarialTrainer(model)
        self.smoothing = RandomizedSmoothing(model)

    def secure_training(self, X_train: np.ndarray,
                       y_train: np.ndarray,
                       epochs: int = 10) -> dict:
        """Complete secure training pipeline."""

        results = {'phases': []}

        # Phase 1: Detect and remove poisoned data
        print("Phase 1: Detecting poisoned data...")
        poison_detection = self.poison_detector.ensemble_detection(X_train)

        clean_mask = np.ones(len(X_train), dtype=bool)
        clean_mask[poison_detection['consensus_indices']] = False

        X_clean = X_train[clean_mask]
        y_clean = y_train[clean_mask]

        results['phases'].append({
            'name': 'poison_detection',
            'removed_samples': (~clean_mask).sum(),
            'remaining_samples': clean_mask.sum()
        })

        # Phase 2: Adversarial training
        print("Phase 2: Adversarial training...")
        X_tensor = torch.tensor(X_clean, dtype=torch.float32)
        y_tensor = torch.tensor(y_clean, dtype=torch.long)

        dataset = TensorDataset(X_tensor, y_tensor)
        dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

        for epoch in range(epochs):
            metrics = self.trainer.train_epoch(dataloader, adv_ratio=0.5)

        results['phases'].append({
            'name': 'adversarial_training',
            'epochs': epochs,
            'final_accuracy': metrics['accuracy']
        })

        # Phase 3: Evaluate robustness
        print("Phase 3: Evaluating robustness...")
        robustness = self.trainer.evaluate_robustness(X_tensor, y_tensor)
        results['phases'].append({
            'name': 'robustness_evaluation',
            **robustness
        })

        return results

    def secure_inference(self, x: torch.Tensor) -> dict:
        """Secure inference with certified prediction."""

        # Get smoothed prediction
        prediction, certified_radius = self.smoothing.predict(x)

        # Regular prediction for comparison
        with torch.no_grad():
            regular_pred = self.model(x).argmax(dim=1).item()

        return {
            'smoothed_prediction': prediction,
            'certified_radius': certified_radius,
            'regular_prediction': regular_pred,
            'predictions_match': prediction == regular_pred,
            'is_certified': certified_radius > 0
        }

# Run defense pipeline
pipeline = AdversarialDefensePipeline(model)

# Secure training
X_np = X.numpy()
y_np = y.numpy()
training_results = pipeline.secure_training(X_np, y_np, epochs=5)

print("\nTraining Results:")
for phase in training_results['phases']:
    print(f"  {phase['name']}: {phase}")

# Secure inference
inference_result = pipeline.secure_inference(X[0:1])
print(f"\nInference Result:")
print(f"  Prediction: {inference_result['smoothed_prediction']}")
print(f"  Certified Radius: {inference_result['certified_radius']:.4f}")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Model not converging | Reduce adversarial ratio, adjust learning rate |
| Low certified radius | Increase noise sigma, more samples |
| High false positive poisoning | Reduce contamination parameter |
| Slow training | Use FGSM instead of PGD for training |
| Accuracy drop | Balance clean vs adversarial examples |

---

## Next Steps

- Implement more attack types (C&W, DeepFool)
- Add input preprocessing defenses
- Build ensemble defense systems
- Add adversarial detection at inference
- Create attack-aware monitoring dashboards

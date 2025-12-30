"""
Lab 17: Adversarial Machine Learning for Security - Solution

Learn about adversarial attacks on ML models and defenses.
Implement FGSM, PGD attacks and adversarial training.
"""

import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np


def setup_llm(provider: str = "auto"):
    """Initialize LLM client based on available API keys."""
    if provider == "auto":
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("GOOGLE_API_KEY"):
            provider = "google"
        else:
            raise ValueError("No API key found.")

    if provider == "anthropic":
        from anthropic import Anthropic

        return ("anthropic", Anthropic())
    elif provider == "openai":
        from openai import OpenAI

        return ("openai", OpenAI())
    elif provider == "google":
        import google.generativeai as genai

        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        return ("google", genai.GenerativeModel("gemini-2.5-pro"))
    else:
        raise ValueError(f"Unknown provider: {provider}")


@dataclass
class MalwareSample:
    """Malware sample with features for classification."""

    sample_id: str
    features: np.ndarray
    label: int
    family: str = ""
    confidence: float = 0.0


@dataclass
class AdversarialExample:
    """Adversarial example generated from original sample."""

    original: MalwareSample
    perturbation: np.ndarray
    adversarial_features: np.ndarray
    attack_type: str
    success: bool
    original_prediction: int
    adversarial_prediction: int
    perturbation_norm: float


@dataclass
class AttackResult:
    """Result of adversarial attack evaluation."""

    attack_type: str
    success_rate: float
    avg_perturbation: float
    samples_tested: int
    successful_examples: List[AdversarialExample] = field(default_factory=list)


class SimpleClassifier:
    """Simple neural network classifier for demonstration."""

    def __init__(self, input_dim: int, hidden_dim: int = 64):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        np.random.seed(42)
        self.W1 = np.random.randn(input_dim, hidden_dim) * 0.1
        self.b1 = np.zeros(hidden_dim)
        self.W2 = np.random.randn(hidden_dim, 2) * 0.1
        self.b2 = np.zeros(2)

    def forward(self, x: np.ndarray) -> np.ndarray:
        """Forward pass through the network."""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        h = np.maximum(0, x @ self.W1 + self.b1)
        return h @ self.W2 + self.b2

    def predict(self, x: np.ndarray) -> np.ndarray:
        """Get class predictions."""
        logits = self.forward(x)
        return np.argmax(logits, axis=-1)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Get class probabilities using softmax."""
        logits = self.forward(x)
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        return exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

    def compute_loss(self, x: np.ndarray, y: np.ndarray) -> float:
        """Compute cross-entropy loss."""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        if isinstance(y, int):
            y = np.array([y])
        probs = self.predict_proba(x)
        n = len(y)
        return -np.sum(np.log(probs[np.arange(n), y] + 1e-8)) / n

    def compute_gradient(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Compute gradient of loss with respect to input."""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        if isinstance(y, int):
            y = np.array([y])

        # Forward pass
        h = x @ self.W1 + self.b1
        h_relu = np.maximum(0, h)
        logits = h_relu @ self.W2 + self.b2

        # Softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

        # Gradient of cross-entropy loss w.r.t. logits
        n = len(y)
        d_logits = probs.copy()
        d_logits[np.arange(n), y] -= 1
        d_logits /= n

        # Backprop through W2
        d_h_relu = d_logits @ self.W2.T

        # Backprop through ReLU
        d_h = d_h_relu * (h > 0)

        # Backprop through W1 to input
        d_x = d_h @ self.W1.T

        return d_x.squeeze()

    def update_weights(self, x: np.ndarray, y: np.ndarray, learning_rate: float):
        """Update model weights using gradient descent."""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        if isinstance(y, int):
            y = np.array([y])

        n = len(y)

        # Forward pass
        h = x @ self.W1 + self.b1
        h_relu = np.maximum(0, h)
        logits = h_relu @ self.W2 + self.b2

        # Softmax and loss gradient
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

        d_logits = probs.copy()
        d_logits[np.arange(n), y] -= 1
        d_logits /= n

        # Gradients for W2, b2
        d_W2 = h_relu.T @ d_logits
        d_b2 = np.sum(d_logits, axis=0)

        # Backprop through ReLU
        d_h_relu = d_logits @ self.W2.T
        d_h = d_h_relu * (h > 0)

        # Gradients for W1, b1
        d_W1 = x.T @ d_h
        d_b1 = np.sum(d_h, axis=0)

        # Update weights
        self.W1 -= learning_rate * d_W1
        self.b1 -= learning_rate * d_b1
        self.W2 -= learning_rate * d_W2
        self.b2 -= learning_rate * d_b2


class FGSMAttack:
    """Fast Gradient Sign Method attack."""

    def __init__(self, model: SimpleClassifier, epsilon: float = 0.1):
        self.model = model
        self.epsilon = epsilon

    def generate(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Generate adversarial example using FGSM."""
        if isinstance(y, int):
            y = np.array([y])

        # Compute gradient of loss w.r.t. input
        gradient = self.model.compute_gradient(x, y)

        # FGSM: x_adv = x + epsilon * sign(gradient)
        perturbation = self.epsilon * np.sign(gradient)
        x_adv = x + perturbation

        return x_adv

    def attack_sample(self, sample: MalwareSample) -> AdversarialExample:
        """Attack a single malware sample."""
        x = sample.features
        y = sample.label

        # Get original prediction
        original_pred = self.model.predict(x.reshape(1, -1))[0]

        # Generate adversarial example
        x_adv = self.generate(x, y)

        # Get adversarial prediction
        adv_pred = self.model.predict(x_adv.reshape(1, -1))[0]

        # Calculate perturbation
        perturbation = x_adv - x
        perturbation_norm = np.linalg.norm(perturbation)

        return AdversarialExample(
            original=sample,
            perturbation=perturbation,
            adversarial_features=x_adv,
            attack_type="fgsm",
            success=(adv_pred != y),
            original_prediction=original_pred,
            adversarial_prediction=adv_pred,
            perturbation_norm=perturbation_norm,
        )

    def evaluate(self, samples: List[MalwareSample]) -> AttackResult:
        """Evaluate attack on multiple samples."""
        successful = []
        total_perturbation = 0.0

        for sample in samples:
            result = self.attack_sample(sample)
            if result.success:
                successful.append(result)
            total_perturbation += result.perturbation_norm

        success_rate = len(successful) / len(samples) if samples else 0.0
        avg_perturbation = total_perturbation / len(samples) if samples else 0.0

        return AttackResult(
            attack_type="fgsm",
            success_rate=success_rate,
            avg_perturbation=avg_perturbation,
            samples_tested=len(samples),
            successful_examples=successful,
        )


class PGDAttack:
    """Projected Gradient Descent attack."""

    def __init__(
        self,
        model: SimpleClassifier,
        epsilon: float = 0.1,
        alpha: float = 0.01,
        num_steps: int = 40,
    ):
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_steps = num_steps

    def generate(self, x: np.ndarray, y: np.ndarray, targeted: bool = False) -> np.ndarray:
        """Generate adversarial example using PGD."""
        if isinstance(y, int):
            y = np.array([y])

        # Initialize with random perturbation in epsilon-ball
        x_adv = x + np.random.uniform(-self.epsilon, self.epsilon, x.shape)
        x_adv = self.project(x_adv, x)

        for _ in range(self.num_steps):
            # Compute gradient
            gradient = self.model.compute_gradient(x_adv, y)

            if targeted:
                # Minimize loss to target class (gradient descent)
                x_adv = x_adv - self.alpha * np.sign(gradient)
            else:
                # Maximize loss (gradient ascent)
                x_adv = x_adv + self.alpha * np.sign(gradient)

            # Project back to epsilon-ball
            x_adv = self.project(x_adv, x)

        return x_adv

    def project(self, x: np.ndarray, x_orig: np.ndarray) -> np.ndarray:
        """Project perturbation back to epsilon-ball (L-infinity)."""
        perturbation = x - x_orig
        perturbation = np.clip(perturbation, -self.epsilon, self.epsilon)
        return x_orig + perturbation

    def attack_sample(
        self, sample: MalwareSample, targeted: bool = False, target_label: int = None
    ) -> AdversarialExample:
        """Attack a single sample."""
        x = sample.features
        y = sample.label if not targeted else target_label

        original_pred = self.model.predict(x.reshape(1, -1))[0]
        x_adv = self.generate(x, y, targeted=targeted)
        adv_pred = self.model.predict(x_adv.reshape(1, -1))[0]

        perturbation = x_adv - x
        perturbation_norm = np.linalg.norm(perturbation)

        success = (adv_pred != sample.label) if not targeted else (adv_pred == target_label)

        return AdversarialExample(
            original=sample,
            perturbation=perturbation,
            adversarial_features=x_adv,
            attack_type="pgd",
            success=success,
            original_prediction=original_pred,
            adversarial_prediction=adv_pred,
            perturbation_norm=perturbation_norm,
        )

    def evaluate(self, samples: List[MalwareSample]) -> AttackResult:
        """Evaluate attack on multiple samples."""
        successful = []
        total_perturbation = 0.0

        for sample in samples:
            result = self.attack_sample(sample)
            if result.success:
                successful.append(result)
            total_perturbation += result.perturbation_norm

        success_rate = len(successful) / len(samples) if samples else 0.0
        avg_perturbation = total_perturbation / len(samples) if samples else 0.0

        return AttackResult(
            attack_type="pgd",
            success_rate=success_rate,
            avg_perturbation=avg_perturbation,
            samples_tested=len(samples),
            successful_examples=successful,
        )


class AdversarialTrainer:
    """Adversarial training to improve model robustness."""

    def __init__(self, model: SimpleClassifier, attack: str = "pgd", epsilon: float = 0.1):
        self.model = model
        self.attack_type = attack
        self.epsilon = epsilon

        if attack == "fgsm":
            self.attack = FGSMAttack(model, epsilon)
        else:
            self.attack = PGDAttack(model, epsilon, alpha=epsilon / 4, num_steps=10)

    def train_step(self, x: np.ndarray, y: np.ndarray, learning_rate: float = 0.01) -> float:
        """Single adversarial training step."""
        # Generate adversarial examples
        x_adv = self.attack.generate(x, y)

        # Compute loss on adversarial examples
        loss = self.model.compute_loss(x_adv, y)

        # Update weights using adversarial examples
        self.model.update_weights(x_adv, y, learning_rate)

        return loss

    def train(
        self, train_data: List[MalwareSample], epochs: int = 10, batch_size: int = 32
    ) -> List[float]:
        """Full adversarial training."""
        losses = []

        X = np.array([s.features for s in train_data])
        y = np.array([s.label for s in train_data])
        n = len(train_data)

        for epoch in range(epochs):
            # Shuffle data
            indices = np.random.permutation(n)
            X_shuffled = X[indices]
            y_shuffled = y[indices]

            epoch_loss = 0.0
            n_batches = 0

            for i in range(0, n, batch_size):
                X_batch = X_shuffled[i : i + batch_size]
                y_batch = y_shuffled[i : i + batch_size]

                batch_loss = self.train_step(X_batch, y_batch)
                epoch_loss += batch_loss
                n_batches += 1

            avg_loss = epoch_loss / n_batches
            losses.append(avg_loss)
            print(f"  Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        return losses

    def evaluate_robustness(
        self, test_data: List[MalwareSample], attacks: List[str] = None
    ) -> dict:
        """Evaluate model robustness against various attacks."""
        if attacks is None:
            attacks = ["clean", "fgsm", "pgd"]

        X = np.array([s.features for s in test_data])
        y = np.array([s.label for s in test_data])

        results = {}

        # Clean accuracy
        if "clean" in attacks:
            predictions = self.model.predict(X)
            results["clean_accuracy"] = np.mean(predictions == y)

        # FGSM attack
        if "fgsm" in attacks:
            fgsm = FGSMAttack(self.model, self.epsilon)
            fgsm_result = fgsm.evaluate(test_data)
            results["fgsm_success_rate"] = fgsm_result.success_rate
            results["adversarial_accuracy"] = 1.0 - fgsm_result.success_rate

        # PGD attack
        if "pgd" in attacks:
            pgd = PGDAttack(self.model, self.epsilon)
            pgd_result = pgd.evaluate(test_data)
            results["pgd_success_rate"] = pgd_result.success_rate

        return results


class RobustClassifier:
    """Malware classifier with built-in defenses."""

    def __init__(self, base_model: SimpleClassifier):
        self.model = base_model
        self.input_transformations: List[Callable] = []
        self.ensemble_models: List[SimpleClassifier] = []

    def add_input_transformation(self, transform: Callable):
        """Add input transformation defense."""
        self.input_transformations.append(transform)

    def add_ensemble_model(self, model: SimpleClassifier):
        """Add model to ensemble for ensemble defense."""
        self.ensemble_models.append(model)

    def detect_adversarial(self, x: np.ndarray) -> Tuple[bool, float]:
        """Detect if input is adversarial."""
        if x.ndim == 1:
            x = x.reshape(1, -1)

        detection_score = 0.0
        checks = 0

        # Check prediction consistency under transformations
        original_pred = self.model.predict(x)[0]

        for transform in self.input_transformations:
            transformed_x = transform(x)
            transformed_pred = self.model.predict(transformed_x)[0]
            if transformed_pred != original_pred:
                detection_score += 1.0
            checks += 1

        # Check ensemble disagreement
        if self.ensemble_models:
            predictions = [self.model.predict(x)[0]]
            for model in self.ensemble_models:
                predictions.append(model.predict(x)[0])

            unique_preds = len(set(predictions))
            if unique_preds > 1:
                detection_score += (unique_preds - 1) / len(predictions)
            checks += 1

        if checks == 0:
            return False, 0.0

        normalized_score = detection_score / checks
        is_adversarial = normalized_score > 0.5

        return is_adversarial, normalized_score

    def predict_robust(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make robust prediction with defense mechanisms."""
        if x.ndim == 1:
            x = x.reshape(1, -1)

        # Apply input transformations (use average)
        if self.input_transformations:
            transformed_probs = []
            for transform in self.input_transformations:
                transformed_x = transform(x)
                probs = self.model.predict_proba(transformed_x)
                transformed_probs.append(probs)

            # Average probabilities
            avg_probs = np.mean(transformed_probs, axis=0)
        else:
            avg_probs = self.model.predict_proba(x)

        # Ensemble voting if available
        if self.ensemble_models:
            all_probs = [avg_probs]
            for model in self.ensemble_models:
                all_probs.append(model.predict_proba(x))
            avg_probs = np.mean(all_probs, axis=0)

        predictions = np.argmax(avg_probs, axis=-1)
        confidences = np.max(avg_probs, axis=-1)

        return predictions, confidences

    def evaluate_defenses(
        self, clean_data: List[MalwareSample], adversarial_data: List[AdversarialExample]
    ) -> dict:
        """Evaluate effectiveness of defenses."""
        results = {}

        # Clean accuracy
        X_clean = np.array([s.features for s in clean_data])
        y_clean = np.array([s.label for s in clean_data])
        clean_preds, _ = self.predict_robust(X_clean)
        results["clean_accuracy"] = np.mean(clean_preds == y_clean)

        # Adversarial accuracy (correctly classifying adversarial examples)
        if adversarial_data:
            X_adv = np.array([e.adversarial_features for e in adversarial_data])
            y_adv = np.array([e.original.label for e in adversarial_data])
            adv_preds, _ = self.predict_robust(X_adv)
            results["adversarial_accuracy"] = np.mean(adv_preds == y_adv)

            # Detection rate
            detected = 0
            for example in adversarial_data:
                is_adv, _ = self.detect_adversarial(example.adversarial_features)
                if is_adv:
                    detected += 1
            results["detection_rate"] = detected / len(adversarial_data)

        return results


def create_sample_data(n_samples: int = 100, n_features: int = 20) -> List[MalwareSample]:
    """Create sample malware dataset for testing."""
    np.random.seed(42)
    samples = []

    for i in range(n_samples):
        label = i % 2
        if label == 1:
            features = np.random.randn(n_features) * 0.5 + 1.0
        else:
            features = np.random.randn(n_features) * 0.5 - 1.0

        samples.append(
            MalwareSample(
                sample_id=f"sample_{i:04d}",
                features=features,
                label=label,
                family="test_family" if label == 1 else "benign",
            )
        )

    return samples


def main():
    """Main entry point for Lab 17."""
    print("=" * 60)
    print("Lab 17: Adversarial Machine Learning - Solution")
    print("=" * 60)

    # Create sample data
    print("\n--- Creating Sample Data ---")
    samples = create_sample_data(n_samples=200, n_features=20)
    train_samples = samples[:160]
    test_samples = samples[160:]
    print(f"Created {len(samples)} samples")

    # Initialize and train model
    print("\n--- Training Classifier ---")
    model = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Simple training first
    X_train = np.array([s.features for s in train_samples])
    y_train = np.array([s.label for s in train_samples])

    for epoch in range(20):
        model.update_weights(X_train, y_train, learning_rate=0.1)

    X_test = np.array([s.features for s in test_samples])
    y_test = np.array([s.label for s in test_samples])
    predictions = model.predict(X_test)
    accuracy = np.mean(predictions == y_test)
    print(f"Clean test accuracy: {accuracy:.2%}")

    # FGSM Attack
    print("\n--- FGSM Attack ---")
    fgsm = FGSMAttack(model, epsilon=0.3)
    fgsm_result = fgsm.evaluate(test_samples)
    print(f"FGSM success rate: {fgsm_result.success_rate:.2%}")
    print(f"Average perturbation: {fgsm_result.avg_perturbation:.4f}")

    # PGD Attack
    print("\n--- PGD Attack ---")
    pgd = PGDAttack(model, epsilon=0.3, alpha=0.05, num_steps=40)
    pgd_result = pgd.evaluate(test_samples)
    print(f"PGD success rate: {pgd_result.success_rate:.2%}")
    print(f"Average perturbation: {pgd_result.avg_perturbation:.4f}")

    # Adversarial Training
    print("\n--- Adversarial Training ---")
    robust_model = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Pre-train on clean data
    for _ in range(10):
        robust_model.update_weights(X_train, y_train, learning_rate=0.1)

    trainer = AdversarialTrainer(robust_model, attack="pgd", epsilon=0.3)
    losses = trainer.train(train_samples, epochs=5, batch_size=32)

    # Evaluate robustness
    print("\n--- Robustness Evaluation ---")
    robustness = trainer.evaluate_robustness(test_samples)
    print(f"Clean accuracy: {robustness.get('clean_accuracy', 0):.2%}")
    print(f"FGSM success rate: {robustness.get('fgsm_success_rate', 0):.2%}")
    print(f"PGD success rate: {robustness.get('pgd_success_rate', 0):.2%}")

    # Robust Classifier with Defenses
    print("\n--- Robust Classifier with Defenses ---")
    robust = RobustClassifier(robust_model)

    # Add noise injection defense
    def add_noise(x):
        return x + np.random.randn(*x.shape) * 0.05

    robust.add_input_transformation(add_noise)

    # Add another transformation
    def gaussian_blur(x):
        # Simple averaging
        kernel_size = 3
        if x.ndim == 1:
            x = x.reshape(1, -1)
        result = np.zeros_like(x)
        for i in range(x.shape[1]):
            start = max(0, i - kernel_size // 2)
            end = min(x.shape[1], i + kernel_size // 2 + 1)
            result[:, i] = np.mean(x[:, start:end], axis=1)
        return result

    robust.add_input_transformation(gaussian_blur)

    # Evaluate defenses
    defense_results = robust.evaluate_defenses(test_samples, pgd_result.successful_examples)
    print(f"Clean accuracy with defenses: {defense_results.get('clean_accuracy', 0):.2%}")
    print(
        f"Adversarial accuracy with defenses: {defense_results.get('adversarial_accuracy', 0):.2%}"
    )
    print(f"Adversarial detection rate: {defense_results.get('detection_rate', 0):.2%}")

    print("\n" + "=" * 60)
    print("Lab 17 Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

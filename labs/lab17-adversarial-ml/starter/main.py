"""
Lab 17: Adversarial Machine Learning for Security - Starter Code

Learn about adversarial attacks on ML models and defenses.
Implement FGSM, PGD attacks and adversarial training.

Complete the TODOs to build adversarial ML capabilities.
"""

import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Callable
import numpy as np


# LLM setup - supports multiple providers
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
            raise ValueError(
                "No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY"
            )

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
    label: int  # 0 = benign, 1 = malware
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
    successful_examples: List[AdversarialExample]


class SimpleClassifier:
    """Simple neural network classifier for demonstration."""

    def __init__(self, input_dim: int, hidden_dim: int = 64):
        """
        Initialize simple classifier.

        Args:
            input_dim: Number of input features
            hidden_dim: Number of hidden neurons
        """
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        # Initialize weights (simplified neural network)
        np.random.seed(42)
        self.W1 = np.random.randn(input_dim, hidden_dim) * 0.1
        self.b1 = np.zeros(hidden_dim)
        self.W2 = np.random.randn(hidden_dim, 2) * 0.1
        self.b2 = np.zeros(2)

    def forward(self, x: np.ndarray) -> np.ndarray:
        """
        Forward pass through the network.

        Args:
            x: Input features (batch_size, input_dim)

        Returns:
            Output logits (batch_size, 2)
        """
        # Hidden layer with ReLU
        h = np.maximum(0, x @ self.W1 + self.b1)
        # Output layer
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
        probs = self.predict_proba(x)
        n = len(y)
        return -np.sum(np.log(probs[np.arange(n), y] + 1e-8)) / n

    def compute_gradient(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """
        Compute gradient of loss with respect to input.

        TODO: Implement gradient computation
        - Forward pass
        - Compute softmax
        - Backpropagate to input

        Args:
            x: Input features
            y: Target labels

        Returns:
            Gradient of loss w.r.t. input
        """
        # TODO: Implement this method
        pass


class FGSMAttack:
    """Fast Gradient Sign Method attack."""

    def __init__(self, model: SimpleClassifier, epsilon: float = 0.1):
        """
        Initialize FGSM attack.

        Args:
            model: Target classifier
            epsilon: Perturbation magnitude
        """
        self.model = model
        self.epsilon = epsilon

    def generate(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """
        Generate adversarial example using FGSM.

        TODO: Implement FGSM
        - Compute gradient of loss w.r.t. input
        - Take sign of gradient
        - Apply epsilon-scaled perturbation

        Args:
            x: Original input
            y: True label

        Returns:
            Adversarial example
        """
        # TODO: Implement this method
        # Formula: x_adv = x + epsilon * sign(gradient)
        pass

    def attack_sample(self, sample: MalwareSample) -> AdversarialExample:
        """
        Attack a single malware sample.

        TODO: Implement sample attack
        - Generate adversarial features
        - Check if attack successful
        - Create AdversarialExample

        Args:
            sample: Original malware sample

        Returns:
            AdversarialExample with results
        """
        # TODO: Implement this method
        pass

    def evaluate(self, samples: List[MalwareSample]) -> AttackResult:
        """
        Evaluate attack on multiple samples.

        TODO: Implement evaluation
        - Attack all samples
        - Calculate success rate
        - Track perturbation magnitudes

        Args:
            samples: List of samples to attack

        Returns:
            AttackResult with statistics
        """
        # TODO: Implement this method
        pass


class PGDAttack:
    """Projected Gradient Descent attack."""

    def __init__(
        self,
        model: SimpleClassifier,
        epsilon: float = 0.1,
        alpha: float = 0.01,
        num_steps: int = 40,
    ):
        """
        Initialize PGD attack.

        Args:
            model: Target classifier
            epsilon: Maximum perturbation (L-infinity)
            alpha: Step size
            num_steps: Number of iterations
        """
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_steps = num_steps

    def generate(self, x: np.ndarray, y: np.ndarray, targeted: bool = False) -> np.ndarray:
        """
        Generate adversarial example using PGD.

        TODO: Implement PGD
        - Initialize with random perturbation in epsilon-ball
        - Iteratively:
          - Compute gradient
          - Take gradient step
          - Project back to epsilon-ball

        Args:
            x: Original input
            y: True/target label
            targeted: If True, minimize loss to target class

        Returns:
            Adversarial example
        """
        # TODO: Implement this method
        pass

    def project(self, x: np.ndarray, x_orig: np.ndarray) -> np.ndarray:
        """
        Project perturbation back to epsilon-ball.

        TODO: Implement projection
        - Clip to L-infinity ball around original

        Args:
            x: Current adversarial example
            x_orig: Original input

        Returns:
            Projected adversarial example
        """
        # TODO: Implement this method
        pass

    def attack_sample(
        self, sample: MalwareSample, targeted: bool = False, target_label: int = None
    ) -> AdversarialExample:
        """
        Attack a single sample.

        Args:
            sample: Original sample
            targeted: Use targeted attack
            target_label: Target class for targeted attack

        Returns:
            AdversarialExample with results
        """
        # TODO: Implement this method
        pass

    def evaluate(self, samples: List[MalwareSample]) -> AttackResult:
        """Evaluate attack on multiple samples."""
        # TODO: Implement this method
        pass


class AdversarialTrainer:
    """Adversarial training to improve model robustness."""

    def __init__(self, model: SimpleClassifier, attack: str = "pgd", epsilon: float = 0.1):
        """
        Initialize adversarial trainer.

        Args:
            model: Model to train
            attack: Attack type for training ("fgsm" or "pgd")
            epsilon: Perturbation magnitude
        """
        self.model = model
        self.attack_type = attack
        self.epsilon = epsilon

        if attack == "fgsm":
            self.attack = FGSMAttack(model, epsilon)
        else:
            self.attack = PGDAttack(model, epsilon)

    def train_step(self, x: np.ndarray, y: np.ndarray, learning_rate: float = 0.01) -> float:
        """
        Single adversarial training step.

        TODO: Implement adversarial training step
        - Generate adversarial examples
        - Compute loss on adversarial examples
        - Update model weights

        Args:
            x: Batch of inputs
            y: Batch of labels
            learning_rate: Learning rate

        Returns:
            Loss value
        """
        # TODO: Implement this method
        pass

    def train(
        self, train_data: List[MalwareSample], epochs: int = 10, batch_size: int = 32
    ) -> List[float]:
        """
        Full adversarial training.

        TODO: Implement training loop
        - Shuffle data each epoch
        - Train in batches
        - Track loss

        Args:
            train_data: Training samples
            epochs: Number of epochs
            batch_size: Batch size

        Returns:
            List of loss values per epoch
        """
        # TODO: Implement this method
        pass

    def evaluate_robustness(
        self, test_data: List[MalwareSample], attacks: List[str] = None
    ) -> dict:
        """
        Evaluate model robustness against various attacks.

        TODO: Implement robustness evaluation
        - Test clean accuracy
        - Test against each attack type
        - Report metrics

        Args:
            test_data: Test samples
            attacks: Attack types to test

        Returns:
            Dictionary of robustness metrics
        """
        # TODO: Implement this method
        pass


class RobustClassifier:
    """Malware classifier with built-in defenses."""

    def __init__(self, base_model: SimpleClassifier):
        """
        Initialize robust classifier.

        Args:
            base_model: Base classifier model
        """
        self.model = base_model
        self.input_transformations = []
        self.ensemble_models = []

    def add_input_transformation(self, transform: Callable):
        """
        Add input transformation defense.

        TODO: Implement transformation addition
        - Store transformation function
        - Will be applied before classification

        Args:
            transform: Transformation function
        """
        # TODO: Implement this method
        pass

    def add_ensemble_model(self, model: SimpleClassifier):
        """
        Add model to ensemble for ensemble defense.

        Args:
            model: Additional model for ensemble
        """
        self.ensemble_models.append(model)

    def detect_adversarial(self, x: np.ndarray) -> Tuple[bool, float]:
        """
        Detect if input is adversarial.

        TODO: Implement adversarial detection
        - Check prediction consistency under transformations
        - Check ensemble disagreement
        - Calculate detection score

        Args:
            x: Input to check

        Returns:
            (is_adversarial, confidence)
        """
        # TODO: Implement this method
        pass

    def predict_robust(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make robust prediction with defense mechanisms.

        TODO: Implement robust prediction
        - Apply input transformations
        - Use ensemble voting if available
        - Return prediction and confidence

        Args:
            x: Input features

        Returns:
            (predictions, confidences)
        """
        # TODO: Implement this method
        pass

    def evaluate_defenses(
        self, clean_data: List[MalwareSample], adversarial_data: List[AdversarialExample]
    ) -> dict:
        """
        Evaluate effectiveness of defenses.

        TODO: Implement defense evaluation
        - Measure clean accuracy
        - Measure adversarial accuracy
        - Measure detection rate

        Args:
            clean_data: Clean test samples
            adversarial_data: Adversarial examples

        Returns:
            Defense effectiveness metrics
        """
        # TODO: Implement this method
        pass


def create_sample_data(n_samples: int = 100, n_features: int = 20) -> List[MalwareSample]:
    """Create sample malware dataset for testing."""
    np.random.seed(42)
    samples = []

    for i in range(n_samples):
        # Generate features
        label = i % 2  # Alternate between benign/malware
        if label == 1:  # Malware
            features = np.random.randn(n_features) * 0.5 + 1.0
        else:  # Benign
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
    print("Lab 17: Adversarial Machine Learning for Security")
    print("=" * 60)

    # Create sample data
    print("\n--- Creating Sample Data ---")
    samples = create_sample_data(n_samples=100, n_features=20)
    train_samples = samples[:80]
    test_samples = samples[80:]
    print(f"Created {len(samples)} samples ({len(train_samples)} train, {len(test_samples)} test)")

    # Initialize model
    print("\n--- Initializing Classifier ---")
    model = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Get test accuracy
    X_test = np.array([s.features for s in test_samples])
    y_test = np.array([s.label for s in test_samples])
    predictions = model.predict(X_test)
    accuracy = np.mean(predictions == y_test)
    print(f"Initial test accuracy: {accuracy:.2%}")

    # Task 1: FGSM Attack
    print("\n--- Task 1: FGSM Attack ---")
    fgsm = FGSMAttack(model, epsilon=0.1)
    fgsm_result = fgsm.evaluate(test_samples)
    if fgsm_result:
        print(f"FGSM success rate: {fgsm_result.success_rate:.2%}")
        print(f"Average perturbation: {fgsm_result.avg_perturbation:.4f}")
    else:
        print("TODO: Implement FGSM attack")

    # Task 2: PGD Attack
    print("\n--- Task 2: PGD Attack ---")
    pgd = PGDAttack(model, epsilon=0.1, alpha=0.01, num_steps=40)
    pgd_result = pgd.evaluate(test_samples)
    if pgd_result:
        print(f"PGD success rate: {pgd_result.success_rate:.2%}")
        print(f"Average perturbation: {pgd_result.avg_perturbation:.4f}")
    else:
        print("TODO: Implement PGD attack")

    # Task 3: Adversarial Training
    print("\n--- Task 3: Adversarial Training ---")
    trainer = AdversarialTrainer(model, attack="pgd", epsilon=0.1)
    losses = trainer.train(train_samples, epochs=5)
    if losses:
        print(f"Training complete. Final loss: {losses[-1]:.4f}")
    else:
        print("TODO: Implement adversarial training")

    # Task 4: Robust Classifier
    print("\n--- Task 4: Robust Classifier ---")
    robust = RobustClassifier(model)

    # Add input transformation (noise injection)
    def add_noise(x):
        return x + np.random.randn(*x.shape) * 0.01

    robust.add_input_transformation(add_noise)

    # Test robust predictions
    robust_preds, confidences = robust.predict_robust(X_test)
    if robust_preds is not None:
        robust_accuracy = np.mean(robust_preds == y_test)
        print(f"Robust accuracy: {robust_accuracy:.2%}")
    else:
        print("TODO: Implement robust prediction")

    # Task 5: Defense Evaluation
    print("\n--- Task 5: Defense Evaluation ---")
    robustness = trainer.evaluate_robustness(test_samples)
    if robustness:
        print(f"Clean accuracy: {robustness.get('clean_accuracy', 'N/A'):.2%}")
        print(f"Adversarial accuracy: {robustness.get('adversarial_accuracy', 'N/A'):.2%}")
    else:
        print("TODO: Implement robustness evaluation")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 17!")
    print("=" * 60)


if __name__ == "__main__":
    main()

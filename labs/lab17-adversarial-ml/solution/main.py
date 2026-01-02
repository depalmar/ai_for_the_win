"""
Lab 17: Adversarial Machine Learning for Security - Solution

Learn about adversarial attacks on ML models and defenses.
Implement FGSM, PGD attacks and adversarial training.

=============================================================================
CONCEPT: ADVERSARIAL MACHINE LEARNING
=============================================================================

Why This Matters for Security:
------------------------------
Security ML models (malware detection, phishing filters, etc.) are prime
targets for adversarial attacks. Attackers WILL try to evade your classifiers.

Key Attack Types:
-----------------
1. EVASION ATTACKS (at inference time):
   - Craft inputs that fool a trained model
   - Example: Malware modified to evade AV detection
   - This lab focuses on evasion

2. POISONING ATTACKS (at training time):
   - Corrupt training data to degrade model
   - Example: Submit mislabeled samples to VirusTotal

3. MODEL EXTRACTION:
   - Query model to steal/clone it
   - Example: Competitor queries your API to recreate model

Attack Algorithms Covered:
--------------------------
FGSM (Fast Gradient Sign Method):
   - Single-step attack using gradient direction
   - Fast but may not find optimal perturbation
   - x_adv = x + epsilon * sign(∇_x Loss)

PGD (Projected Gradient Descent):
   - Iterative version of FGSM
   - More powerful, finds smaller perturbations
   - Multiple steps with projection back to epsilon-ball

Defense Strategies:
-------------------
1. Adversarial Training: Train on adversarial examples
2. Input Validation: Detect anomalous inputs
3. Ensemble Methods: Harder to attack multiple models
4. Gradient Masking: Hide gradient information (weak defense)

Security Implications:
----------------------
- Never assume ML models are robust without testing
- Adversarial testing should be part of security review
- Defense in depth: Don't rely solely on ML for security decisions

=============================================================================
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
    """Simple neural network classifier for demonstration.

    This is a minimal 2-layer neural network for demonstrating
    adversarial attacks. In production, you'd use PyTorch/TensorFlow.

    Architecture:
        Input (n features) → Hidden (64 units, ReLU) → Output (2 classes)

    Key Methods for Adversarial ML:
        - compute_gradient(): Returns ∇_x Loss - the direction to perturb input
        - This gradient tells us how to modify input to INCREASE loss
        - Attackers use this to find minimal perturbations that flip predictions
    """

    def __init__(self, input_dim: int, hidden_dim: int = 64):
        """Initialize classifier with random weights.

        Args:
            input_dim: Number of input features (e.g., malware features)
            hidden_dim: Hidden layer size (more = more capacity, slower)
        """
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        np.random.seed(42)
        # Xavier-style initialization for stable training
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
        """Compute gradient of loss with respect to input.

        THIS IS THE KEY FOR ADVERSARIAL ATTACKS!

        The gradient ∇_x Loss tells us:
        - Direction: Which way to change input to increase loss
        - Magnitude: How sensitive the loss is to each input feature

        For attacks:
        - Add small perturbation in GRADIENT DIRECTION to increase loss
        - This makes the model more likely to misclassify

        Returns:
            Gradient array same shape as input x
        """
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
    """Fast Gradient Sign Method (FGSM) attack.

    FGSM is a single-step attack proposed by Goodfellow et al. (2014).

    How It Works:
    -------------
    1. Compute gradient of loss w.r.t. input: ∇_x Loss
    2. Take the SIGN of gradient (direction only, not magnitude)
    3. Add epsilon * sign(gradient) to original input

    Formula: x_adv = x + ε * sign(∇_x Loss)

    Why Sign Instead of Raw Gradient?
    ----------------------------------
    - Sign ensures UNIFORM perturbation magnitude (epsilon) per feature
    - Makes attack controllable: epsilon directly bounds L∞ norm
    - Works even when gradient magnitudes vary wildly

    Security Context:
    -----------------
    - Fast: Single forward + backward pass
    - Often used as baseline attack
    - Good for generating training data for adversarial training
    - May not find optimal adversarial examples (PGD is stronger)

    Example in Security:
        Original malware detected → Add epsilon perturbation to features →
        Adversarial malware evades detection
    """

    def __init__(self, model: SimpleClassifier, epsilon: float = 0.1):
        """Initialize FGSM attack.

        Args:
            model: Target classifier to attack
            epsilon: Maximum perturbation per feature (L∞ bound).
                    Larger = stronger attack but more detectable.
                    For normalized features, 0.1 = 10% change per feature.
        """
        self.model = model
        self.epsilon = epsilon

    def generate(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Generate adversarial example using FGSM.

        Args:
            x: Original input features (e.g., malware sample)
            y: True label (we want to INCREASE loss for this label)

        Returns:
            Adversarial features (x_adv) that may fool the classifier
        """
        if isinstance(y, int):
            y = np.array([y])

        # Step 1: Compute gradient of loss w.r.t. input
        # This tells us how to change x to INCREASE the loss
        gradient = self.model.compute_gradient(x, y)

        # Step 2: FGSM perturbation
        # sign() converts gradient to -1, 0, or +1
        # epsilon scales the perturbation magnitude
        # Result: x_adv = x + epsilon * sign(gradient)
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
    """Projected Gradient Descent (PGD) attack.

    PGD is an iterative attack by Madry et al. (2017) - considered the
    "gold standard" for evaluating adversarial robustness.

    How It Works:
    -------------
    1. Start with random perturbation within epsilon-ball
    2. Take many small FGSM-like steps (alpha per step)
    3. After each step, PROJECT back to epsilon-ball (clip perturbation)
    4. Repeat for num_steps iterations

    Key Difference from FGSM:
    -------------------------
    FGSM: Single step, might overshoot or miss optimal perturbation
    PGD:  Many small steps, finds better adversarial examples

    Visualization:

        FGSM:         PGD:
        x ───────► adv    x ─► ─► ─► ─► adv
        (one jump)        (many small steps)

    Why Projection Matters:
    -----------------------
    After each step, perturbation might exceed epsilon. We "project"
    back by clipping: ensures x_adv stays in valid epsilon-ball.

    This is the L∞ (infinity norm) constraint:
        max |x_adv - x| ≤ epsilon (per feature)

    Security Implications:
    ----------------------
    - Stronger than FGSM (finds better adversarial examples)
    - Slower (40 steps = 40x forward/backward passes)
    - If model is robust to PGD, it's considered reasonably robust
    - Used as benchmark for adversarial robustness research

    Targeted vs Untargeted:
    -----------------------
    Untargeted: Fool model into ANY wrong prediction
    Targeted: Fool model into SPECIFIC wrong class
        Example: Make "malware" classified as "benign" (not just "unknown")
    """

    def __init__(
        self,
        model: SimpleClassifier,
        epsilon: float = 0.1,
        alpha: float = 0.01,
        num_steps: int = 40,
    ):
        """Initialize PGD attack.

        Args:
            model: Target classifier to attack
            epsilon: Maximum total perturbation (L∞ ball radius)
            alpha: Step size per iteration (typically epsilon/num_steps * 2.5)
            num_steps: Number of iterations (more = stronger attack, slower)
        """
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_steps = num_steps

    def generate(self, x: np.ndarray, y: np.ndarray, targeted: bool = False) -> np.ndarray:
        """Generate adversarial example using PGD.

        Args:
            x: Original input features
            y: Label (true label for untargeted, target for targeted)
            targeted: If True, minimize loss to target; else maximize loss

        Returns:
            Adversarial features within epsilon of original
        """
        if isinstance(y, int):
            y = np.array([y])

        # Step 1: Initialize with RANDOM perturbation in epsilon-ball
        # This helps escape bad local minima and improves attack diversity
        x_adv = x + np.random.uniform(-self.epsilon, self.epsilon, x.shape)
        x_adv = self.project(x_adv, x)

        # Step 2: Iteratively refine the adversarial example
        for _ in range(self.num_steps):
            # Compute gradient of loss w.r.t. current adversarial input
            gradient = self.model.compute_gradient(x_adv, y)

            if targeted:
                # TARGETED: Move TOWARDS target class (gradient DESCENT)
                # We want to MINIMIZE loss for the target label
                x_adv = x_adv - self.alpha * np.sign(gradient)
            else:
                # UNTARGETED: Move AWAY from true class (gradient ASCENT)
                # We want to MAXIMIZE loss for the true label
                x_adv = x_adv + self.alpha * np.sign(gradient)

            # Step 3: Project back to epsilon-ball
            # Ensures we don't exceed perturbation budget
            x_adv = self.project(x_adv, x)

        return x_adv

    def project(self, x: np.ndarray, x_orig: np.ndarray) -> np.ndarray:
        """Project perturbation back to epsilon-ball (L-infinity norm).

        This is the "P" in PGD - Projected Gradient Descent.

        L∞ ball = all points where max|x_i - x_orig_i| ≤ epsilon
        Projection = clip each dimension independently to [-epsilon, epsilon]

        Args:
            x: Current (possibly out-of-bounds) adversarial input
            x_orig: Original unperturbed input (center of epsilon-ball)

        Returns:
            Input projected back into valid epsilon-ball
        """
        perturbation = x - x_orig
        # Clip each feature's perturbation to [-epsilon, +epsilon]
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
    """Adversarial Training - The primary defense against adversarial examples.

    How It Works:
    -------------
    Instead of training only on clean data, we:
    1. Generate adversarial examples using an attack (FGSM/PGD)
    2. Train the model to correctly classify THESE adversarial examples
    3. Model learns to be robust to perturbations

    Intuition:
    ----------
    Normal training: "Learn to classify clean samples correctly"
    Adversarial training: "Learn to classify WORST-CASE samples correctly"

    The model sees the hardest examples during training, so it becomes
    robust to similar perturbations at test time.

    Training Flow:

        Clean Sample (x, y)
              │
              ▼
        ┌─────────────────┐
        │ Generate Attack │  ← FGSM or PGD
        │ x_adv = attack(x)│
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Train on x_adv  │  ← Model learns from adversarial
        │ Loss(model(x_adv), y) │
        └────────┬────────┘
                 │
                 ▼
        Robust Model (resists perturbations)

    Trade-offs:
    -----------
    + Model becomes robust to adversarial attacks
    + Works against multiple attack types
    - Training takes 3-10x longer (attack generation)
    - May slightly reduce clean accuracy (1-2%)

    Security Best Practice:
    -----------------------
    Use PGD adversarial training for security-critical models.
    FGSM is faster but provides weaker robustness guarantees.
    """

    def __init__(self, model: SimpleClassifier, attack: str = "pgd", epsilon: float = 0.1):
        """Initialize adversarial trainer.

        Args:
            model: Model to train (will be modified in-place)
            attack: Attack type for generating adversarial examples
                   "pgd" (recommended) or "fgsm" (faster but weaker)
            epsilon: Perturbation budget for attacks
        """
        self.model = model
        self.attack_type = attack
        self.epsilon = epsilon

        # Initialize the attack that will generate training adversarial examples
        if attack == "fgsm":
            self.attack = FGSMAttack(model, epsilon)
        else:
            # PGD with fewer steps for efficiency during training
            # (40 steps would be too slow for every training batch)
            self.attack = PGDAttack(model, epsilon, alpha=epsilon / 4, num_steps=10)

    def train_step(self, x: np.ndarray, y: np.ndarray, learning_rate: float = 0.01) -> float:
        """Single adversarial training step.

        This is where the magic happens:
        1. Take clean batch
        2. Generate adversarial version
        3. Train model to classify adversarial version correctly

        Args:
            x: Batch of clean input features
            y: Batch of true labels
            learning_rate: Step size for weight updates

        Returns:
            Loss on adversarial examples
        """
        # Step 1: Generate adversarial examples from clean inputs
        # These are the "hardest" versions of each sample
        x_adv = self.attack.generate(x, y)

        # Step 2: Compute loss on adversarial examples
        # We want the model to CORRECTLY classify these perturbed inputs
        loss = self.model.compute_loss(x_adv, y)

        # Step 3: Update weights to reduce loss on adversarial examples
        # This teaches the model to be robust to perturbations
        self.model.update_weights(x_adv, y, learning_rate)

        return loss

    def train(
        self, train_data: List[MalwareSample], epochs: int = 10, batch_size: int = 32
    ) -> List[float]:
        """Full adversarial training loop.

        Note: This is 3-10x slower than normal training because each batch
        requires generating adversarial examples (forward + backward pass).

        Args:
            train_data: List of training samples
            epochs: Number of passes through the data
            batch_size: Samples per batch (larger = faster but more memory)

        Returns:
            List of average loss per epoch (should decrease over time)
        """
        losses = []

        X = np.array([s.features for s in train_data])
        y = np.array([s.label for s in train_data])
        n = len(train_data)

        for epoch in range(epochs):
            # Shuffle data each epoch for better generalization
            indices = np.random.permutation(n)
            X_shuffled = X[indices]
            y_shuffled = y[indices]

            epoch_loss = 0.0
            n_batches = 0

            # Process in batches
            for i in range(0, n, batch_size):
                X_batch = X_shuffled[i : i + batch_size]
                y_batch = y_shuffled[i : i + batch_size]

                # Adversarial training step (generate attack + update weights)
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
    """Malware classifier with built-in defense mechanisms.

    This class wraps a base classifier with multiple defense strategies:

    Defense Strategies Implemented:
    -------------------------------

    1. INPUT TRANSFORMATIONS (Preprocessing Defense):
       Apply random transformations to input before prediction.
       Adversarial perturbations are fragile - small changes can break them.

       Examples:
       - Add small random noise
       - Quantization (round features)
       - Feature squeezing

       Why it works: Adversarial examples are often brittle; transformations
       may "break" the carefully crafted perturbation.

    2. ENSEMBLE DEFENSE (Multiple Models):
       Use multiple models and aggregate predictions.
       Harder for attacker to fool ALL models simultaneously.

       Why it works: Each model has different decision boundaries.
       Adversarial example for Model A may not work on Model B.

    3. DETECTION (Not just defense - detect attacks):
       Identify when an input is likely adversarial.
       - Inconsistent predictions under transformations = suspicious
       - Ensemble disagreement = suspicious

    Defense in Depth Principle:
    ---------------------------
    Don't rely on single defense. Combine multiple approaches:

        Input → [Transform] → [Detect] → [Ensemble] → Prediction
                    ↓            ↓           ↓
               May break    May reject   Harder to
               perturbation  adversarial  fool all

    Security Recommendation:
    ------------------------
    In production security systems:
    1. Use adversarial training as PRIMARY defense
    2. Add input validation as SECONDARY defense
    3. Use ensemble if resources allow
    4. Always have detection/alerting for suspicious inputs
    """

    def __init__(self, base_model: SimpleClassifier):
        """Initialize robust classifier.

        Args:
            base_model: The primary classifier to defend
        """
        self.model = base_model
        self.input_transformations: List[Callable] = []
        self.ensemble_models: List[SimpleClassifier] = []

    def add_input_transformation(self, transform: Callable):
        """Add input transformation defense.

        The transform should be a function: np.ndarray → np.ndarray

        Good transformations:
        - lambda x: x + np.random.normal(0, 0.01, x.shape)  # Add noise
        - lambda x: np.round(x, decimals=2)  # Quantization
        - lambda x: np.clip(x, 0, 1)  # Clipping
        """
        self.input_transformations.append(transform)

    def add_ensemble_model(self, model: SimpleClassifier):
        """Add model to ensemble for ensemble defense.

        For best results, ensemble models should be:
        - Trained on different data subsets OR
        - Have different architectures OR
        - Use different random seeds
        """
        self.ensemble_models.append(model)

    def detect_adversarial(self, x: np.ndarray) -> Tuple[bool, float]:
        """Detect if input is likely adversarial.

        Detection heuristics:
        1. Prediction inconsistency: If transformations change prediction,
           the input might be near decision boundary (suspicious)
        2. Ensemble disagreement: If models disagree, input might be
           adversarial (crafted to fool one model)

        Args:
            x: Input features to check

        Returns:
            (is_adversarial, confidence_score)
            - is_adversarial: True if input is suspicious
            - confidence_score: 0-1, higher = more likely adversarial

        Note: This is DETECTION, not prevention. Use for logging/alerting.
        """
        if x.ndim == 1:
            x = x.reshape(1, -1)

        detection_score = 0.0
        checks = 0

        # Heuristic 1: Check prediction consistency under transformations
        # Adversarial examples are often fragile - they break under small changes
        original_pred = self.model.predict(x)[0]

        for transform in self.input_transformations:
            transformed_x = transform(x)
            transformed_pred = self.model.predict(transformed_x)[0]
            if transformed_pred != original_pred:
                # Prediction changed! This is suspicious.
                detection_score += 1.0
            checks += 1

        # Heuristic 2: Check ensemble disagreement
        # If models disagree, the input might be adversarial
        if self.ensemble_models:
            predictions = [self.model.predict(x)[0]]
            for model in self.ensemble_models:
                predictions.append(model.predict(x)[0])

            unique_preds = len(set(predictions))
            if unique_preds > 1:
                # Models disagree - suspicious!
                detection_score += (unique_preds - 1) / len(predictions)
            checks += 1

        if checks == 0:
            return False, 0.0

        normalized_score = detection_score / checks
        is_adversarial = normalized_score > 0.5  # Threshold for detection

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
    """Create synthetic malware dataset for testing adversarial attacks.

    This generates a simple binary classification dataset where:
    - Class 1 (malware): Features have positive mean (+1.0)
    - Class 0 (benign): Features have negative mean (-1.0)

    The classes are linearly separable (by design) so a simple
    classifier can achieve high accuracy on clean data.

    This makes it easy to demonstrate adversarial attacks:
    - Clean accuracy: ~100%
    - After attack: Much lower (attacks work!)
    - After defense: Improved (defenses work!)
    """
    np.random.seed(42)
    samples = []

    for i in range(n_samples):
        # Alternate between classes
        label = i % 2
        if label == 1:
            # Malware: features centered around +1.0 with small variance
            features = np.random.randn(n_features) * 0.5 + 1.0
        else:
            # Benign: features centered around -1.0 with small variance
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
    """Main entry point for Lab 17 - Adversarial Machine Learning.

    This demonstrates the complete adversarial ML workflow:

    PART 1: Train a classifier (victim model)
    PART 2: Attack it with FGSM and PGD
    PART 3: Defend with adversarial training
    PART 4: Compare robustness before/after defense

    Key Takeaways:
    - Standard classifiers are VERY vulnerable to adversarial attacks
    - FGSM is fast but PGD is stronger
    - Adversarial training significantly improves robustness
    - But may slightly reduce clean accuracy (trade-off)
    """
    print("=" * 60)
    print("Lab 17: Adversarial Machine Learning - Solution")
    print("=" * 60)

    # =========================================================================
    # PART 1: Create data and train initial (vulnerable) model
    # =========================================================================
    print("\n--- Creating Sample Data ---")
    samples = create_sample_data(n_samples=200, n_features=20)
    train_samples = samples[:160]  # 80% for training
    test_samples = samples[160:]    # 20% for testing
    print(f"Created {len(samples)} samples")

    print("\n--- Training Classifier (Standard - No Defenses) ---")
    model = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Standard training: just minimize loss on clean data
    X_train = np.array([s.features for s in train_samples])
    y_train = np.array([s.label for s in train_samples])

    for epoch in range(20):
        model.update_weights(X_train, y_train, learning_rate=0.1)

    # Evaluate on clean test data
    X_test = np.array([s.features for s in test_samples])
    y_test = np.array([s.label for s in test_samples])
    predictions = model.predict(X_test)
    accuracy = np.mean(predictions == y_test)
    print(f"Clean test accuracy: {accuracy:.2%}")
    print("↑ Looks great! But is it robust to attacks?")

    # =========================================================================
    # PART 2: Attack the model with FGSM and PGD
    # =========================================================================
    print("\n--- FGSM Attack (Single-Step) ---")
    print("Epsilon=0.3 means each feature can change by ±0.3")
    fgsm = FGSMAttack(model, epsilon=0.3)
    fgsm_result = fgsm.evaluate(test_samples)
    print(f"FGSM success rate: {fgsm_result.success_rate:.2%}")
    print(f"Average perturbation (L2 norm): {fgsm_result.avg_perturbation:.4f}")
    print("↑ Attack success = model failure!")

    print("\n--- PGD Attack (40-Step Iterative) ---")
    print("PGD is stronger - uses 40 iterations to find better perturbations")
    pgd = PGDAttack(model, epsilon=0.3, alpha=0.05, num_steps=40)
    pgd_result = pgd.evaluate(test_samples)
    print(f"PGD success rate: {pgd_result.success_rate:.2%}")
    print(f"Average perturbation (L2 norm): {pgd_result.avg_perturbation:.4f}")
    print("↑ Usually higher success rate than FGSM")

    # =========================================================================
    # PART 3: Defend with Adversarial Training
    # =========================================================================
    print("\n--- Adversarial Training (The Primary Defense) ---")
    print("Training new model that sees adversarial examples during training...")
    robust_model = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Pre-train on clean data first (helps convergence)
    for _ in range(10):
        robust_model.update_weights(X_train, y_train, learning_rate=0.1)

    # Now do adversarial training - model learns to resist perturbations
    trainer = AdversarialTrainer(robust_model, attack="pgd", epsilon=0.3)
    losses = trainer.train(train_samples, epochs=5, batch_size=32)

    # =========================================================================
    # PART 4: Compare robustness before/after defense
    # =========================================================================
    print("\n--- Robustness Evaluation (After Adversarial Training) ---")
    robustness = trainer.evaluate_robustness(test_samples)
    print(f"Clean accuracy: {robustness.get('clean_accuracy', 0):.2%}")
    print(f"FGSM success rate: {robustness.get('fgsm_success_rate', 0):.2%}")
    print(f"PGD success rate: {robustness.get('pgd_success_rate', 0):.2%}")
    print("↑ Compare to before: Attack success should be LOWER!")
    print("  (Lower attack success = more robust model)")

    # =========================================================================
    # PART 5: Additional Defenses (Input Transformations)
    # =========================================================================
    print("\n--- Robust Classifier with Additional Defenses ---")
    print("Adding input transformations to break adversarial perturbations...")
    robust = RobustClassifier(robust_model)

    # Defense 1: Add random noise to break carefully crafted perturbations
    def add_noise(x):
        """Random noise defense - may disrupt adversarial perturbations."""
        return x + np.random.randn(*x.shape) * 0.05

    robust.add_input_transformation(add_noise)

    # Defense 2: Gaussian blur (smoothing) to remove high-frequency perturbations
    def gaussian_blur(x):
        """Blur defense - smooths out adversarial noise."""
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

    # Evaluate all defenses together
    defense_results = robust.evaluate_defenses(test_samples, pgd_result.successful_examples)
    print(f"Clean accuracy with defenses: {defense_results.get('clean_accuracy', 0):.2%}")
    print(
        f"Adversarial accuracy with defenses: {defense_results.get('adversarial_accuracy', 0):.2%}"
    )
    print(f"Adversarial detection rate: {defense_results.get('detection_rate', 0):.2%}")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print("Lab 17 Complete!")
    print("=" * 60)
    print("\nKey Takeaways:")
    print("1. Standard ML models are VERY vulnerable to adversarial attacks")
    print("2. PGD is stronger than FGSM (iterative > single-step)")
    print("3. Adversarial training is the most effective defense")
    print("4. Additional defenses (noise, blur) provide extra protection")
    print("5. Always test security ML models against adversarial attacks!")


if __name__ == "__main__":
    main()

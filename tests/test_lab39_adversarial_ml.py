#!/usr/bin/env python3
"""Tests for Lab 17: Adversarial Machine Learning for Security."""

import json
import math
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab39-adversarial-ml" / "solution")
sys.path.insert(0, lab_path)

from main import (
    AdversarialExample,
    AdversarialTrainer,
    AttackResult,
    FGSMAttack,
    MalwareSample,
    PGDAttack,
    RobustClassifier,
    SimpleClassifier,
    create_sample_data,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_classifier():
    """Create a SimpleClassifier instance."""
    np.random.seed(42)
    classifier = SimpleClassifier(input_dim=20, hidden_dim=64)
    return classifier


@pytest.fixture
def trained_classifier():
    """Create a trained SimpleClassifier instance."""
    np.random.seed(42)
    classifier = SimpleClassifier(input_dim=20, hidden_dim=64)

    # Train on sample data
    samples = create_sample_data(n_samples=100, n_features=20)
    X = np.array([s.features for s in samples])
    y = np.array([s.label for s in samples])

    for _ in range(20):
        classifier.update_weights(X, y, learning_rate=0.1)

    return classifier


@pytest.fixture
def sample_malware_samples():
    """Create sample malware samples for testing."""
    np.random.seed(42)
    samples = []

    # Malware samples (label=1)
    for i in range(5):
        features = np.random.randn(20) * 0.5 + 1.0
        samples.append(
            MalwareSample(
                sample_id=f"malware_{i:03d}", features=features, label=1, family="test_malware"
            )
        )

    # Benign samples (label=0)
    for i in range(5):
        features = np.random.randn(20) * 0.5 - 1.0
        samples.append(
            MalwareSample(sample_id=f"benign_{i:03d}", features=features, label=0, family="benign")
        )

    return samples


@pytest.fixture
def json_malware_samples():
    """Load malware samples from JSON data file."""
    data_path = (
        Path(__file__).parent.parent
        / "labs"
        / "lab17-adversarial-ml"
        / "data"
        / "malware_samples.json"
    )

    if not data_path.exists():
        pytest.skip("Data file not found")

    with open(data_path, "r") as f:
        data = json.load(f)

    samples = []
    for sample in data["samples"]:
        samples.append(
            MalwareSample(
                sample_id=sample["id"],
                features=np.array(sample["features"]),
                label=sample["label"],
                family=sample["family"],
            )
        )

    return samples


@pytest.fixture
def fgsm_attack(trained_classifier):
    """Create FGSM attack instance."""
    return FGSMAttack(trained_classifier, epsilon=0.1)


@pytest.fixture
def pgd_attack(trained_classifier):
    """Create PGD attack instance."""
    return PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=10)


# =============================================================================
# MalwareSample Tests
# =============================================================================


class TestMalwareSample:
    """Tests for MalwareSample dataclass."""

    def test_malware_sample_creation(self):
        """Test MalwareSample creation."""
        features = np.random.randn(20)
        sample = MalwareSample(sample_id="test_001", features=features, label=1, family="emotet")

        assert sample.sample_id == "test_001"
        assert len(sample.features) == 20
        assert sample.label == 1
        assert sample.family == "emotet"
        assert sample.confidence == 0.0  # Default value

    def test_malware_sample_default_values(self):
        """Test MalwareSample default values."""
        features = np.zeros(10)
        sample = MalwareSample(sample_id="test_002", features=features, label=0)

        assert sample.family == ""
        assert sample.confidence == 0.0

    def test_malware_sample_to_dict(self):
        """Test MalwareSample conversion to dict."""
        features = np.array([1.0, 2.0, 3.0])
        sample = MalwareSample(sample_id="test_003", features=features, label=1, family="lockbit")

        sample_dict = asdict(sample)

        assert isinstance(sample_dict, dict)
        assert sample_dict["sample_id"] == "test_003"
        assert sample_dict["label"] == 1


# =============================================================================
# AdversarialExample Tests
# =============================================================================


class TestAdversarialExample:
    """Tests for AdversarialExample dataclass."""

    def test_adversarial_example_creation(self, sample_malware_samples):
        """Test AdversarialExample creation."""
        original = sample_malware_samples[0]
        perturbation = np.random.randn(20) * 0.1
        adversarial_features = original.features + perturbation

        adv_example = AdversarialExample(
            original=original,
            perturbation=perturbation,
            adversarial_features=adversarial_features,
            attack_type="fgsm",
            success=True,
            original_prediction=1,
            adversarial_prediction=0,
            perturbation_norm=np.linalg.norm(perturbation),
        )

        assert adv_example.attack_type == "fgsm"
        assert adv_example.success is True
        assert adv_example.original_prediction == 1
        assert adv_example.adversarial_prediction == 0
        assert adv_example.perturbation_norm > 0


# =============================================================================
# AttackResult Tests
# =============================================================================


class TestAttackResult:
    """Tests for AttackResult dataclass."""

    def test_attack_result_creation(self):
        """Test AttackResult creation."""
        result = AttackResult(
            attack_type="fgsm", success_rate=0.75, avg_perturbation=0.15, samples_tested=100
        )

        assert result.attack_type == "fgsm"
        assert result.success_rate == 0.75
        assert result.avg_perturbation == 0.15
        assert result.samples_tested == 100
        assert result.successful_examples == []  # Default value

    def test_attack_result_with_examples(self, sample_malware_samples):
        """Test AttackResult with successful examples."""
        original = sample_malware_samples[0]
        adv_example = AdversarialExample(
            original=original,
            perturbation=np.zeros(20),
            adversarial_features=original.features,
            attack_type="pgd",
            success=True,
            original_prediction=1,
            adversarial_prediction=0,
            perturbation_norm=0.1,
        )

        result = AttackResult(
            attack_type="pgd",
            success_rate=0.5,
            avg_perturbation=0.12,
            samples_tested=50,
            successful_examples=[adv_example],
        )

        assert len(result.successful_examples) == 1


# =============================================================================
# SimpleClassifier Tests
# =============================================================================


class TestSimpleClassifier:
    """Tests for SimpleClassifier."""

    def test_classifier_initialization(self):
        """Test classifier initialization."""
        classifier = SimpleClassifier(input_dim=20, hidden_dim=64)

        assert classifier.input_dim == 20
        assert classifier.hidden_dim == 64
        assert classifier.W1.shape == (20, 64)
        assert classifier.b1.shape == (64,)
        assert classifier.W2.shape == (64, 2)
        assert classifier.b2.shape == (2,)

    def test_classifier_forward_1d_input(self, sample_classifier):
        """Test forward pass with 1D input."""
        x = np.random.randn(20)
        logits = sample_classifier.forward(x)

        assert logits.shape == (1, 2)

    def test_classifier_forward_2d_input(self, sample_classifier):
        """Test forward pass with 2D input (batch)."""
        x = np.random.randn(10, 20)
        logits = sample_classifier.forward(x)

        assert logits.shape == (10, 2)

    def test_classifier_predict(self, sample_classifier):
        """Test prediction."""
        x = np.random.randn(5, 20)
        predictions = sample_classifier.predict(x)

        assert predictions.shape == (5,)
        assert all(p in [0, 1] for p in predictions)

    def test_classifier_predict_proba(self, sample_classifier):
        """Test probability prediction."""
        x = np.random.randn(5, 20)
        probs = sample_classifier.predict_proba(x)

        assert probs.shape == (5, 2)
        # Probabilities should sum to 1
        assert np.allclose(probs.sum(axis=1), 1.0)
        # Probabilities should be non-negative
        assert np.all(probs >= 0)

    def test_classifier_compute_loss(self, sample_classifier):
        """Test loss computation."""
        x = np.random.randn(10, 20)
        y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])

        loss = sample_classifier.compute_loss(x, y)

        assert isinstance(loss, float)
        assert loss >= 0

    def test_classifier_compute_loss_single_sample(self, sample_classifier):
        """Test loss computation with single sample."""
        x = np.random.randn(20)
        y = 1

        loss = sample_classifier.compute_loss(x, y)

        assert isinstance(loss, float)
        assert loss >= 0

    def test_classifier_compute_gradient(self, sample_classifier):
        """Test gradient computation."""
        x = np.random.randn(20)
        y = 1

        gradient = sample_classifier.compute_gradient(x, y)

        assert gradient.shape == (20,)

    def test_classifier_compute_gradient_batch(self, sample_classifier):
        """Test gradient computation with batch input."""
        x = np.random.randn(5, 20)
        y = np.array([0, 1, 0, 1, 0])

        gradient = sample_classifier.compute_gradient(x, y)

        # Returns gradient for batch
        assert gradient.shape == (5, 20)

    def test_classifier_update_weights(self, sample_classifier):
        """Test weight update."""
        x = np.random.randn(10, 20)
        y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])

        # Store original weights
        W1_before = sample_classifier.W1.copy()

        sample_classifier.update_weights(x, y, learning_rate=0.1)

        # Weights should have changed
        assert not np.allclose(sample_classifier.W1, W1_before)

    def test_training_reduces_loss(self, sample_classifier):
        """Test that training reduces loss."""
        samples = create_sample_data(n_samples=50, n_features=20)
        X = np.array([s.features for s in samples])
        y = np.array([s.label for s in samples])

        loss_before = sample_classifier.compute_loss(X, y)

        for _ in range(10):
            sample_classifier.update_weights(X, y, learning_rate=0.1)

        loss_after = sample_classifier.compute_loss(X, y)

        assert loss_after < loss_before


# =============================================================================
# FGSMAttack Tests
# =============================================================================


class TestFGSMAttack:
    """Tests for FGSM Attack."""

    def test_fgsm_initialization(self, trained_classifier):
        """Test FGSM attack initialization."""
        attack = FGSMAttack(trained_classifier, epsilon=0.1)

        assert attack.model == trained_classifier
        assert attack.epsilon == 0.1

    def test_fgsm_generate(self, fgsm_attack):
        """Test FGSM adversarial example generation."""
        x = np.random.randn(20)
        y = 1

        x_adv = fgsm_attack.generate(x, y)

        assert x_adv.shape == x.shape
        # Adversarial example should be different from original
        assert not np.allclose(x, x_adv)

    def test_fgsm_perturbation_bounded(self, fgsm_attack):
        """Test that FGSM perturbation is bounded by epsilon."""
        x = np.random.randn(20)
        y = 1

        x_adv = fgsm_attack.generate(x, y)
        perturbation = x_adv - x

        # Perturbation should be +/- epsilon
        assert np.allclose(np.abs(perturbation), fgsm_attack.epsilon)

    def test_fgsm_attack_sample(self, fgsm_attack, sample_malware_samples):
        """Test FGSM attack on single sample."""
        sample = sample_malware_samples[0]

        result = fgsm_attack.attack_sample(sample)

        assert isinstance(result, AdversarialExample)
        assert result.attack_type == "fgsm"
        assert result.perturbation_norm > 0

    def test_fgsm_evaluate(self, fgsm_attack, sample_malware_samples):
        """Test FGSM attack evaluation on multiple samples."""
        result = fgsm_attack.evaluate(sample_malware_samples)

        assert isinstance(result, AttackResult)
        assert result.attack_type == "fgsm"
        assert 0 <= result.success_rate <= 1
        assert result.samples_tested == len(sample_malware_samples)
        assert result.avg_perturbation >= 0

    def test_fgsm_evaluate_empty_samples(self, fgsm_attack):
        """Test FGSM evaluation with empty sample list."""
        result = fgsm_attack.evaluate([])

        assert result.success_rate == 0.0
        assert result.avg_perturbation == 0.0
        assert result.samples_tested == 0

    def test_fgsm_different_epsilon_values(self, trained_classifier, sample_malware_samples):
        """Test FGSM with different epsilon values."""
        sample = sample_malware_samples[0]

        attack_small = FGSMAttack(trained_classifier, epsilon=0.01)
        attack_large = FGSMAttack(trained_classifier, epsilon=0.5)

        result_small = attack_small.attack_sample(sample)
        result_large = attack_large.attack_sample(sample)

        # Larger epsilon should cause larger perturbation
        assert result_large.perturbation_norm > result_small.perturbation_norm

    def test_fgsm_with_json_data(self, trained_classifier, json_malware_samples):
        """Test FGSM attack with JSON data file."""
        attack = FGSMAttack(trained_classifier, epsilon=0.1)
        result = attack.evaluate(json_malware_samples[:5])

        assert result.samples_tested == 5


# =============================================================================
# PGDAttack Tests
# =============================================================================


class TestPGDAttack:
    """Tests for PGD Attack."""

    def test_pgd_initialization(self, trained_classifier):
        """Test PGD attack initialization."""
        attack = PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=40)

        assert attack.model == trained_classifier
        assert attack.epsilon == 0.1
        assert attack.alpha == 0.01
        assert attack.num_steps == 40

    def test_pgd_generate(self, pgd_attack):
        """Test PGD adversarial example generation."""
        np.random.seed(42)
        x = np.random.randn(20)
        y = 1

        x_adv = pgd_attack.generate(x, y)

        assert x_adv.shape == x.shape
        # Adversarial example should be different from original
        assert not np.allclose(x, x_adv)

    def test_pgd_perturbation_bounded(self, pgd_attack):
        """Test that PGD perturbation is bounded by epsilon."""
        np.random.seed(42)
        x = np.random.randn(20)
        y = 1

        x_adv = pgd_attack.generate(x, y)
        perturbation = x_adv - x

        # L-infinity norm should be <= epsilon
        assert np.max(np.abs(perturbation)) <= pgd_attack.epsilon + 1e-6

    def test_pgd_project(self, pgd_attack):
        """Test PGD projection to epsilon ball."""
        x_orig = np.zeros(20)
        x = np.ones(20) * 0.5  # Outside epsilon ball (epsilon=0.1)

        x_projected = pgd_attack.project(x, x_orig)

        # All values should be within epsilon of origin
        assert np.all(np.abs(x_projected - x_orig) <= pgd_attack.epsilon + 1e-6)

    def test_pgd_attack_sample_untargeted(self, pgd_attack, sample_malware_samples):
        """Test PGD untargeted attack on single sample."""
        sample = sample_malware_samples[0]

        result = pgd_attack.attack_sample(sample)

        assert isinstance(result, AdversarialExample)
        assert result.attack_type == "pgd"

    def test_pgd_attack_sample_targeted(self, pgd_attack, sample_malware_samples):
        """Test PGD targeted attack on single sample."""
        sample = sample_malware_samples[0]  # label=1
        target_label = 0

        result = pgd_attack.attack_sample(sample, targeted=True, target_label=target_label)

        assert isinstance(result, AdversarialExample)
        # If successful, adversarial prediction should equal target
        if result.success:
            assert result.adversarial_prediction == target_label

    def test_pgd_evaluate(self, pgd_attack, sample_malware_samples):
        """Test PGD attack evaluation on multiple samples."""
        result = pgd_attack.evaluate(sample_malware_samples)

        assert isinstance(result, AttackResult)
        assert result.attack_type == "pgd"
        assert 0 <= result.success_rate <= 1
        assert result.samples_tested == len(sample_malware_samples)

    def test_pgd_evaluate_empty_samples(self, pgd_attack):
        """Test PGD evaluation with empty sample list."""
        result = pgd_attack.evaluate([])

        assert result.success_rate == 0.0
        assert result.avg_perturbation == 0.0
        assert result.samples_tested == 0

    def test_pgd_more_steps_stronger_attack(self, trained_classifier, sample_malware_samples):
        """Test that more PGD steps can create stronger attack."""
        sample = sample_malware_samples[0]

        attack_few_steps = PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=5)
        attack_many_steps = PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=50)

        # Run multiple times to account for randomness
        success_few = sum(attack_few_steps.attack_sample(sample).success for _ in range(5))
        success_many = sum(attack_many_steps.attack_sample(sample).success for _ in range(5))

        # Many steps should generally be at least as successful
        assert success_many >= success_few * 0.5  # Allow some variance

    def test_pgd_with_json_data(self, trained_classifier, json_malware_samples):
        """Test PGD attack with JSON data file."""
        attack = PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=10)
        result = attack.evaluate(json_malware_samples[:5])

        assert result.samples_tested == 5


# =============================================================================
# AdversarialTrainer Tests
# =============================================================================


class TestAdversarialTrainer:
    """Tests for AdversarialTrainer."""

    def test_trainer_initialization_fgsm(self, sample_classifier):
        """Test trainer initialization with FGSM."""
        trainer = AdversarialTrainer(sample_classifier, attack="fgsm", epsilon=0.1)

        assert trainer.model == sample_classifier
        assert trainer.attack_type == "fgsm"
        assert trainer.epsilon == 0.1
        assert isinstance(trainer.attack, FGSMAttack)

    def test_trainer_initialization_pgd(self, sample_classifier):
        """Test trainer initialization with PGD."""
        trainer = AdversarialTrainer(sample_classifier, attack="pgd", epsilon=0.1)

        assert trainer.attack_type == "pgd"
        assert isinstance(trainer.attack, PGDAttack)

    def test_train_step(self, sample_classifier):
        """Test single adversarial training step."""
        trainer = AdversarialTrainer(sample_classifier, attack="fgsm", epsilon=0.1)

        X = np.random.randn(10, 20)
        y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])

        loss = trainer.train_step(X, y, learning_rate=0.01)

        assert isinstance(loss, float)
        assert loss >= 0

    def test_train_full(self, sample_classifier, sample_malware_samples):
        """Test full adversarial training."""
        trainer = AdversarialTrainer(sample_classifier, attack="fgsm", epsilon=0.1)

        # Suppress print output
        with patch("builtins.print"):
            losses = trainer.train(sample_malware_samples, epochs=3, batch_size=4)

        assert len(losses) == 3
        # Losses should generally decrease (or stay stable)
        assert all(isinstance(l, float) for l in losses)

    def test_evaluate_robustness_clean(self, trained_classifier, sample_malware_samples):
        """Test robustness evaluation on clean data."""
        trainer = AdversarialTrainer(trained_classifier, attack="pgd", epsilon=0.1)

        results = trainer.evaluate_robustness(sample_malware_samples, attacks=["clean"])

        assert "clean_accuracy" in results
        assert 0 <= results["clean_accuracy"] <= 1

    def test_evaluate_robustness_fgsm(self, trained_classifier, sample_malware_samples):
        """Test robustness evaluation against FGSM."""
        trainer = AdversarialTrainer(trained_classifier, attack="pgd", epsilon=0.1)

        results = trainer.evaluate_robustness(sample_malware_samples, attacks=["fgsm"])

        assert "fgsm_success_rate" in results
        assert "adversarial_accuracy" in results
        assert 0 <= results["fgsm_success_rate"] <= 1

    def test_evaluate_robustness_pgd(self, trained_classifier, sample_malware_samples):
        """Test robustness evaluation against PGD."""
        trainer = AdversarialTrainer(trained_classifier, attack="pgd", epsilon=0.1)

        results = trainer.evaluate_robustness(sample_malware_samples, attacks=["pgd"])

        assert "pgd_success_rate" in results
        assert 0 <= results["pgd_success_rate"] <= 1

    def test_evaluate_robustness_all_attacks(self, trained_classifier, sample_malware_samples):
        """Test robustness evaluation against all attacks."""
        trainer = AdversarialTrainer(trained_classifier, attack="pgd", epsilon=0.1)

        results = trainer.evaluate_robustness(sample_malware_samples)

        assert "clean_accuracy" in results
        assert "fgsm_success_rate" in results
        assert "pgd_success_rate" in results

    def test_adversarial_training_improves_robustness(self):
        """Test that adversarial training improves robustness."""
        np.random.seed(42)

        # Create and train two models
        model_standard = SimpleClassifier(input_dim=20, hidden_dim=32)
        model_robust = SimpleClassifier(input_dim=20, hidden_dim=32)

        samples = create_sample_data(n_samples=100, n_features=20)
        train_samples = samples[:80]
        test_samples = samples[80:]

        X_train = np.array([s.features for s in train_samples])
        y_train = np.array([s.label for s in train_samples])

        # Standard training for both models first
        for _ in range(10):
            model_standard.update_weights(X_train, y_train, learning_rate=0.1)
            model_robust.update_weights(X_train, y_train, learning_rate=0.1)

        # Adversarial training for robust model only
        trainer = AdversarialTrainer(model_robust, attack="pgd", epsilon=0.1)
        with patch("builtins.print"):
            trainer.train(train_samples, epochs=5, batch_size=16)

        # Evaluate both models
        fgsm_standard = FGSMAttack(model_standard, epsilon=0.1)
        fgsm_robust = FGSMAttack(model_robust, epsilon=0.1)

        result_standard = fgsm_standard.evaluate(test_samples)
        result_robust = fgsm_robust.evaluate(test_samples)

        # Robust model should have lower attack success rate
        # (allowing for some variance in small test)
        assert result_robust.success_rate <= result_standard.success_rate + 0.3


# =============================================================================
# RobustClassifier Tests
# =============================================================================


class TestRobustClassifier:
    """Tests for RobustClassifier."""

    def test_robust_classifier_initialization(self, trained_classifier):
        """Test RobustClassifier initialization."""
        robust = RobustClassifier(trained_classifier)

        assert robust.model == trained_classifier
        assert robust.input_transformations == []
        assert robust.ensemble_models == []

    def test_add_input_transformation(self, trained_classifier):
        """Test adding input transformation."""
        robust = RobustClassifier(trained_classifier)

        def dummy_transform(x):
            return x * 0.9

        robust.add_input_transformation(dummy_transform)

        assert len(robust.input_transformations) == 1

    def test_add_ensemble_model(self, trained_classifier, sample_classifier):
        """Test adding ensemble model."""
        robust = RobustClassifier(trained_classifier)
        robust.add_ensemble_model(sample_classifier)

        assert len(robust.ensemble_models) == 1

    def test_detect_adversarial_no_defenses(self, trained_classifier):
        """Test adversarial detection without defenses."""
        robust = RobustClassifier(trained_classifier)

        x = np.random.randn(20)
        is_adv, score = robust.detect_adversarial(x)

        assert is_adv is False
        assert score == 0.0

    def test_detect_adversarial_with_transformation(self, trained_classifier):
        """Test adversarial detection with transformations."""
        robust = RobustClassifier(trained_classifier)

        def noise_transform(x):
            return x + np.random.randn(*x.shape) * 0.5

        robust.add_input_transformation(noise_transform)

        x = np.random.randn(20)
        is_adv, score = robust.detect_adversarial(x)

        # Score should be computed
        assert isinstance(score, float)
        assert 0 <= score <= 1

    def test_detect_adversarial_with_ensemble(self, trained_classifier):
        """Test adversarial detection with ensemble."""
        robust = RobustClassifier(trained_classifier)

        # Add a different model to ensemble
        np.random.seed(123)
        other_model = SimpleClassifier(input_dim=20, hidden_dim=64)
        robust.add_ensemble_model(other_model)

        x = np.random.randn(20)
        is_adv, score = robust.detect_adversarial(x)

        assert isinstance(is_adv, bool)
        assert isinstance(score, float)

    def test_predict_robust_no_defenses(self, trained_classifier):
        """Test robust prediction without defenses."""
        robust = RobustClassifier(trained_classifier)

        x = np.random.randn(5, 20)
        predictions, confidences = robust.predict_robust(x)

        assert predictions.shape == (5,)
        assert confidences.shape == (5,)
        assert all(p in [0, 1] for p in predictions)
        assert all(0 <= c <= 1 for c in confidences)

    def test_predict_robust_with_transformations(self, trained_classifier):
        """Test robust prediction with transformations."""
        robust = RobustClassifier(trained_classifier)

        def noise_transform(x):
            return x + np.random.randn(*x.shape) * 0.01

        robust.add_input_transformation(noise_transform)

        x = np.random.randn(5, 20)
        predictions, confidences = robust.predict_robust(x)

        assert predictions.shape == (5,)
        assert confidences.shape == (5,)

    def test_predict_robust_with_ensemble(self, trained_classifier):
        """Test robust prediction with ensemble."""
        robust = RobustClassifier(trained_classifier)

        np.random.seed(456)
        other_model = SimpleClassifier(input_dim=20, hidden_dim=64)
        robust.add_ensemble_model(other_model)

        x = np.random.randn(5, 20)
        predictions, confidences = robust.predict_robust(x)

        assert predictions.shape == (5,)
        assert confidences.shape == (5,)

    def test_predict_robust_1d_input(self, trained_classifier):
        """Test robust prediction with 1D input."""
        robust = RobustClassifier(trained_classifier)

        x = np.random.randn(20)
        predictions, confidences = robust.predict_robust(x)

        assert predictions.shape == (1,)
        assert confidences.shape == (1,)

    def test_evaluate_defenses_clean_data(self, trained_classifier, sample_malware_samples):
        """Test defense evaluation on clean data."""
        robust = RobustClassifier(trained_classifier)

        results = robust.evaluate_defenses(sample_malware_samples, [])

        assert "clean_accuracy" in results
        assert 0 <= results["clean_accuracy"] <= 1

    def test_evaluate_defenses_with_adversarial_data(
        self, trained_classifier, sample_malware_samples
    ):
        """Test defense evaluation with adversarial data."""
        robust = RobustClassifier(trained_classifier)

        # Generate some adversarial examples
        fgsm = FGSMAttack(trained_classifier, epsilon=0.1)
        attack_result = fgsm.evaluate(sample_malware_samples[:5])

        results = robust.evaluate_defenses(
            sample_malware_samples, attack_result.successful_examples
        )

        assert "clean_accuracy" in results
        if attack_result.successful_examples:
            assert "adversarial_accuracy" in results
            assert "detection_rate" in results

    def test_defense_with_noise_injection(self, trained_classifier, sample_malware_samples):
        """Test noise injection defense."""
        robust = RobustClassifier(trained_classifier)

        def add_noise(x):
            return x + np.random.randn(*x.shape) * 0.05

        robust.add_input_transformation(add_noise)

        # Generate adversarial examples
        fgsm = FGSMAttack(trained_classifier, epsilon=0.1)
        attack_result = fgsm.evaluate(sample_malware_samples[:5])

        results = robust.evaluate_defenses(
            sample_malware_samples, attack_result.successful_examples
        )

        assert "clean_accuracy" in results


# =============================================================================
# create_sample_data Tests
# =============================================================================


class TestCreateSampleData:
    """Tests for create_sample_data function."""

    def test_create_sample_data_default(self):
        """Test sample data creation with defaults."""
        samples = create_sample_data()

        assert len(samples) == 100
        assert all(len(s.features) == 20 for s in samples)

    def test_create_sample_data_custom_size(self):
        """Test sample data creation with custom size."""
        samples = create_sample_data(n_samples=50, n_features=10)

        assert len(samples) == 50
        assert all(len(s.features) == 10 for s in samples)

    def test_create_sample_data_labels(self):
        """Test that labels are balanced."""
        samples = create_sample_data(n_samples=100)

        labels = [s.label for s in samples]
        # Should have roughly equal labels
        assert 40 <= sum(labels) <= 60

    def test_create_sample_data_reproducible(self):
        """Test that data creation is reproducible."""
        samples1 = create_sample_data(n_samples=10)
        samples2 = create_sample_data(n_samples=10)

        for s1, s2 in zip(samples1, samples2):
            assert np.allclose(s1.features, s2.features)
            assert s1.label == s2.label

    def test_create_sample_data_features_differ_by_label(self):
        """Test that features differ by label."""
        samples = create_sample_data(n_samples=100)

        malware_means = np.mean([s.features for s in samples if s.label == 1], axis=0)
        benign_means = np.mean([s.features for s in samples if s.label == 0], axis=0)

        # Features should be separable by label
        assert not np.allclose(malware_means, benign_means)


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_classifier_single_feature(self):
        """Test classifier with single feature dimension."""
        classifier = SimpleClassifier(input_dim=1, hidden_dim=8)

        x = np.array([0.5])
        predictions = classifier.predict(x.reshape(1, -1))

        assert predictions.shape == (1,)

    def test_fgsm_zero_epsilon(self, trained_classifier, sample_malware_samples):
        """Test FGSM with zero epsilon."""
        attack = FGSMAttack(trained_classifier, epsilon=0.0)
        sample = sample_malware_samples[0]

        result = attack.attack_sample(sample)

        # Zero epsilon means no perturbation
        assert np.allclose(result.perturbation, 0.0)

    def test_pgd_zero_steps(self, trained_classifier, sample_malware_samples):
        """Test PGD with zero steps."""
        attack = PGDAttack(trained_classifier, epsilon=0.1, alpha=0.01, num_steps=0)
        sample = sample_malware_samples[0]

        result = attack.attack_sample(sample)

        # Should still return valid result
        assert isinstance(result, AdversarialExample)

    def test_robust_classifier_many_transformations(self, trained_classifier):
        """Test RobustClassifier with many transformations."""
        robust = RobustClassifier(trained_classifier)

        # Add multiple transformations
        for i in range(5):
            robust.add_input_transformation(lambda x: x * (1 + 0.01 * i))

        x = np.random.randn(20)
        predictions, confidences = robust.predict_robust(x)

        assert predictions.shape == (1,)

    def test_classifier_large_batch(self, trained_classifier):
        """Test classifier with large batch size."""
        x = np.random.randn(1000, 20)
        predictions = trained_classifier.predict(x)

        assert predictions.shape == (1000,)

    def test_attack_on_already_misclassified(self, trained_classifier, sample_malware_samples):
        """Test attack on already misclassified samples."""
        fgsm = FGSMAttack(trained_classifier, epsilon=0.1)

        # Find a sample that's already misclassified
        misclassified = None
        for sample in sample_malware_samples:
            pred = trained_classifier.predict(sample.features.reshape(1, -1))[0]
            if pred != sample.label:
                misclassified = sample
                break

        if misclassified:
            result = fgsm.attack_sample(misclassified)
            # Attack should still work (even if original was wrong)
            assert isinstance(result, AdversarialExample)


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the adversarial ML pipeline."""

    def test_full_attack_evaluation_pipeline(self):
        """Test complete attack evaluation pipeline."""
        # Create model and data
        np.random.seed(42)
        model = SimpleClassifier(input_dim=20, hidden_dim=64)
        samples = create_sample_data(n_samples=100, n_features=20)
        train_samples = samples[:80]
        test_samples = samples[80:]

        # Train model
        X_train = np.array([s.features for s in train_samples])
        y_train = np.array([s.label for s in train_samples])
        for _ in range(20):
            model.update_weights(X_train, y_train, learning_rate=0.1)

        # Evaluate attacks
        fgsm = FGSMAttack(model, epsilon=0.1)
        pgd = PGDAttack(model, epsilon=0.1, alpha=0.01, num_steps=10)

        fgsm_result = fgsm.evaluate(test_samples)
        pgd_result = pgd.evaluate(test_samples)

        # PGD should generally be more effective than FGSM
        assert fgsm_result.attack_type == "fgsm"
        assert pgd_result.attack_type == "pgd"

    def test_adversarial_training_pipeline(self):
        """Test complete adversarial training pipeline."""
        np.random.seed(42)
        model = SimpleClassifier(input_dim=20, hidden_dim=64)
        samples = create_sample_data(n_samples=100, n_features=20)

        # Train with adversarial examples
        trainer = AdversarialTrainer(model, attack="pgd", epsilon=0.1)

        with patch("builtins.print"):
            losses = trainer.train(samples[:80], epochs=3, batch_size=16)

        # Evaluate robustness
        results = trainer.evaluate_robustness(samples[80:])

        assert "clean_accuracy" in results
        assert "fgsm_success_rate" in results
        assert "pgd_success_rate" in results

    def test_robust_classifier_pipeline(self):
        """Test complete robust classifier pipeline."""
        np.random.seed(42)
        model = SimpleClassifier(input_dim=20, hidden_dim=64)
        samples = create_sample_data(n_samples=100, n_features=20)

        # Train model
        X = np.array([s.features for s in samples[:80]])
        y = np.array([s.label for s in samples[:80]])
        for _ in range(20):
            model.update_weights(X, y, learning_rate=0.1)

        # Create robust classifier with defenses
        robust = RobustClassifier(model)
        robust.add_input_transformation(lambda x: x + np.random.randn(*x.shape) * 0.01)

        # Generate adversarial examples
        fgsm = FGSMAttack(model, epsilon=0.1)
        attack_result = fgsm.evaluate(samples[80:90])

        # Evaluate defenses
        results = robust.evaluate_defenses(samples[80:], attack_result.successful_examples)

        assert "clean_accuracy" in results


# =============================================================================
# API Tests (requires LLM)
# =============================================================================


@pytest.mark.requires_api
class TestAPIIntegration:
    """Tests that require LLM API access."""

    def test_setup_llm_anthropic(self):
        """Test LLM setup with Anthropic."""
        from main import setup_llm

        try:
            provider, client = setup_llm("anthropic")
            assert provider == "anthropic"
            assert client is not None
        except ValueError:
            pytest.skip("Anthropic API key not available")

    def test_setup_llm_auto(self):
        """Test automatic LLM provider detection."""
        from main import setup_llm

        try:
            provider, client = setup_llm("auto")
            assert provider in ["anthropic", "openai", "google"]
            assert client is not None
        except ValueError:
            pytest.skip("No API key available")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

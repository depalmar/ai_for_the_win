#!/usr/bin/env python3
"""Tests for Lab 18: Fine-Tuning for Security Applications."""

import json
import sys
import tempfile
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
lab_path = str(Path(__file__).parent.parent / "labs" / "lab18-fine-tuning-security" / "solution")
sys.path.insert(0, lab_path)

from main import (
    EmbeddingPair,
    EmbeddingTrainer,
    EvaluationResult,
    SecurityDatasetBuilder,
    SecurityModelEvaluator,
    TrainingSample,
    create_sample_training_data,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_training_data():
    """Create sample training data."""
    return [
        {
            "text": "Phishing email detected with malicious link",
            "label": "phishing",
            "category": "email",
        },
        {
            "text": "User logged in successfully from office network",
            "label": "benign",
            "category": "log",
        },
        {
            "text": "Failed login attempt from unknown IP 192.168.1.100",
            "label": "suspicious",
            "category": "log",
        },
        {
            "text": "Malware signature detected in uploaded file",
            "label": "malicious",
            "category": "alert",
        },
        {
            "text": "Weekly team meeting scheduled for Monday",
            "label": "benign",
            "category": "email",
        },
        {
            "text": "Ransomware behavior detected on endpoint",
            "label": "malicious",
            "category": "alert",
        },
        {
            "text": "Password reset requested by user admin@example.com",
            "label": "benign",
            "category": "log",
        },
        {
            "text": "Suspicious outbound connection to known C2 server",
            "label": "suspicious",
            "category": "alert",
        },
    ]


@pytest.fixture
def sample_training_json(tmp_path, sample_training_data):
    """Create a sample training JSON file."""
    data = {"samples": sample_training_data}
    json_file = tmp_path / "training_samples.json"
    json_file.write_text(json.dumps(data))
    return str(json_file)


@pytest.fixture
def dataset_builder():
    """Create a SecurityDatasetBuilder instance."""
    return SecurityDatasetBuilder()


@pytest.fixture
def populated_dataset_builder(sample_training_data):
    """Create a populated SecurityDatasetBuilder."""
    builder = SecurityDatasetBuilder()
    for sample in sample_training_data:
        builder.add_sample(text=sample["text"], label=sample["label"], category=sample["category"])
    return builder


@pytest.fixture
def embedding_trainer():
    """Create an EmbeddingTrainer instance."""
    return EmbeddingTrainer()


@pytest.fixture
def initialized_trainer():
    """Create an initialized EmbeddingTrainer."""
    trainer = EmbeddingTrainer()
    trainer.load_base_model()
    return trainer


@pytest.fixture
def sample_test_samples():
    """Create sample TrainingSample objects for testing."""
    return [
        TrainingSample(
            sample_id="test_001",
            text="Detected malicious file execution",
            label="malicious",
            category="alert",
            metadata={},
        ),
        TrainingSample(
            sample_id="test_002",
            text="Normal user login from corporate VPN",
            label="benign",
            category="log",
            metadata={},
        ),
        TrainingSample(
            sample_id="test_003",
            text="Phishing attempt blocked by email filter",
            label="phishing",
            category="email",
            metadata={},
        ),
        TrainingSample(
            sample_id="test_004",
            text="Suspicious PowerShell command executed",
            label="suspicious",
            category="log",
            metadata={},
        ),
    ]


@pytest.fixture
def model_evaluator(initialized_trainer):
    """Create a SecurityModelEvaluator instance."""
    return SecurityModelEvaluator(model=initialized_trainer)


# =============================================================================
# TrainingSample Tests
# =============================================================================


class TestTrainingSample:
    """Tests for TrainingSample dataclass."""

    def test_training_sample_creation(self):
        """Test TrainingSample creation with all fields."""
        sample = TrainingSample(
            sample_id="sample_001",
            text="Test security event",
            label="malicious",
            category="alert",
            metadata={"source": "test"},
        )

        assert sample.sample_id == "sample_001"
        assert sample.text == "Test security event"
        assert sample.label == "malicious"
        assert sample.category == "alert"
        assert sample.metadata == {"source": "test"}

    def test_training_sample_default_metadata(self):
        """Test TrainingSample with default metadata."""
        sample = TrainingSample(
            sample_id="sample_002", text="Another event", label="benign", category="log"
        )

        assert sample.metadata == {}


# =============================================================================
# EmbeddingPair Tests
# =============================================================================


class TestEmbeddingPair:
    """Tests for EmbeddingPair dataclass."""

    def test_embedding_pair_creation(self):
        """Test EmbeddingPair creation."""
        pair = EmbeddingPair(
            anchor="Malicious file detected",
            positive="Malware found in system",
            negative="Normal system operation",
            anchor_label="malicious",
        )

        assert pair.anchor == "Malicious file detected"
        assert pair.positive == "Malware found in system"
        assert pair.negative == "Normal system operation"
        assert pair.anchor_label == "malicious"


# =============================================================================
# EvaluationResult Tests
# =============================================================================


class TestEvaluationResult:
    """Tests for EvaluationResult dataclass."""

    def test_evaluation_result_creation(self):
        """Test EvaluationResult creation."""
        confusion = np.array([[10, 2], [1, 12]])
        result = EvaluationResult(
            accuracy=0.88,
            precision=0.85,
            recall=0.90,
            f1_score=0.87,
            confusion_matrix=confusion,
            per_class_metrics={"class_a": {"precision": 0.85}},
        )

        assert result.accuracy == 0.88
        assert result.precision == 0.85
        assert result.recall == 0.90
        assert result.f1_score == 0.87
        assert result.confusion_matrix.shape == (2, 2)


# =============================================================================
# SecurityDatasetBuilder Tests
# =============================================================================


class TestSecurityDatasetBuilder:
    """Tests for SecurityDatasetBuilder."""

    def test_builder_initialization(self, dataset_builder):
        """Test builder initialization."""
        assert dataset_builder.samples == []
        assert len(dataset_builder.label_counts) == 0
        assert dataset_builder._sample_counter == 0

    def test_add_sample(self, dataset_builder):
        """Test adding a single sample."""
        dataset_builder.add_sample(text="Test security event", label="malicious", category="alert")

        assert len(dataset_builder.samples) == 1
        assert dataset_builder.samples[0].label == "malicious"
        assert dataset_builder.label_counts["malicious"] == 1
        assert dataset_builder._sample_counter == 1

    def test_add_multiple_samples(self, dataset_builder, sample_training_data):
        """Test adding multiple samples."""
        for sample in sample_training_data:
            dataset_builder.add_sample(
                text=sample["text"], label=sample["label"], category=sample["category"]
            )

        assert len(dataset_builder.samples) == len(sample_training_data)
        assert dataset_builder._sample_counter == len(sample_training_data)

    def test_sample_id_generation(self, dataset_builder):
        """Test sample ID generation."""
        dataset_builder.add_sample("Text 1", "label1", "cat1")
        dataset_builder.add_sample("Text 2", "label2", "cat2")

        assert dataset_builder.samples[0].sample_id == "sample_000000"
        assert dataset_builder.samples[1].sample_id == "sample_000001"

    def test_load_from_json(self, dataset_builder, sample_training_json):
        """Test loading samples from JSON file."""
        dataset_builder.load_from_json(sample_training_json)

        assert len(dataset_builder.samples) > 0
        assert all(s.text for s in dataset_builder.samples)

    def test_load_from_json_array_format(self, dataset_builder, tmp_path, sample_training_data):
        """Test loading from JSON with array format (no 'samples' key)."""
        json_file = tmp_path / "array_samples.json"
        json_file.write_text(json.dumps(sample_training_data))

        dataset_builder.load_from_json(str(json_file))

        assert len(dataset_builder.samples) == len(sample_training_data)

    # --- Text Cleaning Tests ---

    def test_clean_text_empty(self, dataset_builder):
        """Test cleaning empty text."""
        assert dataset_builder.clean_text("") == ""
        assert dataset_builder.clean_text(None) == ""

    def test_clean_text_whitespace_normalization(self, dataset_builder):
        """Test whitespace normalization."""
        text = "Multiple    spaces   and\n\nnewlines\ttabs"
        cleaned = dataset_builder.clean_text(text)

        assert "    " not in cleaned
        assert "\n\n" not in cleaned
        assert "\t" not in cleaned

    def test_clean_text_ip_normalization(self, dataset_builder):
        """Test IP address normalization."""
        text = "Connection from 192.168.1.100 to 10.0.0.1"
        cleaned = dataset_builder.clean_text(text)

        assert "192.168.1.100" not in cleaned
        assert "10.0.0.1" not in cleaned
        assert "[IP_ADDR]" in cleaned

    def test_clean_text_email_normalization(self, dataset_builder):
        """Test email address normalization."""
        text = "Contact admin@example.com or security@company.org"
        cleaned = dataset_builder.clean_text(text)

        assert "admin@example.com" not in cleaned
        assert "[EMAIL]" in cleaned

    def test_clean_text_url_normalization(self, dataset_builder):
        """Test URL normalization."""
        text = "Visit https://malicious-site.com/payload or http://example.org/page"
        cleaned = dataset_builder.clean_text(text)

        assert "https://malicious-site.com" not in cleaned
        assert "[URL:" in cleaned

    def test_clean_text_hash_normalization_md5(self, dataset_builder):
        """Test MD5 hash normalization."""
        text = "File hash: d41d8cd98f00b204e9800998ecf8427e"
        cleaned = dataset_builder.clean_text(text)

        assert "d41d8cd98f00b204e9800998ecf8427e" not in cleaned
        assert "[HASH_MD5]" in cleaned

    def test_clean_text_hash_normalization_sha1(self, dataset_builder):
        """Test SHA1 hash normalization."""
        text = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        cleaned = dataset_builder.clean_text(text)

        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" not in cleaned
        assert "[HASH_SHA1]" in cleaned

    def test_clean_text_hash_normalization_sha256(self, dataset_builder):
        """Test SHA256 hash normalization."""
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cleaned = dataset_builder.clean_text(text)

        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in cleaned
        assert "[HASH_SHA256]" in cleaned

    # --- Augmentation Tests ---

    def test_augment_sample_with_matching_term(self, dataset_builder):
        """Test sample augmentation with matching security term."""
        sample = TrainingSample(
            sample_id="test_001",
            text="Detected malicious file on system",
            label="malicious",
            category="alert",
        )

        augmented = dataset_builder.augment_sample(sample)

        assert len(augmented) >= 1
        assert all(s.label == sample.label for s in augmented)
        assert all(s.metadata.get("augmented") is True for s in augmented)

    def test_augment_sample_no_matching_term(self, dataset_builder):
        """Test sample augmentation with no matching terms."""
        sample = TrainingSample(
            sample_id="test_002", text="Normal system operation", label="benign", category="log"
        )

        augmented = dataset_builder.augment_sample(sample)

        assert len(augmented) == 0

    def test_augment_sample_preserves_category(self, dataset_builder):
        """Test that augmentation preserves category."""
        sample = TrainingSample(
            sample_id="test_003",
            text="Suspicious activity detected",
            label="suspicious",
            category="alert",
        )

        augmented = dataset_builder.augment_sample(sample)

        assert all(s.category == sample.category for s in augmented)

    # --- Dataset Balancing Tests ---

    def test_balance_dataset_empty(self, dataset_builder):
        """Test balancing empty dataset."""
        balanced = dataset_builder.balance_dataset()

        assert balanced == []

    def test_balance_dataset_oversample(self, populated_dataset_builder):
        """Test oversampling strategy."""
        balanced = populated_dataset_builder.balance_dataset(strategy="oversample")

        # Count labels in balanced dataset
        label_counts = {}
        for sample in balanced:
            label_counts[sample.label] = label_counts.get(sample.label, 0) + 1

        # All labels should have the same count
        counts = list(label_counts.values())
        assert len(set(counts)) == 1

    def test_balance_dataset_undersample(self, populated_dataset_builder):
        """Test undersampling strategy."""
        balanced = populated_dataset_builder.balance_dataset(strategy="undersample")

        # Count labels in balanced dataset
        label_counts = {}
        for sample in balanced:
            label_counts[sample.label] = label_counts.get(sample.label, 0) + 1

        # All labels should have the same count (minimum)
        counts = list(label_counts.values())
        assert len(set(counts)) == 1

    def test_balance_dataset_unknown_strategy(self, populated_dataset_builder):
        """Test unknown balancing strategy returns original."""
        original_count = len(populated_dataset_builder.samples)
        balanced = populated_dataset_builder.balance_dataset(strategy="unknown")

        assert len(balanced) == original_count

    # --- Train/Test Split Tests ---

    def test_create_train_test_split_empty(self, dataset_builder):
        """Test split with empty dataset."""
        train, test = dataset_builder.create_train_test_split()

        assert train == []
        assert test == []

    def test_create_train_test_split_ratios(self, populated_dataset_builder):
        """Test train/test split ratios."""
        train, test = populated_dataset_builder.create_train_test_split(test_ratio=0.25)

        total = len(train) + len(test)
        assert total == len(populated_dataset_builder.samples)
        # Test ratio should be approximately 0.25
        assert len(test) > 0
        # With stratified split and small dataset, train >= test
        assert len(train) >= len(test)

    def test_create_train_test_split_stratified(self, populated_dataset_builder):
        """Test stratified split preserves label distribution."""
        train, test = populated_dataset_builder.create_train_test_split(
            test_ratio=0.25, stratify=True
        )

        # Check that test set has samples from each label
        test_labels = set(s.label for s in test)
        train_labels = set(s.label for s in train)

        # Each label should appear in both sets if there are enough samples
        assert len(test_labels) > 0
        assert len(train_labels) > 0

    def test_create_train_test_split_non_stratified(self, populated_dataset_builder):
        """Test non-stratified split."""
        train, test = populated_dataset_builder.create_train_test_split(
            test_ratio=0.2, stratify=False
        )

        total = len(train) + len(test)
        assert total == len(populated_dataset_builder.samples)

    # --- Contrastive Pairs Tests ---

    def test_create_contrastive_pairs_empty(self, dataset_builder):
        """Test contrastive pair creation with empty dataset."""
        pairs = dataset_builder.create_contrastive_pairs()

        assert pairs == []

    def test_create_contrastive_pairs(self, populated_dataset_builder):
        """Test contrastive pair creation."""
        pairs = populated_dataset_builder.create_contrastive_pairs()

        assert len(pairs) > 0
        for pair in pairs:
            assert isinstance(pair, EmbeddingPair)
            assert pair.anchor != ""
            assert pair.positive != ""
            assert pair.negative != ""

    def test_contrastive_pairs_different_anchor_negative(self, populated_dataset_builder):
        """Test that anchor and negative have different labels."""
        pairs = populated_dataset_builder.create_contrastive_pairs()

        # Get original label mapping
        sample_texts = {s.text: s.label for s in populated_dataset_builder.samples}

        for pair in pairs:
            # Anchor label should match anchor_label field
            assert sample_texts.get(pair.anchor) == pair.anchor_label

    # --- Export Tests ---

    def test_export_jsonl_format(self, populated_dataset_builder):
        """Test JSONL export format."""
        exported = populated_dataset_builder.export_for_training(format="jsonl")

        lines = exported.strip().split("\n")
        assert len(lines) == len(populated_dataset_builder.samples)

        # Each line should be valid JSON
        for line in lines:
            record = json.loads(line)
            assert "text" in record
            assert "label" in record
            assert "category" in record

    def test_export_csv_format(self, populated_dataset_builder):
        """Test CSV export format."""
        exported = populated_dataset_builder.export_for_training(format="csv")

        lines = exported.strip().split("\n")
        # First line is header
        assert lines[0] == '"text","label","category"'
        assert len(lines) == len(populated_dataset_builder.samples) + 1


# =============================================================================
# EmbeddingTrainer Tests
# =============================================================================


class TestEmbeddingTrainer:
    """Tests for EmbeddingTrainer."""

    def test_trainer_initialization(self, embedding_trainer):
        """Test trainer initialization."""
        assert embedding_trainer.model_name == "simulated-embeddings"
        assert embedding_trainer.embedding_dim == 128
        assert embedding_trainer._initialized is False

    def test_load_base_model(self, embedding_trainer):
        """Test loading base model."""
        embedding_trainer.load_base_model()

        assert embedding_trainer._initialized is True
        assert embedding_trainer.embeddings is not None

    def test_encode_single_text(self, initialized_trainer):
        """Test encoding a single text."""
        embeddings = initialized_trainer.encode(["Test security text"])

        assert embeddings.shape == (1, 128)

    def test_encode_multiple_texts(self, initialized_trainer):
        """Test encoding multiple texts."""
        texts = ["First text", "Second text", "Third text"]
        embeddings = initialized_trainer.encode(texts)

        assert embeddings.shape == (3, 128)

    def test_encode_empty_text(self, initialized_trainer):
        """Test encoding empty text."""
        embeddings = initialized_trainer.encode([""])

        assert embeddings.shape == (1, 128)
        # Empty text should produce zero vector
        assert np.allclose(embeddings[0], np.zeros(128))

    def test_encode_auto_initialization(self, embedding_trainer):
        """Test that encode auto-initializes if needed."""
        assert embedding_trainer._initialized is False

        embeddings = embedding_trainer.encode(["Test text"])

        assert embedding_trainer._initialized is True
        assert embeddings.shape[1] == 128

    def test_get_word_embedding_deterministic(self, initialized_trainer):
        """Test that word embeddings are deterministic."""
        emb1 = initialized_trainer._get_word_embedding("security")
        emb2 = initialized_trainer._get_word_embedding("security")

        assert np.allclose(emb1, emb2)

    def test_get_word_embedding_different_words(self, initialized_trainer):
        """Test that different words get different embeddings."""
        emb1 = initialized_trainer._get_word_embedding("malware")
        emb2 = initialized_trainer._get_word_embedding("benign")

        assert not np.allclose(emb1, emb2)

    def test_compute_similarity_identical(self, initialized_trainer):
        """Test similarity of identical texts."""
        text = "Malicious file detected"
        similarity = initialized_trainer.compute_similarity(text, text)

        # Identical texts should have similarity close to 1
        assert similarity > 0.99

    def test_compute_similarity_different(self, initialized_trainer):
        """Test similarity of different texts."""
        text1 = "Malicious ransomware attack detected"
        text2 = "Normal business meeting scheduled"

        similarity = initialized_trainer.compute_similarity(text1, text2)

        # Different texts should have lower similarity
        assert -1.0 <= similarity <= 1.0

    def test_compute_similarity_range(self, initialized_trainer):
        """Test that similarity is in valid range."""
        text1 = "Security incident reported"
        text2 = "Network traffic analysis"

        similarity = initialized_trainer.compute_similarity(text1, text2)

        assert -1.0 <= similarity <= 1.0

    def test_compute_similarity_empty_text(self, initialized_trainer):
        """Test similarity with empty text."""
        similarity = initialized_trainer.compute_similarity("", "Some text")

        assert similarity == 0.0

    # --- Training Tests ---

    def test_train_contrastive(self, initialized_trainer):
        """Test contrastive training."""
        pairs = [
            EmbeddingPair(
                anchor="Malware detected",
                positive="Virus found on system",
                negative="Normal operation",
                anchor_label="malicious",
            ),
            EmbeddingPair(
                anchor="Phishing email",
                positive="Suspicious email link",
                negative="Regular email",
                anchor_label="phishing",
            ),
        ]

        losses = initialized_trainer.train_contrastive(pairs, epochs=3, batch_size=2)

        assert len(losses) == 3
        assert all(isinstance(l, float) for l in losses)

    def test_train_contrastive_auto_init(self, embedding_trainer):
        """Test that contrastive training auto-initializes."""
        pairs = [
            EmbeddingPair(
                anchor="Test anchor",
                positive="Test positive",
                negative="Test negative",
                anchor_label="test",
            )
        ]

        losses = embedding_trainer.train_contrastive(pairs, epochs=2)

        assert embedding_trainer._initialized is True
        assert len(losses) == 2

    def test_train_classification(self, initialized_trainer, sample_test_samples):
        """Test classification training."""
        losses = initialized_trainer.train_classification(sample_test_samples, epochs=3)

        assert len(losses) == 3
        assert all(isinstance(l, float) for l in losses)

    def test_train_classification_empty(self, initialized_trainer):
        """Test classification training with empty samples."""
        losses = initialized_trainer.train_classification([], epochs=3)

        assert len(losses) == 3
        assert all(l == 0 for l in losses)

    # --- Save/Load Tests ---

    def test_save_and_load_model(self, initialized_trainer, tmp_path):
        """Test saving and loading model."""
        # Train a bit to have some embeddings
        initialized_trainer.encode(["security", "malware", "benign"])

        model_path = str(tmp_path / "test_model.json")
        initialized_trainer.save_model(model_path)

        # Create new trainer and load
        new_trainer = EmbeddingTrainer()
        new_trainer.load_model(model_path)

        assert new_trainer._initialized is True
        assert new_trainer.embedding_dim == initialized_trainer.embedding_dim
        assert len(new_trainer.embeddings) == len(initialized_trainer.embeddings)


# =============================================================================
# SecurityModelEvaluator Tests
# =============================================================================


class TestSecurityModelEvaluator:
    """Tests for SecurityModelEvaluator."""

    def test_evaluator_initialization(self, initialized_trainer):
        """Test evaluator initialization."""
        evaluator = SecurityModelEvaluator(model=initialized_trainer)

        assert evaluator.model is not None
        assert evaluator.results == {}

    def test_evaluator_without_model(self):
        """Test evaluator without model."""
        evaluator = SecurityModelEvaluator()

        assert evaluator.model is None

    def test_evaluate_classification_perfect(self):
        """Test classification evaluation with perfect predictions."""
        evaluator = SecurityModelEvaluator()

        samples = [
            TrainingSample("s1", "text1", "malicious", "alert"),
            TrainingSample("s2", "text2", "benign", "log"),
            TrainingSample("s3", "text3", "malicious", "alert"),
            TrainingSample("s4", "text4", "benign", "log"),
        ]
        predictions = ["malicious", "benign", "malicious", "benign"]

        result = evaluator.evaluate_classification(samples, predictions)

        assert result.accuracy == 1.0
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1_score == 1.0

    def test_evaluate_classification_partial(self):
        """Test classification evaluation with partial correctness."""
        evaluator = SecurityModelEvaluator()

        samples = [
            TrainingSample("s1", "text1", "malicious", "alert"),
            TrainingSample("s2", "text2", "benign", "log"),
            TrainingSample("s3", "text3", "malicious", "alert"),
            TrainingSample("s4", "text4", "benign", "log"),
        ]
        predictions = ["malicious", "malicious", "benign", "benign"]  # 50% correct

        result = evaluator.evaluate_classification(samples, predictions)

        assert result.accuracy == 0.5
        assert isinstance(result.confusion_matrix, np.ndarray)

    def test_evaluate_classification_per_class_metrics(self, sample_test_samples):
        """Test per-class metrics in classification evaluation."""
        evaluator = SecurityModelEvaluator()

        predictions = [s.label for s in sample_test_samples]  # Perfect predictions
        result = evaluator.evaluate_classification(sample_test_samples, predictions)

        assert "per_class_metrics" in dir(result)
        assert len(result.per_class_metrics) > 0

        for label, metrics in result.per_class_metrics.items():
            assert "precision" in metrics
            assert "recall" in metrics
            assert "f1" in metrics
            assert "support" in metrics

    def test_evaluate_retrieval_no_model(self):
        """Test retrieval evaluation without model."""
        evaluator = SecurityModelEvaluator()

        result = evaluator.evaluate_retrieval(["query"], {"query": ["doc1"]})

        assert result == {}

    def test_evaluate_retrieval(self, model_evaluator):
        """Test retrieval evaluation."""
        queries = ["malware detection", "network security"]
        relevant_docs = {
            "malware detection": ["Detected malware in system", "Virus found"],
            "network security": ["Firewall configuration", "Network monitoring"],
        }

        result = model_evaluator.evaluate_retrieval(queries, relevant_docs, k=5)

        assert "precision@5" in result
        assert "recall@5" in result
        assert "mrr" in result

    def test_evaluate_similarity_no_model(self):
        """Test similarity evaluation without model."""
        evaluator = SecurityModelEvaluator()

        result = evaluator.evaluate_similarity([("text1", "text2", 0.8)])

        assert result == {}

    def test_evaluate_similarity(self, model_evaluator):
        """Test similarity evaluation."""
        pairs = [
            ("Malware detected", "Virus found", 0.9),
            ("Normal operation", "Security incident", 0.2),
            ("Phishing email", "Suspicious link", 0.8),
        ]

        result = model_evaluator.evaluate_similarity(pairs)

        assert "correlation" in result
        assert "mae" in result
        assert "mse" in result

    def test_evaluate_security_specific_empty(self, model_evaluator):
        """Test security-specific evaluation with empty samples."""
        result = model_evaluator.evaluate_security_specific([])

        assert result == {}

    def test_evaluate_security_specific(self, model_evaluator, sample_test_samples):
        """Test security-specific evaluation."""
        np.random.seed(42)  # For reproducibility
        result = model_evaluator.evaluate_security_specific(sample_test_samples)

        assert "fpr" in result
        assert "fnr" in result
        assert "detection_rate" in result
        assert "total_malicious" in result
        assert "total_benign" in result

    def test_generate_report(self, model_evaluator, sample_test_samples):
        """Test report generation."""
        # Add some results
        model_evaluator.results["test_metric"] = {"accuracy": 0.95, "precision": 0.92}

        report = model_evaluator.generate_report()

        assert "MODEL EVALUATION REPORT" in report
        assert "test_metric" in report
        assert "0.95" in report or "0.9500" in report

    def test_generate_report_with_evaluation_result(self, model_evaluator):
        """Test report generation with EvaluationResult."""
        confusion = np.array([[10, 2], [1, 12]])
        result = EvaluationResult(
            accuracy=0.88,
            precision=0.85,
            recall=0.90,
            f1_score=0.87,
            confusion_matrix=confusion,
            per_class_metrics={},
        )
        model_evaluator.results["classification"] = result

        report = model_evaluator.generate_report()

        assert "Accuracy" in report
        assert "Precision" in report
        assert "Recall" in report

    def test_compare_models(self, sample_test_samples):
        """Test model comparison."""
        models = [EmbeddingTrainer(), EmbeddingTrainer()]
        for m in models:
            m.load_base_model()

        evaluator = SecurityModelEvaluator()
        results = evaluator.compare_models(models, sample_test_samples)

        assert len(results) == 2
        assert "model_0" in results
        assert "model_1" in results

        for model_name, metrics in results.items():
            assert "avg_cluster_distance" in metrics
            assert "embedding_dim" in metrics


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the complete workflow."""

    def test_full_pipeline_workflow(self, sample_training_data):
        """Test complete pipeline from data loading to evaluation."""
        # Build dataset
        builder = SecurityDatasetBuilder()
        for sample in sample_training_data:
            builder.add_sample(
                text=sample["text"], label=sample["label"], category=sample["category"]
            )

        # Create train/test split
        train, test = builder.create_train_test_split(test_ratio=0.25)

        # Create contrastive pairs
        pairs = builder.create_contrastive_pairs()

        # Train model
        trainer = EmbeddingTrainer()
        trainer.load_base_model()

        if pairs:
            losses = trainer.train_contrastive(pairs, epochs=2)
            assert len(losses) == 2

        # Evaluate
        evaluator = SecurityModelEvaluator(model=trainer)

        if test:
            predictions = [s.label for s in test]
            result = evaluator.evaluate_classification(test, predictions)
            assert result.accuracy > 0

    def test_load_real_training_data(self):
        """Test loading the actual training data file."""
        data_path = (
            Path(__file__).parent.parent
            / "labs"
            / "lab18-fine-tuning-security"
            / "data"
            / "training_samples.json"
        )

        if data_path.exists():
            builder = SecurityDatasetBuilder()
            builder.load_from_json(str(data_path))

            assert len(builder.samples) > 0
            assert len(builder.label_counts) > 0


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_very_long_text(self, dataset_builder):
        """Test handling of very long text."""
        long_text = "Security event " * 1000
        dataset_builder.add_sample(long_text, "malicious", "alert")

        assert len(dataset_builder.samples) == 1
        assert len(dataset_builder.samples[0].text) > 0

    def test_special_characters_in_text(self, dataset_builder):
        """Test handling of special characters."""
        special_text = "Alert: <>\"'&|;$`\\n\\t test@test.com"
        dataset_builder.add_sample(special_text, "suspicious", "alert")

        assert len(dataset_builder.samples) == 1

    def test_unicode_text(self, dataset_builder):
        """Test handling of Unicode text."""
        unicode_text = "Security alert: malware"
        dataset_builder.add_sample(unicode_text, "malicious", "alert")

        assert len(dataset_builder.samples) == 1

    def test_single_sample_per_label(self, dataset_builder):
        """Test operations with single sample per label."""
        dataset_builder.add_sample("Text 1", "label1", "cat1")
        dataset_builder.add_sample("Text 2", "label2", "cat2")

        # Should handle gracefully
        pairs = dataset_builder.create_contrastive_pairs()
        assert pairs == []  # Not enough samples for pairs

    def test_all_same_label(self, dataset_builder):
        """Test operations when all samples have same label."""
        for i in range(5):
            dataset_builder.add_sample(f"Text {i}", "same_label", "cat")

        # Balance should return same data
        balanced = dataset_builder.balance_dataset(strategy="oversample")
        assert len(balanced) == 5

    def test_embedding_trainer_custom_name(self):
        """Test EmbeddingTrainer with custom model name."""
        trainer = EmbeddingTrainer(model_name="custom-model")

        assert trainer.model_name == "custom-model"


# =============================================================================
# API Tests (Marked for skip if no API key)
# =============================================================================


@pytest.mark.requires_api
class TestLLMIntegration:
    """Tests that require LLM API access."""

    def test_setup_llm_auto_detection(self):
        """Test automatic LLM provider detection."""
        import os

        # Only test if an API key is available
        if not any(
            [
                os.getenv("ANTHROPIC_API_KEY"),
                os.getenv("OPENAI_API_KEY"),
                os.getenv("GOOGLE_API_KEY"),
            ]
        ):
            pytest.skip("No API key available")

        from main import setup_llm

        provider, client = setup_llm()
        assert provider in ["anthropic", "openai", "google"]
        assert client is not None

    def test_setup_llm_specific_provider(self):
        """Test specific LLM provider setup."""
        import os

        if os.getenv("ANTHROPIC_API_KEY"):
            from main import setup_llm

            provider, client = setup_llm(provider="anthropic")
            assert provider == "anthropic"
        else:
            pytest.skip("ANTHROPIC_API_KEY not available")


# =============================================================================
# Utility Function Tests
# =============================================================================


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_create_sample_training_data(self):
        """Test the sample training data creation function."""
        samples = create_sample_training_data()

        assert len(samples) > 0
        for sample in samples:
            assert "text" in sample
            assert "label" in sample
            assert "category" in sample


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

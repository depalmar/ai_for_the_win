"""
Lab 18: Fine-Tuning for Security Applications - Starter Code

Learn to prepare security datasets, fine-tune embeddings,
and evaluate models for security-specific tasks.

Complete the TODOs to build a security model fine-tuning pipeline.
"""

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

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
class TrainingSample:
    """Single training sample for security model."""

    sample_id: str
    text: str
    label: str  # e.g., 'malicious', 'benign', 'phishing', etc.
    category: str  # e.g., 'email', 'log', 'url', etc.
    metadata: Dict = field(default_factory=dict)


@dataclass
class EmbeddingPair:
    """Pair of texts for contrastive learning."""

    anchor: str
    positive: str
    negative: str
    anchor_label: str


@dataclass
class EvaluationResult:
    """Model evaluation result."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: np.ndarray
    per_class_metrics: Dict


class SecurityDatasetBuilder:
    """Build and preprocess security datasets for fine-tuning."""

    def __init__(self):
        self.samples = []
        self.label_counts = defaultdict(int)
        self.augmenters = []

    def add_sample(self, text: str, label: str, category: str, metadata: dict = None):
        """
        Add a training sample.

        TODO: Implement sample addition
        - Clean and normalize text
        - Track label distribution
        - Create TrainingSample

        Args:
            text: Sample text
            label: Classification label
            category: Sample category
            metadata: Additional metadata
        """
        # TODO: Implement this method
        pass

    def load_from_json(self, filepath: str):
        """
        Load samples from JSON file.

        TODO: Implement JSON loading
        - Parse JSON structure
        - Add each sample
        - Handle different formats

        Args:
            filepath: Path to JSON file
        """
        # TODO: Implement this method
        pass

    def clean_text(self, text: str) -> str:
        """
        Clean and normalize text for training.

        TODO: Implement text cleaning
        - Remove excessive whitespace
        - Normalize unicode
        - Handle special security tokens (IPs, hashes, etc.)

        Args:
            text: Raw text

        Returns:
            Cleaned text
        """
        # TODO: Implement this method
        pass

    def augment_sample(self, sample: TrainingSample) -> List[TrainingSample]:
        """
        Augment a training sample.

        TODO: Implement data augmentation
        - Synonym replacement for security terms
        - Back-translation simulation
        - Entity replacement (IP, domain variations)

        Args:
            sample: Original sample

        Returns:
            List of augmented samples
        """
        # TODO: Implement this method
        pass

    def balance_dataset(self, strategy: str = "oversample") -> List[TrainingSample]:
        """
        Balance dataset by label distribution.

        TODO: Implement balancing
        - Oversample minority classes, OR
        - Undersample majority classes, OR
        - Use SMOTE-like technique

        Args:
            strategy: Balancing strategy

        Returns:
            Balanced list of samples
        """
        # TODO: Implement this method
        pass

    def create_train_test_split(
        self, test_ratio: float = 0.2, stratify: bool = True
    ) -> Tuple[List, List]:
        """
        Split dataset into train and test sets.

        TODO: Implement stratified split
        - Maintain label proportions if stratify=True
        - Random shuffle before split

        Args:
            test_ratio: Fraction for test set
            stratify: Whether to stratify by label

        Returns:
            (train_samples, test_samples)
        """
        # TODO: Implement this method
        pass

    def create_contrastive_pairs(self) -> List[EmbeddingPair]:
        """
        Create pairs for contrastive learning.

        TODO: Implement pair creation
        - Group samples by label
        - Create (anchor, positive, negative) triplets
        - Positive = same label, Negative = different label

        Returns:
            List of EmbeddingPairs
        """
        # TODO: Implement this method
        pass

    def export_for_training(self, format: str = "jsonl") -> str:
        """
        Export dataset in training format.

        TODO: Implement export
        - Support JSONL, CSV formats
        - Include all necessary fields

        Args:
            format: Export format

        Returns:
            Exported data as string
        """
        # TODO: Implement this method
        pass


class EmbeddingTrainer:
    """Train and fine-tune embeddings for security tasks."""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """
        Initialize embedding trainer.

        Args:
            model_name: Base model to fine-tune
        """
        self.model_name = model_name
        self.model = None
        self.tokenizer = None

    def load_base_model(self):
        """
        Load the base embedding model.

        TODO: Implement model loading
        - Load model and tokenizer
        - Set up for fine-tuning

        Note: This is a simulation - real implementation
        would use sentence-transformers or similar
        """
        # TODO: Implement this method
        # For simulation, we'll use simple word vectors
        pass

    def encode(self, texts: List[str]) -> np.ndarray:
        """
        Encode texts to embeddings.

        TODO: Implement encoding
        - Tokenize texts
        - Generate embeddings
        - Return as numpy array

        Args:
            texts: List of texts to encode

        Returns:
            Embeddings array (n_texts, embedding_dim)
        """
        # TODO: Implement this method
        pass

    def compute_similarity(self, text1: str, text2: str) -> float:
        """
        Compute similarity between two texts.

        TODO: Implement similarity computation
        - Encode both texts
        - Calculate cosine similarity

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score
        """
        # TODO: Implement this method
        pass

    def train_contrastive(
        self, pairs: List[EmbeddingPair], epochs: int = 10, batch_size: int = 32
    ) -> List[float]:
        """
        Train with contrastive loss.

        TODO: Implement contrastive training
        - For each triplet (anchor, positive, negative)
        - Minimize distance to positive
        - Maximize distance to negative

        Args:
            pairs: Training pairs
            epochs: Number of epochs
            batch_size: Batch size

        Returns:
            Loss values per epoch
        """
        # TODO: Implement this method
        pass

    def train_classification(self, samples: List[TrainingSample], epochs: int = 10) -> List[float]:
        """
        Train for classification task.

        TODO: Implement classification training
        - Add classification head
        - Train on labeled samples

        Args:
            samples: Training samples
            epochs: Number of epochs

        Returns:
            Loss values per epoch
        """
        # TODO: Implement this method
        pass

    def save_model(self, path: str):
        """Save fine-tuned model."""
        # TODO: Implement model saving
        pass

    def load_model(self, path: str):
        """Load fine-tuned model."""
        # TODO: Implement model loading
        pass


class SecurityModelEvaluator:
    """Evaluate security models comprehensively."""

    def __init__(self, model: EmbeddingTrainer = None):
        """
        Initialize evaluator.

        Args:
            model: Model to evaluate
        """
        self.model = model
        self.results = {}

    def evaluate_classification(
        self, test_samples: List[TrainingSample], predictions: List[str]
    ) -> EvaluationResult:
        """
        Evaluate classification performance.

        TODO: Implement classification evaluation
        - Calculate accuracy, precision, recall, F1
        - Build confusion matrix
        - Per-class metrics

        Args:
            test_samples: Test samples with true labels
            predictions: Model predictions

        Returns:
            EvaluationResult with all metrics
        """
        # TODO: Implement this method
        pass

    def evaluate_retrieval(
        self, queries: List[str], relevant_docs: Dict[str, List[str]], k: int = 10
    ) -> dict:
        """
        Evaluate retrieval performance.

        TODO: Implement retrieval evaluation
        - Calculate precision@k, recall@k
        - Calculate MRR (Mean Reciprocal Rank)
        - Calculate NDCG

        Args:
            queries: Query texts
            relevant_docs: Ground truth relevant docs per query
            k: Top-k for evaluation

        Returns:
            Retrieval metrics
        """
        # TODO: Implement this method
        pass

    def evaluate_similarity(self, pairs: List[Tuple[str, str, float]]) -> dict:
        """
        Evaluate similarity predictions.

        TODO: Implement similarity evaluation
        - Compare predicted similarities to ground truth
        - Calculate correlation
        - Calculate MAE/MSE

        Args:
            pairs: List of (text1, text2, true_similarity)

        Returns:
            Similarity metrics
        """
        # TODO: Implement this method
        pass

    def evaluate_security_specific(self, test_samples: List[TrainingSample]) -> dict:
        """
        Security-specific evaluation metrics.

        TODO: Implement security metrics
        - False positive rate (benign classified as malicious)
        - False negative rate (malicious missed)
        - Detection rate by threat category
        - Time to detect (if applicable)

        Args:
            test_samples: Test samples

        Returns:
            Security-specific metrics
        """
        # TODO: Implement this method
        pass

    def generate_report(self) -> str:
        """
        Generate comprehensive evaluation report.

        TODO: Implement report generation

        Returns:
            Formatted report string
        """
        # TODO: Implement this method
        pass

    def compare_models(
        self, models: List[EmbeddingTrainer], test_samples: List[TrainingSample]
    ) -> dict:
        """
        Compare multiple models.

        TODO: Implement model comparison
        - Evaluate each model
        - Compare metrics
        - Statistical significance tests

        Args:
            models: Models to compare
            test_samples: Test samples

        Returns:
            Comparison results
        """
        # TODO: Implement this method
        pass


def create_sample_training_data() -> List[dict]:
    """Create sample training data for demonstration."""
    return [
        {
            "text": "Urgent: Your account has been compromised. Click here to secure it now!",
            "label": "phishing",
            "category": "email",
        },
        {
            "text": "Meeting scheduled for tomorrow at 2pm in conference room B.",
            "label": "benign",
            "category": "email",
        },
        {
            "text": "Invoice #12345 attached. Please process payment immediately.",
            "label": "phishing",
            "category": "email",
        },
        {
            "text": "Weekly team standup notes attached for your review.",
            "label": "benign",
            "category": "email",
        },
        {
            "text": "Failed login attempt from 185.234.72.19 for user admin",
            "label": "suspicious",
            "category": "log",
        },
        {
            "text": "User jsmith logged in successfully from 192.168.1.10",
            "label": "benign",
            "category": "log",
        },
        {
            "text": "PowerShell -enc base64encodedcommand executed by SYSTEM",
            "label": "malicious",
            "category": "log",
        },
        {"text": "Scheduled backup completed successfully", "label": "benign", "category": "log"},
        {
            "text": "http://secure-bank-login.evil.com/verify.php",
            "label": "malicious",
            "category": "url",
        },
        {"text": "https://www.google.com/search?q=security", "label": "benign", "category": "url"},
    ]


def main():
    """Main entry point for Lab 18."""
    print("=" * 60)
    print("Lab 18: Fine-Tuning for Security Applications")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "training_samples.json"), "r") as f:
            data = json.load(f)
        print(f"\nLoaded {len(data.get('samples', []))} training samples")
    except FileNotFoundError:
        print("Sample data not found. Using demo data.")
        data = {"samples": create_sample_training_data()}

    # Task 1: Build Dataset
    print("\n--- Task 1: Build Security Dataset ---")
    builder = SecurityDatasetBuilder()

    for sample in data.get("samples", []):
        builder.add_sample(text=sample["text"], label=sample["label"], category=sample["category"])

    if builder.samples:
        print(f"Added {len(builder.samples)} samples")
        print(f"Label distribution: {dict(builder.label_counts)}")
    else:
        print("TODO: Implement add_sample()")

    # Task 2: Data Preparation
    print("\n--- Task 2: Data Preparation ---")
    train_samples, test_samples = builder.create_train_test_split(test_ratio=0.2)
    if train_samples:
        print(f"Train: {len(train_samples)}, Test: {len(test_samples)}")
    else:
        print("TODO: Implement create_train_test_split()")

    # Task 3: Create Contrastive Pairs
    print("\n--- Task 3: Create Contrastive Pairs ---")
    pairs = builder.create_contrastive_pairs()
    if pairs:
        print(f"Created {len(pairs)} contrastive pairs")
    else:
        print("TODO: Implement create_contrastive_pairs()")

    # Task 4: Train Embeddings
    print("\n--- Task 4: Train Embeddings ---")
    trainer = EmbeddingTrainer()
    trainer.load_base_model()

    if pairs:
        losses = trainer.train_contrastive(pairs, epochs=5)
        if losses:
            print(f"Training complete. Final loss: {losses[-1]:.4f}")
        else:
            print("TODO: Implement train_contrastive()")

    # Task 5: Evaluate Model
    print("\n--- Task 5: Evaluate Model ---")
    evaluator = SecurityModelEvaluator(trainer)

    if test_samples:
        # Get predictions (simulated)
        predictions = [s.label for s in test_samples]  # Perfect predictions for demo
        result = evaluator.evaluate_classification(test_samples, predictions)
        if result:
            print(f"Accuracy: {result.accuracy:.2%}")
            print(f"F1 Score: {result.f1_score:.2%}")
        else:
            print("TODO: Implement evaluate_classification()")

    # Task 6: Security-Specific Evaluation
    print("\n--- Task 6: Security-Specific Evaluation ---")
    security_metrics = evaluator.evaluate_security_specific(test_samples or [])
    if security_metrics:
        print(f"False Positive Rate: {security_metrics.get('fpr', 'N/A')}")
        print(f"Detection Rate: {security_metrics.get('detection_rate', 'N/A')}")
    else:
        print("TODO: Implement evaluate_security_specific()")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 18!")
    print("=" * 60)


if __name__ == "__main__":
    main()

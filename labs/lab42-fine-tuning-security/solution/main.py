"""
Lab 18: Fine-Tuning for Security Applications - Solution

Learn to prepare security datasets, fine-tune embeddings,
and evaluate models for security-specific tasks.
"""

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

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
class TrainingSample:
    """Single training sample for security model."""

    sample_id: str
    text: str
    label: str
    category: str
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
        self.samples: List[TrainingSample] = []
        self.label_counts = defaultdict(int)
        self.augmenters = []
        self._sample_counter = 0

    def add_sample(self, text: str, label: str, category: str, metadata: dict = None):
        """Add a training sample."""
        # Clean text
        cleaned_text = self.clean_text(text)

        # Create sample
        sample = TrainingSample(
            sample_id=f"sample_{self._sample_counter:06d}",
            text=cleaned_text,
            label=label,
            category=category,
            metadata=metadata or {},
        )

        self.samples.append(sample)
        self.label_counts[label] += 1
        self._sample_counter += 1

    def load_from_json(self, filepath: str):
        """Load samples from JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)

        samples = data.get("samples", data) if isinstance(data, dict) else data

        for item in samples:
            self.add_sample(
                text=item.get("text", ""),
                label=item.get("label", "unknown"),
                category=item.get("category", "general"),
                metadata=item.get("metadata", {}),
            )

    def clean_text(self, text: str) -> str:
        """Clean and normalize text for training."""
        if not text:
            return ""

        # Normalize whitespace
        text = re.sub(r"\s+", " ", text).strip()

        # Normalize IP addresses to placeholder
        text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP_ADDR]", text)

        # Normalize email addresses
        text = re.sub(r"\b[\w.-]+@[\w.-]+\.\w+\b", "[EMAIL]", text)

        # Normalize URLs (keep domain structure for learning)
        text = re.sub(r"https?://([^\s/]+)[^\s]*", r"[URL:\1]", text)

        # Normalize hashes (MD5, SHA1, SHA256)
        text = re.sub(r"\b[a-fA-F0-9]{32}\b", "[HASH_MD5]", text)
        text = re.sub(r"\b[a-fA-F0-9]{40}\b", "[HASH_SHA1]", text)
        text = re.sub(r"\b[a-fA-F0-9]{64}\b", "[HASH_SHA256]", text)

        return text

    def augment_sample(self, sample: TrainingSample) -> List[TrainingSample]:
        """Augment a training sample."""
        augmented = []

        # Security-specific synonym replacement
        security_synonyms = {
            "malicious": ["malware", "threat", "attack"],
            "suspicious": ["anomalous", "unusual", "potentially harmful"],
            "compromised": ["breached", "infected", "hacked"],
            "phishing": ["credential theft", "social engineering"],
        }

        text_lower = sample.text.lower()
        for term, synonyms in security_synonyms.items():
            if term in text_lower:
                for synonym in synonyms[:1]:  # Limit augmentations
                    new_text = re.sub(term, synonym, sample.text, flags=re.IGNORECASE)
                    augmented.append(
                        TrainingSample(
                            sample_id=f"{sample.sample_id}_aug_{len(augmented)}",
                            text=new_text,
                            label=sample.label,
                            category=sample.category,
                            metadata={**sample.metadata, "augmented": True},
                        )
                    )

        return augmented

    def balance_dataset(self, strategy: str = "oversample") -> List[TrainingSample]:
        """Balance dataset by label distribution."""
        if not self.samples:
            return []

        # Group by label
        by_label = defaultdict(list)
        for sample in self.samples:
            by_label[sample.label].append(sample)

        if strategy == "oversample":
            max_count = max(len(samples) for samples in by_label.values())
            balanced = []

            for label, samples in by_label.items():
                balanced.extend(samples)
                # Oversample to match max
                while len([s for s in balanced if s.label == label]) < max_count:
                    sample = np.random.choice(samples)
                    new_sample = TrainingSample(
                        sample_id=f"{sample.sample_id}_dup_{len(balanced)}",
                        text=sample.text,
                        label=sample.label,
                        category=sample.category,
                        metadata={**sample.metadata, "duplicated": True},
                    )
                    balanced.append(new_sample)

        elif strategy == "undersample":
            min_count = min(len(samples) for samples in by_label.values())
            balanced = []

            for label, samples in by_label.items():
                selected = np.random.choice(samples, size=min_count, replace=False)
                balanced.extend(selected)

        else:
            balanced = self.samples.copy()

        np.random.shuffle(balanced)
        return balanced

    def create_train_test_split(
        self, test_ratio: float = 0.2, stratify: bool = True
    ) -> Tuple[List, List]:
        """Split dataset into train and test sets."""
        if not self.samples:
            return [], []

        if stratify:
            train = []
            test = []

            # Group by label
            by_label = defaultdict(list)
            for sample in self.samples:
                by_label[sample.label].append(sample)

            for label, samples in by_label.items():
                np.random.shuffle(samples)
                n_test = max(1, int(len(samples) * test_ratio))
                test.extend(samples[:n_test])
                train.extend(samples[n_test:])

            np.random.shuffle(train)
            np.random.shuffle(test)

        else:
            shuffled = self.samples.copy()
            np.random.shuffle(shuffled)
            n_test = int(len(shuffled) * test_ratio)
            test = shuffled[:n_test]
            train = shuffled[n_test:]

        return train, test

    def create_contrastive_pairs(self) -> List[EmbeddingPair]:
        """Create pairs for contrastive learning."""
        pairs = []

        # Group by label
        by_label = defaultdict(list)
        for sample in self.samples:
            by_label[sample.label].append(sample)

        labels = list(by_label.keys())

        for label in labels:
            samples = by_label[label]
            other_labels = [l for l in labels if l != label]

            for i, anchor_sample in enumerate(samples):
                # Get positive (same label, different sample)
                positives = [s for j, s in enumerate(samples) if j != i]
                if not positives:
                    continue

                positive_sample = np.random.choice(positives)

                # Get negative (different label)
                if other_labels:
                    neg_label = np.random.choice(other_labels)
                    negative_sample = np.random.choice(by_label[neg_label])

                    pairs.append(
                        EmbeddingPair(
                            anchor=anchor_sample.text,
                            positive=positive_sample.text,
                            negative=negative_sample.text,
                            anchor_label=label,
                        )
                    )

        return pairs

    def export_for_training(self, format: str = "jsonl") -> str:
        """Export dataset in training format."""
        lines = []

        for sample in self.samples:
            record = {"text": sample.text, "label": sample.label, "category": sample.category}

            if format == "jsonl":
                lines.append(json.dumps(record))
            elif format == "csv":
                # Escape quotes in text
                text = sample.text.replace('"', '""')
                lines.append(f'"{text}","{sample.label}","{sample.category}"')

        if format == "csv":
            header = '"text","label","category"'
            return header + "\n" + "\n".join(lines)

        return "\n".join(lines)


class EmbeddingTrainer:
    """Train and fine-tune embeddings for security tasks."""

    def __init__(self, model_name: str = "simulated-embeddings"):
        self.model_name = model_name
        self.embedding_dim = 128
        self.vocab = {}
        self.embeddings = None
        self._initialized = False

    def load_base_model(self):
        """Load the base embedding model (simulated)."""
        # Simulate loading a model with random embeddings
        np.random.seed(42)
        self.embeddings = {}
        self._initialized = True
        print(f"  Loaded simulated embedding model ({self.embedding_dim}d)")

    def _get_word_embedding(self, word: str) -> np.ndarray:
        """Get embedding for a word."""
        word = word.lower()
        if word not in self.embeddings:
            # Create deterministic random embedding based on word hash
            seed = hash(word) % (2**32)
            np.random.seed(seed)
            self.embeddings[word] = np.random.randn(self.embedding_dim)

        return self.embeddings[word]

    def encode(self, texts: List[str]) -> np.ndarray:
        """Encode texts to embeddings."""
        if not self._initialized:
            self.load_base_model()

        result = []
        for text in texts:
            words = text.lower().split()
            if not words:
                result.append(np.zeros(self.embedding_dim))
            else:
                word_embeddings = [self._get_word_embedding(w) for w in words]
                # Average word embeddings
                result.append(np.mean(word_embeddings, axis=0))

        return np.array(result)

    def compute_similarity(self, text1: str, text2: str) -> float:
        """Compute similarity between two texts."""
        embeddings = self.encode([text1, text2])
        e1, e2 = embeddings[0], embeddings[1]

        # Cosine similarity
        norm1 = np.linalg.norm(e1)
        norm2 = np.linalg.norm(e2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(np.dot(e1, e2) / (norm1 * norm2))

    def train_contrastive(
        self, pairs: List[EmbeddingPair], epochs: int = 10, batch_size: int = 32
    ) -> List[float]:
        """Train with contrastive loss (simulated)."""
        if not self._initialized:
            self.load_base_model()

        losses = []
        n = len(pairs)

        for epoch in range(epochs):
            epoch_loss = 0.0
            np.random.shuffle(pairs)

            for i in range(0, n, batch_size):
                batch = pairs[i : i + batch_size]

                for pair in batch:
                    # Encode triplet
                    anchor = self.encode([pair.anchor])[0]
                    positive = self.encode([pair.positive])[0]
                    negative = self.encode([pair.negative])[0]

                    # Triplet loss: max(0, d(a,p) - d(a,n) + margin)
                    margin = 0.5
                    d_pos = np.linalg.norm(anchor - positive)
                    d_neg = np.linalg.norm(anchor - negative)
                    loss = max(0, d_pos - d_neg + margin)
                    epoch_loss += loss

                    # Simulated gradient update
                    if loss > 0:
                        # Move anchor closer to positive
                        direction = (positive - anchor) * 0.01
                        for word in pair.anchor.lower().split():
                            if word in self.embeddings:
                                self.embeddings[word] += direction

            avg_loss = epoch_loss / n
            losses.append(avg_loss)
            print(f"  Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        return losses

    def train_classification(self, samples: List[TrainingSample], epochs: int = 10) -> List[float]:
        """Train for classification task (simulated)."""
        if not self._initialized:
            self.load_base_model()

        # Group by label for contrastive-style training
        by_label = defaultdict(list)
        for sample in samples:
            by_label[sample.label].append(sample.text)

        losses = []
        for epoch in range(epochs):
            epoch_loss = 0.0

            for label, texts in by_label.items():
                if len(texts) < 2:
                    continue

                embeddings = self.encode(texts)

                # Pull same-class embeddings closer
                centroid = np.mean(embeddings, axis=0)
                for emb in embeddings:
                    loss = np.linalg.norm(emb - centroid)
                    epoch_loss += loss

            avg_loss = epoch_loss / len(samples) if samples else 0
            losses.append(avg_loss)

        return losses

    def save_model(self, path: str):
        """Save fine-tuned model."""
        with open(path, "w") as f:
            json.dump(
                {
                    "model_name": self.model_name,
                    "embedding_dim": self.embedding_dim,
                    "embeddings": {k: v.tolist() for k, v in self.embeddings.items()},
                },
                f,
            )

    def load_model(self, path: str):
        """Load fine-tuned model."""
        with open(path, "r") as f:
            data = json.load(f)

        self.model_name = data["model_name"]
        self.embedding_dim = data["embedding_dim"]
        self.embeddings = {k: np.array(v) for k, v in data["embeddings"].items()}
        self._initialized = True


class SecurityModelEvaluator:
    """Evaluate security models comprehensively."""

    def __init__(self, model: EmbeddingTrainer = None):
        self.model = model
        self.results = {}

    def evaluate_classification(
        self, test_samples: List[TrainingSample], predictions: List[str]
    ) -> EvaluationResult:
        """Evaluate classification performance."""
        true_labels = [s.label for s in test_samples]
        labels = list(set(true_labels + predictions))
        n_classes = len(labels)
        label_to_idx = {l: i for i, l in enumerate(labels)}

        # Confusion matrix
        confusion = np.zeros((n_classes, n_classes), dtype=int)
        for true, pred in zip(true_labels, predictions):
            confusion[label_to_idx[true]][label_to_idx[pred]] += 1

        # Overall metrics
        accuracy = np.sum([1 for t, p in zip(true_labels, predictions) if t == p]) / len(
            true_labels
        )

        # Per-class metrics
        per_class = {}
        precisions = []
        recalls = []

        for label in labels:
            idx = label_to_idx[label]
            tp = confusion[idx][idx]
            fp = np.sum(confusion[:, idx]) - tp
            fn = np.sum(confusion[idx, :]) - tp

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            per_class[label] = {
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "support": int(np.sum(confusion[idx, :])),
            }
            precisions.append(precision)
            recalls.append(recall)

        avg_precision = np.mean(precisions)
        avg_recall = np.mean(recalls)
        f1_score = (
            2 * avg_precision * avg_recall / (avg_precision + avg_recall)
            if (avg_precision + avg_recall) > 0
            else 0
        )

        return EvaluationResult(
            accuracy=accuracy,
            precision=avg_precision,
            recall=avg_recall,
            f1_score=f1_score,
            confusion_matrix=confusion,
            per_class_metrics=per_class,
        )

    def evaluate_retrieval(
        self, queries: List[str], relevant_docs: Dict[str, List[str]], k: int = 10
    ) -> dict:
        """Evaluate retrieval performance."""
        if not self.model:
            return {}

        all_docs = list(set(doc for docs in relevant_docs.values() for doc in docs))
        doc_embeddings = self.model.encode(all_docs)

        precisions = []
        recalls = []
        mrrs = []

        for query in queries:
            query_emb = self.model.encode([query])[0]
            relevant = set(relevant_docs.get(query, []))

            if not relevant:
                continue

            # Calculate similarities
            similarities = []
            for i, doc in enumerate(all_docs):
                sim = np.dot(query_emb, doc_embeddings[i]) / (
                    np.linalg.norm(query_emb) * np.linalg.norm(doc_embeddings[i]) + 1e-8
                )
                similarities.append((doc, sim))

            # Sort by similarity
            similarities.sort(key=lambda x: x[1], reverse=True)
            top_k = [doc for doc, _ in similarities[:k]]

            # Precision@k
            relevant_in_k = len(set(top_k) & relevant)
            precisions.append(relevant_in_k / k)

            # Recall@k
            recalls.append(relevant_in_k / len(relevant))

            # MRR
            for i, doc in enumerate(top_k):
                if doc in relevant:
                    mrrs.append(1.0 / (i + 1))
                    break
            else:
                mrrs.append(0.0)

        return {
            f"precision@{k}": np.mean(precisions) if precisions else 0,
            f"recall@{k}": np.mean(recalls) if recalls else 0,
            "mrr": np.mean(mrrs) if mrrs else 0,
        }

    def evaluate_similarity(self, pairs: List[Tuple[str, str, float]]) -> dict:
        """Evaluate similarity predictions."""
        if not self.model:
            return {}

        predicted = []
        actual = []

        for text1, text2, true_sim in pairs:
            pred_sim = self.model.compute_similarity(text1, text2)
            predicted.append(pred_sim)
            actual.append(true_sim)

        predicted = np.array(predicted)
        actual = np.array(actual)

        # Correlation
        correlation = np.corrcoef(predicted, actual)[0, 1]

        # MAE
        mae = np.mean(np.abs(predicted - actual))

        # MSE
        mse = np.mean((predicted - actual) ** 2)

        return {
            "correlation": float(correlation) if not np.isnan(correlation) else 0,
            "mae": float(mae),
            "mse": float(mse),
        }

    def evaluate_security_specific(self, test_samples: List[TrainingSample]) -> dict:
        """Security-specific evaluation metrics."""
        if not test_samples:
            return {}

        # Categorize labels
        malicious_labels = {"malicious", "phishing", "suspicious", "attack"}
        benign_labels = {"benign", "safe", "clean"}

        true_malicious = 0
        true_benign = 0
        detected_malicious = 0
        false_positives = 0
        false_negatives = 0

        for sample in test_samples:
            is_malicious = sample.label.lower() in malicious_labels
            is_benign = sample.label.lower() in benign_labels

            if is_malicious:
                true_malicious += 1
                # Simulate detection (for demo, assume 80% detection rate)
                if np.random.random() < 0.8:
                    detected_malicious += 1
                else:
                    false_negatives += 1
            elif is_benign:
                true_benign += 1
                # Simulate false positive (for demo, assume 5% FPR)
                if np.random.random() < 0.05:
                    false_positives += 1

        fpr = false_positives / true_benign if true_benign > 0 else 0
        fnr = false_negatives / true_malicious if true_malicious > 0 else 0
        detection_rate = detected_malicious / true_malicious if true_malicious > 0 else 0

        return {
            "fpr": fpr,
            "fnr": fnr,
            "detection_rate": detection_rate,
            "total_malicious": true_malicious,
            "total_benign": true_benign,
            "detected": detected_malicious,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }

    def generate_report(self) -> str:
        """Generate comprehensive evaluation report."""
        lines = []
        lines.append("=" * 60)
        lines.append("MODEL EVALUATION REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")

        for metric_name, result in self.results.items():
            lines.append(f"--- {metric_name} ---")
            if isinstance(result, dict):
                for k, v in result.items():
                    if isinstance(v, float):
                        lines.append(f"  {k}: {v:.4f}")
                    else:
                        lines.append(f"  {k}: {v}")
            elif isinstance(result, EvaluationResult):
                lines.append(f"  Accuracy: {result.accuracy:.4f}")
                lines.append(f"  Precision: {result.precision:.4f}")
                lines.append(f"  Recall: {result.recall:.4f}")
                lines.append(f"  F1 Score: {result.f1_score:.4f}")
            lines.append("")

        return "\n".join(lines)

    def compare_models(
        self, models: List[EmbeddingTrainer], test_samples: List[TrainingSample]
    ) -> dict:
        """Compare multiple models."""
        results = {}

        for i, model in enumerate(models):
            self.model = model
            model_name = f"model_{i}"

            # Evaluate each model
            texts = [s.text for s in test_samples]
            embeddings = model.encode(texts)

            # Calculate average embedding quality (cluster tightness)
            by_label = defaultdict(list)
            for j, sample in enumerate(test_samples):
                by_label[sample.label].append(embeddings[j])

            avg_tightness = 0
            for label, embs in by_label.items():
                if len(embs) > 1:
                    centroid = np.mean(embs, axis=0)
                    distances = [np.linalg.norm(e - centroid) for e in embs]
                    avg_tightness += np.mean(distances)

            results[model_name] = {
                "avg_cluster_distance": avg_tightness / len(by_label),
                "embedding_dim": model.embedding_dim,
            }

        return results


def main():
    """Main entry point for Lab 18."""
    print("=" * 60)
    print("Lab 18: Fine-Tuning for Security Applications - Solution")
    print("=" * 60)

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "training_samples.json"), "r") as f:
            data = json.load(f)
        print(f"\nLoaded {len(data.get('samples', []))} training samples")
    except FileNotFoundError:
        print("Sample data not found. Creating demo data.")
        data = {"samples": create_sample_training_data()}

    # Build Dataset
    print("\n--- Building Security Dataset ---")
    builder = SecurityDatasetBuilder()

    for sample in data.get("samples", []):
        builder.add_sample(
            text=sample["text"], label=sample["label"], category=sample.get("category", "general")
        )

    print(f"Added {len(builder.samples)} samples")
    print(f"Label distribution: {dict(builder.label_counts)}")

    # Data Preparation
    print("\n--- Data Preparation ---")
    train_samples, test_samples = builder.create_train_test_split(test_ratio=0.2)
    print(f"Train: {len(train_samples)}, Test: {len(test_samples)}")

    # Create Contrastive Pairs
    print("\n--- Creating Contrastive Pairs ---")
    pairs = builder.create_contrastive_pairs()
    print(f"Created {len(pairs)} contrastive pairs")

    # Train Embeddings
    print("\n--- Training Embeddings ---")
    trainer = EmbeddingTrainer()
    trainer.load_base_model()

    if pairs:
        losses = trainer.train_contrastive(pairs, epochs=5)
        print(f"Final loss: {losses[-1]:.4f}")

    # Test similarity
    print("\n--- Testing Similarity ---")
    test_pairs = [
        ("Phishing email detected with malicious link", "Suspicious email with harmful URL"),
        ("User logged in successfully", "Authentication successful for user"),
        ("Malware detected in system32", "Normal system process running"),
    ]
    for text1, text2 in test_pairs:
        sim = trainer.compute_similarity(text1, text2)
        print(f"  '{text1[:30]}...' vs '{text2[:30]}...': {sim:.3f}")

    # Evaluate Model
    print("\n--- Evaluating Model ---")
    evaluator = SecurityModelEvaluator(trainer)

    # Simulate predictions
    predictions = []
    for sample in test_samples:
        # Simple rule-based prediction for demo
        text_lower = sample.text.lower()
        if any(kw in text_lower for kw in ["malicious", "attack", "threat", "hack"]):
            predictions.append("malicious")
        elif any(kw in text_lower for kw in ["phishing", "urgent", "click here"]):
            predictions.append("phishing")
        elif any(kw in text_lower for kw in ["suspicious", "failed", "unauthorized"]):
            predictions.append("suspicious")
        else:
            predictions.append("benign")

    result = evaluator.evaluate_classification(test_samples, predictions)
    print(f"Accuracy: {result.accuracy:.2%}")
    print(f"Precision: {result.precision:.2%}")
    print(f"Recall: {result.recall:.2%}")
    print(f"F1 Score: {result.f1_score:.2%}")

    # Security-Specific Evaluation
    print("\n--- Security-Specific Evaluation ---")
    security_metrics = evaluator.evaluate_security_specific(test_samples)
    print(f"False Positive Rate: {security_metrics.get('fpr', 0):.2%}")
    print(f"False Negative Rate: {security_metrics.get('fnr', 0):.2%}")
    print(f"Detection Rate: {security_metrics.get('detection_rate', 0):.2%}")

    # Export dataset
    print("\n--- Exporting Dataset ---")
    jsonl_export = builder.export_for_training(format="jsonl")
    print(f"Exported {len(jsonl_export.split(chr(10)))} lines in JSONL format")

    print("\n" + "=" * 60)
    print("Lab 18 Complete!")
    print("=" * 60)


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
            "text": "Malicious file detected: trojan.exe with hash abc123",
            "label": "malicious",
            "category": "alert",
        },
        {
            "text": "Normal software update downloaded from vendor.com",
            "label": "benign",
            "category": "log",
        },
    ]


if __name__ == "__main__":
    main()

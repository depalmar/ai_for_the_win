# Lab 18: Fine-tuning for Security - Solution Walkthrough

## Overview

Learn to fine-tune LLMs for security tasks using LoRA/QLoRA, train security-focused embeddings, and build specialized models for threat detection.

**Time:** 4-6 hours
**Difficulty:** Expert

---

## Task 1: Dataset Preparation

### Building Security Fine-tuning Datasets

```python
import json
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class SecuritySample:
    instruction: str
    input_text: str
    output: str
    category: str  # classification, extraction, analysis, generation
    source: Optional[str] = None

class SecurityDatasetBuilder:
    def __init__(self):
        self.samples = []

    def add_classification_samples(self, texts: list[str],
                                   labels: list[str],
                                   task_description: str):
        """Add classification training samples."""

        for text, label in zip(texts, labels):
            sample = SecuritySample(
                instruction=task_description,
                input_text=text,
                output=label,
                category='classification'
            )
            self.samples.append(sample)

    def add_extraction_samples(self, texts: list[str],
                              extractions: list[dict]):
        """Add IOC/entity extraction samples."""

        instruction = "Extract all indicators of compromise (IOCs) from the following text. Return as JSON with types: ip, domain, hash, email, url."

        for text, extraction in zip(texts, extractions):
            sample = SecuritySample(
                instruction=instruction,
                input_text=text,
                output=json.dumps(extraction),
                category='extraction'
            )
            self.samples.append(sample)

    def add_analysis_samples(self, reports: list[dict]):
        """Add threat analysis samples."""

        instruction = "Analyze the following security alert and provide: 1) Threat assessment, 2) MITRE ATT&CK techniques, 3) Recommended actions."

        for report in reports:
            sample = SecuritySample(
                instruction=instruction,
                input_text=report['alert'],
                output=report['analysis'],
                category='analysis'
            )
            self.samples.append(sample)

    def to_alpaca_format(self) -> list[dict]:
        """Convert to Alpaca instruction format."""

        alpaca_data = []
        for sample in self.samples:
            alpaca_data.append({
                "instruction": sample.instruction,
                "input": sample.input_text,
                "output": sample.output
            })
        return alpaca_data

    def to_chat_format(self) -> list[dict]:
        """Convert to chat/conversation format."""

        chat_data = []
        for sample in self.samples:
            chat_data.append({
                "messages": [
                    {"role": "system", "content": "You are a security analyst assistant."},
                    {"role": "user", "content": f"{sample.instruction}\n\n{sample.input_text}"},
                    {"role": "assistant", "content": sample.output}
                ]
            })
        return chat_data

    def save_dataset(self, filepath: str, format: str = 'alpaca'):
        """Save dataset to file."""

        if format == 'alpaca':
            data = self.to_alpaca_format()
        else:
            data = self.to_chat_format()

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Saved {len(data)} samples to {filepath}")

# Build dataset
builder = SecurityDatasetBuilder()

# Add phishing classification samples
phishing_texts = [
    "Your account has been compromised! Click here to verify: http://evil.com/verify",
    "Meeting notes from yesterday's security review attached.",
    "URGENT: Wire transfer needed immediately. Reply with bank details."
]
phishing_labels = ["phishing", "legitimate", "phishing"]

builder.add_classification_samples(
    phishing_texts,
    phishing_labels,
    "Classify the following email as 'phishing' or 'legitimate':"
)

# Add IOC extraction samples
ioc_texts = [
    "The malware connected to 192.168.1.100 and downloaded payload from evil-domain.com",
]
ioc_extractions = [
    {"ip": ["192.168.1.100"], "domain": ["evil-domain.com"], "hash": [], "url": []}
]

builder.add_extraction_samples(ioc_texts, ioc_extractions)

# Save dataset
builder.save_dataset("security_finetune_data.json", format='alpaca')
```

---

## Task 2: LoRA Fine-tuning

### Efficient Fine-tuning with LoRA

```python
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    TaskType
)
from datasets import Dataset
import torch

class SecurityLoRATrainer:
    def __init__(self, base_model: str = "mistralai/Mistral-7B-v0.1"):
        self.base_model = base_model
        self.tokenizer = None
        self.model = None

    def setup_model(self, load_in_4bit: bool = True):
        """Load base model with optional 4-bit quantization."""

        # Tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model)
        self.tokenizer.pad_token = self.tokenizer.eos_token

        # Model with quantization
        if load_in_4bit:
            from transformers import BitsAndBytesConfig

            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True
            )

            self.model = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                quantization_config=bnb_config,
                device_map="auto",
                trust_remote_code=True
            )

            self.model = prepare_model_for_kbit_training(self.model)
        else:
            self.model = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                torch_dtype=torch.float16,
                device_map="auto"
            )

    def apply_lora(self, r: int = 16, alpha: int = 32,
                   dropout: float = 0.05):
        """Apply LoRA adapter to model."""

        lora_config = LoraConfig(
            r=r,
            lora_alpha=alpha,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
            lora_dropout=dropout,
            bias="none",
            task_type=TaskType.CAUSAL_LM
        )

        self.model = get_peft_model(self.model, lora_config)
        self.model.print_trainable_parameters()

    def prepare_dataset(self, data_path: str) -> Dataset:
        """Prepare dataset for training."""

        with open(data_path, 'r') as f:
            data = json.load(f)

        def format_prompt(sample):
            prompt = f"""### Instruction:
{sample['instruction']}

### Input:
{sample['input']}

### Response:
{sample['output']}"""
            return prompt

        # Tokenize
        def tokenize(sample):
            prompt = format_prompt(sample)
            result = self.tokenizer(
                prompt,
                truncation=True,
                max_length=512,
                padding="max_length"
            )
            result["labels"] = result["input_ids"].copy()
            return result

        dataset = Dataset.from_list(data)
        dataset = dataset.map(tokenize, remove_columns=dataset.column_names)

        return dataset

    def train(self, dataset: Dataset, output_dir: str = "./security-lora",
              epochs: int = 3, batch_size: int = 4):
        """Train LoRA adapter."""

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=4,
            learning_rate=2e-4,
            fp16=True,
            save_strategy="epoch",
            logging_steps=10,
            warmup_ratio=0.03,
            lr_scheduler_type="cosine",
            report_to="none"
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=dataset,
            data_collator=DataCollatorForSeq2Seq(
                self.tokenizer,
                pad_to_multiple_of=8,
                return_tensors="pt",
                padding=True
            )
        )

        trainer.train()
        trainer.save_model(output_dir)

        return output_dir

    def inference(self, instruction: str, input_text: str) -> str:
        """Run inference with fine-tuned model."""

        prompt = f"""### Instruction:
{instruction}

### Input:
{input_text}

### Response:
"""

        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=256,
                temperature=0.7,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )

        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response.split("### Response:")[-1].strip()

# Fine-tune model
trainer = SecurityLoRATrainer("mistralai/Mistral-7B-v0.1")
trainer.setup_model(load_in_4bit=True)
trainer.apply_lora(r=16, alpha=32)

# Prepare and train
dataset = trainer.prepare_dataset("security_finetune_data.json")
trainer.train(dataset, epochs=3)

# Test inference
result = trainer.inference(
    "Classify the following email as 'phishing' or 'legitimate':",
    "Click here to reset your password: http://suspicious-link.com"
)
print(f"Classification: {result}")
```

---

## Task 3: Security Embeddings

### Training Specialized Embedding Models

```python
from sentence_transformers import SentenceTransformer, InputExample, losses
from torch.utils.data import DataLoader

class SecurityEmbeddingTrainer:
    def __init__(self, base_model: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(base_model)

    def prepare_contrastive_pairs(self, data: list[dict]) -> list[InputExample]:
        """Prepare contrastive learning pairs."""

        examples = []

        # Positive pairs: similar security concepts
        for item in data:
            if 'similar' in item:
                examples.append(InputExample(
                    texts=[item['text'], item['similar']],
                    label=1.0
                ))

            # Negative pairs: dissimilar concepts
            if 'dissimilar' in item:
                examples.append(InputExample(
                    texts=[item['text'], item['dissimilar']],
                    label=0.0
                ))

        return examples

    def prepare_triplets(self, data: list[dict]) -> list[InputExample]:
        """Prepare triplet training data (anchor, positive, negative)."""

        examples = []

        for item in data:
            if 'anchor' in item and 'positive' in item and 'negative' in item:
                examples.append(InputExample(
                    texts=[item['anchor'], item['positive'], item['negative']]
                ))

        return examples

    def train_contrastive(self, examples: list[InputExample],
                         output_path: str = "./security-embeddings",
                         epochs: int = 3):
        """Train with contrastive loss."""

        train_dataloader = DataLoader(examples, shuffle=True, batch_size=16)

        train_loss = losses.CosineSimilarityLoss(self.model)

        self.model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            epochs=epochs,
            warmup_steps=100,
            output_path=output_path
        )

        return output_path

    def train_triplet(self, examples: list[InputExample],
                     output_path: str = "./security-embeddings-triplet",
                     epochs: int = 3):
        """Train with triplet loss."""

        train_dataloader = DataLoader(examples, shuffle=True, batch_size=16)

        train_loss = losses.TripletLoss(
            model=self.model,
            distance_metric=losses.TripletDistanceMetric.COSINE,
            triplet_margin=0.5
        )

        self.model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            epochs=epochs,
            warmup_steps=100,
            output_path=output_path
        )

        return output_path

    def evaluate_similarity(self, test_pairs: list[tuple]) -> dict:
        """Evaluate embedding quality on security similarity task."""

        correct = 0
        total = 0

        for text1, text2, expected_similar in test_pairs:
            emb1 = self.model.encode(text1)
            emb2 = self.model.encode(text2)

            # Cosine similarity
            from sklearn.metrics.pairwise import cosine_similarity
            similarity = cosine_similarity([emb1], [emb2])[0][0]

            # Threshold at 0.7
            predicted_similar = similarity > 0.7

            if predicted_similar == expected_similar:
                correct += 1
            total += 1

        return {
            'accuracy': correct / total,
            'total_pairs': total
        }

# Train security embeddings
embedding_trainer = SecurityEmbeddingTrainer()

# Contrastive pairs
contrastive_data = [
    {
        'text': 'Ransomware encrypts files and demands payment',
        'similar': 'Crypto-locker malware holds data hostage for ransom',
        'dissimilar': 'Firewall blocks unauthorized network traffic'
    },
    {
        'text': 'Phishing email tricks users into revealing credentials',
        'similar': 'Social engineering attack to steal login information',
        'dissimilar': 'Vulnerability scanner identifies system weaknesses'
    }
]

examples = embedding_trainer.prepare_contrastive_pairs(contrastive_data)
embedding_trainer.train_contrastive(examples, epochs=2)

# Evaluate
test_pairs = [
    ("SQL injection attack", "Database exploitation via malicious queries", True),
    ("SQL injection attack", "Network packet analysis", False)
]

eval_results = embedding_trainer.evaluate_similarity(test_pairs)
print(f"Embedding Accuracy: {eval_results['accuracy']:.2%}")
```

---

## Task 4: Classification Fine-tuning

### Training Security Classifiers

```python
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    TrainingArguments,
    Trainer
)
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score
import numpy as np

class SecurityClassifierTrainer:
    def __init__(self, model_name: str = "distilbert-base-uncased",
                 num_labels: int = 2):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=num_labels
        )
        self.label_map = {}

    def prepare_dataset(self, texts: list[str], labels: list[str]) -> Dataset:
        """Prepare classification dataset."""

        # Create label mapping
        unique_labels = sorted(set(labels))
        self.label_map = {label: i for i, label in enumerate(unique_labels)}

        # Convert labels to integers
        label_ids = [self.label_map[label] for label in labels]

        # Tokenize
        encodings = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=256,
            return_tensors="pt"
        )

        dataset = Dataset.from_dict({
            'input_ids': encodings['input_ids'],
            'attention_mask': encodings['attention_mask'],
            'labels': label_ids
        })

        return dataset

    def compute_metrics(self, eval_pred):
        """Compute evaluation metrics."""

        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)

        return {
            'accuracy': accuracy_score(labels, predictions),
            'f1': f1_score(labels, predictions, average='weighted')
        }

    def train(self, train_dataset: Dataset, eval_dataset: Dataset = None,
              output_dir: str = "./security-classifier", epochs: int = 3):
        """Train classifier."""

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            warmup_steps=100,
            weight_decay=0.01,
            logging_steps=10,
            eval_strategy="epoch" if eval_dataset else "no",
            save_strategy="epoch",
            load_best_model_at_end=True if eval_dataset else False,
            report_to="none"
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            compute_metrics=self.compute_metrics
        )

        trainer.train()
        trainer.save_model(output_dir)

        return output_dir

    def predict(self, text: str) -> dict:
        """Predict class for single text."""

        inputs = self.tokenizer(
            text,
            truncation=True,
            padding=True,
            return_tensors="pt"
        ).to(self.model.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)[0]

        # Reverse label map
        id_to_label = {v: k for k, v in self.label_map.items()}

        predicted_id = probs.argmax().item()
        return {
            'label': id_to_label[predicted_id],
            'confidence': probs[predicted_id].item(),
            'all_probabilities': {
                id_to_label[i]: probs[i].item()
                for i in range(len(probs))
            }
        }

# Train phishing classifier
classifier = SecurityClassifierTrainer(num_labels=2)

# Sample data
train_texts = [
    "Your account has been suspended. Click to verify.",
    "Meeting reminder for tomorrow at 3pm.",
    "URGENT: Transfer funds immediately!",
    "Project status update attached.",
    # Add more samples
]
train_labels = ["phishing", "legitimate", "phishing", "legitimate"]

# Prepare and train
train_dataset = classifier.prepare_dataset(train_texts, train_labels)
classifier.train(train_dataset, epochs=3)

# Test prediction
result = classifier.predict("Click here to claim your prize!")
print(f"Prediction: {result['label']} ({result['confidence']:.2%})")
```

---

## Task 5: Complete Fine-tuning Pipeline

### Integrated Security Model Training

```python
class SecurityFineTuningPipeline:
    def __init__(self):
        self.dataset_builder = SecurityDatasetBuilder()
        self.lora_trainer = None
        self.embedding_trainer = None
        self.classifier_trainer = None

    def build_comprehensive_dataset(self, raw_data: dict) -> str:
        """Build comprehensive security dataset."""

        # Classification samples
        if 'classification' in raw_data:
            for task_name, task_data in raw_data['classification'].items():
                self.dataset_builder.add_classification_samples(
                    task_data['texts'],
                    task_data['labels'],
                    task_data['instruction']
                )

        # Extraction samples
        if 'extraction' in raw_data:
            self.dataset_builder.add_extraction_samples(
                raw_data['extraction']['texts'],
                raw_data['extraction']['extractions']
            )

        # Analysis samples
        if 'analysis' in raw_data:
            self.dataset_builder.add_analysis_samples(
                raw_data['analysis']
            )

        # Save dataset
        output_path = "comprehensive_security_dataset.json"
        self.dataset_builder.save_dataset(output_path)

        return output_path

    def train_all_models(self, dataset_path: str,
                        output_dir: str = "./security-models") -> dict:
        """Train all security models."""

        results = {}

        # Train LoRA model (if GPU available)
        try:
            print("Training LoRA model...")
            self.lora_trainer = SecurityLoRATrainer()
            self.lora_trainer.setup_model(load_in_4bit=True)
            self.lora_trainer.apply_lora()
            dataset = self.lora_trainer.prepare_dataset(dataset_path)
            results['lora'] = self.lora_trainer.train(
                dataset,
                output_dir=f"{output_dir}/lora"
            )
        except Exception as e:
            results['lora'] = f"Failed: {e}"

        # Train embeddings
        print("Training embeddings...")
        self.embedding_trainer = SecurityEmbeddingTrainer()
        # Would need contrastive pairs
        results['embeddings'] = f"{output_dir}/embeddings"

        # Train classifier
        print("Training classifier...")
        self.classifier_trainer = SecurityClassifierTrainer()
        # Would need labeled data
        results['classifier'] = f"{output_dir}/classifier"

        return results

    def evaluate_pipeline(self, test_data: dict) -> dict:
        """Evaluate all trained models."""

        results = {}

        # Evaluate LoRA model
        if self.lora_trainer:
            lora_results = []
            for sample in test_data.get('generation', []):
                output = self.lora_trainer.inference(
                    sample['instruction'],
                    sample['input']
                )
                lora_results.append({
                    'input': sample['input'][:50],
                    'expected': sample['expected'][:50],
                    'output': output[:50]
                })
            results['lora'] = lora_results

        # Evaluate classifier
        if self.classifier_trainer:
            correct = 0
            for sample in test_data.get('classification', []):
                pred = self.classifier_trainer.predict(sample['text'])
                if pred['label'] == sample['label']:
                    correct += 1
            results['classifier_accuracy'] = correct / len(test_data.get('classification', [1]))

        return results

# Run pipeline
pipeline = SecurityFineTuningPipeline()

# Raw training data
raw_data = {
    'classification': {
        'phishing': {
            'texts': phishing_texts,
            'labels': phishing_labels,
            'instruction': 'Classify as phishing or legitimate'
        }
    },
    'extraction': {
        'texts': ioc_texts,
        'extractions': ioc_extractions
    }
}

# Build dataset
dataset_path = pipeline.build_comprehensive_dataset(raw_data)
print(f"Dataset saved to: {dataset_path}")

# Train models (requires GPU)
# results = pipeline.train_all_models(dataset_path)
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| OOM errors | Use 4-bit quantization, reduce batch size |
| Poor convergence | Adjust learning rate, more epochs |
| Overfitting | Add dropout, use validation set |
| Slow training | Use gradient accumulation |
| Bad generations | Improve dataset quality |

---

## Next Steps

- Add more security-specific datasets
- Implement RLHF for alignment
- Build model evaluation benchmarks
- Add continuous fine-tuning pipeline
- Create model serving infrastructure

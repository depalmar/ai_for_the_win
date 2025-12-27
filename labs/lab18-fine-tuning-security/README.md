# Lab 18: Fine-Tuning Models for Security

## Train Custom Security Models with Domain-Specific Data

```
+-----------------------------------------------------------------------------+
|                    FINE-TUNING PIPELINE FOR SECURITY                         |
+-----------------------------------------------------------------------------+
|                                                                             |
|   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ |
|   │  Security   │    │   Data      │    │   Fine-     │    │   Deploy    │ |
|   │   Data      │--->│   Prep      │--->│   Tuning    │--->│   & Eval    │ |
|   │  Collection │    │   Pipeline  │    │   Training  │    │   Model     │ |
|   └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘ |
|         |                  |                  |                  |          |
|   • Logs              • Cleaning        • LoRA/QLoRA        • Inference    |
|   • Alerts            • Formatting      • Full Fine-tune    • Benchmarks   |
|   • Reports           • Tokenization    • RLHF              • A/B Testing  |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Overview

| Aspect | Details |
|--------|---------|
| **Time** | 6-8 hours |
| **Difficulty** | Expert |
| **Prerequisites** | Labs 01-05, Python, ML fundamentals |
| **Skills** | Fine-tuning, embeddings, model evaluation |

## Learning Objectives

By the end of this lab, you will be able to:

1. **Prepare security datasets** for fine-tuning
2. **Fine-tune embedding models** for security similarity search
3. **Fine-tune LLMs** using LoRA for security tasks
4. **Evaluate fine-tuned models** against baselines
5. **Deploy and serve** custom security models

---

## Part 1: When to Fine-Tune

### Decision Framework

```
                    Do you need fine-tuning?
                              |
            +------------ Is prompt engineering enough? ------------+
            |                                                       |
           YES                                                      NO
            |                                                       |
    Use few-shot prompts                              Do you have labeled data?
                                                              |
                                        +-----------+---------+-----------+
                                        |           |                     |
                                      < 100      100-10K               > 10K
                                     samples     samples              samples
                                        |           |                     |
                                   Use RAG     Fine-tune            Full fine-tune
                                              embeddings             or LoRA
```

### Fine-Tuning Use Cases for Security

| Use Case | Approach | Data Needed |
|----------|----------|-------------|
| **Log classification** | Fine-tune classifier | 1000+ labeled logs |
| **Threat report generation** | LoRA fine-tune LLM | 500+ report examples |
| **IOC extraction** | Fine-tune NER model | 2000+ annotated samples |
| **Malware similarity** | Fine-tune embeddings | 5000+ malware samples |
| **Alert triage** | Fine-tune classifier | 5000+ triaged alerts |

---

## Part 2: Dataset Preparation

### 2.1 Creating Training Data

```python
"""
Prepare security data for fine-tuning
"""
import json
import pandas as pd
from typing import List, Dict
from sklearn.model_selection import train_test_split

class SecurityDatasetBuilder:
    """Build datasets for fine-tuning security models"""

    def __init__(self):
        self.data = []

    def add_log_classification_sample(self,
                                       log_text: str,
                                       label: str,
                                       metadata: dict = None):
        """Add a log classification training sample"""
        self.data.append({
            "text": log_text,
            "label": label,
            "task": "classification",
            "metadata": metadata or {}
        })

    def add_generation_sample(self,
                              prompt: str,
                              completion: str,
                              metadata: dict = None):
        """Add an instruction-following sample"""
        self.data.append({
            "prompt": prompt,
            "completion": completion,
            "task": "generation",
            "metadata": metadata or {}
        })

    def add_ner_sample(self,
                       text: str,
                       entities: List[Dict],
                       metadata: dict = None):
        """Add a Named Entity Recognition sample"""
        self.data.append({
            "text": text,
            "entities": entities,  # [{"start": 0, "end": 10, "label": "IP"}]
            "task": "ner",
            "metadata": metadata or {}
        })

    def export_for_classification(self, output_path: str):
        """Export data in classification format"""
        classification_data = [
            {"text": d["text"], "label": d["label"]}
            for d in self.data if d["task"] == "classification"
        ]

        train, test = train_test_split(classification_data, test_size=0.2)

        with open(f"{output_path}/train.jsonl", 'w') as f:
            for item in train:
                f.write(json.dumps(item) + '\n')

        with open(f"{output_path}/test.jsonl", 'w') as f:
            for item in test:
                f.write(json.dumps(item) + '\n')

        print(f"Exported {len(train)} training, {len(test)} test samples")

    def export_for_instruct_tuning(self, output_path: str):
        """Export data in instruction tuning format"""
        instruct_data = []

        for d in self.data:
            if d["task"] == "generation":
                instruct_data.append({
                    "instruction": d["prompt"],
                    "output": d["completion"]
                })

        train, test = train_test_split(instruct_data, test_size=0.1)

        with open(f"{output_path}/train.jsonl", 'w') as f:
            for item in train:
                f.write(json.dumps(item) + '\n')

        return len(train), len(test)


# Example: Build log classification dataset
def build_log_classification_dataset():
    """Example: Create dataset for log severity classification"""

    builder = SecurityDatasetBuilder()

    # Sample data (in practice, load from your security tools)
    samples = [
        ("Failed password for admin from 192.168.1.100 port 22", "warning"),
        ("Connection closed by 10.0.0.1 [preauth]", "info"),
        ("POSSIBLE BREAK-IN ATTEMPT! from 185.234.72.19", "critical"),
        ("Accepted publickey for deploy from 10.0.0.50", "info"),
        ("Maximum authentication attempts exceeded", "warning"),
        ("reverse mapping checking failed", "warning"),
    ]

    for log, label in samples:
        builder.add_log_classification_sample(log, label)

    builder.export_for_classification("./data/fine-tuning/log-classification")
```

### 2.2 Data Quality Checks

```python
"""
Validate and clean training data
"""

class DataQualityChecker:
    """Check and improve training data quality"""

    def __init__(self, data: List[Dict]):
        self.data = data
        self.issues = []

    def check_duplicates(self) -> int:
        """Find and report duplicate samples"""
        seen = set()
        duplicates = 0

        for item in self.data:
            key = json.dumps(item, sort_keys=True)
            if key in seen:
                duplicates += 1
            seen.add(key)

        if duplicates > 0:
            self.issues.append(f"Found {duplicates} duplicate samples")

        return duplicates

    def check_label_balance(self) -> dict:
        """Check class balance for classification tasks"""
        labels = [d.get("label") for d in self.data if d.get("label")]
        label_counts = pd.Series(labels).value_counts()

        imbalance_ratio = label_counts.max() / label_counts.min()

        if imbalance_ratio > 10:
            self.issues.append(f"Severe class imbalance: {imbalance_ratio:.1f}x")

        return label_counts.to_dict()

    def check_text_length(self, max_length: int = 2048) -> int:
        """Check for samples exceeding max token length"""
        long_samples = 0

        for item in self.data:
            text = item.get("text", "") or item.get("prompt", "")
            # Rough estimate: 1 token ≈ 4 characters
            if len(text) > max_length * 4:
                long_samples += 1

        if long_samples > 0:
            self.issues.append(f"{long_samples} samples exceed max length")

        return long_samples

    def check_sensitive_data(self) -> List[str]:
        """Check for potentially sensitive data that shouldn't be in training"""
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IP (might be intentional)
            r'password\s*[=:]\s*\S+',  # Passwords
            r'api[_-]?key\s*[=:]\s*\S+',  # API keys
        ]

        found = []
        import re

        for item in self.data:
            text = str(item)
            for pattern in sensitive_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    found.append(pattern)
                    break

        return list(set(found))

    def generate_report(self) -> str:
        """Generate data quality report"""
        self.check_duplicates()
        self.check_label_balance()
        self.check_text_length()
        sensitive = self.check_sensitive_data()

        report = f"""
# Data Quality Report

## Summary
- Total samples: {len(self.data)}
- Issues found: {len(self.issues)}

## Issues
{chr(10).join(f'- {issue}' for issue in self.issues) or '- No issues found'}

## Sensitive Data Patterns
{chr(10).join(f'- {p}' for p in sensitive) or '- None detected'}
"""
        return report
```

---

## Part 3: Fine-Tuning Embeddings

### 3.1 Security Embedding Model

```python
"""
Fine-tune embeddings for security similarity search
"""
from sentence_transformers import SentenceTransformer, InputExample, losses
from torch.utils.data import DataLoader

class SecurityEmbeddingTrainer:
    """Fine-tune embedding model for security text"""

    def __init__(self, base_model: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(base_model)

    def prepare_triplets(self, data: List[Dict]) -> List[InputExample]:
        """
        Prepare triplet data for contrastive learning

        Each sample: (anchor, positive, negative)
        - Anchor: A security log/alert
        - Positive: Similar log (same attack type)
        - Negative: Different log (different attack type)
        """
        examples = []

        for item in data:
            examples.append(InputExample(
                texts=[
                    item["anchor"],
                    item["positive"],
                    item["negative"]
                ]
            ))

        return examples

    def prepare_pairs(self, data: List[Dict]) -> List[InputExample]:
        """
        Prepare pair data with similarity scores

        Each sample: (text1, text2, similarity_score)
        """
        examples = []

        for item in data:
            examples.append(InputExample(
                texts=[item["text1"], item["text2"]],
                label=float(item["similarity"])
            ))

        return examples

    def train(self, train_examples: List[InputExample],
              epochs: int = 3,
              batch_size: int = 16,
              output_path: str = "./models/security-embeddings"):
        """Train the embedding model"""

        train_dataloader = DataLoader(
            train_examples,
            shuffle=True,
            batch_size=batch_size
        )

        # Use triplet loss for triplets, cosine similarity for pairs
        train_loss = losses.TripletLoss(model=self.model)

        self.model.fit(
            train_objectives=[(train_dataloader, train_loss)],
            epochs=epochs,
            warmup_steps=100,
            output_path=output_path
        )

        print(f"Model saved to {output_path}")

    def evaluate(self, test_data: List[Dict]) -> dict:
        """Evaluate embedding quality"""
        from sklearn.metrics.pairwise import cosine_similarity

        correct = 0
        total = 0

        for item in test_data:
            anchor_emb = self.model.encode(item["anchor"])
            pos_emb = self.model.encode(item["positive"])
            neg_emb = self.model.encode(item["negative"])

            pos_sim = cosine_similarity([anchor_emb], [pos_emb])[0][0]
            neg_sim = cosine_similarity([anchor_emb], [neg_emb])[0][0]

            if pos_sim > neg_sim:
                correct += 1
            total += 1

        accuracy = correct / total
        return {"triplet_accuracy": accuracy}


# Example usage
def train_security_embeddings():
    """Example: Train embeddings for malware similarity"""

    # Sample triplet data
    triplet_data = [
        {
            "anchor": "Process mimikatz.exe spawned by cmd.exe",
            "positive": "Credential dumping tool executed via command line",
            "negative": "Chrome browser opened new tab"
        },
        {
            "anchor": "PowerShell encoded command execution",
            "positive": "Base64 encoded PowerShell payload detected",
            "negative": "User logged in successfully"
        }
    ]

    trainer = SecurityEmbeddingTrainer()
    examples = trainer.prepare_triplets(triplet_data)
    trainer.train(examples, epochs=3)
```

---

## Part 4: Fine-Tuning LLMs with LoRA

### 4.1 LoRA Setup

```python
"""
Fine-tune LLM with LoRA for security tasks
"""
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
import torch

class SecurityLLMTrainer:
    """Fine-tune LLMs for security analysis using LoRA"""

    def __init__(self,
                 base_model: str = "mistralai/Mistral-7B-Instruct-v0.2",
                 use_4bit: bool = True):
        """
        Initialize trainer

        Args:
            base_model: HuggingFace model ID
            use_4bit: Use 4-bit quantization (QLoRA)
        """
        self.model_id = base_model

        # Quantization config for QLoRA
        if use_4bit:
            from transformers import BitsAndBytesConfig
            self.bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True
            )
        else:
            self.bnb_config = None

        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        self.tokenizer.pad_token = self.tokenizer.eos_token

        # Load model
        self.model = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=self.bnb_config,
            device_map="auto",
            trust_remote_code=True
        )

        if use_4bit:
            self.model = prepare_model_for_kbit_training(self.model)

    def setup_lora(self,
                   r: int = 16,
                   lora_alpha: int = 32,
                   target_modules: list = None):
        """Configure LoRA adapters"""

        if target_modules is None:
            target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"]

        lora_config = LoraConfig(
            r=r,
            lora_alpha=lora_alpha,
            target_modules=target_modules,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM"
        )

        self.model = get_peft_model(self.model, lora_config)
        self.model.print_trainable_parameters()

    def format_training_sample(self, sample: dict) -> str:
        """Format sample for instruction tuning"""
        return f"""### Instruction:
{sample['instruction']}

### Response:
{sample['output']}"""

    def train(self,
              train_dataset,
              output_dir: str = "./models/security-llm-lora",
              epochs: int = 3,
              batch_size: int = 4,
              learning_rate: float = 2e-4):
        """Train the model"""
        from trl import SFTTrainer

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=4,
            learning_rate=learning_rate,
            weight_decay=0.01,
            warmup_ratio=0.03,
            logging_steps=10,
            save_steps=100,
            fp16=True,
            optim="paged_adamw_8bit"
        )

        trainer = SFTTrainer(
            model=self.model,
            train_dataset=train_dataset,
            tokenizer=self.tokenizer,
            args=training_args,
            formatting_func=self.format_training_sample,
            max_seq_length=2048
        )

        trainer.train()
        trainer.save_model(output_dir)

    def generate(self, prompt: str, max_length: int = 512) -> str:
        """Generate response using fine-tuned model"""
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

        outputs = self.model.generate(
            **inputs,
            max_new_tokens=max_length,
            temperature=0.7,
            do_sample=True,
            top_p=0.9
        )

        return self.tokenizer.decode(outputs[0], skip_special_tokens=True)
```

### 4.2 Security-Specific Training Data

```python
"""
Create training data for security LLM fine-tuning
"""

SECURITY_TRAINING_SAMPLES = [
    {
        "instruction": "Analyze this Windows Security event and identify potential threats:\nEvent ID: 4625, Account Name: Administrator, Source IP: 185.234.72.19, Failure Reason: Unknown user name or bad password",
        "output": """## Analysis

**Threat Level:** High

**Summary:** Failed login attempt for Administrator account from external IP address.

**Indicators:**
- Source IP 185.234.72.19 is external (potential attacker)
- Target is privileged Administrator account
- Failure reason suggests password guessing

**MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing

**Recommended Actions:**
1. Block source IP at firewall
2. Check for additional failed attempts from this IP
3. Verify no successful logins followed this attempt
4. Consider implementing account lockout policy"""
    },
    {
        "instruction": "Extract IOCs from this threat report:\nThe malware connects to evil-domain.com on port 443 and downloads additional payloads from 192.168.1.100. File hash: a1b2c3d4e5f6...",
        "output": """## Extracted IOCs

**Domains:**
- evil-domain.com (C2 server)

**IP Addresses:**
- 192.168.1.100 (payload server)

**File Hashes:**
- a1b2c3d4e5f6... (malware sample)

**Network Indicators:**
- Port 443/TCP to evil-domain.com

**Recommended Blocks:**
1. Block evil-domain.com at DNS/proxy
2. Block 192.168.1.100 at firewall
3. Add hash to EDR block list"""
    },
    {
        "instruction": "Write a YARA rule to detect this malware behavior: PowerShell script that downloads and executes content from pastebin",
        "output": """```yara
rule PowerShell_Pastebin_Downloader {
    meta:
        description = "Detects PowerShell downloading from Pastebin"
        author = "Security Team"
        severity = "high"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "Invoke-WebRequest" nocase
        $dl3 = "wget" nocase
        $pb1 = "pastebin.com" nocase
        $pb2 = "paste.ee" nocase
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "iex" nocase

    condition:
        ($ps1 or $ps2) and
        ($dl1 or $dl2 or $dl3) and
        ($pb1 or $pb2) and
        ($exec1 or $exec2)
}
```"""
    }
]
```

---

## Part 5: Evaluation and Deployment

### 5.1 Model Evaluation

```python
"""
Evaluate fine-tuned security models
"""
from sklearn.metrics import classification_report
import numpy as np

class SecurityModelEvaluator:
    """Evaluate fine-tuned models on security tasks"""

    def __init__(self, model, tokenizer=None):
        self.model = model
        self.tokenizer = tokenizer

    def evaluate_classification(self, test_data: List[Dict]) -> dict:
        """Evaluate classification model"""
        predictions = []
        labels = []

        for item in test_data:
            pred = self.model.predict(item["text"])
            predictions.append(pred)
            labels.append(item["label"])

        report = classification_report(labels, predictions, output_dict=True)
        return report

    def evaluate_generation(self, test_data: List[Dict],
                           reference_model=None) -> dict:
        """Evaluate generation quality"""
        from rouge_score import rouge_scorer

        scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'])

        scores = []
        for item in test_data:
            generated = self.model.generate(item["instruction"])
            reference = item["output"]

            score = scorer.score(reference, generated)
            scores.append({
                "rouge1": score["rouge1"].fmeasure,
                "rouge2": score["rouge2"].fmeasure,
                "rougeL": score["rougeL"].fmeasure
            })

        avg_scores = {
            k: np.mean([s[k] for s in scores])
            for k in scores[0].keys()
        }

        return avg_scores

    def security_specific_eval(self, test_data: List[Dict]) -> dict:
        """Security-specific evaluation metrics"""
        results = {
            "ioc_extraction_accuracy": 0,
            "threat_level_accuracy": 0,
            "mitre_mapping_accuracy": 0
        }

        # Implement security-specific evaluations
        # ...

        return results
```

### 5.2 Model Serving

```python
"""
Deploy fine-tuned security models
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Security AI Model Server")

class AnalysisRequest(BaseModel):
    text: str
    task: str = "analyze"  # analyze, classify, extract_iocs

class AnalysisResponse(BaseModel):
    result: str
    confidence: float = None
    model_version: str

# Load model at startup
model = None

@app.on_event("startup")
async def load_model():
    global model
    model = load_fine_tuned_model("./models/security-llm-lora")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    """Analyze security text using fine-tuned model"""
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    result = model.generate(request.text)

    return AnalysisResponse(
        result=result,
        model_version="1.0.0"
    )
```

---

## Exercises

### Exercise 1: Build Log Classification Dataset
Create a dataset of 500+ security logs with severity labels.

### Exercise 2: Fine-tune Embeddings
Train security embeddings and compare to base model on similarity search.

### Exercise 3: LoRA Fine-tuning
Fine-tune an LLM for threat report generation.

### Exercise 4: A/B Testing
Compare fine-tuned model to base model on real security tasks.

---

## Resources

- [PEFT Library](https://github.com/huggingface/peft)
- [Sentence Transformers](https://www.sbert.net/)
- [QLoRA Paper](https://arxiv.org/abs/2305.14314)
- [TRL Library](https://github.com/huggingface/trl)

---

> **Stuck?** See the [Lab 18 Walkthrough](../../docs/walkthroughs/lab18-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 19 - Cloud Security with AI](../lab19-cloud-security-ai/)
# Lab 17: Embeddings & Vectors Explained [Bridge Lab]

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Lab 15

> **Bridge Lab:** This lab explains how vectors and embeddings work before building a RAG system in Lab 42.

Understand how AI "understands" meaning through vector representations.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab17_embeddings_vectors.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand what embeddings are and why they matter
- Create and visualize text embeddings
- Measure similarity between security concepts
- Build a simple semantic search system
- Be prepared for Lab 42 (RAG) and Lab 21 (YARA Generator)

## Prerequisites

- Completed Lab 15 (basic LLM understanding)
- API key for embeddings (OpenAI, Anthropic, or use free sentence-transformers)

## Time Required

⏱️ **45-60 minutes**

---

## 📋 Quick Reference Cheat Sheet

### What Are Embeddings?

```
┌─────────────────────────────────────────────────────────────┐
│                    EMBEDDINGS EXPLAINED                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   TEXT                          VECTOR (numbers)            │
│   ────                          ────────────────            │
│                                                             │
│   "malware"        →    [0.23, -0.45, 0.78, 0.12, ...]     │
│   "virus"          →    [0.21, -0.43, 0.76, 0.14, ...]     │
│   "quarterly report" → [-0.89, 0.34, -0.12, 0.67, ...]     │
│                                                             │
│   Similar meaning = Similar vectors                         │
│   Different meaning = Different vectors                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Concepts at a Glance

| Concept | What It Is | Security Example |
|---------|------------|------------------|
| **Embedding** | Text → Numbers | "phishing" → [0.2, 0.5, -0.3, ...] |
| **Vector** | List of numbers | [0.2, 0.5, -0.3, 0.8] |
| **Dimension** | Length of vector | 384, 768, 1536 common |
| **Similarity** | How close vectors are | cosine similarity (0-1) |
| **Semantic search** | Find by meaning | "credential theft" finds "password stealing" |

### Similarity Scores

```
1.0  = Identical meaning
0.8+ = Very similar (synonyms, same topic)
0.5-0.8 = Related
0.3-0.5 = Loosely related
<0.3 = Unrelated
```

---

## Why This Matters for Security

Embeddings power many modern security tools:

| Use Case | How Embeddings Help |
|----------|---------------------|
| **Threat Intel Search** | Find related IOCs even with different wording |
| **Alert Deduplication** | Group similar alerts automatically |
| **Malware Similarity** | Compare code/behavior semantically |
| **RAG Systems** | Retrieve relevant docs for LLM context |
| **Log Clustering** | Group similar events without rules |

---

## The Problem: Computers Don't Understand Words

Traditional text matching fails for security:

```python
# Exact match fails
"credential theft" == "password stealing"  # False!
"C2 beacon" == "command and control callback"  # False!

# Even contains() fails
"lateral movement" in "attacker pivoted to other hosts"  # False!
```

**Solution**: Convert text to numbers that capture **meaning**.

---

## How Embeddings Work

### Step 1: Text Goes In

```python
text = "The malware establishes persistence via registry run keys"
```

### Step 2: AI Model Processes It

The embedding model:
1. Breaks text into tokens
2. Runs through neural network layers
3. Outputs a fixed-size vector

### Step 3: Vector Comes Out

```python
embedding = [0.023, -0.156, 0.892, ..., 0.445]  # 384-1536 numbers
```

### Step 4: Compare Vectors

```python
similarity = cosine_similarity(embedding1, embedding2)
# Returns 0-1, higher = more similar
```

---

## Visualizing Embeddings

Imagine a 2D space where similar concepts cluster together:

```
                    ATTACK TECHNIQUES
                          │
         Persistence ●    │    ● Credential Access
                     ●    │   ●
              Registry    │  Mimikatz
                          │
    ──────────────────────┼──────────────────────
                          │
         Defense ●        │     ● Data Loss
              ●           │        ●
         AV Bypass        │     Exfiltration
                          │
                    DEFENSIVE CONCEPTS
```

In reality, embeddings have 384-1536 dimensions, but the principle is the same: **similar meanings are nearby**.

---

## Your Task

Build a security-focused embedding system that:
1. Creates embeddings for threat descriptions
2. Finds similar threats by meaning
3. Implements semantic search

### TODOs

1. **TODO 1**: Create embeddings for security text
2. **TODO 2**: Calculate similarity between threats
3. **TODO 3**: Build semantic search function
4. **TODO 4**: Visualize embeddings in 2D
5. **TODO 5**: Find related IOCs

---

## Hints

<details>
<summary>💡 Hint 1: Creating Embeddings</summary>

Using sentence-transformers (free, local):
```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('all-MiniLM-L6-v2')
embedding = model.encode("malware using PowerShell")
```

Using OpenAI:
```python
from openai import OpenAI
client = OpenAI()

response = client.embeddings.create(
    model="text-embedding-3-small",
    input="malware using PowerShell"
)
embedding = response.data[0].embedding
```

</details>

<details>
<summary>💡 Hint 2: Cosine Similarity</summary>

```python
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

# Two embeddings as numpy arrays
similarity = cosine_similarity([emb1], [emb2])[0][0]
print(f"Similarity: {similarity:.3f}")
```

</details>

<details>
<summary>💡 Hint 3: Semantic Search</summary>

```python
def semantic_search(query, documents, model, top_k=3):
    """Find most similar documents to query."""
    query_emb = model.encode(query)
    doc_embs = model.encode(documents)

    similarities = cosine_similarity([query_emb], doc_embs)[0]
    top_indices = np.argsort(similarities)[::-1][:top_k]

    return [(documents[i], similarities[i]) for i in top_indices]
```

</details>

---

## Expected Output

```
🔢 Embeddings & Vectors - Security Semantic Search
===================================================

1. Creating Embeddings
   "Malware using PowerShell for execution"
   → Vector of 384 dimensions
   → First 5 values: [0.023, -0.156, 0.892, 0.234, -0.567]

2. Similarity Comparison
   ─────────────────────────────────────────────────
   "credential theft"    vs "password stealing"     : 0.89 ✅ Very similar!
   "credential theft"    vs "lateral movement"      : 0.45 ~ Related
   "credential theft"    vs "quarterly report"      : 0.12 ✗ Unrelated

3. Semantic Search Demo
   Query: "attacker stealing passwords"
   ─────────────────────────────────────────────────
   1. "Mimikatz used to dump credentials" (0.87)
   2. "Password harvesting via keylogger" (0.82)
   3. "LSASS memory access detected" (0.76)

4. IOC Clustering
   Cluster 1 (C2): beacon.evil.com, c2.malware.net
   Cluster 2 (Phishing): fake-login.com, credential-harvest.com
   Cluster 3 (Malware): trojan.exe hash, backdoor.dll hash

✅ You now understand embeddings! Ready for Lab 42 (RAG).
```

---

## Common Embedding Models

| Model | Dimensions | Speed | Quality | Cost |
|-------|------------|-------|---------|------|
| `all-MiniLM-L6-v2` | 384 | Fast | Good | Free |
| `all-mpnet-base-v2` | 768 | Medium | Better | Free |
| `text-embedding-3-small` | 1536 | Fast | Great | $0.02/1M tokens |
| `text-embedding-3-large` | 3072 | Medium | Best | $0.13/1M tokens |

**Recommendation**: Start with `all-MiniLM-L6-v2` (free, fast, good enough for learning).

---

## Key Takeaways

1. **Embeddings capture meaning** - Similar text → similar vectors
2. **Cosine similarity** - Standard way to compare embeddings (0-1)
3. **Semantic search** - Find by meaning, not exact words
4. **Dimension matters** - More dimensions = more nuance, but slower
5. **Foundation for RAG** - Embeddings power retrieval in RAG systems

---

## What's Next?

Now that you understand embeddings:

- **Lab 42**: Build a full RAG system with ChromaDB
- **Lab 21**: Use embeddings to find similar malware patterns
- **Lab 36**: Use embeddings for threat actor clustering

You've unlocked semantic AI! 🔓

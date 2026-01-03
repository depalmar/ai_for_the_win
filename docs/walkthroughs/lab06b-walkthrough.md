# Lab 06b: Embeddings & Vectors Walkthrough

Step-by-step guide to understanding how AI captures meaning through embeddings.

## Overview

This walkthrough guides you through:
1. Creating text embeddings
2. Calculating similarity between concepts
3. Building semantic search
4. Visualizing high-dimensional data

**Difficulty:** Intermediate
**Time:** 45-60 minutes
**Prerequisites:** Lab 04 (LLM basics)

---

## The Core Problem

Traditional text matching fails for security:

```python
# These are semantically identical, but...
"credential theft" == "password stealing"  # False!
"C2 beacon" == "command and control callback"  # False!
```

**Solution**: Convert text to numbers that capture meaning.

---

## Exercise 1: Creating Embeddings (TODO 1)

### Using sentence-transformers (Free, Local)

```python
from sentence_transformers import SentenceTransformer

# Load model (downloads ~90MB first time)
model = SentenceTransformer('all-MiniLM-L6-v2')

# Create embedding
text = "The malware establishes persistence via registry keys"
embedding = model.encode(text)

print(f"Shape: {embedding.shape}")  # (384,)
print(f"First 5 values: {embedding[:5]}")
# [0.023, -0.156, 0.892, 0.234, -0.567]
```

### Using OpenAI API

```python
from openai import OpenAI

client = OpenAI()

response = client.embeddings.create(
    model="text-embedding-3-small",
    input="The malware establishes persistence via registry keys"
)

embedding = response.data[0].embedding
print(f"Dimensions: {len(embedding)}")  # 1536
```

### Model Comparison

| Model | Dimensions | Speed | Quality | Cost |
|-------|------------|-------|---------|------|
| `all-MiniLM-L6-v2` | 384 | Fast | Good | Free |
| `all-mpnet-base-v2` | 768 | Medium | Better | Free |
| `text-embedding-3-small` | 1536 | Fast | Great | ~$0.02/1M tokens* |
| `text-embedding-3-large` | 3072 | Medium | Best | ~$0.13/1M tokens* |

*API pricing changes frequently - check provider documentation for current rates.*

---

## Exercise 2: Calculating Similarity (TODO 2)

### Cosine Similarity

```python
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

def calculate_similarity(text1: str, text2: str, model) -> float:
    """Calculate semantic similarity between two texts."""
    emb1 = model.encode(text1)
    emb2 = model.encode(text2)

    # Reshape for sklearn
    similarity = cosine_similarity([emb1], [emb2])[0][0]
    return similarity
```

### Testing It

```python
model = SentenceTransformer('all-MiniLM-L6-v2')

# Similar concepts
sim1 = calculate_similarity("credential theft", "password stealing", model)
print(f"credential theft vs password stealing: {sim1:.3f}")  # ~0.85

# Related concepts
sim2 = calculate_similarity("credential theft", "lateral movement", model)
print(f"credential theft vs lateral movement: {sim2:.3f}")  # ~0.45

# Unrelated
sim3 = calculate_similarity("credential theft", "quarterly report", model)
print(f"credential theft vs quarterly report: {sim3:.3f}")  # ~0.15
```

### Similarity Interpretation

> **Note**: Cosine similarity ranges from -1 to 1, but for text embeddings, values are typically 0 to 1 since embeddings tend to have positive values.

```
1.0  = Identical meaning
0.8+ = Very similar (synonyms, same topic)
0.5-0.8 = Related
0.3-0.5 = Loosely related
<0.3 = Unrelated
```

*Thresholds are approximate and vary by model. Always calibrate for your specific use case.*

---

## Exercise 3: Semantic Search (TODO 3)

### Building the Search Function

```python
def semantic_search(query: str, documents: list, model, top_k: int = 3) -> list:
    """Find documents most similar to query by meaning."""
    # Embed query
    query_emb = model.encode(query)

    # Embed all documents
    doc_embs = model.encode(documents)

    # Calculate similarities
    similarities = cosine_similarity([query_emb], doc_embs)[0]

    # Get top-k indices (highest similarity first)
    top_indices = np.argsort(similarities)[::-1][:top_k]

    # Return results with scores
    results = []
    for idx in top_indices:
        results.append({
            "document": documents[idx],
            "score": similarities[idx]
        })

    return results
```

### Security-Focused Example

```python
threat_intel = [
    "Mimikatz used to dump credentials from LSASS memory",
    "Ransomware encrypting files with .locked extension",
    "C2 beacon communicating with evil-c2.com",
    "Password harvesting via keylogger installation",
    "Lateral movement using PsExec to remote hosts",
    "Data exfiltration to cloud storage provider",
]

# Search by meaning, not keywords
results = semantic_search("attacker stealing passwords", threat_intel, model)

for r in results:
    print(f"{r['score']:.3f}: {r['document']}")

# Output:
# 0.87: Mimikatz used to dump credentials from LSASS memory
# 0.82: Password harvesting via keylogger installation
# 0.45: Ransomware encrypting files with .locked extension
```

**Key Insight**: Query was "stealing passwords" but found "dump credentials" and "password harvesting" - semantic match!

---

## Exercise 4: Visualizing Embeddings (TODO 4)

### Reducing Dimensions with t-SNE

```python
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt

def visualize_embeddings(texts: list, labels: list, model):
    """Visualize embeddings in 2D."""
    # Get embeddings
    embeddings = model.encode(texts)

    # Reduce to 2D
    tsne = TSNE(n_components=2, random_state=42, perplexity=min(5, len(texts)-1))
    coords = tsne.fit_transform(embeddings)

    # Plot
    plt.figure(figsize=(10, 8))
    for label in set(labels):
        mask = [l == label for l in labels]
        plt.scatter(
            coords[mask, 0],
            coords[mask, 1],
            label=label,
            alpha=0.7,
            s=100
        )

    # Add text annotations
    for i, text in enumerate(texts):
        plt.annotate(text[:20] + "...", coords[i], fontsize=8)

    plt.legend()
    plt.title("Security Concepts in Embedding Space")
    plt.show()
```

### Security Concept Clustering

```python
security_texts = [
    # Credential attacks
    "Password dumping with Mimikatz",
    "Credential theft from memory",
    "Keylogger capturing passwords",

    # Persistence
    "Registry run key persistence",
    "Scheduled task for persistence",
    "Service installation for backdoor",

    # Lateral movement
    "PsExec lateral movement",
    "WMI remote execution",
    "RDP to internal hosts",
]

labels = ["Credential"] * 3 + ["Persistence"] * 3 + ["Lateral Movement"] * 3

visualize_embeddings(security_texts, labels, model)
```

---

## Exercise 5: IOC Similarity (TODO 5)

### Finding Related IOCs

```python
def find_related_iocs(target_ioc: str, ioc_database: list, model, threshold: float = 0.6) -> list:
    """Find IOCs semantically related to target."""
    target_emb = model.encode(target_ioc)

    related = []
    for ioc in ioc_database:
        ioc_emb = model.encode(ioc["description"])
        sim = cosine_similarity([target_emb], [ioc_emb])[0][0]

        if sim >= threshold:
            related.append({
                "ioc": ioc["value"],
                "type": ioc["type"],
                "similarity": sim
            })

    return sorted(related, key=lambda x: x["similarity"], reverse=True)

# Example IOC database
iocs = [
    {"value": "evil-c2.com", "type": "domain", "description": "C2 server for RAT malware"},
    {"value": "185.143.223.47", "type": "ip", "description": "Command and control callback"},
    {"value": "mimikatz.exe", "type": "file", "description": "Credential dumping tool"},
    {"value": "beacon.dll", "type": "file", "description": "Cobalt Strike beacon payload"},
]

# Find IOCs related to "remote access trojan communication"
related = find_related_iocs("remote access trojan communication", iocs, model)
```

---

## Complete Security Embedding System

```python
class SecurityEmbeddingSystem:
    """Semantic search system for security data."""

    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)
        self.documents = []
        self.embeddings = None

    def add_documents(self, docs: list):
        """Add documents to the index."""
        self.documents.extend(docs)
        self.embeddings = self.model.encode(self.documents)

    def search(self, query: str, top_k: int = 5) -> list:
        """Semantic search."""
        query_emb = self.model.encode(query)
        similarities = cosine_similarity([query_emb], self.embeddings)[0]
        top_indices = np.argsort(similarities)[::-1][:top_k]

        return [
            {"document": self.documents[i], "score": similarities[i]}
            for i in top_indices
        ]

    def find_similar(self, doc_index: int, top_k: int = 5) -> list:
        """Find documents similar to a specific document."""
        similarities = cosine_similarity(
            [self.embeddings[doc_index]],
            self.embeddings
        )[0]

        # Exclude self
        top_indices = np.argsort(similarities)[::-1][1:top_k+1]

        return [
            {"document": self.documents[i], "score": similarities[i]}
            for i in top_indices
        ]

    def cluster_similar(self, threshold: float = 0.7) -> list:
        """Group similar documents."""
        from collections import defaultdict

        clusters = defaultdict(list)
        assigned = set()

        for i, doc in enumerate(self.documents):
            if i in assigned:
                continue

            cluster_id = len(clusters)
            clusters[cluster_id].append(doc)
            assigned.add(i)

            # Find similar docs
            sims = cosine_similarity([self.embeddings[i]], self.embeddings)[0]
            for j, sim in enumerate(sims):
                if j != i and j not in assigned and sim >= threshold:
                    clusters[cluster_id].append(self.documents[j])
                    assigned.add(j)

        return list(clusters.values())
```

---

## Common Errors

### 1. Wrong Embedding Dimension

```python
# Problem: Comparing embeddings from different models
emb1 = model_a.encode("text")  # 384 dim
emb2 = model_b.encode("text")  # 1536 dim
cosine_similarity([emb1], [emb2])  # Error!

# Solution: Use same model for all embeddings
emb1 = model.encode("text1")
emb2 = model.encode("text2")
```

### 2. Not Normalizing for Batch

```python
# Problem: Single embedding vs batch
query = model.encode("query")  # Shape: (384,)
docs = model.encode(["doc1", "doc2"])  # Shape: (2, 384)
cosine_similarity(query, docs)  # Error!

# Solution: Reshape query
cosine_similarity([query], docs)  # Works!
```

### 3. Expecting Exact Matches

```python
# Problem: Thinking similarity = 1.0 means identical
# Even identical strings rarely get 1.0 due to floating point

# Solution: Use threshold
if similarity > 0.95:
    print("Essentially identical")
```

---

## Key Takeaways

1. **Embeddings capture meaning** - Similar text → similar vectors
2. **Cosine similarity** - Standard comparison (0-1)
3. **Semantic search** - Find by meaning, not keywords
4. **Dimension trade-offs** - More dims = more nuance but slower
5. **Foundation for RAG** - Embeddings power retrieval

---

## Next Steps

Now that you understand embeddings:

- **Lab 06**: Build a full RAG system with ChromaDB
- **Lab 07**: Use embeddings to find similar malware
- **Lab 16**: Cluster threat actors by TTP similarity

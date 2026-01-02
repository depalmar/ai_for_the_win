# Embeddings and Vector Databases Guide

Understanding the foundation of semantic search and RAG for security applications.

---

## Table of Contents

1. [What Are Embeddings?](#what-are-embeddings)
2. [Creating Embeddings](#creating-embeddings)
3. [Vector Databases](#vector-databases)
4. [Similarity Search](#similarity-search)
5. [Security Applications](#security-applications)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## What Are Embeddings?

### The Concept

Embeddings convert text (or other data) into numerical vectors that capture semantic meaning:

```
Text: "malware detected on server"
     ↓ Embedding Model
Vector: [0.23, -0.45, 0.12, ..., 0.67]  (768-1536 dimensions)

Similar meaning → Similar vectors
Different meaning → Different vectors
```

### Why They Matter for Security

| Use Case      | Without Embeddings       | With Embeddings                      |
| ------------- | ------------------------ | ------------------------------------ |
| Log search    | Exact keyword match only | Find semantically similar logs       |
| Threat intel  | Manual IOC lookup        | Find related threats by behavior     |
| Documentation | Keyword search           | Natural language Q&A                 |
| Alert triage  | Rule-based grouping      | Cluster similar alerts automatically |

### Visual Intuition

```
                    ↑ "malicious"
                    │
     "ransomware" ● │ ● "cryptolocker"
                    │
  "phishing" ●      │      ● "credential theft"
                    │
─────────────●──────┼────────────────→ "network"
       "firewall"   │
                    │
     "backup" ●     │     ● "disaster recovery"
                    │
                    ↓ "legitimate"

Similar concepts cluster together in vector space
```

---

## Creating Embeddings

### Using sentence-transformers (Local, Free)

```python
from sentence_transformers import SentenceTransformer

# Load a security-friendly model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Create embeddings
texts = [
    "Suspicious login attempt from unknown IP",
    "Failed authentication for user admin",
    "Successful file download from SharePoint",
    "Malware signature detected in attachment"
]

embeddings = model.encode(texts)

print(f"Shape: {embeddings.shape}")  # (4, 384)
print(f"First embedding: {embeddings[0][:5]}...")  # [0.23, -0.12, ...]
```

### Using OpenAI Embeddings

```python
from openai import OpenAI

client = OpenAI()

def get_embedding(text: str, model: str = "text-embedding-3-small") -> list:
    """Get embedding from OpenAI."""
    response = client.embeddings.create(
        model=model,
        input=text
    )
    return response.data[0].embedding

# Create embeddings
embedding = get_embedding("Suspicious network traffic detected")
print(f"Dimensions: {len(embedding)}")  # 1536
```

### Using Anthropic (via Voyage AI)

```python
import voyageai

vo = voyageai.Client()

def get_voyage_embedding(texts: list) -> list:
    """Get embeddings from Voyage AI (recommended for Claude users)."""
    result = vo.embed(
        texts,
        model="voyage-2",
        input_type="document"
    )
    return result.embeddings

embeddings = get_voyage_embedding([
    "Ransomware encrypted 500 files",
    "Malware encrypted user documents"
])
```

### Choosing an Embedding Model

| Model                  | Dimensions | Speed  | Quality   | Cost     |
| ---------------------- | ---------- | ------ | --------- | -------- |
| all-MiniLM-L6-v2       | 384        | Fast   | Good      | Free     |
| all-mpnet-base-v2      | 768        | Medium | Better    | Free     |
| text-embedding-3-small | 1536       | API    | Very Good | $0.02/1M |
| text-embedding-3-large | 3072       | API    | Excellent | $0.13/1M |
| voyage-2               | 1024       | API    | Excellent | $0.10/1M |

**Recommendation for security**: Start with `all-MiniLM-L6-v2` (free, local), upgrade to API models if needed.

---

## Vector Databases

### ChromaDB (Recommended for Learning)

```python
import chromadb
from chromadb.utils import embedding_functions

# Initialize ChromaDB
client = chromadb.Client()  # In-memory
# client = chromadb.PersistentClient(path="./chroma_db")  # Persistent

# Use sentence-transformers for embeddings
embedding_func = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# Create a collection
collection = client.create_collection(
    name="security_logs",
    embedding_function=embedding_func
)

# Add documents
collection.add(
    documents=[
        "Failed login attempt for root from 192.168.1.100",
        "Successful sudo command by admin user",
        "SSH brute force attack detected from 10.0.0.50",
        "Firewall blocked outbound connection to known C2 IP"
    ],
    metadatas=[
        {"severity": "high", "type": "auth"},
        {"severity": "low", "type": "auth"},
        {"severity": "critical", "type": "attack"},
        {"severity": "high", "type": "network"}
    ],
    ids=["log1", "log2", "log3", "log4"]
)
```

### Querying ChromaDB

```python
# Semantic search
results = collection.query(
    query_texts=["authentication failure"],
    n_results=3
)

print("Similar logs:")
for doc, metadata, distance in zip(
    results['documents'][0],
    results['metadatas'][0],
    results['distances'][0]
):
    print(f"  [{metadata['severity']}] {doc}")
    print(f"    Distance: {distance:.4f}")
```

### Filtering with Metadata

```python
# Find high-severity auth events
results = collection.query(
    query_texts=["suspicious activity"],
    n_results=5,
    where={
        "$and": [
            {"severity": {"$in": ["high", "critical"]}},
            {"type": "auth"}
        ]
    }
)
```

### Other Vector Databases

```python
# FAISS (Facebook AI Similarity Search) - Fast, local
import faiss
import numpy as np

# Create index
dimension = 384  # Must match embedding dimension
index = faiss.IndexFlatL2(dimension)

# Add vectors
vectors = np.array(embeddings).astype('float32')
index.add(vectors)

# Search
query_vector = model.encode(["login failure"]).astype('float32')
distances, indices = index.search(query_vector, k=3)

# Pinecone - Cloud, scalable
import pinecone

pinecone.init(api_key="your-key", environment="us-west1-gcp")
index = pinecone.Index("security-logs")

index.upsert(
    vectors=[
        ("log1", embedding1, {"severity": "high"}),
        ("log2", embedding2, {"severity": "low"})
    ]
)

results = index.query(query_vector, top_k=5, include_metadata=True)
```

---

## Similarity Search

### Distance Metrics

```python
import numpy as np
from scipy.spatial.distance import cosine, euclidean

def compare_embeddings(emb1, emb2):
    """Compare two embeddings using different metrics."""

    # Cosine similarity (most common for text)
    # Range: -1 to 1, higher = more similar
    cos_sim = 1 - cosine(emb1, emb2)

    # Euclidean distance
    # Range: 0 to inf, lower = more similar
    euc_dist = euclidean(emb1, emb2)

    # Dot product
    # Range: varies, higher = more similar (for normalized vectors)
    dot_prod = np.dot(emb1, emb2)

    return {
        "cosine_similarity": cos_sim,
        "euclidean_distance": euc_dist,
        "dot_product": dot_prod
    }

# Example
emb_malware = model.encode(["ransomware encrypted files"])
emb_attack = model.encode(["cryptolocker attack detected"])
emb_backup = model.encode(["scheduled backup completed"])

print("Malware vs Attack:", compare_embeddings(emb_malware[0], emb_attack[0]))
print("Malware vs Backup:", compare_embeddings(emb_malware[0], emb_backup[0]))
```

### Similarity Threshold

```python
def find_similar(query: str, collection, threshold: float = 0.7) -> list:
    """Find documents above similarity threshold."""

    results = collection.query(
        query_texts=[query],
        n_results=100  # Get many, filter by threshold
    )

    similar = []
    for doc, distance in zip(results['documents'][0], results['distances'][0]):
        # ChromaDB uses L2 distance, convert to similarity
        similarity = 1 / (1 + distance)

        if similarity >= threshold:
            similar.append({
                "document": doc,
                "similarity": similarity
            })

    return similar
```

### Batch Similarity

```python
def find_all_similar_pairs(embeddings: np.ndarray, threshold: float = 0.9) -> list:
    """Find all pairs above similarity threshold."""

    from sklearn.metrics.pairwise import cosine_similarity

    # Compute all pairwise similarities
    sim_matrix = cosine_similarity(embeddings)

    pairs = []
    n = len(embeddings)

    for i in range(n):
        for j in range(i + 1, n):
            if sim_matrix[i, j] >= threshold:
                pairs.append({
                    "indices": (i, j),
                    "similarity": sim_matrix[i, j]
                })

    return pairs
```

---

## Security Applications

### 1. Log Clustering

```python
from sklearn.cluster import KMeans
import numpy as np

def cluster_logs(logs: list, n_clusters: int = 5) -> dict:
    """Cluster similar logs together."""

    # Generate embeddings
    embeddings = model.encode(logs)

    # Cluster
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    labels = kmeans.fit_predict(embeddings)

    # Group by cluster
    clusters = {}
    for i, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(logs[i])

    return clusters

# Example usage
logs = [
    "Failed SSH login for root",
    "Failed SSH login for admin",
    "File downloaded from external IP",
    "Large file upload detected",
    "Malware signature found",
    "Virus detected in email attachment"
]

clusters = cluster_logs(logs, n_clusters=3)
for cluster_id, cluster_logs in clusters.items():
    print(f"\nCluster {cluster_id}:")
    for log in cluster_logs:
        print(f"  - {log}")
```

### 2. Threat Intel Matching

```python
class ThreatIntelMatcher:
    """Match alerts against threat intelligence using embeddings."""

    def __init__(self):
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.client = chromadb.Client()
        self.collection = self.client.create_collection("threat_intel")

    def load_threat_intel(self, reports: list):
        """Load threat intelligence reports."""
        for i, report in enumerate(reports):
            self.collection.add(
                documents=[report["description"]],
                metadatas=[{
                    "threat_actor": report.get("actor", "Unknown"),
                    "malware_family": report.get("malware", "Unknown"),
                    "tactics": ",".join(report.get("tactics", []))
                }],
                ids=[f"intel_{i}"]
            )

    def match_alert(self, alert_text: str, top_k: int = 3) -> list:
        """Find matching threat intelligence for an alert."""
        results = self.collection.query(
            query_texts=[alert_text],
            n_results=top_k
        )

        matches = []
        for doc, meta, dist in zip(
            results['documents'][0],
            results['metadatas'][0],
            results['distances'][0]
        ):
            matches.append({
                "description": doc,
                "threat_actor": meta["threat_actor"],
                "malware_family": meta["malware_family"],
                "similarity": 1 / (1 + dist)
            })

        return matches
```

### 3. RAG for Security Documentation

```python
class SecurityRAG:
    """RAG system for security documentation Q&A."""

    def __init__(self, llm_client):
        self.llm = llm_client
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.client = chromadb.PersistentClient(path="./security_docs")
        self.collection = self.client.get_or_create_collection("docs")

    def index_documents(self, documents: list):
        """Index security documents."""
        for i, doc in enumerate(documents):
            # Chunk large documents
            chunks = self._chunk_text(doc["content"])

            for j, chunk in enumerate(chunks):
                self.collection.add(
                    documents=[chunk],
                    metadatas=[{
                        "source": doc["source"],
                        "title": doc["title"],
                        "chunk": j
                    }],
                    ids=[f"doc_{i}_chunk_{j}"]
                )

    def _chunk_text(self, text: str, chunk_size: int = 500) -> list:
        """Split text into chunks."""
        words = text.split()
        chunks = []

        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i + chunk_size])
            chunks.append(chunk)

        return chunks

    def query(self, question: str) -> str:
        """Answer question using RAG."""

        # Retrieve relevant chunks
        results = self.collection.query(
            query_texts=[question],
            n_results=5
        )

        context = "\n\n".join(results['documents'][0])

        # Generate answer
        prompt = f"""Based on the following security documentation, answer the question.

Documentation:
{context}

Question: {question}

Answer:"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text
```

### 4. Alert Deduplication

```python
def deduplicate_alerts(alerts: list, similarity_threshold: float = 0.85) -> list:
    """Remove duplicate/similar alerts."""

    if not alerts:
        return []

    # Generate embeddings
    texts = [a["message"] for a in alerts]
    embeddings = model.encode(texts)

    # Track which alerts to keep
    keep = [True] * len(alerts)

    for i in range(len(alerts)):
        if not keep[i]:
            continue

        for j in range(i + 1, len(alerts)):
            if not keep[j]:
                continue

            # Calculate similarity
            sim = 1 - cosine(embeddings[i], embeddings[j])

            if sim >= similarity_threshold:
                # Keep the one with higher severity
                if alerts[i].get("severity", 0) >= alerts[j].get("severity", 0):
                    keep[j] = False
                else:
                    keep[i] = False
                    break

    return [a for i, a in enumerate(alerts) if keep[i]]
```

---

## Best Practices

### 1. Preprocessing Text

```python
import re

def preprocess_for_embedding(text: str) -> str:
    """Clean text before embedding."""

    # Normalize whitespace
    text = " ".join(text.split())

    # Remove excessive special characters
    text = re.sub(r'[^\w\s\-\.@:/]', '', text)

    # Truncate to reasonable length (most models have limits)
    max_tokens = 512
    words = text.split()
    if len(words) > max_tokens:
        text = " ".join(words[:max_tokens])

    return text
```

### 2. Chunking Strategy

```python
def smart_chunk(text: str, chunk_size: int = 500, overlap: int = 50) -> list:
    """Chunk text with overlap for better context."""

    sentences = text.replace('\n', ' ').split('. ')
    chunks = []
    current_chunk = []
    current_size = 0

    for sentence in sentences:
        words = sentence.split()

        if current_size + len(words) > chunk_size:
            # Save current chunk
            chunks.append(". ".join(current_chunk) + ".")

            # Keep some overlap
            overlap_sentences = []
            overlap_size = 0
            for s in reversed(current_chunk):
                if overlap_size + len(s.split()) <= overlap:
                    overlap_sentences.insert(0, s)
                    overlap_size += len(s.split())
                else:
                    break

            current_chunk = overlap_sentences
            current_size = overlap_size

        current_chunk.append(sentence)
        current_size += len(words)

    if current_chunk:
        chunks.append(". ".join(current_chunk) + ".")

    return chunks
```

### 3. Caching Embeddings

```python
import hashlib
import pickle
from pathlib import Path

class EmbeddingCache:
    """Cache embeddings to avoid recomputation."""

    def __init__(self, cache_dir: str = ".embedding_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def _get_cache_path(self, text: str) -> Path:
        text_hash = hashlib.md5(text.encode()).hexdigest()
        return self.cache_dir / f"{text_hash}.pkl"

    def get_embedding(self, text: str) -> np.ndarray:
        cache_path = self._get_cache_path(text)

        if cache_path.exists():
            with open(cache_path, 'rb') as f:
                return pickle.load(f)

        embedding = self.model.encode([text])[0]

        with open(cache_path, 'wb') as f:
            pickle.dump(embedding, f)

        return embedding
```

### 4. Monitoring Embedding Quality

```python
def evaluate_embedding_quality(test_pairs: list) -> dict:
    """Evaluate if embeddings capture semantic similarity correctly."""

    correct = 0
    total = len(test_pairs)

    for pair in test_pairs:
        text1, text2, expected_similar = pair

        emb1 = model.encode([text1])[0]
        emb2 = model.encode([text2])[0]

        similarity = 1 - cosine(emb1, emb2)

        # Expected similar pairs should have high similarity
        # Expected dissimilar pairs should have low similarity
        if expected_similar and similarity > 0.7:
            correct += 1
        elif not expected_similar and similarity < 0.5:
            correct += 1

    return {
        "accuracy": correct / total,
        "total_pairs": total
    }

# Test pairs: (text1, text2, should_be_similar)
test_pairs = [
    ("malware detected", "virus found", True),
    ("login failed", "authentication error", True),
    ("malware detected", "backup completed", False),
    ("SSH attack", "database query", False),
]
```

---

## Troubleshooting

### Common Issues

| Problem                 | Cause                     | Solution                               |
| ----------------------- | ------------------------- | -------------------------------------- |
| Poor similarity results | Model mismatch            | Use domain-specific model or fine-tune |
| Slow embedding          | Large batch               | Use batching, GPU, or caching          |
| Out of memory           | Too many vectors          | Use disk-based index (FAISS, Pinecone) |
| Inconsistent results    | Preprocessing differences | Standardize preprocessing              |

### Debugging Similarity Issues

```python
def debug_similarity(text1: str, text2: str):
    """Debug why two texts have unexpected similarity."""

    emb1 = model.encode([text1])[0]
    emb2 = model.encode([text2])[0]

    similarity = 1 - cosine(emb1, emb2)

    print(f"Text 1: {text1}")
    print(f"Text 2: {text2}")
    print(f"Similarity: {similarity:.4f}")

    # Find which dimensions contribute most to similarity
    diff = emb1 - emb2
    top_dims = np.argsort(np.abs(diff))[-10:]

    print(f"Top differing dimensions: {top_dims}")
    print(f"Dimension values:")
    for dim in top_dims:
        print(f"  Dim {dim}: {emb1[dim]:.4f} vs {emb2[dim]:.4f}")
```

### Performance Optimization

```python
# Batch processing for speed
def batch_embed(texts: list, batch_size: int = 32) -> np.ndarray:
    """Embed texts in batches for efficiency."""

    all_embeddings = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        embeddings = model.encode(batch, show_progress_bar=False)
        all_embeddings.append(embeddings)

    return np.vstack(all_embeddings)

# Use GPU if available
model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')

# Reduce dimensionality for faster search
from sklearn.decomposition import PCA

pca = PCA(n_components=128)
reduced_embeddings = pca.fit_transform(embeddings)
```

---

## Quick Reference

### Embedding Workflow

```
1. Preprocess text → Clean, normalize, chunk
2. Generate embedding → model.encode(text)
3. Store in vector DB → collection.add(...)
4. Query → collection.query(query_texts=[...])
5. Use results → Pass to LLM for RAG, clustering, etc.
```

### Key Code Snippets

```python
# Quick setup
from sentence_transformers import SentenceTransformer
import chromadb

model = SentenceTransformer('all-MiniLM-L6-v2')
client = chromadb.Client()
collection = client.create_collection("my_collection")

# Add documents
collection.add(documents=texts, ids=ids)

# Search
results = collection.query(query_texts=["search query"], n_results=5)
```

---

## Next Steps

| If you want to...           | Go to...                                                    |
| --------------------------- | ----------------------------------------------------------- |
| Build a RAG system          | [Lab 06](../../labs/lab06-security-rag/)                    |
| Parse LLM outputs           | [Structured Output Guide](./structured-output-parsing.md)   |
| Test your system            | [LLM Evaluation Guide](./llm-evaluation-testing.md)         |
| Understand vectors visually | [Lab 02 - Clustering](../../labs/lab02-malware-clustering/) |

---

_Last updated: January 2025_

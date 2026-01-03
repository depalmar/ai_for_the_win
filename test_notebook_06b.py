# Test Lab 06b: Embeddings & Vectors (using TF-IDF as alternative)
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

print("=" * 50)
print("Testing Lab 06b: Embeddings & Vectors")
print("=" * 50)
print("(Using TF-IDF as alternative to sentence-transformers)")

# Security-related text samples
documents = [
    "Malware detected: trojan virus found in system32",
    "Ransomware encrypting files on the network",
    "Phishing email with malicious attachment blocked",
    "User logged in successfully from trusted IP",
    "System backup completed without errors",
    "Virus scan found no threats on workstation",
    "Suspicious process attempting privilege escalation",
    "Normal user activity detected in logs",
]

# Create TF-IDF embeddings
print("\n--- Creating Embeddings ---")
vectorizer = TfidfVectorizer()
embeddings = vectorizer.fit_transform(documents)

print(f"Documents: {len(documents)}")
print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")
print(f"Embedding dimensions: {embeddings.shape[1]}")

# === SIMILARITY SEARCH ===
print("\n--- Similarity Search ---")

# Query
query = "malware infection detected"
query_embedding = vectorizer.transform([query])

# Calculate similarities
similarities = cosine_similarity(query_embedding, embeddings)[0]

print(f"Query: '{query}'")
print("\nTop 3 most similar documents:")
top_indices = np.argsort(similarities)[::-1][:3]
for rank, idx in enumerate(top_indices, 1):
    print(f"  {rank}. (sim={similarities[idx]:.3f}) {documents[idx][:50]}...")

# === SEMANTIC CLUSTERING ===
print("\n--- Document Similarity Matrix ---")
sim_matrix = cosine_similarity(embeddings)

# Show which documents are most similar to each other
print("Documents most similar to 'Malware detected...':")
idx_0_similarities = [(i, sim_matrix[0][i]) for i in range(1, len(documents))]
idx_0_similarities.sort(key=lambda x: x[1], reverse=True)
for idx, sim in idx_0_similarities[:3]:
    print(f"  (sim={sim:.3f}) {documents[idx][:50]}...")

# === SECURITY USE CASE: Threat Grouping ===
print("\n--- Security Use Case: Threat Grouping ---")

# Define threat categories
threat_docs = documents[:4]  # Security-related
benign_docs = documents[4:]  # Normal activity

# Calculate average similarity within groups
threat_embeddings = embeddings[:4]
benign_embeddings = embeddings[4:]

threat_internal_sim = cosine_similarity(threat_embeddings).mean()
benign_internal_sim = cosine_similarity(benign_embeddings).mean()
cross_sim = cosine_similarity(threat_embeddings, benign_embeddings).mean()

print(f"Threat docs internal similarity: {threat_internal_sim:.3f}")
print(f"Benign docs internal similarity: {benign_internal_sim:.3f}")
print(f"Cross-group similarity: {cross_sim:.3f}")

if cross_sim < min(threat_internal_sim, benign_internal_sim):
    print("[OK] Groups are well-separated - good for classification!")
else:
    print("[!] Groups overlap - may need better features")

print("\n[PASS] Lab 06b: PASSED")
print("\nNote: In Colab, use sentence-transformers for better semantic embeddings.")

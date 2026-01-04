"""
Lab 06a: Embeddings & Vectors Explained (Solution)

A complete semantic search system for security applications.
"""

import numpy as np
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from sentence_transformers import SentenceTransformer

    HAVE_TRANSFORMERS = True
except ImportError:
    HAVE_TRANSFORMERS = False


# Security documents for testing (required by tests)
SECURITY_DOCUMENTS = [
    "Malware detected: Trojan.GenericKD virus found in system32 folder",
    "Successful login from authorized user at normal business hours",
    "Ransomware attack encrypting files with .locked extension",
    "Normal system update completed successfully",
    "Phishing email detected with malicious attachment",
    "User accessed approved cloud storage service",
    "Command and control beacon detected calling external server",
    "Routine backup operation completed without errors",
    "Credential dumping tool Mimikatz detected in memory",
    "Standard antivirus scan completed with no threats found",
]


THREAT_DESCRIPTIONS = [
    "Malware using PowerShell for command execution",
    "Attacker dumped credentials using Mimikatz",
    "Ransomware encrypting files with AES-256",
    "C2 beacon communicating over HTTPS",
    "Lateral movement via PsExec to domain controller",
    "Phishing email with malicious macro attachment",
    "Data exfiltration to cloud storage service",
    "Keylogger capturing user credentials",
    "Rootkit hiding processes from task manager",
    "SQL injection attack on login form",
]

IOC_SAMPLES = [
    {"type": "domain", "value": "evil-c2.com", "description": "Command and control server"},
    {"type": "domain", "value": "phish-login.net", "description": "Credential harvesting site"},
    {"type": "hash", "value": "abc123def456", "description": "Ransomware payload"},
    {"type": "hash", "value": "789xyz000aaa", "description": "Credential stealer trojan"},
    {"type": "ip", "value": "192.168.1.100", "description": "Internal pivot point"},
    {"type": "ip", "value": "45.33.32.156", "description": "External C2 IP"},
]


def create_tfidf_embeddings(documents: list) -> tuple:
    """Create TF-IDF embeddings for documents.

    Args:
        documents: List of document strings

    Returns:
        Tuple of (vectorizer, embeddings matrix)
    """
    vectorizer = TfidfVectorizer(stop_words="english")
    embeddings = vectorizer.fit_transform(documents)
    return vectorizer, embeddings.toarray()


def calculate_similarity_matrix(embeddings: np.ndarray) -> np.ndarray:
    """Calculate pairwise cosine similarity matrix.

    Args:
        embeddings: Document embeddings matrix

    Returns:
        Similarity matrix
    """
    return cosine_similarity(embeddings)


def similarity_search(
    query: str, vectorizer: TfidfVectorizer, embeddings: np.ndarray, documents: list, top_k: int = 5
) -> list:
    """Search for similar documents using TF-IDF.

    Args:
        query: Search query string
        vectorizer: Fitted TF-IDF vectorizer
        embeddings: Document embeddings
        documents: Original documents
        top_k: Number of results to return

    Returns:
        List of (index, similarity, document) tuples
    """
    query_vec = vectorizer.transform([query]).toarray()
    similarities = cosine_similarity(query_vec, embeddings)[0]

    # Get top k indices
    top_indices = np.argsort(similarities)[::-1][:top_k]

    results = []
    for idx in top_indices:
        results.append((idx, similarities[idx], documents[idx]))

    return results


def create_embedding(text: str, model) -> np.ndarray:
    """Create an embedding vector for the given text."""
    return model.encode(text)


def create_embeddings_batch(texts: list, model) -> np.ndarray:
    """Create embeddings for multiple texts at once."""
    return model.encode(texts)


def calculate_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """Calculate cosine similarity between two embeddings."""
    return cosine_similarity([emb1], [emb2])[0][0]


def compare_texts(text1: str, text2: str, model) -> float:
    """Compare two texts and return their semantic similarity."""
    emb1 = create_embedding(text1, model)
    emb2 = create_embedding(text2, model)
    return calculate_similarity(emb1, emb2)


def semantic_search(query: str, documents: list, model, top_k: int = 3) -> list:
    """Find documents most similar to the query."""
    # Create embeddings
    query_emb = create_embedding(query, model)
    doc_embs = create_embeddings_batch(documents, model)

    # Calculate similarities
    similarities = cosine_similarity([query_emb], doc_embs)[0]

    # Get top results
    top_indices = np.argsort(similarities)[::-1][:top_k]

    return [(documents[i], similarities[i]) for i in top_indices]


def visualize_embeddings(texts: list, model):
    """Reduce embeddings to 2D and visualize."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("   ⚠️ matplotlib not available for visualization")
        return

    # Create embeddings
    embeddings = create_embeddings_batch(texts, model)

    # Reduce to 2D
    pca = PCA(n_components=2)
    reduced = pca.fit_transform(embeddings)

    # Plot
    plt.figure(figsize=(10, 8))
    plt.scatter(reduced[:, 0], reduced[:, 1], s=100)

    for i, text in enumerate(texts):
        plt.annotate(
            text[:30] + "...", (reduced[i, 0], reduced[i, 1]), fontsize=8, ha="center", va="bottom"
        )

    plt.title("Security Threat Embeddings (2D PCA)")
    plt.xlabel("Component 1")
    plt.ylabel("Component 2")
    plt.tight_layout()
    plt.savefig("embeddings_visualization.png", dpi=150)
    print("   📊 Saved visualization to embeddings_visualization.png")


def find_related_iocs(query: str, iocs: list, model, threshold: float = 0.5) -> list:
    """Find IOCs related to a query based on description similarity."""
    descriptions = [ioc["description"] for ioc in iocs]

    query_emb = create_embedding(query, model)
    desc_embs = create_embeddings_batch(descriptions, model)

    similarities = cosine_similarity([query_emb], desc_embs)[0]

    results = []
    for i, (ioc, sim) in enumerate(zip(iocs, similarities)):
        if sim >= threshold:
            results.append((ioc, sim))

    # Sort by similarity
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def demonstrate_embedding_math(model):
    """Show interesting embedding arithmetic."""
    print("\n" + "=" * 55)
    print("5. Embedding Arithmetic (Bonus)")
    print("-" * 55)

    # Create embeddings for concepts
    malware = create_embedding("malware", model)
    windows = create_embedding("Windows operating system", model)
    mac = create_embedding("Mac operating system", model)

    # malware + Windows should be similar to Windows malware
    windows_malware_calc = malware + windows
    windows_malware_actual = create_embedding("Windows malware", model)
    mac_malware_actual = create_embedding("Mac malware", model)

    sim_windows = calculate_similarity(windows_malware_calc, windows_malware_actual)
    sim_mac = calculate_similarity(windows_malware_calc, mac_malware_actual)

    print("   Concept: malware + Windows ≈ Windows malware?")
    print(f"   Similarity to 'Windows malware': {sim_windows:.3f}")
    print(f"   Similarity to 'Mac malware': {sim_mac:.3f}")
    print(f"   ✅ Closer to Windows malware!" if sim_windows > sim_mac else "")


def main():
    print("🔢 Embeddings & Vectors - Security Semantic Search")
    print("=" * 55)

    if not HAVE_TRANSFORMERS:
        print("\n❌ Install: pip install sentence-transformers")
        return

    print("\n📦 Loading embedding model...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    print(f"   Model: all-MiniLM-L6-v2 (384 dimensions)")

    # 1. Create embeddings
    print("\n" + "=" * 55)
    print("1. Creating Embeddings")
    print("-" * 55)

    test_text = "Malware using PowerShell for execution"
    embedding = create_embedding(test_text, model)

    print(f'   Text: "{test_text}"')
    print(f"   → Vector of {len(embedding)} dimensions")
    print(f"   → First 5 values: [{', '.join(f'{v:.3f}' for v in embedding[:5])}]")
    print(f"   → Sum: {embedding.sum():.3f}, Mean: {embedding.mean():.3f}")

    # 2. Similarity comparison
    print("\n" + "=" * 55)
    print("2. Similarity Comparison")
    print("-" * 55)

    test_pairs = [
        ("credential theft", "password stealing"),
        ("credential theft", "lateral movement"),
        ("credential theft", "quarterly report"),
        ("C2 beacon", "command and control callback"),
        ("phishing email", "legitimate newsletter"),
    ]

    for text1, text2 in test_pairs:
        sim = compare_texts(text1, text2, model)
        if sim > 0.7:
            indicator = "✅ Very similar!"
        elif sim > 0.4:
            indicator = "~ Related"
        else:
            indicator = "✗ Unrelated"
        print(f'   "{text1:25s}" vs "{text2:25s}": {sim:.2f} {indicator}')

    # 3. Semantic search
    print("\n" + "=" * 55)
    print("3. Semantic Search Demo")
    print("-" * 55)

    queries = [
        "attacker stealing passwords",
        "encrypted malicious traffic",
        "code execution via scripts",
    ]

    for query in queries:
        print(f'\n   Query: "{query}"')
        results = semantic_search(query, THREAT_DESCRIPTIONS, model, top_k=3)
        for i, (doc, score) in enumerate(results, 1):
            print(f"   {i}. ({score:.2f}) {doc}")

    # 4. Related IOCs
    print("\n" + "=" * 55)
    print("4. Finding Related IOCs")
    print("-" * 55)

    ioc_queries = [
        "command and control communication",
        "credential stealing malware",
    ]

    for query in ioc_queries:
        print(f'\n   Query: "{query}"')
        related = find_related_iocs(query, IOC_SAMPLES, model, threshold=0.3)
        for ioc, score in related[:3]:
            print(
                f"   • [{ioc['type']:6s}] {ioc['value']:20s} ({score:.2f}) - {ioc['description']}"
            )

    # 5. Embedding arithmetic
    demonstrate_embedding_math(model)

    # 6. Visualization (optional)
    print("\n" + "=" * 55)
    print("6. Visualization")
    print("-" * 55)
    visualize_embeddings(THREAT_DESCRIPTIONS, model)

    # Summary
    print("\n" + "=" * 55)
    print("📊 KEY TAKEAWAYS")
    print("=" * 55)
    print(
        """
   1. Embeddings convert text → numbers that capture meaning
   2. Similar text → similar vectors (close in vector space)
   3. Cosine similarity measures how "aligned" vectors are
   4. Semantic search finds relevant content regardless of wording
   5. This is the foundation for RAG systems!
   
   Next: Lab 06 (RAG) - Use embeddings with a vector database
    """
    )


if __name__ == "__main__":
    main()

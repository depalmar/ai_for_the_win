"""
Lab 06b: Embeddings & Vectors Explained (Starter)

Learn how AI "understands" meaning through vector representations.
Complete the TODOs to build a semantic search system for security.
"""

import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

# We'll use sentence-transformers (free, runs locally)
# Install: pip install sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    HAVE_TRANSFORMERS = True
except ImportError:
    HAVE_TRANSFORMERS = False
    print("⚠️ Install sentence-transformers: pip install sentence-transformers")


# ============================================================================
# SAMPLE SECURITY DATA
# ============================================================================

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


# ============================================================================
# TODO 1: Create embeddings for text
# ============================================================================

def create_embedding(text: str, model) -> np.ndarray:
    """
    Create an embedding vector for the given text.
    
    Args:
        text: The text to embed
        model: The sentence transformer model
        
    Returns:
        Numpy array of embedding values
    """
    # TODO: Use model.encode() to create embedding
    # Hint: embedding = model.encode(text)
    
    # Your code here:
    pass


def create_embeddings_batch(texts: list, model) -> np.ndarray:
    """
    Create embeddings for multiple texts at once (more efficient).
    
    Args:
        texts: List of texts to embed
        model: The sentence transformer model
        
    Returns:
        2D numpy array of embeddings (one row per text)
    """
    # TODO: Use model.encode() with list of texts
    # Hint: embeddings = model.encode(texts)
    
    # Your code here:
    pass


# ============================================================================
# TODO 2: Calculate similarity between texts
# ============================================================================

def calculate_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
    """
    Calculate cosine similarity between two embeddings.
    
    Cosine similarity ranges from -1 to 1:
    - 1 = identical direction (same meaning)
    - 0 = perpendicular (unrelated)
    - -1 = opposite direction (opposite meaning)
    
    Args:
        emb1: First embedding vector
        emb2: Second embedding vector
        
    Returns:
        Similarity score (typically 0-1 for text)
    """
    # TODO: Use cosine_similarity from sklearn
    # Hint: cosine_similarity expects 2D arrays: [[emb1]], [[emb2]]
    # Hint: similarity = cosine_similarity([emb1], [emb2])[0][0]
    
    # Your code here:
    pass


def compare_texts(text1: str, text2: str, model) -> float:
    """
    Compare two texts and return their semantic similarity.
    
    Args:
        text1: First text
        text2: Second text
        model: Embedding model
        
    Returns:
        Similarity score
    """
    # TODO: Create embeddings for both texts
    # TODO: Calculate and return similarity
    
    # Your code here:
    pass


# ============================================================================
# TODO 3: Build semantic search
# ============================================================================

def semantic_search(query: str, documents: list, model, top_k: int = 3) -> list:
    """
    Find documents most similar to the query.
    
    Args:
        query: Search query
        documents: List of documents to search
        model: Embedding model
        top_k: Number of results to return
        
    Returns:
        List of (document, similarity_score) tuples
    """
    # TODO: 
    # 1. Create embedding for query
    # 2. Create embeddings for all documents
    # 3. Calculate similarity between query and each document
    # 4. Sort by similarity (descending)
    # 5. Return top_k results
    
    # Your code here:
    pass


# ============================================================================
# TODO 4: Visualize embeddings (optional)
# ============================================================================

def visualize_embeddings(texts: list, model):
    """
    Reduce embeddings to 2D and visualize with matplotlib.
    
    This shows how similar concepts cluster together.
    """
    # TODO (Optional):
    # 1. Create embeddings for all texts
    # 2. Use PCA or t-SNE to reduce to 2D
    # 3. Plot with matplotlib
    
    # Hint:
    # from sklearn.decomposition import PCA
    # pca = PCA(n_components=2)
    # reduced = pca.fit_transform(embeddings)
    
    # Your code here:
    pass


# ============================================================================
# TODO 5: Find related IOCs
# ============================================================================

def find_related_iocs(query: str, iocs: list, model, threshold: float = 0.5) -> list:
    """
    Find IOCs related to a query based on description similarity.
    
    Args:
        query: What to search for (e.g., "credential theft")
        iocs: List of IOC dictionaries with 'description' field
        model: Embedding model
        threshold: Minimum similarity to include
        
    Returns:
        List of related IOCs with similarity scores
    """
    # TODO:
    # 1. Extract descriptions from IOCs
    # 2. Use semantic_search to find similar
    # 3. Return IOCs above threshold
    
    # Your code here:
    pass


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("🔢 Embeddings & Vectors - Security Semantic Search")
    print("=" * 55)
    
    if not HAVE_TRANSFORMERS:
        print("\n❌ Please install sentence-transformers:")
        print("   pip install sentence-transformers")
        return
    
    # Load model
    print("\n📦 Loading embedding model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    print(f"   Model: all-MiniLM-L6-v2 (384 dimensions)")
    
    # Test 1: Create embeddings
    print("\n" + "=" * 55)
    print("1. Creating Embeddings")
    print("-" * 55)
    
    test_text = "Malware using PowerShell for execution"
    embedding = create_embedding(test_text, model)
    
    if embedding is not None:
        print(f"   Text: \"{test_text}\"")
        print(f"   → Vector of {len(embedding)} dimensions")
        print(f"   → First 5 values: [{', '.join(f'{v:.3f}' for v in embedding[:5])}]")
    else:
        print("   ❌ Complete TODO 1 to create embeddings")
    
    # Test 2: Similarity comparison
    print("\n" + "=" * 55)
    print("2. Similarity Comparison")
    print("-" * 55)
    
    test_pairs = [
        ("credential theft", "password stealing"),
        ("credential theft", "lateral movement"),
        ("credential theft", "quarterly report"),
    ]
    
    for text1, text2 in test_pairs:
        sim = compare_texts(text1, text2, model)
        if sim is not None:
            indicator = "✅ Very similar!" if sim > 0.7 else ("~ Related" if sim > 0.4 else "✗ Unrelated")
            print(f"   \"{text1:20s}\" vs \"{text2:20s}\": {sim:.2f} {indicator}")
        else:
            print("   ❌ Complete TODO 2 to compare texts")
            break
    
    # Test 3: Semantic search
    print("\n" + "=" * 55)
    print("3. Semantic Search Demo")
    print("-" * 55)
    
    query = "attacker stealing passwords"
    results = semantic_search(query, THREAT_DESCRIPTIONS, model, top_k=3)
    
    if results:
        print(f"   Query: \"{query}\"")
        print("-" * 55)
        for i, (doc, score) in enumerate(results, 1):
            print(f"   {i}. \"{doc}\" ({score:.2f})")
    else:
        print("   ❌ Complete TODO 3 to build semantic search")
    
    # Test 4: Related IOCs
    print("\n" + "=" * 55)
    print("4. Finding Related IOCs")
    print("-" * 55)
    
    ioc_query = "command and control communication"
    related = find_related_iocs(ioc_query, IOC_SAMPLES, model)
    
    if related:
        print(f"   Query: \"{ioc_query}\"")
        print("-" * 55)
        for ioc, score in related:
            print(f"   • [{ioc['type']}] {ioc['value']} ({score:.2f})")
            print(f"     {ioc['description']}")
    else:
        print("   ❌ Complete TODO 5 to find related IOCs")
    
    # Summary
    print("\n" + "=" * 55)
    completed = sum([
        embedding is not None,
        any(compare_texts(t1, t2, model) is not None for t1, t2 in test_pairs[:1]),
        results is not None and len(results) > 0,
        related is not None and len(related) > 0,
    ])
    print(f"Progress: {completed}/4 main TODOs complete")
    
    if completed >= 3:
        print("\n✅ You understand embeddings! Ready for Lab 06 (RAG).")
    else:
        print("\n📝 Keep working on the TODOs!")


if __name__ == "__main__":
    main()

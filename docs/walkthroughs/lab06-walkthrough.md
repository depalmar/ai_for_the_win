# Lab 06: Security RAG - Solution Walkthrough

## Overview

Build a Retrieval-Augmented Generation (RAG) system for security documentation Q&A. This system allows security teams to query their knowledge base using natural language.

**Time:** 2-3 hours
**Difficulty:** Intermediate

---

## Task 1: Document Ingestion

### Loading Security Documents

```python
import os
from pathlib import Path

def load_documents(docs_path: str) -> list[dict]:
    """Load security documents from directory."""
    documents = []
    supported_extensions = ['.txt', '.md', '.pdf', '.json']

    for file_path in Path(docs_path).rglob('*'):
        if file_path.suffix.lower() in supported_extensions:
            try:
                if file_path.suffix == '.pdf':
                    content = extract_pdf_text(file_path)
                else:
                    content = file_path.read_text(encoding='utf-8')

                documents.append({
                    'content': content,
                    'source': str(file_path),
                    'filename': file_path.name,
                    'type': file_path.suffix[1:]
                })
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

    return documents

def extract_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF using PyPDF2."""
    from PyPDF2 import PdfReader

    reader = PdfReader(str(pdf_path))
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return text
```

### Expected Output
```
Loaded 45 documents from ./security_docs/
- 20 .md files (playbooks)
- 15 .txt files (procedures)
- 10 .pdf files (policies)
```

---

## Task 2: Text Chunking

### Implementing Recursive Chunking

```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

def chunk_documents(documents: list[dict],
                   chunk_size: int = 1000,
                   chunk_overlap: int = 200) -> list[dict]:
    """Split documents into overlapping chunks."""

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        separators=["\n\n", "\n", ". ", " ", ""]
    )

    chunks = []
    for doc in documents:
        doc_chunks = splitter.split_text(doc['content'])

        for i, chunk in enumerate(doc_chunks):
            chunks.append({
                'content': chunk,
                'source': doc['source'],
                'chunk_id': f"{doc['filename']}_{i}",
                'metadata': {
                    'filename': doc['filename'],
                    'chunk_index': i,
                    'total_chunks': len(doc_chunks)
                }
            })

    return chunks

# Process documents
chunks = chunk_documents(documents)
print(f"Created {len(chunks)} chunks from {len(documents)} documents")
```

### Chunk Statistics
```
Total chunks: 342
Average chunk size: 856 characters
Chunks per document: 7.6 average
```

---

## Task 3: Vector Embeddings

### Creating Embeddings with Sentence Transformers

```python
from sentence_transformers import SentenceTransformer
import numpy as np

class EmbeddingEngine:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.embedding_dim = self.model.get_sentence_embedding_dimension()

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        """Generate embeddings for a list of texts."""
        embeddings = self.model.encode(
            texts,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        return embeddings

    def embed_query(self, query: str) -> np.ndarray:
        """Generate embedding for a single query."""
        return self.model.encode(query, convert_to_numpy=True)

# Initialize and embed chunks
embedder = EmbeddingEngine()
chunk_texts = [c['content'] for c in chunks]
embeddings = embedder.embed_texts(chunk_texts)

print(f"Generated {len(embeddings)} embeddings")
print(f"Embedding dimension: {embeddings.shape[1]}")
```

---

## Task 4: Vector Database Setup

### Using ChromaDB for Storage

```python
import chromadb
from chromadb.config import Settings

def setup_vector_db(chunks: list[dict],
                    embeddings: np.ndarray,
                    collection_name: str = "security_docs") -> chromadb.Collection:
    """Initialize ChromaDB and store embeddings."""

    # Initialize persistent client
    client = chromadb.Client(Settings(
        chroma_db_impl="duckdb+parquet",
        persist_directory="./chroma_db"
    ))

    # Create or get collection
    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={"description": "Security documentation"}
    )

    # Add documents with embeddings
    collection.add(
        ids=[c['chunk_id'] for c in chunks],
        embeddings=embeddings.tolist(),
        documents=[c['content'] for c in chunks],
        metadatas=[c['metadata'] for c in chunks]
    )

    return collection

# Setup database
collection = setup_vector_db(chunks, embeddings)
print(f"Stored {collection.count()} chunks in ChromaDB")
```

---

## Task 5: Retrieval Implementation

### Semantic Search Function

```python
def retrieve_relevant_chunks(query: str,
                            collection: chromadb.Collection,
                            embedder: EmbeddingEngine,
                            top_k: int = 5) -> list[dict]:
    """Retrieve most relevant chunks for a query."""

    # Generate query embedding
    query_embedding = embedder.embed_query(query)

    # Search in ChromaDB
    results = collection.query(
        query_embeddings=[query_embedding.tolist()],
        n_results=top_k,
        include=["documents", "metadatas", "distances"]
    )

    # Format results
    retrieved = []
    for i in range(len(results['ids'][0])):
        retrieved.append({
            'content': results['documents'][0][i],
            'metadata': results['metadatas'][0][i],
            'distance': results['distances'][0][i],
            'relevance_score': 1 - results['distances'][0][i]
        })

    return retrieved

# Test retrieval
query = "How do I respond to a ransomware incident?"
results = retrieve_relevant_chunks(query, collection, embedder)

for i, r in enumerate(results):
    print(f"\n--- Result {i+1} (Score: {r['relevance_score']:.3f}) ---")
    print(f"Source: {r['metadata']['filename']}")
    print(f"Content: {r['content'][:200]}...")
```

---

## Task 6: RAG Pipeline

### Complete Q&A System

```python
import anthropic

class SecurityRAG:
    def __init__(self, collection, embedder):
        self.collection = collection
        self.embedder = embedder
        self.client = anthropic.Anthropic()

    def answer_query(self, query: str, top_k: int = 5) -> dict:
        """Answer a security question using RAG."""

        # Retrieve relevant context
        context_chunks = retrieve_relevant_chunks(
            query, self.collection, self.embedder, top_k
        )

        # Build context string
        context = "\n\n---\n\n".join([
            f"Source: {c['metadata']['filename']}\n{c['content']}"
            for c in context_chunks
        ])

        # Generate answer with Claude
        prompt = f"""You are a security analyst assistant. Answer the question based on the provided context from our security documentation.

Context:
{context}

Question: {query}

Instructions:
- Only use information from the provided context
- If the context doesn't contain the answer, say so
- Cite sources when possible
- Be specific and actionable

Answer:"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        return {
            'answer': response.content[0].text,
            'sources': [c['metadata']['filename'] for c in context_chunks],
            'context_chunks': context_chunks
        }

# Initialize RAG system
rag = SecurityRAG(collection, embedder)

# Test query
result = rag.answer_query("What are the first steps in ransomware response?")
print("Answer:", result['answer'])
print("\nSources:", result['sources'])
```

### Expected Output
```
Answer: Based on the security documentation, the first steps in ransomware response are:

1. **Isolate affected systems** - Immediately disconnect infected machines from the network to prevent lateral spread (IR-Playbook-001.md)

2. **Preserve evidence** - Do not shut down systems; instead, capture memory and disk images for forensic analysis (Forensics-Procedures.txt)

3. **Identify the variant** - Check ransom notes and file extensions against known ransomware families (Threat-Intel-Guide.md)

4. **Assess scope** - Determine which systems and data are affected using EDR/SIEM queries (Detection-Procedures.md)

5. **Activate IR team** - Notify stakeholders per the communication plan (IR-Communication-Plan.pdf)

Sources: ['IR-Playbook-001.md', 'Forensics-Procedures.txt', 'Threat-Intel-Guide.md']
```

---

## Task 7: Advanced Features

### Hybrid Search (Keyword + Semantic)

```python
from rank_bm25 import BM25Okapi
import re

class HybridRetriever:
    def __init__(self, chunks, collection, embedder):
        self.chunks = chunks
        self.collection = collection
        self.embedder = embedder

        # Build BM25 index
        tokenized = [self._tokenize(c['content']) for c in chunks]
        self.bm25 = BM25Okapi(tokenized)

    def _tokenize(self, text: str) -> list[str]:
        """Simple tokenization."""
        return re.findall(r'\w+', text.lower())

    def search(self, query: str, top_k: int = 5,
               semantic_weight: float = 0.7) -> list[dict]:
        """Hybrid search combining BM25 and semantic."""

        # Semantic search
        semantic_results = retrieve_relevant_chunks(
            query, self.collection, self.embedder, top_k * 2
        )

        # BM25 search
        tokenized_query = self._tokenize(query)
        bm25_scores = self.bm25.get_scores(tokenized_query)

        # Combine scores
        combined = {}
        for i, chunk in enumerate(self.chunks):
            chunk_id = chunk['chunk_id']
            bm25_score = bm25_scores[i] / max(bm25_scores)  # Normalize

            semantic_score = 0
            for sr in semantic_results:
                if sr['metadata'].get('chunk_id') == chunk_id:
                    semantic_score = sr['relevance_score']
                    break

            combined[chunk_id] = (
                semantic_weight * semantic_score +
                (1 - semantic_weight) * bm25_score
            )

        # Sort and return top-k
        sorted_ids = sorted(combined, key=combined.get, reverse=True)[:top_k]
        return [c for c in self.chunks if c['chunk_id'] in sorted_ids]
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Slow embedding | Use batch processing, GPU acceleration |
| Poor retrieval | Adjust chunk size, increase top_k |
| Generic answers | Add more specific context, refine prompts |
| Missing context | Implement hybrid search |
| Large documents | Use hierarchical chunking |

---

## Next Steps

- Add conversation memory for follow-up questions
- Implement source highlighting in documents
- Add relevance feedback for learning
- Build a web interface with Streamlit
- Add multi-language support

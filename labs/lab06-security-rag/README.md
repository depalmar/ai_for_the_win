# Lab 06: RAG System for Security Documentation

Build a Retrieval-Augmented Generation system for querying security documentation.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand RAG architecture and components
2. Create document embeddings with security context
3. Build a vector database for semantic search
4. Implement retrieval-augmented LLM responses
5. Handle security-specific document types (CVEs, playbooks, TTPs)

---

## ⏱️ Estimated Time

75-90 minutes (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 04-05
- Anthropic or OpenAI API key
- Understanding of embeddings and vector search

> **New to embeddings?** Start with our [Embeddings and Vectors Guide](../../docs/guides/embeddings-and-vectors.md) for an introduction to how embeddings work, how to create them, and how vector databases enable semantic search.

### Required Libraries

```bash
pip install langchain langchain-anthropic chromadb sentence-transformers
pip install tiktoken pypdf docx2txt  # Document processing
```

---

## 📖 Background

### What is RAG?

**R**etrieval-**A**ugmented **G**eneration combines:
1. **Retrieval**: Find relevant documents using semantic search
2. **Augmentation**: Add retrieved context to the prompt
3. **Generation**: LLM generates response using context

```
┌─────────────────────────────────────────────────────────────┐
│                      RAG Pipeline                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Query ─────► Embed ─────► Vector Search ─────► Top K Docs │
│                  │                                    │      │
│                  ▼                                    ▼      │
│            Query Vector                         Retrieved   │
│                                                  Context    │
│                                                    │        │
│                                                    ▼        │
│   Query + Context ─────────────────────────────► LLM        │
│                                                    │        │
│                                                    ▼        │
│                                               Response      │
└─────────────────────────────────────────────────────────────┘
```

### Security Documentation Types

| Doc Type | Use Case | Chunking Strategy |
|----------|----------|-------------------|
| CVE Descriptions | Vulnerability lookup | Per-CVE chunks |
| MITRE ATT&CK | Technique reference | Per-technique |
| IR Playbooks | Response procedures | Per-step |
| Sigma Rules | Detection reference | Per-rule |
| Threat Reports | Context & attribution | Semantic sections |

### ⚠️ RAG Reduces (But Doesn't Eliminate) Hallucinations

RAG grounds LLM responses in retrieved documents, but risks remain:

| Risk | Example | Mitigation |
|------|---------|------------|
| **Wrong retrieval** | Retrieved docs don't match query | Check retrieval relevance scores |
| **Mixing sources** | LLM combines chunks incorrectly | Ask LLM to cite specific sources |
| **Beyond context** | LLM adds info not in retrieved docs | Prompt: "Only use provided context" |
| **Outdated info** | Document database is stale | Track document freshness |

**Key principle:** RAG provides context, but verify the response matches retrieved documents.

```python
# Good practice: Verify response cites retrieved docs
prompt = """
Answer using ONLY the context provided. 
For each claim, cite which document supports it.
If the answer isn't in the context, say "Not found in documentation."
"""
```

> 📖 See [Security Prompts Template](../../templates/prompts/security_prompts.md) for anti-hallucination patterns.

---

## 🔬 Lab Tasks

### Task 1: Document Ingestion (15 min)

```python
class SecurityDocLoader:
    """Load and process security documents."""
    
    def load_cve_data(self, filepath: str) -> List[Document]:
        """
        Load CVE data and create documents.
        
        TODO:
        1. Parse CVE JSON/CSV
        2. Create Document for each CVE
        3. Add metadata (CVE ID, CVSS, date)
        4. Return list of Documents
        """
        pass
    
    def load_mitre_attack(self, filepath: str) -> List[Document]:
        """
        Load MITRE ATT&CK techniques.
        
        TODO:
        1. Parse ATT&CK JSON
        2. Create Document per technique
        3. Include detection and mitigation info
        4. Add tactic and technique IDs as metadata
        """
        pass
    
    def load_playbooks(self, directory: str) -> List[Document]:
        """
        Load IR playbooks from markdown files.
        
        TODO:
        1. Find all .md files
        2. Parse each playbook
        3. Chunk by sections (triggers, steps, actions)
        4. Preserve playbook metadata
        """
        pass
```

### Task 2: Text Chunking (15 min)

```python
def chunk_security_documents(documents: List[Document]) -> List[Document]:
    """
    Chunk documents for optimal retrieval.
    
    TODO:
    1. Use RecursiveCharacterTextSplitter
    2. Set appropriate chunk size (500-1000 tokens)
    3. Set overlap (50-100 tokens)
    4. Preserve section boundaries
    5. Keep metadata with chunks
    
    Security considerations:
    - Don't split CVE IDs mid-chunk
    - Keep technique IDs with descriptions
    - Preserve code blocks intact
    """
    pass
```

### Task 3: Create Embeddings (15 min)

```python
def create_vector_store(chunks: List[Document]) -> Chroma:
    """
    Create vector store with embeddings.
    
    TODO:
    1. Initialize embedding model
    2. Create ChromaDB collection
    3. Add documents with embeddings
    4. Configure similarity metric
    
    Options:
    - OpenAI embeddings (best quality)
    - Sentence-transformers (local, free)
    - Security-specific models if available
    """
    pass
```

### Task 4: Build Retriever (10 min)

```python
def create_security_retriever(
    vector_store: Chroma,
    k: int = 5
) -> VectorStoreRetriever:
    """
    Create retriever with security-optimized settings.
    
    TODO:
    1. Configure similarity search
    2. Set number of results (k)
    3. Add metadata filtering capabilities
    4. Implement re-ranking (optional)
    """
    pass
```

### Task 5: RAG Chain (15 min)

```python
class SecurityRAG:
    """RAG system for security queries."""
    
    def __init__(self, retriever, llm):
        self.retriever = retriever
        self.llm = llm
        self.prompt = self._create_prompt()
    
    def _create_prompt(self) -> ChatPromptTemplate:
        """
        Create prompt template for security Q&A.
        
        TODO:
        1. Include system context (security analyst role)
        2. Add placeholder for retrieved docs
        3. Add placeholder for user question
        4. Include instructions for citing sources
        """
        pass
    
    def query(self, question: str) -> dict:
        """
        Answer security question using RAG.
        
        TODO:
        1. Retrieve relevant documents
        2. Format context from documents
        3. Generate response with citations
        4. Return answer and sources
        """
        pass
    
    def query_with_filters(
        self, 
        question: str, 
        doc_type: str = None,
        severity: str = None
    ) -> dict:
        """
        Query with metadata filters.
        
        TODO:
        1. Build filter dict
        2. Apply to retriever
        3. Execute filtered search
        4. Generate response
        """
        pass
```

### Task 6: Evaluation (10 min)

```python
def evaluate_rag_system(rag: SecurityRAG, test_cases: List[dict]) -> dict:
    """
    Evaluate RAG system performance.
    
    Test cases format:
    {
        "question": "What is CVE-2024-1234?",
        "expected_keywords": ["remote code execution", "critical"],
        "expected_sources": ["CVE-2024-1234"]
    }
    
    TODO:
    1. Run each test case
    2. Check for expected keywords in response
    3. Verify correct sources retrieved
    4. Calculate precision/recall
    """
    pass
```

---

## 📁 Files

```
lab06-security-rag/
├── README.md
├── starter/
│   ├── main.py
│   ├── loaders.py
│   └── rag_chain.py
├── solution/
│   └── main.py
├── data/
│   ├── cves/
│   │   └── sample_cves.json
│   ├── mitre/
│   │   └── attack_techniques.json
│   └── playbooks/
│       ├── ransomware_response.md
│       └── phishing_response.md
└── tests/
    └── test_rag.py
```

---

## 🧪 Sample Queries

Test your RAG system with these:

```python
queries = [
    # CVE queries
    "What is CVE-2024-1234 and how do I mitigate it?",
    "List all critical CVEs affecting Apache from 2024",
    
    # MITRE queries  
    "How do attackers use PowerShell for execution?",
    "What are detection strategies for credential dumping?",
    
    # Playbook queries
    "What are the first steps when responding to ransomware?",
    "How should I handle a phishing incident?",
    
    # Complex queries
    "I found T1059.001 activity - what should I do?",
    "Compare different lateral movement techniques"
]
```

---

## ✅ Success Criteria

- [ ] Documents load without errors
- [ ] Chunking preserves important boundaries
- [ ] Vector store queries return relevant results
- [ ] RAG responses cite sources correctly
- [ ] System handles different document types
- [ ] Response quality is helpful and accurate

---

## 🚀 Bonus Challenges

1. **Hybrid Search**: Combine vector + keyword search
2. **Query Expansion**: Auto-expand security acronyms
3. **Multi-Index**: Separate indices per doc type
4. **Chat Memory**: Maintain conversation context
5. **Streaming**: Stream responses for better UX

---

## 💡 Hints

<details>
<summary>Hint: Good Chunk Size for Security Docs</summary>

```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

splitter = RecursiveCharacterTextSplitter(
    chunk_size=800,
    chunk_overlap=100,
    separators=["\n## ", "\n### ", "\n\n", "\n", " "],
    length_function=len,
)
```
</details>

<details>
<summary>Hint: Security-Aware Prompt</summary>

```python
SYSTEM_PROMPT = """You are a security analyst assistant with access to:
- CVE database
- MITRE ATT&CK framework
- Incident response playbooks

When answering:
1. Always cite your sources with [Source: document_name]
2. Include CVE IDs, technique IDs when relevant
3. Provide actionable recommendations
4. Note any caveats or limitations

Context from knowledge base:
{context}

Question: {question}
"""
```
</details>

---

## 📚 Resources

- [LangChain RAG Tutorial](https://python.langchain.com/docs/tutorials/rag)
- [ChromaDB Documentation](https://docs.trychroma.com/)
- [Sentence Transformers](https://www.sbert.net/)
- [MITRE ATT&CK STIX Data](https://github.com/mitre/cti)

---

> **Stuck?** See the [Lab 06 Walkthrough](../../docs/walkthroughs/lab06-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 07 - YARA Rule Generator](../lab07-yara-generator/)


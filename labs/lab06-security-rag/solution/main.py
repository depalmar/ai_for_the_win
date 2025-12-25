#!/usr/bin/env python3
"""
Lab 06: RAG System for Security Documentation - Solution

Complete implementation of RAG for security documentation.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_anthropic import ChatAnthropic
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain_core.documents import Document
    from langchain_core.messages import HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

    class Document:
        def __init__(self, page_content, metadata=None):
            self.page_content = page_content
            self.metadata = metadata or {}


from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()


# =============================================================================
# Task 1: Document Ingestion - SOLUTION
# =============================================================================


class SecurityDocLoader:
    """Load and process security documents."""

    def load_cve_data(self, filepath: str) -> List[Document]:
        """Load CVE data and create documents."""
        with open(filepath, "r") as f:
            cves = json.load(f)

        documents = []
        for cve in cves:
            content = f"""CVE ID: {cve['cve_id']}
Severity: {cve['severity']} (CVSS: {cve['cvss_score']})

Description:
{cve['description']}

Affected Products:
{', '.join(cve.get('affected_products', []))}

Mitigation:
{cve.get('mitigation', 'No mitigation information available.')}
"""
            doc = Document(
                page_content=content,
                metadata={
                    "source": cve["cve_id"],
                    "doc_type": "cve",
                    "severity": cve["severity"],
                    "cvss_score": cve["cvss_score"],
                },
            )
            documents.append(doc)

        return documents

    def load_mitre_attack(self, filepath: str) -> List[Document]:
        """Load MITRE ATT&CK techniques."""
        with open(filepath, "r") as f:
            techniques = json.load(f)

        documents = []
        for tech in techniques:
            content = f"""MITRE ATT&CK Technique: {tech['technique_id']} - {tech['name']}
Tactic: {tech['tactic']}

Description:
{tech['description']}

Detection:
{tech.get('detection', 'No detection guidance available.')}

Mitigations:
{chr(10).join('- ' + m for m in tech.get('mitigations', []))}
"""
            doc = Document(
                page_content=content,
                metadata={
                    "source": tech["technique_id"],
                    "doc_type": "mitre",
                    "tactic": tech["tactic"],
                    "technique_name": tech["name"],
                },
            )
            documents.append(doc)

        return documents

    def load_playbooks(self, directory: str) -> List[Document]:
        """Load IR playbooks from markdown files."""
        playbook_dir = Path(directory)
        documents = []

        for md_file in playbook_dir.glob("*.md"):
            content = md_file.read_text()
            playbook_name = md_file.stem.replace("_", " ").title()

            doc = Document(
                page_content=content,
                metadata={
                    "source": md_file.name,
                    "doc_type": "playbook",
                    "playbook_name": playbook_name,
                },
            )
            documents.append(doc)

        return documents

    def load_all_documents(self, data_dir: str) -> List[Document]:
        """Load all document types from data directory."""
        data_path = Path(data_dir)
        all_docs = []

        # Load CVEs
        cve_file = data_path / "cves" / "sample_cves.json"
        if cve_file.exists():
            all_docs.extend(self.load_cve_data(str(cve_file)))
            console.print(f"  Loaded CVEs from {cve_file}")

        # Load MITRE
        mitre_file = data_path / "mitre" / "attack_techniques.json"
        if mitre_file.exists():
            all_docs.extend(self.load_mitre_attack(str(mitre_file)))
            console.print(f"  Loaded MITRE from {mitre_file}")

        # Load Playbooks
        playbook_dir = data_path / "playbooks"
        if playbook_dir.exists():
            all_docs.extend(self.load_playbooks(str(playbook_dir)))
            console.print(f"  Loaded playbooks from {playbook_dir}")

        return all_docs


# =============================================================================
# Task 2: Text Chunking - SOLUTION
# =============================================================================


def chunk_security_documents(
    documents: List[Document], chunk_size: int = 800, chunk_overlap: int = 100
) -> List[Document]:
    """Chunk documents for optimal retrieval."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n## ", "\n### ", "\n\n", "\n", " "],
        length_function=len,
    )

    chunks = []
    for doc in documents:
        doc_chunks = splitter.split_documents([doc])
        # Preserve original metadata in each chunk
        for chunk in doc_chunks:
            chunk.metadata.update(doc.metadata)
        chunks.extend(doc_chunks)

    return chunks


# =============================================================================
# Task 3: Create Embeddings - SOLUTION
# =============================================================================


def create_vector_store(chunks: List[Document], persist_directory: str = None) -> "Chroma":
    """Create vector store with embeddings."""
    # Use HuggingFace embeddings (free, local)
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2", model_kwargs={"device": "cpu"}
    )

    if persist_directory:
        vector_store = Chroma.from_documents(
            documents=chunks, embedding=embeddings, persist_directory=persist_directory
        )
    else:
        vector_store = Chroma.from_documents(documents=chunks, embedding=embeddings)

    return vector_store


def load_vector_store(persist_directory: str) -> "Chroma":
    """Load existing vector store from disk."""
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    return Chroma(persist_directory=persist_directory, embedding_function=embeddings)


# =============================================================================
# Task 4: Build Retriever - SOLUTION
# =============================================================================


def create_security_retriever(vector_store: "Chroma", k: int = 5):
    """Create retriever with security-optimized settings."""
    retriever = vector_store.as_retriever(search_type="similarity", search_kwargs={"k": k})
    return retriever


# =============================================================================
# Task 5: RAG Chain - SOLUTION
# =============================================================================

SECURITY_RAG_PROMPT = """You are a security analyst assistant with access to:
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

Provide a comprehensive answer based on the context above."""


class SecurityRAG:
    """RAG system for security queries."""

    def __init__(self, retriever, llm):
        self.retriever = retriever
        self.llm = llm

    def _format_context(self, documents: List[Document]) -> str:
        """Format retrieved documents into context string."""
        context_parts = []
        for i, doc in enumerate(documents, 1):
            source = doc.metadata.get("source", "Unknown")
            doc_type = doc.metadata.get("doc_type", "document")
            context_parts.append(f"[Document {i} - {doc_type}: {source}]\n{doc.page_content}\n")
        return "\n---\n".join(context_parts)

    def query(self, question: str) -> dict:
        """Answer security question using RAG."""
        # Retrieve relevant documents
        docs = self.retriever.get_relevant_documents(question)

        if not docs:
            return {
                "answer": "No relevant information found in the knowledge base.",
                "sources": [],
                "confidence": 0.0,
            }

        # Format context
        context = self._format_context(docs)

        # Generate response
        prompt = SECURITY_RAG_PROMPT.format(context=context, question=question)
        messages = [HumanMessage(content=prompt)]
        response = self.llm.invoke(messages)

        # Extract sources
        sources = [doc.metadata.get("source", "Unknown") for doc in docs]

        return {
            "answer": response.content,
            "sources": list(set(sources)),
            "confidence": len(docs) / 5.0,  # Simple confidence based on docs found
        }

    def query_with_filters(self, question: str, doc_type: str = None, severity: str = None) -> dict:
        """Query with metadata filters."""
        # Build filter
        filter_dict = {}
        if doc_type:
            filter_dict["doc_type"] = doc_type
        if severity:
            filter_dict["severity"] = severity

        # Create filtered retriever
        if filter_dict:
            docs = self.retriever.vectorstore.similarity_search(question, k=5, filter=filter_dict)
        else:
            docs = self.retriever.get_relevant_documents(question)

        if not docs:
            return {
                "answer": "No matching documents found with the specified filters.",
                "sources": [],
                "confidence": 0.0,
            }

        context = self._format_context(docs)
        prompt = SECURITY_RAG_PROMPT.format(context=context, question=question)
        messages = [HumanMessage(content=prompt)]
        response = self.llm.invoke(messages)

        sources = [doc.metadata.get("source", "Unknown") for doc in docs]

        return {
            "answer": response.content,
            "sources": list(set(sources)),
            "confidence": len(docs) / 5.0,
        }


# =============================================================================
# Task 6: Evaluation - SOLUTION
# =============================================================================


def evaluate_rag_system(rag: SecurityRAG, test_cases: List[dict]) -> dict:
    """Evaluate RAG system performance."""
    results = {
        "total": len(test_cases),
        "keyword_matches": 0,
        "source_matches": 0,
        "details": [],
    }

    for test in test_cases:
        question = test["question"]
        expected_keywords = test.get("expected_keywords", [])
        expected_sources = test.get("expected_sources", [])

        result = rag.query(question)
        answer = result["answer"].lower()

        # Check keywords
        keywords_found = sum(1 for kw in expected_keywords if kw.lower() in answer)
        keyword_score = keywords_found / len(expected_keywords) if expected_keywords else 1.0

        # Check sources
        sources_found = sum(1 for src in expected_sources if src in result["sources"])
        source_score = sources_found / len(expected_sources) if expected_sources else 1.0

        if keyword_score > 0.5:
            results["keyword_matches"] += 1
        if source_score > 0.5:
            results["source_matches"] += 1

        results["details"].append(
            {
                "question": question,
                "keyword_score": keyword_score,
                "source_score": source_score,
                "sources_retrieved": result["sources"],
            }
        )

    results["keyword_accuracy"] = results["keyword_matches"] / results["total"]
    results["source_accuracy"] = results["source_matches"] / results["total"]

    return results


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    console.print(
        Panel.fit("[bold]Lab 06: Security RAG System - SOLUTION[/bold]", border_style="blue")
    )

    if not LANGCHAIN_AVAILABLE:
        console.print("[red]LangChain not available.[/red]")
        console.print(
            "Install: pip install langchain langchain-anthropic chromadb sentence-transformers"
        )
        return

    data_dir = Path(__file__).parent.parent / "data"

    if not data_dir.exists():
        console.print("Creating sample data...")
        create_sample_data(data_dir)

    # Step 1: Load documents
    console.print("\n[yellow]Step 1:[/yellow] Loading documents...")
    loader = SecurityDocLoader()
    documents = loader.load_all_documents(str(data_dir))
    console.print(f"Loaded {len(documents)} documents")

    # Step 2: Chunk documents
    console.print("\n[yellow]Step 2:[/yellow] Chunking documents...")
    chunks = chunk_security_documents(documents)
    console.print(f"Created {len(chunks)} chunks")

    # Step 3: Create vector store
    console.print("\n[yellow]Step 3:[/yellow] Creating vector store...")
    vector_store = create_vector_store(chunks)
    console.print("Vector store created")

    # Step 4: Create retriever
    console.print("\n[yellow]Step 4:[/yellow] Creating retriever...")
    retriever = create_security_retriever(vector_store)

    # Step 5: Initialize RAG
    console.print("\n[yellow]Step 5:[/yellow] Initializing RAG system...")
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        console.print("[yellow]No API key found. Showing retrieval results only.[/yellow]")
        # Demo retrieval only
        test_queries = [
            "What is CVE-2024-1234?",
            "How do attackers use PowerShell?",
            "What are the first steps for ransomware response?",
        ]
        for query in test_queries:
            console.print(f"\n[bold]Query:[/bold] {query}")
            docs = retriever.get_relevant_documents(query)
            console.print(f"[green]Retrieved {len(docs)} documents:[/green]")
            for doc in docs[:2]:
                console.print(f"  - {doc.metadata.get('source', 'Unknown')}")
        return

    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
    rag = SecurityRAG(retriever, llm)

    # Step 6: Test queries
    console.print("\n[yellow]Step 6:[/yellow] Testing queries...")
    test_queries = [
        "What is CVE-2024-1234 and how do I mitigate it?",
        "How do attackers use PowerShell for execution?",
        "What are the first steps when responding to ransomware?",
    ]

    for query in test_queries:
        console.print(f"\n[bold]Query:[/bold] {query}")
        result = rag.query(query)
        console.print(f"[green]Sources:[/green] {result['sources']}")
        console.print(Markdown(result["answer"][:500] + "..."))

    console.print("\n" + "=" * 60)
    console.print("[green]RAG system complete![/green]")


def create_sample_data(data_dir: Path):
    """Create sample security documents."""
    data_dir.mkdir(parents=True, exist_ok=True)

    # Sample CVE data
    cves = [
        {
            "cve_id": "CVE-2024-1234",
            "description": "Remote code execution vulnerability in Apache HTTP Server allows attackers to execute arbitrary code via crafted requests.",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_products": ["Apache HTTP Server 2.4.x < 2.4.58"],
            "mitigation": "Update to Apache 2.4.58 or later. Apply vendor patches immediately.",
        },
        {
            "cve_id": "CVE-2024-5678",
            "description": "SQL injection vulnerability in MySQL allows authenticated users to execute arbitrary SQL commands.",
            "cvss_score": 8.5,
            "severity": "HIGH",
            "affected_products": ["MySQL 8.0.x < 8.0.35"],
            "mitigation": "Update to MySQL 8.0.35 or later. Implement input validation.",
        },
    ]

    cve_dir = data_dir / "cves"
    cve_dir.mkdir(exist_ok=True)
    (cve_dir / "sample_cves.json").write_text(json.dumps(cves, indent=2))

    # Sample MITRE ATT&CK data
    mitre = [
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "detection": "Monitor PowerShell script block logging, command-line arguments.",
            "mitigations": [
                "Disable PowerShell for users who don't need it",
                "Enable AMSI",
            ],
        }
    ]

    mitre_dir = data_dir / "mitre"
    mitre_dir.mkdir(exist_ok=True)
    (mitre_dir / "attack_techniques.json").write_text(json.dumps(mitre, indent=2))

    # Sample playbook
    playbook = """# Ransomware Response Playbook

## Immediate Actions
1. Isolate affected systems
2. Preserve evidence
3. Identify scope

## Investigation
1. Identify ransomware variant
2. Determine infection vector

## Recovery
1. Restore from backups
2. Reset credentials
"""
    playbook_dir = data_dir / "playbooks"
    playbook_dir.mkdir(exist_ok=True)
    (playbook_dir / "ransomware_response.md").write_text(playbook)


if __name__ == "__main__":
    main()

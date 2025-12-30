#!/usr/bin/env python3
"""
Lab 06: RAG System for Security Documentation - Starter Code

Build a Retrieval-Augmented Generation system for querying security documentation.

Instructions:
1. Complete each TODO section
2. Test with sample data in data/ folder
3. Compare your results with the solution
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
    Document = dict

from rich.console import Console
from rich.panel import Panel

console = Console()


# =============================================================================
# Task 1: Document Ingestion
# =============================================================================


class SecurityDocLoader:
    """Load and process security documents."""

    def load_cve_data(self, filepath: str) -> List[Document]:
        """
        Load CVE data and create documents.

        TODO: Ask your AI assistant:
        "Write Python code to load CVE data from a JSON file at 'filepath',
        parse each CVE entry, create a LangChain Document for each with the
        CVE description as page_content, and include metadata fields for
        cve_id, cvss_score, severity, and date. Return a list of Documents."

        Then review and test the generated code.
        """
        pass

    def load_mitre_attack(self, filepath: str) -> List[Document]:
        """
        Load MITRE ATT&CK techniques.

        TODO: Ask your AI assistant:
        "Write Python code to load MITRE ATT&CK techniques from a JSON file
        at 'filepath', create a LangChain Document for each technique with
        the technique name, description, detection info, and mitigations as
        page_content. Include tactic and technique_id as metadata. Return a
        list of Documents."

        Then review and test the generated code.
        """
        pass

    def load_playbooks(self, directory: str) -> List[Document]:
        """
        Load IR playbooks from markdown files.

        TODO: Ask your AI assistant:
        "Write Python code to find all markdown (.md) files in 'directory',
        read each playbook file, chunk the content by sections (using headers),
        create a LangChain Document for each section with the section content
        as page_content and playbook name and section title as metadata.
        Return a list of Documents."

        Then review and test the generated code.
        """
        pass

    def load_all_documents(self, data_dir: str) -> List[Document]:
        """Load all document types from data directory."""
        # TODO: Ask your AI assistant:
        # "Write Python code to load all documents from 'data_dir' by calling
        # load_cve_data for the 'cves' subdirectory, load_mitre_attack for
        # the 'mitre' subdirectory, and load_playbooks for the 'playbooks'
        # subdirectory. Combine and return all documents as a single list."
        #
        # Then review and test the generated code.
        pass


# =============================================================================
# Task 2: Text Chunking
# =============================================================================


def chunk_security_documents(
    documents: List[Document], chunk_size: int = 800, chunk_overlap: int = 100
) -> List[Document]:
    """
    Chunk documents for optimal retrieval.

    TODO: Ask your AI assistant:
    "Write Python code to chunk a list of LangChain Documents using
    RecursiveCharacterTextSplitter with the specified chunk_size and
    chunk_overlap. Preserve section boundaries where possible and ensure
    each chunk retains its original document metadata. Return the list
    of chunked Documents."

    Then review and test the generated code.
    """
    pass


# =============================================================================
# Task 3: Create Embeddings
# =============================================================================


def create_vector_store(chunks: List[Document], persist_directory: str = None) -> object:
    """
    Create vector store with embeddings.

    TODO: Ask your AI assistant:
    "Write Python code to create a ChromaDB vector store from a list of
    Document chunks. Initialize HuggingFaceEmbeddings as the embedding
    model, create the Chroma collection with the documents and embeddings,
    and optionally persist to disk at 'persist_directory' if provided.
    Return the vector store object."

    Then review and test the generated code.
    """
    pass


def load_vector_store(persist_directory: str) -> object:
    """Load existing vector store from disk."""
    # TODO: Ask your AI assistant:
    # "Write Python code to load an existing ChromaDB vector store from
    # 'persist_directory' using HuggingFaceEmbeddings. Return the loaded
    # vector store object."
    #
    # Then review and test the generated code.
    pass


# =============================================================================
# Task 4: Build Retriever
# =============================================================================


def create_security_retriever(vector_store, k: int = 5):
    """
    Create retriever with security-optimized settings.

    TODO: Ask your AI assistant:
    "Write Python code to create a retriever from a ChromaDB vector store.
    Configure it to use similarity search and return the top k most relevant
    documents. Return the retriever object."

    Then review and test the generated code.
    """
    pass


# =============================================================================
# Task 5: RAG Chain
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
        """
        Initialize the RAG system.

        Args:
            retriever: Document retriever
            llm: Language model client
        """
        self.retriever = retriever
        self.llm = llm

    def _format_context(self, documents: List[Document]) -> str:
        """Format retrieved documents into context string."""
        # TODO: Ask your AI assistant:
        # "Write Python code to format a list of LangChain Documents into
        # a single context string. Include each document's page_content and
        # relevant metadata (like source, cve_id, or technique_id) in a
        # readable format. Return the formatted context string."
        #
        # Then review and test the generated code.
        pass

    def query(self, question: str) -> dict:
        """
        Answer security question using RAG.

        TODO: Ask your AI assistant:
        "Write Python code for a RAG query method that: (1) uses self.retriever
        to get relevant documents for the question, (2) formats the documents
        into a context string using _format_context, (3) sends the question
        and context to self.llm using SECURITY_RAG_PROMPT, (4) parses the
        response and returns a dict with 'answer', 'sources' (list of source
        documents), and 'confidence' (float 0.0-1.0 based on retrieval scores)."

        Then review and test the generated code.
        """
        pass

    def query_with_filters(self, question: str, doc_type: str = None, severity: str = None) -> dict:
        """
        Query with metadata filters.

        TODO: Ask your AI assistant:
        "Write Python code to perform a filtered RAG query. Build a metadata
        filter dict from doc_type and severity parameters (if provided),
        apply the filter to the retriever search, retrieve matching documents,
        and generate a response using the LLM. Return a dict with 'answer',
        'sources', and 'confidence'."

        Then review and test the generated code.
        """
        pass


# =============================================================================
# Task 6: Evaluation
# =============================================================================


def evaluate_rag_system(rag: SecurityRAG, test_cases: List[dict]) -> dict:
    """
    Evaluate RAG system performance.

    Test case format:
    {
        "question": "What is CVE-2024-1234?",
        "expected_keywords": ["remote code execution", "critical"],
        "expected_sources": ["CVE-2024-1234"]
    }

    TODO: Ask your AI assistant:
    "Write Python code to evaluate a RAG system against test cases. For each
    test case, run rag.query() with the question, check if expected_keywords
    appear in the answer, verify expected_sources are in the returned sources,
    and calculate metrics including accuracy, keyword_recall, and source_recall.
    Return a dict with overall metrics and per-case results."

    Then review and test the generated code.
    """
    pass


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    console.print(Panel.fit("[bold]Lab 06: Security RAG System[/bold]", border_style="blue"))

    if not LANGCHAIN_AVAILABLE:
        console.print("[red]LangChain not available. Install required packages.[/red]")
        return

    data_dir = Path(__file__).parent.parent / "data"

    if not data_dir.exists():
        console.print("Creating sample data...")
        create_sample_data(data_dir)

    # Step 1: Load documents
    console.print("\n[yellow]Step 1:[/yellow] Loading documents...")
    loader = SecurityDocLoader()
    documents = loader.load_all_documents(str(data_dir))

    if not documents:
        console.print("[red]No documents loaded. Complete the TODO sections![/red]")
        return

    console.print(f"Loaded {len(documents)} documents")

    # Step 2: Chunk documents
    console.print("\n[yellow]Step 2:[/yellow] Chunking documents...")
    chunks = chunk_security_documents(documents)

    if not chunks:
        console.print("[red]No chunks created. Complete the TODO sections![/red]")
        return

    console.print(f"Created {len(chunks)} chunks")

    # Step 3: Create vector store
    console.print("\n[yellow]Step 3:[/yellow] Creating vector store...")
    vector_store = create_vector_store(chunks)

    if vector_store is None:
        console.print("[red]Vector store not created. Complete the TODO sections![/red]")
        return

    # Step 4: Create retriever
    console.print("\n[yellow]Step 4:[/yellow] Creating retriever...")
    retriever = create_security_retriever(vector_store)

    # Step 5: Initialize RAG
    console.print("\n[yellow]Step 5:[/yellow] Initializing RAG system...")
    # llm = ChatAnthropic(model="claude-sonnet-4-20250514")
    # rag = SecurityRAG(retriever, llm)

    # Step 6: Test queries
    console.print("\n[yellow]Step 6:[/yellow] Testing queries...")
    test_queries = [
        "What is CVE-2024-1234 and how do I mitigate it?",
        "How do attackers use PowerShell for execution?",
        "What are the first steps when responding to ransomware?",
    ]

    for query in test_queries:
        console.print(f"\n[bold]Query:[/bold] {query}")
        # result = rag.query(query)
        # console.print(f"[green]Answer:[/green] {result['answer'][:200]}...")

    console.print("\n" + "=" * 60)
    console.print("RAG system test complete!")


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
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        },
        {
            "cve_id": "CVE-2024-5678",
            "description": "SQL injection vulnerability in MySQL allows authenticated users to execute arbitrary SQL commands.",
            "cvss_score": 8.5,
            "severity": "HIGH",
            "affected_products": ["MySQL 8.0.x < 8.0.35"],
            "mitigation": "Update to MySQL 8.0.35 or later. Implement input validation.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
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
            "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.",
            "detection": "Monitor for loading of PowerShell modules. Enable PowerShell script block logging. Look for obfuscated commands.",
            "mitigations": [
                "Disable PowerShell for users who don't need it",
                "Enable Constrained Language Mode",
                "Use application whitelisting",
            ],
        },
        {
            "technique_id": "T1053.005",
            "name": "Scheduled Task",
            "tactic": "Persistence",
            "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
            "detection": "Monitor scheduled task creation via schtasks.exe, at.exe, or Task Scheduler MMC.",
            "mitigations": [
                "Restrict task creation permissions",
                "Monitor scheduled task changes",
            ],
        },
    ]

    mitre_dir = data_dir / "mitre"
    mitre_dir.mkdir(exist_ok=True)
    (mitre_dir / "attack_techniques.json").write_text(json.dumps(mitre, indent=2))

    # Sample playbook
    playbook_content = """# Ransomware Response Playbook

## Trigger Conditions
- Detection of ransomware indicators (file encryption, ransom notes)
- Alert from EDR/AV for ransomware family
- User report of encrypted files

## Immediate Actions (First 15 minutes)

1. **Isolate affected systems** - Disconnect from network immediately
2. **Preserve evidence** - Take memory dump if possible
3. **Identify scope** - Check for lateral movement indicators
4. **Notify stakeholders** - Alert security team, management

## Investigation Phase

1. Identify ransomware variant
2. Determine infection vector
3. Map affected systems and data
4. Check backup availability

## Remediation

1. Remove malware from affected systems
2. Restore from clean backups
3. Reset compromised credentials
4. Patch vulnerability exploited

## Recovery

1. Validate system integrity
2. Gradual network reconnection
3. Monitor for reinfection
4. Document lessons learned
"""

    playbook_dir = data_dir / "playbooks"
    playbook_dir.mkdir(exist_ok=True)
    (playbook_dir / "ransomware_response.md").write_text(playbook_content)

    console.print(f"Created sample data in {data_dir}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
RAG Agent Template

A reusable template for building Retrieval-Augmented Generation agents
for security documentation and knowledge bases.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain.chains import RetrievalQA
    from langchain.schema import Document
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_anthropic import ChatAnthropic
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print(
        "Install dependencies: pip install langchain langchain-anthropic chromadb sentence-transformers"
    )


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class RAGConfig:
    """Configuration for the RAG agent."""

    collection_name: str = "security_docs"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    persist_directory: str = "./chroma_db"
    llm_model: str = "claude-sonnet-4-5"


# =============================================================================
# Document Loaders
# =============================================================================


def load_markdown_docs(directory: str) -> List[Document]:
    """Load markdown documents from a directory."""
    documents = []
    path = Path(directory)

    for md_file in path.glob("**/*.md"):
        with open(md_file, "r", encoding="utf-8") as f:
            content = f.read()
            documents.append(
                Document(
                    page_content=content,
                    metadata={"source": str(md_file), "filename": md_file.name},
                )
            )

    return documents


def load_json_docs(filepath: str, content_key: str = "content") -> List[Document]:
    """Load documents from a JSON file."""
    import json

    documents = []
    with open(filepath, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        for item in data:
            content = item.get(content_key, str(item))
            documents.append(Document(page_content=content, metadata=item))

    return documents


# =============================================================================
# RAG Agent Class
# =============================================================================


class RAGAgent:
    """A reusable RAG agent for security knowledge bases."""

    def __init__(self, config: RAGConfig = None):
        self.config = config or RAGConfig()
        self.vectorstore = None
        self.qa_chain = None
        self.embeddings = None

        if LANGCHAIN_AVAILABLE:
            self._initialize_embeddings()

    def _initialize_embeddings(self):
        """Initialize the embedding model."""
        self.embeddings = HuggingFaceEmbeddings(model_name=self.config.embedding_model)

    def load_documents(self, documents: List[Document]):
        """Load and index documents."""
        if not LANGCHAIN_AVAILABLE:
            print("LangChain not available")
            return

        # Split documents into chunks
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.config.chunk_size, chunk_overlap=self.config.chunk_overlap
        )
        chunks = splitter.split_documents(documents)

        # Create vector store
        self.vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=self.embeddings,
            collection_name=self.config.collection_name,
            persist_directory=self.config.persist_directory,
        )

        # Create QA chain
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            llm = ChatAnthropic(model=self.config.llm_model, temperature=0)

            self.qa_chain = RetrievalQA.from_chain_type(
                llm=llm,
                chain_type="stuff",
                retriever=self.vectorstore.as_retriever(search_kwargs={"k": 5}),
            )

    def load_from_directory(self, directory: str):
        """Load documents from a directory."""
        documents = load_markdown_docs(directory)
        self.load_documents(documents)
        print(f"Loaded {len(documents)} documents")

    def query(self, question: str) -> str:
        """Query the knowledge base."""
        if not self.qa_chain:
            return "RAG agent not initialized. Load documents first."

        result = self.qa_chain.invoke(question)
        return result.get("result", str(result))

    def search(self, query: str, k: int = 5) -> List[Document]:
        """Search for relevant documents."""
        if not self.vectorstore:
            return []

        return self.vectorstore.similarity_search(query, k=k)


# =============================================================================
# Usage Example
# =============================================================================


def main():
    """Example usage of the RAG agent template."""
    print("RAG Agent Template")
    print("=" * 40)

    # Create sample documents
    sample_docs = [
        Document(
            page_content="SQL injection is a code injection technique that exploits security vulnerabilities in an application's database layer.",
            metadata={"topic": "vulnerabilities", "type": "definition"},
        ),
        Document(
            page_content="To prevent SQL injection, use parameterized queries or prepared statements instead of string concatenation.",
            metadata={"topic": "vulnerabilities", "type": "mitigation"},
        ),
        Document(
            page_content="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
            metadata={"topic": "vulnerabilities", "type": "definition"},
        ),
    ]

    # Initialize and load
    config = RAGConfig(collection_name="security_kb")
    agent = RAGAgent(config)
    agent.load_documents(sample_docs)

    # Query examples
    queries = [
        "What is SQL injection?",
        "How do I prevent SQL injection?",
        "What is XSS?",
    ]

    for query in queries:
        print(f"\nQuery: {query}")
        print("-" * 40)
        result = agent.query(query)
        print(f"Answer: {result}")


if __name__ == "__main__":
    main()

"""Tests for Lab 06a: Embeddings & Vectors."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab06a-embeddings-vectors" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        SECURITY_DOCUMENTS,
        calculate_similarity_matrix,
        create_tfidf_embeddings,
        similarity_search,
    )


def test_security_documents_defined():
    """Test that security documents are defined."""
    from main import SECURITY_DOCUMENTS

    assert len(SECURITY_DOCUMENTS) > 0
    # Should have mix of malicious and benign
    assert any("malware" in doc.lower() or "virus" in doc.lower() for doc in SECURITY_DOCUMENTS)
    assert any("successful" in doc.lower() or "normal" in doc.lower() for doc in SECURITY_DOCUMENTS)


def test_tfidf_embeddings():
    """Test TF-IDF embedding creation."""
    from main import create_tfidf_embeddings

    documents = ["test document one", "another test document"]
    vectorizer, embeddings = create_tfidf_embeddings(documents)

    assert embeddings.shape[0] == 2  # Two documents
    assert embeddings.shape[1] > 0  # Some features


def test_similarity_search():
    """Test similarity search functionality."""
    from main import SECURITY_DOCUMENTS, create_tfidf_embeddings, similarity_search

    vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
    results = similarity_search("malware infection", vectorizer, embeddings, SECURITY_DOCUMENTS)

    assert len(results) > 0
    # Results should be tuples of (index, similarity, document)
    for result in results:
        assert len(result) == 3
        assert 0 <= result[1] <= 1  # Similarity score


def test_similarity_matrix():
    """Test similarity matrix calculation."""
    from main import SECURITY_DOCUMENTS, calculate_similarity_matrix, create_tfidf_embeddings

    vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
    matrix = calculate_similarity_matrix(embeddings)

    # Should be square matrix
    assert matrix.shape[0] == matrix.shape[1]
    assert matrix.shape[0] == len(SECURITY_DOCUMENTS)
    # Diagonal should be 1.0 (self-similarity)
    for i in range(len(SECURITY_DOCUMENTS)):
        assert abs(matrix[i][i] - 1.0) < 0.01

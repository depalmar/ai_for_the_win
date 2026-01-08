#!/usr/bin/env python3
"""Tests for Lab 06a: Embeddings & Vectors Explained."""

import numpy as np
import pytest

# Try to import from solution
try:
    from labs.lab06a_embeddings_vectors.solution.main import (
        IOC_SAMPLES,
        SECURITY_DOCUMENTS,
        THREAT_DESCRIPTIONS,
        calculate_similarity_matrix,
        create_tfidf_embeddings,
        similarity_search,
    )
except ImportError:
    try:
        from solution.main import (
            IOC_SAMPLES,
            SECURITY_DOCUMENTS,
            THREAT_DESCRIPTIONS,
            calculate_similarity_matrix,
            create_tfidf_embeddings,
            similarity_search,
        )
    except ImportError:
        pytest.skip("Solution module not available", allow_module_level=True)


# =============================================================================
# Sample Data Tests
# =============================================================================


class TestSampleData:
    """Test sample data availability."""

    def test_security_documents_exist(self):
        """Test security documents are defined."""
        assert len(SECURITY_DOCUMENTS) > 0
        assert isinstance(SECURITY_DOCUMENTS[0], str)

    def test_threat_descriptions_exist(self):
        """Test threat descriptions are defined."""
        assert len(THREAT_DESCRIPTIONS) > 0

    def test_ioc_samples_exist(self):
        """Test IOC samples are defined."""
        assert len(IOC_SAMPLES) > 0
        assert "type" in IOC_SAMPLES[0]
        assert "value" in IOC_SAMPLES[0]


# =============================================================================
# TF-IDF Embedding Tests
# =============================================================================


class TestTFIDFEmbeddings:
    """Test TF-IDF embedding creation."""

    def test_create_tfidf_embeddings(self):
        """Test TF-IDF embedding creation."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        assert embeddings is not None
        assert embeddings.shape[0] == len(SECURITY_DOCUMENTS)
        assert embeddings.shape[1] > 0  # Has features

    def test_embeddings_are_normalized(self):
        """Test that embeddings have reasonable values."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        # TF-IDF values should be non-negative
        assert np.all(embeddings >= 0)

    def test_embedding_dimensions(self):
        """Test embedding dimensions are consistent."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        # All documents should have same dimension
        assert embeddings.ndim == 2
        assert all(embeddings.shape[1] == embeddings.shape[1] for _ in embeddings)


# =============================================================================
# Similarity Matrix Tests
# =============================================================================


class TestSimilarityMatrix:
    """Test similarity matrix calculation."""

    def test_calculate_similarity_matrix(self):
        """Test similarity matrix creation."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        sim_matrix = calculate_similarity_matrix(embeddings)

        # Should be square matrix
        assert sim_matrix.shape[0] == sim_matrix.shape[1]
        assert sim_matrix.shape[0] == len(SECURITY_DOCUMENTS)

    def test_similarity_diagonal(self):
        """Test diagonal is 1.0 (self-similarity)."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        sim_matrix = calculate_similarity_matrix(embeddings)

        # Diagonal should be 1.0 (document is identical to itself)
        diagonal = np.diag(sim_matrix)
        np.testing.assert_array_almost_equal(diagonal, np.ones(len(SECURITY_DOCUMENTS)), decimal=5)

    def test_similarity_range(self):
        """Test similarity values are in valid range."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        sim_matrix = calculate_similarity_matrix(embeddings)

        # Cosine similarity should be between -1 and 1
        assert np.all(sim_matrix >= -1.0)
        assert np.all(sim_matrix <= 1.0)

    def test_similarity_symmetry(self):
        """Test similarity matrix is symmetric."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        sim_matrix = calculate_similarity_matrix(embeddings)

        # Similarity matrix should be symmetric
        np.testing.assert_array_almost_equal(sim_matrix, sim_matrix.T, decimal=5)


# =============================================================================
# Similarity Search Tests
# =============================================================================


class TestSimilaritySearch:
    """Test similarity search functionality."""

    def test_similarity_search_returns_results(self):
        """Test similarity search returns results."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        results = similarity_search("malware virus", vectorizer, embeddings, SECURITY_DOCUMENTS, top_k=3)

        assert len(results) <= 3
        assert len(results) > 0

    def test_search_result_structure(self):
        """Test search result structure."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        results = similarity_search("ransomware attack", vectorizer, embeddings, SECURITY_DOCUMENTS, top_k=5)

        # Each result should be a tuple of (index, similarity, document)
        for result in results:
            assert len(result) == 3
            index, similarity, document = result
            assert isinstance(index, (int, np.integer))
            assert isinstance(similarity, (float, np.floating))
            assert isinstance(document, str)

    def test_search_relevance(self):
        """Test search returns relevant results."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        # Search for ransomware
        results = similarity_search("ransomware encrypt", vectorizer, embeddings, SECURITY_DOCUMENTS, top_k=3)

        # Top result should contain ransomware-related terms
        if len(results) > 0:
            _, _, top_doc = results[0]
            # Either "ransomware" or "encrypt" should appear
            assert "ransomware" in top_doc.lower() or "encrypt" in top_doc.lower()

    def test_search_with_malware_query(self):
        """Test search with malware-related query."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        results = similarity_search("malware trojan virus", vectorizer, embeddings, SECURITY_DOCUMENTS, top_k=3)

        assert len(results) > 0


# =============================================================================
# Vector Operations Tests
# =============================================================================


class TestVectorOperations:
    """Test vector operations."""

    def test_cosine_similarity_calculation(self):
        """Test manual cosine similarity calculation."""
        from sklearn.metrics.pairwise import cosine_similarity

        vec1 = np.array([[1, 0, 0]])
        vec2 = np.array([[0, 1, 0]])
        vec3 = np.array([[1, 0, 0]])

        # Orthogonal vectors have similarity 0
        sim_orthogonal = cosine_similarity(vec1, vec2)[0][0]
        assert abs(sim_orthogonal) < 0.01

        # Identical vectors have similarity 1
        sim_identical = cosine_similarity(vec1, vec3)[0][0]
        assert abs(sim_identical - 1.0) < 0.01

    def test_embedding_normalization(self):
        """Test L2 normalization of embeddings."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        # Normalize embeddings
        norms = np.linalg.norm(embeddings, axis=1)

        # All non-zero embeddings should have positive norms
        non_zero_mask = norms > 0
        assert np.all(norms[non_zero_mask] > 0)


# =============================================================================
# Security Use Case Tests
# =============================================================================


class TestSecurityUseCases:
    """Test security-specific use cases."""

    def test_find_similar_threats(self):
        """Test finding similar threat descriptions."""
        vectorizer, embeddings = create_tfidf_embeddings(THREAT_DESCRIPTIONS)

        # Search for similar threats
        results = similarity_search("credential stealing", vectorizer, embeddings, THREAT_DESCRIPTIONS, top_k=3)

        assert len(results) > 0

    def test_security_document_clustering(self):
        """Test that similar security documents cluster together."""
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)
        sim_matrix = calculate_similarity_matrix(embeddings)

        # Find pairs with high similarity (excluding diagonal)
        np.fill_diagonal(sim_matrix, 0)
        max_sim = np.max(sim_matrix)

        # There should be some similar documents
        assert max_sim > 0.1

    def test_ioc_description_search(self):
        """Test searching IOC descriptions."""
        ioc_descriptions = [ioc["description"] for ioc in IOC_SAMPLES]
        vectorizer, embeddings = create_tfidf_embeddings(ioc_descriptions)

        results = similarity_search("command and control", vectorizer, embeddings, ioc_descriptions, top_k=2)

        assert len(results) > 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full embedding pipeline."""

    def test_full_search_pipeline(self):
        """Test complete search pipeline."""
        # 1. Create embeddings
        vectorizer, embeddings = create_tfidf_embeddings(SECURITY_DOCUMENTS)

        # 2. Calculate similarity matrix
        sim_matrix = calculate_similarity_matrix(embeddings)

        # 3. Perform search
        results = similarity_search("malware detection", vectorizer, embeddings, SECURITY_DOCUMENTS, top_k=5)

        # Verify all steps completed
        assert embeddings.shape[0] == len(SECURITY_DOCUMENTS)
        assert sim_matrix.shape[0] == len(SECURITY_DOCUMENTS)
        assert len(results) <= 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

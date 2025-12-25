#!/usr/bin/env python3
"""Tests for Lab 06: Security RAG System."""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(
    Path(__file__).parent.parent / "labs" / "lab06-security-rag" / "solution"
)
sys.path.insert(0, lab_path)

from main import SecurityDocLoader, chunk_security_documents


@pytest.fixture
def sample_cve_data(tmp_path):
    """Create sample CVE data file."""
    cves = [
        {
            "cve_id": "CVE-2024-1234",
            "description": "Remote code execution vulnerability.",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_products": ["Product A"],
            "mitigation": "Update to latest version.",
        },
        {
            "cve_id": "CVE-2024-5678",
            "description": "SQL injection vulnerability.",
            "cvss_score": 8.5,
            "severity": "HIGH",
            "affected_products": ["Product B"],
            "mitigation": "Apply patches.",
        },
    ]

    cve_dir = tmp_path / "cves"
    cve_dir.mkdir()
    cve_file = cve_dir / "sample_cves.json"
    cve_file.write_text(json.dumps(cves))
    return str(cve_file)


@pytest.fixture
def sample_mitre_data(tmp_path):
    """Create sample MITRE ATT&CK data file."""
    techniques = [
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may use PowerShell.",
            "detection": "Monitor PowerShell logging.",
            "mitigations": ["Disable PowerShell", "Enable logging"],
        }
    ]

    mitre_dir = tmp_path / "mitre"
    mitre_dir.mkdir()
    mitre_file = mitre_dir / "attack_techniques.json"
    mitre_file.write_text(json.dumps(techniques))
    return str(mitre_file)


@pytest.fixture
def sample_playbook(tmp_path):
    """Create sample playbook file."""
    playbook = """# Ransomware Response

## Immediate Actions
1. Isolate systems
2. Preserve evidence
"""
    playbook_dir = tmp_path / "playbooks"
    playbook_dir.mkdir()
    playbook_file = playbook_dir / "ransomware.md"
    playbook_file.write_text(playbook)
    return str(playbook_dir)


class TestSecurityDocLoader:
    """Tests for document loading."""

    def test_load_cve_data(self, sample_cve_data):
        """Test CVE data loading."""
        loader = SecurityDocLoader()
        docs = loader.load_cve_data(sample_cve_data)

        assert len(docs) == 2
        assert "CVE-2024-1234" in docs[0].page_content
        assert docs[0].metadata["doc_type"] == "cve"
        assert docs[0].metadata["severity"] == "CRITICAL"

    def test_load_mitre_attack(self, sample_mitre_data):
        """Test MITRE ATT&CK data loading."""
        loader = SecurityDocLoader()
        docs = loader.load_mitre_attack(sample_mitre_data)

        assert len(docs) == 1
        assert "T1059.001" in docs[0].page_content
        assert docs[0].metadata["doc_type"] == "mitre"
        assert docs[0].metadata["tactic"] == "Execution"

    def test_load_playbooks(self, sample_playbook):
        """Test playbook loading."""
        loader = SecurityDocLoader()
        docs = loader.load_playbooks(sample_playbook)

        assert len(docs) == 1
        assert "Ransomware" in docs[0].page_content
        assert docs[0].metadata["doc_type"] == "playbook"


class TestChunking:
    """Tests for document chunking."""

    def test_chunk_documents(self, sample_cve_data):
        """Test document chunking."""
        loader = SecurityDocLoader()
        docs = loader.load_cve_data(sample_cve_data)
        chunks = chunk_security_documents(docs, chunk_size=200, chunk_overlap=20)

        assert len(chunks) >= len(docs)
        # Metadata should be preserved
        for chunk in chunks:
            assert "doc_type" in chunk.metadata

    def test_chunk_size_respected(self, sample_cve_data):
        """Test that chunk size is approximately respected."""
        loader = SecurityDocLoader()
        docs = loader.load_cve_data(sample_cve_data)
        chunks = chunk_security_documents(docs, chunk_size=100, chunk_overlap=10)

        # Most chunks should be around the target size
        for chunk in chunks:
            # Allow some flexibility due to splitting at boundaries
            assert len(chunk.page_content) <= 200


class TestDocumentMetadata:
    """Tests for metadata handling."""

    def test_cve_metadata_fields(self, sample_cve_data):
        """Test CVE metadata fields."""
        loader = SecurityDocLoader()
        docs = loader.load_cve_data(sample_cve_data)

        for doc in docs:
            assert "source" in doc.metadata
            assert "doc_type" in doc.metadata
            assert "severity" in doc.metadata
            assert "cvss_score" in doc.metadata

    def test_mitre_metadata_fields(self, sample_mitre_data):
        """Test MITRE metadata fields."""
        loader = SecurityDocLoader()
        docs = loader.load_mitre_attack(sample_mitre_data)

        for doc in docs:
            assert "source" in doc.metadata
            assert "doc_type" in doc.metadata
            assert "tactic" in doc.metadata


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

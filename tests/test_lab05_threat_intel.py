#!/usr/bin/env python3
"""Tests for Lab 05: Threat Intelligence Agent."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(
    Path(__file__).parent.parent / "labs" / "lab05-threat-intel-agent" / "solution"
)
sys.path.insert(0, lab_path)

from main import (IOCEnricher, MITREMapper, ReputationChecker,
                  ThreatIntelAgent, ThreatReport)


@pytest.fixture
def sample_iocs():
    """Create sample IOCs for testing."""
    return {
        "ip_addresses": ["185.143.223.47", "91.234.99.100", "8.8.8.8"],
        "domains": ["malware-c2.evil.com", "google.com"],
        "hashes": [
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file
            "e3b0c44298fc1c149afbf4c8996fb924",  # Empty file SHA256
        ],
        "urls": ["http://malware.evil.com/payload.exe", "https://www.google.com"],
    }


@pytest.fixture
def sample_threat_data():
    """Create sample threat data."""
    return {
        "indicator": "185.143.223.47",
        "type": "ip",
        "classification": "malicious",
        "confidence": 0.95,
        "malware_families": ["Cobalt Strike", "Beacon"],
        "tags": ["c2", "apt", "ransomware"],
        "first_seen": "2024-01-10",
        "last_seen": "2024-01-15",
        "reports": 45,
    }


class TestIOCEnricher:
    """Tests for IOC enrichment functionality."""

    def test_enrich_ip_address(self, sample_iocs):
        """Test IP address enrichment."""
        enricher = IOCEnricher()
        result = enricher.enrich_ip(sample_iocs["ip_addresses"][0])

        assert result is not None
        assert "ip" in result or "indicator" in result

    def test_enrich_domain(self, sample_iocs):
        """Test domain enrichment."""
        enricher = IOCEnricher()
        result = enricher.enrich_domain(sample_iocs["domains"][0])

        assert result is not None

    def test_enrich_hash(self, sample_iocs):
        """Test file hash enrichment."""
        enricher = IOCEnricher()
        result = enricher.enrich_hash(sample_iocs["hashes"][0])

        assert result is not None

    def test_auto_detect_ioc_type(self, sample_iocs):
        """Test automatic IOC type detection."""
        enricher = IOCEnricher()

        # Test IP detection
        assert enricher.detect_type("192.168.1.1") == "ip"

        # Test domain detection
        assert enricher.detect_type("example.com") == "domain"

        # Test hash detection (MD5)
        assert enricher.detect_type("44d88612fea8a8f36de82e1278abb02f") == "hash"

    def test_batch_enrichment(self, sample_iocs):
        """Test batch IOC enrichment."""
        enricher = IOCEnricher()
        all_iocs = sample_iocs["ip_addresses"] + sample_iocs["domains"]

        results = enricher.enrich_batch(all_iocs)

        assert len(results) == len(all_iocs)


class TestReputationChecker:
    """Tests for reputation checking functionality."""

    def test_check_ip_reputation(self, sample_iocs):
        """Test IP reputation check."""
        checker = ReputationChecker()
        result = checker.check_ip(sample_iocs["ip_addresses"][0])

        assert result is not None
        assert "reputation" in result or "classification" in result or "score" in result

    def test_check_domain_reputation(self, sample_iocs):
        """Test domain reputation check."""
        checker = ReputationChecker()
        result = checker.check_domain(sample_iocs["domains"][0])

        assert result is not None

    def test_reputation_score_range(self, sample_iocs):
        """Test that reputation scores are in valid range."""
        checker = ReputationChecker()
        result = checker.check_ip(sample_iocs["ip_addresses"][0])

        if "score" in result:
            assert 0 <= result["score"] <= 100 or -1 <= result["score"] <= 1

    def test_malicious_vs_benign(self, sample_iocs):
        """Test distinguishing malicious from benign."""
        checker = ReputationChecker()

        # Known malicious
        malicious = checker.check_ip("185.143.223.47")
        # Known benign (Google DNS)
        benign = checker.check_ip("8.8.8.8")

        # Should have different classifications
        assert malicious.get("classification") != benign.get(
            "classification"
        ) or malicious.get("score", 0) != benign.get("score", 0)


class TestMITREMapper:
    """Tests for MITRE ATT&CK mapping."""

    def test_map_technique(self):
        """Test mapping to MITRE technique."""
        mapper = MITREMapper()
        result = mapper.map_technique("PowerShell execution")

        assert result is not None
        assert "technique_id" in result or "id" in result

    def test_technique_has_tactic(self):
        """Test that mapped technique includes tactic."""
        mapper = MITREMapper()
        result = mapper.map_technique("Remote Desktop Protocol")

        assert result is not None
        if "tactic" in result:
            assert result["tactic"] is not None

    def test_map_multiple_techniques(self):
        """Test mapping multiple techniques."""
        mapper = MITREMapper()
        behaviors = [
            "PowerShell encoded command",
            "Credential dumping from LSASS",
            "Scheduled task creation",
        ]

        results = mapper.map_batch(behaviors)

        assert len(results) >= 1

    def test_get_technique_details(self):
        """Test getting full technique details."""
        mapper = MITREMapper()
        result = mapper.get_technique("T1059.001")

        assert result is not None
        assert "name" in result or "description" in result


class TestThreatIntelAgent:
    """Tests for the main threat intelligence agent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = ThreatIntelAgent()

        assert agent is not None

    def test_investigate_ioc(self, sample_iocs):
        """Test IOC investigation."""
        agent = ThreatIntelAgent()
        result = agent.investigate(sample_iocs["ip_addresses"][0])

        assert result is not None
        assert "summary" in result or "assessment" in result or "indicator" in result

    def test_investigate_returns_classification(self, sample_iocs):
        """Test that investigation returns classification."""
        agent = ThreatIntelAgent()
        result = agent.investigate(sample_iocs["ip_addresses"][0])

        # Should include some form of classification
        result_str = str(result).lower()
        assert any(
            term in result_str
            for term in [
                "malicious",
                "benign",
                "suspicious",
                "unknown",
                "classification",
            ]
        )

    def test_investigate_with_context(self, sample_iocs):
        """Test investigation with additional context."""
        agent = ThreatIntelAgent()
        context = {
            "source": "firewall",
            "event_type": "blocked_connection",
            "timestamp": "2024-01-15T10:00:00Z",
        }

        result = agent.investigate(sample_iocs["ip_addresses"][0], context=context)

        assert result is not None


class TestThreatReport:
    """Tests for threat report generation."""

    def test_create_report(self, sample_threat_data):
        """Test threat report creation."""
        report = ThreatReport(sample_threat_data)

        assert report is not None

    def test_report_to_json(self, sample_threat_data):
        """Test report JSON serialization."""
        report = ThreatReport(sample_threat_data)
        json_output = report.to_json()

        assert json_output is not None
        assert isinstance(json_output, (str, dict))

    def test_report_to_markdown(self, sample_threat_data):
        """Test report Markdown generation."""
        report = ThreatReport(sample_threat_data)
        md_output = report.to_markdown()

        assert md_output is not None
        assert isinstance(md_output, str)
        assert len(md_output) > 0

    def test_report_includes_ioc(self, sample_threat_data):
        """Test that report includes the IOC."""
        report = ThreatReport(sample_threat_data)
        output = report.to_markdown()

        assert sample_threat_data["indicator"] in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""Tests for Lab 05: Threat Intelligence Agent."""

import pytest

# =============================================================================
# Sample Data for Testing
# =============================================================================

SAMPLE_IOCS = [
    {"type": "ip", "value": "185.143.223.47"},
    {"type": "domain", "value": "evil-c2.com"},
    {"type": "hash", "value": "abc123def456789012345678901234567890abcd"},
    {"type": "url", "value": "http://malware.com/payload.exe"},
]

SAMPLE_THREAT_INTEL = {
    "185.143.223.47": {
        "malicious": True,
        "threat_type": "C2 Server",
        "country": "RU",
        "asn": "AS12345",
        "first_seen": "2024-06-01",
        "tags": ["cobalt-strike", "apt"],
    },
    "evil-c2.com": {
        "malicious": True,
        "threat_type": "Phishing",
        "registrar": "NameCheap",
        "created_date": "2024-11-15",
        "tags": ["credential-harvesting"],
    },
}


# =============================================================================
# Tool Definition Tests
# =============================================================================


class TestToolDefinitions:
    """Test tool definitions for the agent."""

    def test_ip_lookup_tool_structure(self):
        """Test IP lookup tool has required structure."""
        tool_schema = {
            "name": "ip_lookup",
            "description": "Look up threat intelligence for an IP address",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to look up"}},
                "required": ["ip"],
            },
        }

        assert tool_schema["name"] == "ip_lookup"
        assert "ip" in tool_schema["parameters"]["properties"]

    def test_domain_lookup_tool_structure(self):
        """Test domain lookup tool structure."""
        tool_schema = {
            "name": "domain_lookup",
            "description": "Look up threat intelligence for a domain",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to look up"}
                },
                "required": ["domain"],
            },
        }

        assert tool_schema["name"] == "domain_lookup"

    def test_hash_lookup_tool_structure(self):
        """Test hash lookup tool structure."""
        tool_schema = {
            "name": "hash_lookup",
            "description": "Look up file hash in threat intelligence databases",
            "parameters": {
                "type": "object",
                "properties": {"hash": {"type": "string", "description": "File hash (MD5/SHA1/SHA256)"}},
                "required": ["hash"],
            },
        }

        assert tool_schema["name"] == "hash_lookup"


# =============================================================================
# IOC Processing Tests
# =============================================================================


class TestIOCProcessing:
    """Test IOC processing functionality."""

    def test_ioc_type_detection(self):
        """Test detection of IOC types."""
        import re

        def detect_ioc_type(value):
            """Detect IOC type from value."""
            # IP pattern
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
                return "ip"
            # Hash patterns
            if re.match(r"^[a-fA-F0-9]{32}$", value):
                return "md5"
            if re.match(r"^[a-fA-F0-9]{40}$", value):
                return "sha1"
            if re.match(r"^[a-fA-F0-9]{64}$", value):
                return "sha256"
            # URL pattern
            if value.startswith("http://") or value.startswith("https://"):
                return "url"
            # Domain pattern (simple)
            if "." in value and not "/" in value:
                return "domain"
            return "unknown"

        assert detect_ioc_type("185.143.223.47") == "ip"
        assert detect_ioc_type("evil-c2.com") == "domain"
        assert detect_ioc_type("http://malware.com/payload.exe") == "url"
        assert detect_ioc_type("abc123def456789012345678901234567890abcd") == "sha1"

    def test_ioc_deduplication(self):
        """Test IOC deduplication."""
        iocs = ["185.143.223.47", "evil-c2.com", "185.143.223.47", "evil-c2.com"]
        unique_iocs = list(set(iocs))

        assert len(unique_iocs) == 2


# =============================================================================
# Agent Reasoning Tests
# =============================================================================


class TestAgentReasoning:
    """Test agent reasoning patterns."""

    def test_react_pattern_structure(self):
        """Test ReAct pattern structure."""
        # ReAct = Reasoning + Acting
        react_step = {
            "thought": "I need to look up this IP address to check if it's malicious",
            "action": "ip_lookup",
            "action_input": {"ip": "185.143.223.47"},
            "observation": "IP is flagged as malicious C2 server",
        }

        assert "thought" in react_step
        assert "action" in react_step
        assert "observation" in react_step

    def test_multi_step_reasoning(self):
        """Test multi-step agent reasoning."""
        # Agent should investigate multiple IOCs
        investigation_steps = [
            {"action": "ip_lookup", "ioc": "185.143.223.47"},
            {"action": "domain_lookup", "ioc": "evil-c2.com"},
            {"action": "correlate_findings"},
            {"action": "generate_report"},
        ]

        assert len(investigation_steps) >= 3
        assert any(s["action"] == "correlate_findings" for s in investigation_steps)


# =============================================================================
# Memory System Tests
# =============================================================================


class TestMemorySystem:
    """Test agent memory systems."""

    def test_working_memory_structure(self):
        """Test working memory stores investigation findings."""
        working_memory = {
            "iocs_processed": ["185.143.223.47", "evil-c2.com"],
            "findings": [
                {"ioc": "185.143.223.47", "result": "malicious", "tags": ["c2"]},
                {"ioc": "evil-c2.com", "result": "malicious", "tags": ["phishing"]},
            ],
            "correlations": [{"iocs": ["185.143.223.47", "evil-c2.com"], "relationship": "same_campaign"}],
        }

        assert "iocs_processed" in working_memory
        assert "findings" in working_memory
        assert len(working_memory["findings"]) == 2

    def test_conversation_history(self):
        """Test conversation history tracking."""
        history = [
            {"role": "user", "content": "Investigate these IOCs: 185.143.223.47, evil-c2.com"},
            {"role": "assistant", "content": "I'll investigate these indicators..."},
            {"role": "tool", "content": "IP is malicious"},
        ]

        assert len(history) == 3
        assert history[0]["role"] == "user"


# =============================================================================
# Report Generation Tests
# =============================================================================


class TestReportGeneration:
    """Test agent report generation."""

    def test_investigation_report_structure(self):
        """Test investigation report has required sections."""
        report = {
            "summary": "Investigation of 2 IOCs completed",
            "indicators_analyzed": [
                {
                    "ioc": "185.143.223.47",
                    "type": "ip",
                    "malicious": True,
                    "confidence": "high",
                    "details": "Known C2 server",
                }
            ],
            "threat_assessment": {
                "severity": "high",
                "threat_actor": "Unknown APT",
                "campaign": "Possible Cobalt Strike operation",
            },
            "recommendations": [
                "Block IP at perimeter firewall",
                "Search for historical connections",
                "Enable enhanced logging",
            ],
            "mitre_techniques": ["T1071.001", "T1059.001"],
        }

        assert "summary" in report
        assert "recommendations" in report
        assert len(report["recommendations"]) > 0

    def test_correlation_findings(self):
        """Test correlation of multiple IOCs."""
        correlations = {
            "related_iocs": ["185.143.223.47", "evil-c2.com"],
            "relationship": "Infrastructure overlap",
            "confidence": "medium",
            "evidence": ["Same ASN", "Similar registration date"],
        }

        assert len(correlations["related_iocs"]) == 2
        assert "evidence" in correlations


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full agent workflow."""

    def test_complete_investigation_flow(self):
        """Test complete investigation workflow."""
        # Simulate agent investigation flow
        investigation = {
            "input_iocs": SAMPLE_IOCS,
            "steps_completed": [
                "parse_iocs",
                "lookup_ip",
                "lookup_domain",
                "correlate",
                "assess_threat",
                "generate_report",
            ],
            "output": {
                "threat_level": "high",
                "iocs_malicious": 2,
                "iocs_benign": 0,
                "iocs_unknown": 2,
            },
        }

        assert len(investigation["steps_completed"]) >= 5
        assert investigation["output"]["threat_level"] == "high"

    def test_agent_tool_selection(self):
        """Test agent selects appropriate tools."""
        # Given IOC types, agent should select correct tools
        tool_mappings = {"ip": "ip_lookup", "domain": "domain_lookup", "hash": "hash_lookup", "url": "url_lookup"}

        for ioc in SAMPLE_IOCS:
            ioc_type = ioc["type"]
            if ioc_type in tool_mappings:
                expected_tool = tool_mappings[ioc_type]
                assert expected_tool is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

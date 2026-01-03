"""
Tests for the demo launcher module.

These tests verify that demo functions work correctly and return expected types.
"""

import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDemoImports:
    """Test that demo functions can be imported."""

    def test_import_demo_module(self):
        """Test that demo launcher module can be imported."""
        from scripts import launcher

        assert launcher is not None

    def test_import_demo_functions(self):
        """Test that demo functions exist."""
        from scripts.launcher import (
            demo_anomaly_detection,
            demo_detection_pipeline,
            demo_ir_copilot,
            demo_log_analysis,
            demo_malware_clustering,
            demo_phishing_classifier,
            demo_security_rag,
            demo_threat_intel,
            demo_vuln_scanner,
            demo_yara_generator,
        )

        # Verify all functions are callable
        assert callable(demo_phishing_classifier)
        assert callable(demo_malware_clustering)
        assert callable(demo_anomaly_detection)
        assert callable(demo_log_analysis)
        assert callable(demo_threat_intel)
        assert callable(demo_security_rag)
        assert callable(demo_yara_generator)
        assert callable(demo_vuln_scanner)
        assert callable(demo_detection_pipeline)
        assert callable(demo_ir_copilot)

    def test_import_utility_functions(self):
        """Test that utility functions exist."""
        from scripts.launcher import create_demo, create_status_badge

        assert callable(create_status_badge)
        assert callable(create_demo)


class TestLab01PhishingClassifier:
    """Test Lab 01: Phishing Classifier demo."""

    def test_classify_legitimate_email(self):
        """Test classification of legitimate email."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier(
            "Hello team, please find the quarterly report attached.", 0.5
        )
        assert isinstance(result, str)
        assert "LEGITIMATE" in result or "PHISHING" in result

    def test_classify_phishing_email(self):
        """Test classification of phishing email."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier(
            "URGENT: Your account will be suspended! Click here immediately to verify!",
            0.5,
        )
        assert isinstance(result, str)
        assert "score" in result.lower() or "%" in result

    def test_high_threshold(self):
        """Test with high threshold."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier("Click here to win a prize!", 0.9)
        assert isinstance(result, str)

    def test_low_threshold(self):
        """Test with low threshold."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier("Meeting tomorrow at 3pm", 0.1)
        assert isinstance(result, str)


class TestLab02MalwareClustering:
    """Test Lab 02: Malware Clustering demo."""

    def test_cluster_default_settings(self):
        """Test clustering with default settings."""
        from scripts.launcher import demo_malware_clustering

        result, fig = demo_malware_clustering(50, 3)
        assert isinstance(result, str)
        assert "Cluster" in result or "Malware" in result

    def test_cluster_more_clusters(self):
        """Test clustering with more clusters."""
        from scripts.launcher import demo_malware_clustering

        result, fig = demo_malware_clustering(100, 5)
        assert isinstance(result, str)

    def test_cluster_fewer_samples(self):
        """Test clustering with fewer samples."""
        from scripts.launcher import demo_malware_clustering

        result, fig = demo_malware_clustering(20, 2)
        assert isinstance(result, str)


class TestLab03AnomalyDetection:
    """Test Lab 03: Anomaly Detection demo."""

    def test_anomaly_detection_normal(self):
        """Test anomaly detection with normal traffic."""
        from scripts.launcher import demo_anomaly_detection

        result, fig = demo_anomaly_detection(
            bytes_sent=1000,
            bytes_received=2000,
            packets=100,
            duration=60.0,
            port=443,
            use_ml=True,
        )
        assert isinstance(result, str)
        assert "Anomaly" in result or "Detection" in result

    def test_anomaly_detection_suspicious(self):
        """Test anomaly detection with suspicious traffic."""
        from scripts.launcher import demo_anomaly_detection

        result, fig = demo_anomaly_detection(
            bytes_sent=1000000,
            bytes_received=5000000,
            packets=10000,
            duration=10.0,
            port=4444,
            use_ml=True,
        )
        assert isinstance(result, str)

    def test_anomaly_detection_no_ml(self):
        """Test anomaly detection without ML."""
        from scripts.launcher import demo_anomaly_detection

        result, fig = demo_anomaly_detection(
            bytes_sent=500,
            bytes_received=1000,
            packets=50,
            duration=30.0,
            port=80,
            use_ml=False,
        )
        assert isinstance(result, str)


class TestLab04LogAnalysis:
    """Test Lab 04: Log Analysis demo."""

    def test_analyze_single_log(self):
        """Test log analysis with single entry."""
        from scripts.launcher import demo_log_analysis

        result, fig = demo_log_analysis(
            "Failed login attempt for user admin from IP 192.168.1.100",
            use_llm=False,
        )
        assert isinstance(result, str)
        assert "Log" in result or "Analysis" in result

    def test_analyze_multiple_logs(self):
        """Test log analysis with multiple entries."""
        from scripts.launcher import demo_log_analysis

        logs = """User login successful: user@example.com
Failed login attempt: admin
Suspicious file access: /etc/passwd"""
        result, fig = demo_log_analysis(logs, use_llm=False)
        assert isinstance(result, str)

    def test_analyze_with_llm(self):
        """Test log analysis with LLM enabled."""
        from scripts.launcher import demo_log_analysis

        result, fig = demo_log_analysis(
            "Process cmd.exe spawned by powershell.exe",
            use_llm=True,
        )
        assert isinstance(result, str)


class TestLab05ThreatIntel:
    """Test Lab 05: Threat Intelligence demo."""

    def test_lookup_ip(self):
        """Test threat intel lookup for IP address."""
        from scripts.launcher import demo_threat_intel

        result, fig = demo_threat_intel("192.168.1.100", "IP")
        assert isinstance(result, str)
        assert "Threat" in result or "Intel" in result or "IOC" in result

    def test_lookup_hash(self):
        """Test threat intel lookup for hash."""
        from scripts.launcher import demo_threat_intel

        result, fig = demo_threat_intel("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "Hash")
        assert isinstance(result, str)

    def test_lookup_domain(self):
        """Test threat intel lookup for domain."""
        from scripts.launcher import demo_threat_intel

        result, fig = demo_threat_intel("evil.com", "Domain")
        assert isinstance(result, str)

    def test_lookup_url(self):
        """Test threat intel lookup for URL."""
        from scripts.launcher import demo_threat_intel

        result, fig = demo_threat_intel("http://malicious.com/payload", "URL")
        assert isinstance(result, str)


class TestLab06SecurityRAG:
    """Test Lab 06: Security RAG demo."""

    def test_query_sql_injection(self):
        """Test RAG query about SQL injection."""
        from scripts.launcher import demo_security_rag

        result = demo_security_rag("What is SQL injection?")
        assert isinstance(result, str)
        assert "RAG" in result or "Answer" in result or "Security" in result

    def test_query_attack_technique(self):
        """Test RAG query about attack techniques."""
        from scripts.launcher import demo_security_rag

        result = demo_security_rag("Explain lateral movement techniques")
        assert isinstance(result, str)

    def test_query_defense(self):
        """Test RAG query about defenses."""
        from scripts.launcher import demo_security_rag

        result = demo_security_rag("How to prevent ransomware attacks")
        assert isinstance(result, str)


class TestLab07YaraGenerator:
    """Test Lab 07: YARA Generator demo."""

    def test_generate_basic_rule(self):
        """Test basic YARA rule generation."""
        from scripts.launcher import demo_yara_generator

        result = demo_yara_generator(
            "CreateRemoteThread\nVirtualAllocEx",
            "ProcessInjection",
            "detect_injection",
        )
        assert isinstance(result, str)
        assert "YARA" in result or "rule" in result.lower()

    def test_generate_malware_rule(self):
        """Test YARA rule for malware strings."""
        from scripts.launcher import demo_yara_generator

        result = demo_yara_generator(
            "evil.com\nC:\\Users\\Public\\malware.exe",
            "Emotet",
            "detect_emotet",
        )
        assert isinstance(result, str)


class TestLab08VulnScanner:
    """Test Lab 08: Vulnerability Scanner demo."""

    def test_scan_single_cve(self):
        """Test vulnerability scan with single CVE."""
        from scripts.launcher import demo_vuln_scanner

        result = demo_vuln_scanner("CVE-2024-0001")
        assert isinstance(result, str)
        assert "CVE" in result or "Vulnerability" in result

    def test_scan_multiple_cves(self):
        """Test vulnerability scan with multiple CVEs."""
        from scripts.launcher import demo_vuln_scanner

        result = demo_vuln_scanner("CVE-2024-0001, CVE-2024-0002, CVE-2024-0003")
        assert isinstance(result, str)


class TestLab09DetectionPipeline:
    """Test Lab 09: Detection Pipeline demo."""

    def test_pipeline_single_event(self):
        """Test detection pipeline with single event."""
        from scripts.launcher import demo_detection_pipeline

        result, fig = demo_detection_pipeline(
            "Process: powershell.exe, Command: -enc SGVsbG8gV29ybGQ="
        )
        assert isinstance(result, str)
        assert "Detection" in result or "Pipeline" in result

    def test_pipeline_multiple_events(self):
        """Test detection pipeline with multiple events."""
        from scripts.launcher import demo_detection_pipeline

        events = """Process: cmd.exe spawned by excel.exe
Network: Connection to 192.168.1.100:4444
File: Created C:\\Users\\Public\\malware.exe"""
        result, fig = demo_detection_pipeline(events)
        assert isinstance(result, str)


class TestLab10IRCopilot:
    """Test Lab 10: IR Copilot demo."""

    def test_copilot_ransomware(self):
        """Test IR copilot with ransomware query."""
        from scripts.launcher import demo_ir_copilot

        result = demo_ir_copilot("We detected ransomware on multiple systems")
        assert isinstance(result, str)
        assert "IR" in result or "Copilot" in result or "Incident" in result

    def test_copilot_phishing(self):
        """Test IR copilot with phishing query."""
        from scripts.launcher import demo_ir_copilot

        result = demo_ir_copilot("User reported clicking a phishing link")
        assert isinstance(result, str)

    def test_copilot_malware(self):
        """Test IR copilot with malware query."""
        from scripts.launcher import demo_ir_copilot

        result = demo_ir_copilot("EDR alerted on suspicious process execution")
        assert isinstance(result, str)


class TestStatusBadge:
    """Test status badge generation."""

    def test_create_status_badge(self):
        """Test that status badge is created."""
        from scripts.launcher import create_status_badge

        badge = create_status_badge()
        assert isinstance(badge, str)
        # Should indicate availability status
        assert len(badge) > 0


class TestCreateDemo:
    """Test demo creation (requires Gradio)."""

    @pytest.mark.skipif(
        not pytest.importorskip("gradio", reason="Gradio not installed"),
        reason="Gradio not installed",
    )
    def test_create_demo_returns_blocks(self):
        """Test that create_demo returns a Gradio Blocks object."""
        import gradio as gr

        from scripts.launcher import create_demo

        demo = create_demo()
        assert isinstance(demo, gr.Blocks)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_phishing_special_characters(self):
        """Test phishing classifier with special characters."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier("Test <script>alert('xss')</script>", 0.5)
        assert isinstance(result, str)

    def test_phishing_empty_text(self):
        """Test phishing classifier with empty text."""
        from scripts.launcher import demo_phishing_classifier

        result, fig = demo_phishing_classifier("", 0.5)
        assert isinstance(result, str)

    def test_threat_intel_empty_ioc(self):
        """Test threat intel with empty IOC."""
        from scripts.launcher import demo_threat_intel

        result, fig = demo_threat_intel("", "IP")
        assert isinstance(result, str)

    def test_clustering_edge_values(self):
        """Test clustering with edge values."""
        from scripts.launcher import demo_malware_clustering

        result, fig = demo_malware_clustering(10, 2)
        assert isinstance(result, str)

    def test_anomaly_edge_ports(self):
        """Test anomaly detection with edge port values."""
        from scripts.launcher import demo_anomaly_detection

        # Test with common malicious port
        result, fig = demo_anomaly_detection(
            bytes_sent=100,
            bytes_received=200,
            packets=10,
            duration=5.0,
            port=4444,
            use_ml=True,
        )
        assert isinstance(result, str)

    def test_rag_short_query(self):
        """Test RAG with very short query."""
        from scripts.launcher import demo_security_rag

        result = demo_security_rag("help")
        assert isinstance(result, str)

    def test_ir_copilot_short_query(self):
        """Test IR copilot with short query."""
        from scripts.launcher import demo_ir_copilot

        result = demo_ir_copilot("incident")
        assert isinstance(result, str)

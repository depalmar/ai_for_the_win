#!/usr/bin/env python3
"""Tests for Lab 14: AI-Powered C2 Traffic Analysis."""

import importlib
import json
import math
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab14-c2-traffic-analysis" / "solution")
sys.path.insert(0, lab_path)

from main import (
    BeaconCandidate,
    BeaconDetector,
    C2DetectionPipeline,
    C2Report,
    DNSTunnelDetector,
    HTTPC2Detector,
    HTTPFlow,
    TLSCertAnalyzer,
    TunnelingCandidate,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_beacon_connections():
    """Create sample beacon-like connections with regular intervals."""
    base_time = 1705312800  # 2024-01-15T09:00:00
    connections = []

    # Create beacon traffic with ~60 second interval and small jitter
    for i in range(15):
        connections.append(
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "185.234.72.19",
                "dst_port": 443,
                "timestamp": base_time + i * 60 + np.random.uniform(-3, 3),
                "protocol": "TCP",
            }
        )

    return connections


@pytest.fixture
def sample_normal_connections():
    """Create sample normal (non-beacon) connections with irregular intervals."""
    base_time = 1705312800
    connections = []

    # Create irregular traffic
    for i in range(10):
        connections.append(
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "timestamp": base_time + np.random.uniform(0, 3600),
                "protocol": "UDP",
            }
        )

    return connections


@pytest.fixture
def sample_dns_tunneling_queries():
    """Create sample DNS queries indicative of tunneling."""
    queries = []
    base_time = 1705312800

    # High entropy DNS tunneling queries
    tunnel_subdomains = [
        "aGVsbG8gd29ybGQgZnJvbSBtYWx3YXJl",
        "dGhpcyBpcyBlbmNvZGVkIGRhdGE",
        "c2VjcmV0IGluZm9ybWF0aW9u",
        "ZXhmaWx0cmF0aW9uIGRhdGE",
        "bW9yZSBzZWNyZXQgZGF0YQ",
        "4a5b6c7d8e9f0a1b2c3d4e5f",
        "9f8e7d6c5b4a3021fedcba98",
        "deadbeefcafebabe12345678",
        "abcdef1234567890abcdef12",
        "feedface0badf00d12345678",
        "1234abcd5678ef90abcdef12",
    ]

    for i, subdomain in enumerate(tunnel_subdomains):
        queries.append(
            {
                "query": f"{subdomain}.evil-tunnel.com",
                "type": "TXT" if i % 3 == 0 else "A",
                "timestamp": base_time + i * 10,
            }
        )

    return queries


@pytest.fixture
def sample_normal_dns_queries():
    """Create sample normal DNS queries."""
    queries = []
    base_time = 1705312800

    normal_domains = [
        "www.google.com",
        "mail.google.com",
        "github.com",
        "api.github.com",
        "www.microsoft.com",
        "outlook.office365.com",
        "cdn.example.com",
        "static.example.com",
    ]

    for i, domain in enumerate(normal_domains):
        queries.append({"query": domain, "type": "A", "timestamp": base_time + i * 100})

    return queries


@pytest.fixture
def sample_http_c2_flows():
    """Create sample HTTP flows with C2 indicators."""
    base_time = 1705312800

    return [
        {
            "timestamp": base_time,
            "method": "GET",
            "uri": "/submit.php?id=1",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
            "response_code": 200,
            "response_size": 1024,
        },
        {
            "timestamp": base_time + 60,
            "method": "POST",
            "uri": "/submit.php",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
            "response_code": 200,
            "response_size": 1024,
        },
        {
            "timestamp": base_time + 120,
            "method": "GET",
            "uri": "/__utm.gif",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
            "response_code": 200,
            "response_size": 1024,
        },
        {
            "timestamp": base_time + 180,
            "method": "GET",
            "uri": "/pixel.gif?data=abc",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
            "response_code": 200,
            "response_size": 1024,
        },
        {
            "timestamp": base_time + 240,
            "method": "GET",
            "uri": "/submit.php?id=5",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
            "response_code": 200,
            "response_size": 1024,
        },
    ]


@pytest.fixture
def sample_normal_http_flows():
    """Create sample normal HTTP flows."""
    base_time = 1705312800

    return [
        {
            "timestamp": base_time,
            "method": "GET",
            "uri": "/index.html",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "response_code": 200,
            "response_size": 15000,
        },
        {
            "timestamp": base_time + 5,
            "method": "GET",
            "uri": "/styles.css",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "response_code": 200,
            "response_size": 5000,
        },
        {
            "timestamp": base_time + 300,
            "method": "GET",
            "uri": "/api/data",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "response_code": 200,
            "response_size": 8000,
        },
    ]


@pytest.fixture
def sample_self_signed_cert():
    """Create sample self-signed TLS certificate data."""
    return {
        "subject": "CN=update-server.com",
        "issuer": "CN=update-server.com",
        "subject_cn": "update-server.com",
        "not_before": "2024-01-10T00:00:00Z",
        "not_after": "2024-04-10T00:00:00Z",
    }


@pytest.fixture
def sample_valid_cert():
    """Create sample valid TLS certificate data."""
    return {
        "subject": "CN=www.google.com",
        "issuer": "CN=GTS CA 1C3, O=Google Trust Services LLC",
        "subject_cn": "www.google.com",
        "not_before": "2023-12-01T00:00:00Z",
        "not_after": "2024-12-01T00:00:00Z",
    }


@pytest.fixture
def sample_free_ca_cert():
    """Create sample certificate from free CA provider."""
    return {
        "subject": "CN=suspicious.example.com",
        "issuer": "CN=Let's Encrypt Authority X3",
        "subject_cn": "suspicious.example.com",
        "not_before": datetime.now().isoformat(),
        "not_after": (datetime.now().replace(month=datetime.now().month % 12 + 1)).isoformat(),
    }


@pytest.fixture
def full_traffic_data(
    sample_beacon_connections,
    sample_dns_tunneling_queries,
    sample_http_c2_flows,
    sample_self_signed_cert,
):
    """Create complete traffic data for pipeline testing."""
    return {
        "connections": sample_beacon_connections,
        "dns": sample_dns_tunneling_queries,
        "http_sessions": [
            {"dst_ip": "185.234.72.19", "dst_port": 443, "flows": sample_http_c2_flows}
        ],
        "tls_certs": [sample_self_signed_cert],
    }


@pytest.fixture
def beacon_detector():
    """Create BeaconDetector instance."""
    return BeaconDetector(jitter_tolerance=0.2)


@pytest.fixture
def dns_detector():
    """Create DNSTunnelDetector instance."""
    return DNSTunnelDetector()


@pytest.fixture
def http_detector():
    """Create HTTPC2Detector instance."""
    return HTTPC2Detector()


@pytest.fixture
def tls_analyzer():
    """Create TLSCertAnalyzer instance."""
    return TLSCertAnalyzer()


# =============================================================================
# BeaconDetector Tests
# =============================================================================


class TestBeaconDetector:
    """Tests for BeaconDetector."""

    def test_detector_initialization(self, beacon_detector):
        """Test detector initialization."""
        assert beacon_detector is not None
        assert beacon_detector.jitter_tolerance == 0.2

    def test_detector_custom_jitter_tolerance(self):
        """Test detector with custom jitter tolerance."""
        detector = BeaconDetector(jitter_tolerance=0.5)
        assert detector.jitter_tolerance == 0.5

    def test_extract_connection_timings(self, beacon_detector, sample_beacon_connections):
        """Test extraction of connection timings."""
        timings = beacon_detector.extract_connection_timings(
            sample_beacon_connections, src_ip="192.168.1.100", dst_ip="185.234.72.19", dst_port=443
        )

        assert len(timings) == 15
        assert all(isinstance(t, float) for t in timings)
        assert timings == sorted(timings)  # Should be sorted

    def test_extract_connection_timings_no_match(self, beacon_detector, sample_beacon_connections):
        """Test extraction with no matching connections."""
        timings = beacon_detector.extract_connection_timings(
            sample_beacon_connections, src_ip="10.0.0.1", dst_ip="10.0.0.2"
        )

        assert len(timings) == 0

    def test_extract_connection_timings_iso_timestamp(self, beacon_detector):
        """Test extraction with ISO format timestamps."""
        connections = [
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "dst_port": 443,
                "timestamp": "2024-01-15T09:00:00Z",
            },
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "dst_port": 443,
                "timestamp": "2024-01-15T09:01:00Z",
            },
        ]

        timings = beacon_detector.extract_connection_timings(
            connections, "192.168.1.1", "10.0.0.1", 443
        )

        assert len(timings) == 2

    def test_calculate_intervals(self, beacon_detector):
        """Test interval calculation."""
        timings = [100, 160, 220, 280, 340]
        intervals = beacon_detector.calculate_intervals(timings)

        assert len(intervals) == 4
        assert all(i == 60 for i in intervals)

    def test_calculate_intervals_empty(self, beacon_detector):
        """Test interval calculation with empty list."""
        intervals = beacon_detector.calculate_intervals([])
        assert intervals == []

    def test_calculate_intervals_single(self, beacon_detector):
        """Test interval calculation with single timing."""
        intervals = beacon_detector.calculate_intervals([100])
        assert intervals == []

    def test_detect_periodicity_beacon_pattern(self, beacon_detector):
        """Test periodicity detection with beacon-like pattern."""
        # Create timings with 60 second interval and small jitter
        base_time = 1000
        timings = [base_time + i * 60 + np.random.uniform(-2, 2) for i in range(20)]

        result = beacon_detector.detect_periodicity(timings)

        assert result["is_beacon"] == True
        assert 55 < result["interval"] < 65  # Around 60 seconds
        assert result["jitter"] < 0.2
        assert result["confidence"] > 0

    def test_detect_periodicity_random_pattern(self, beacon_detector):
        """Test periodicity detection with random pattern."""
        base_time = 1000
        timings = sorted([base_time + np.random.uniform(0, 3600) for _ in range(20)])

        result = beacon_detector.detect_periodicity(timings)

        assert result["is_beacon"] == False

    def test_detect_periodicity_insufficient_data(self, beacon_detector):
        """Test periodicity detection with insufficient data."""
        timings = [100, 160, 220]  # Only 3 points

        result = beacon_detector.detect_periodicity(timings)

        assert result["is_beacon"] is False
        assert result["confidence"] == 0

    def test_detect_periodicity_empty(self, beacon_detector):
        """Test periodicity detection with empty timings."""
        result = beacon_detector.detect_periodicity([])

        assert result["is_beacon"] is False
        assert result["interval"] == 0

    def test_analyze_all_pairs(self, beacon_detector, sample_beacon_connections):
        """Test analysis of all source-destination pairs."""
        candidates = beacon_detector.analyze_all_pairs(sample_beacon_connections)

        assert len(candidates) >= 1
        beacon = candidates[0]
        assert beacon.src_ip == "192.168.1.100"
        assert beacon.dst_ip == "185.234.72.19"
        assert beacon.dst_port == 443

    def test_analyze_all_pairs_sorted_by_confidence(self, beacon_detector):
        """Test that candidates are sorted by confidence."""
        # Create two beacon patterns with different quality
        connections = []
        base_time = 1000

        # High quality beacon
        for i in range(30):
            connections.append(
                {
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 443,
                    "timestamp": base_time + i * 60,
                }
            )

        # Lower quality beacon with more jitter
        for i in range(10):
            connections.append(
                {
                    "src_ip": "192.168.1.2",
                    "dst_ip": "10.0.0.2",
                    "dst_port": 443,
                    "timestamp": base_time + i * 60 + np.random.uniform(-8, 8),
                }
            )

        candidates = beacon_detector.analyze_all_pairs(connections)

        if len(candidates) >= 2:
            assert candidates[0].confidence >= candidates[1].confidence


# =============================================================================
# DNSTunnelDetector Tests
# =============================================================================


class TestDNSTunnelDetector:
    """Tests for DNSTunnelDetector."""

    def test_detector_initialization(self, dns_detector):
        """Test detector initialization."""
        assert dns_detector is not None
        assert dns_detector.entropy_threshold == 3.5
        assert dns_detector.length_threshold == 50

    def test_calculate_entropy_empty(self, dns_detector):
        """Test entropy calculation with empty string."""
        entropy = dns_detector.calculate_entropy("")
        assert entropy == 0.0

    def test_calculate_entropy_uniform(self, dns_detector):
        """Test entropy calculation with uniform string."""
        entropy = dns_detector.calculate_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_calculate_entropy_high(self, dns_detector):
        """Test entropy calculation with high entropy string."""
        # Random hex string should have high entropy
        entropy = dns_detector.calculate_entropy("deadbeefcafebabe12345678")
        assert entropy > 3.0

    def test_calculate_entropy_normal_text(self, dns_detector):
        """Test entropy calculation with normal text."""
        entropy = dns_detector.calculate_entropy("www.google.com")
        assert 2.0 < entropy < 4.0

    def test_extract_subdomain(self, dns_detector):
        """Test subdomain extraction."""
        subdomain = dns_detector.extract_subdomain("encoded.data.evil-tunnel.com")
        assert subdomain == "encoded.data"

    def test_extract_subdomain_short(self, dns_detector):
        """Test subdomain extraction with short domain."""
        subdomain = dns_detector.extract_subdomain("google.com")
        assert subdomain == ""

    def test_extract_subdomain_single_level(self, dns_detector):
        """Test subdomain extraction with single-level subdomain."""
        subdomain = dns_detector.extract_subdomain("www.google.com")
        assert subdomain == "www"

    def test_get_base_domain(self, dns_detector):
        """Test base domain extraction."""
        base = dns_detector.get_base_domain("encoded.data.evil-tunnel.com")
        assert base == "evil-tunnel.com"

    def test_get_base_domain_already_base(self, dns_detector):
        """Test base domain extraction with already base domain."""
        base = dns_detector.get_base_domain("google.com")
        assert base == "google.com"

    def test_analyze_query_suspicious(self, dns_detector):
        """Test analysis of suspicious DNS query."""
        query = "aGVsbG8gd29ybGQgZnJvbSBtYWx3YXJl.evil-tunnel.com"
        result = dns_detector.analyze_query(query)

        assert result["is_suspicious"] is True
        assert result["subdomain_entropy"] > 3.5
        assert len(result["indicators"]) > 0

    def test_analyze_query_normal(self, dns_detector):
        """Test analysis of normal DNS query."""
        result = dns_detector.analyze_query("www.google.com")

        assert result["is_suspicious"] is False
        assert len(result["indicators"]) == 0

    def test_analyze_query_base64_detection(self, dns_detector):
        """Test detection of Base64-like encoding."""
        query = "SGVsbG9Xb3JsZA.example.com"
        result = dns_detector.analyze_query(query)

        # Should detect Base64-like pattern
        base64_detected = any("Base64" in ind for ind in result["indicators"])
        assert base64_detected or result["is_suspicious"]

    def test_analyze_query_hex_detection(self, dns_detector):
        """Test detection of hex encoding."""
        query = "deadbeef1234567890abcdef.example.com"
        result = dns_detector.analyze_query(query)

        hex_detected = any("Hex" in ind for ind in result["indicators"])
        assert hex_detected or result["is_suspicious"]

    def test_analyze_query_long_subdomain(self, dns_detector):
        """Test detection of long subdomain."""
        long_subdomain = "a" * 60 + ".example.com"
        result = dns_detector.analyze_query(long_subdomain)

        long_detected = any("Long subdomain" in ind for ind in result["indicators"])
        assert long_detected

    def test_detect_tunneling_domain(self, dns_detector, sample_dns_tunneling_queries):
        """Test detection of tunneling domain."""
        candidates = dns_detector.detect_tunneling_domain(sample_dns_tunneling_queries)

        assert len(candidates) >= 1
        tunnel = candidates[0]
        assert "evil-tunnel.com" in tunnel.domain
        assert tunnel.confidence > 0.3

    def test_detect_tunneling_domain_min_queries(self, dns_detector):
        """Test minimum query requirement."""
        # Only 5 queries - should not detect with default min_queries=10
        queries = [{"query": f"data{i}.evil.com", "type": "A"} for i in range(5)]

        candidates = dns_detector.detect_tunneling_domain(queries, min_queries=10)
        assert len(candidates) == 0

    def test_detect_tunneling_domain_txt_records(self, dns_detector):
        """Test that TXT record usage increases confidence."""
        queries = []
        for i in range(15):
            queries.append({"query": f"{'a' * 30 + str(i)}.tunnel.com", "type": "TXT"})

        candidates = dns_detector.detect_tunneling_domain(queries, min_queries=10)

        if candidates:
            assert "TXT" in candidates[0].record_types

    def test_detect_tunneling_normal_traffic(self, dns_detector, sample_normal_dns_queries):
        """Test that normal traffic is not flagged."""
        # Add more queries to meet minimum
        queries = sample_normal_dns_queries * 3
        candidates = dns_detector.detect_tunneling_domain(queries, min_queries=5)

        # Normal traffic should not be detected as tunneling
        # or should have very low confidence
        high_confidence = [c for c in candidates if c.confidence > 0.5]
        assert len(high_confidence) == 0


# =============================================================================
# HTTPC2Detector Tests
# =============================================================================


class TestHTTPC2Detector:
    """Tests for HTTPC2Detector."""

    def test_detector_initialization(self, http_detector):
        """Test detector initialization."""
        assert http_detector is not None
        assert http_detector.llm is None  # LLM not initialized until needed

    def test_c2_uri_patterns_exist(self, http_detector):
        """Test that C2 URI patterns are defined."""
        assert len(http_detector.C2_URI_PATTERNS) > 0
        assert "/submit.php" in http_detector.C2_URI_PATTERNS
        assert "/pixel.gif" in http_detector.C2_URI_PATTERNS

    def test_suspicious_ua_patterns_exist(self, http_detector):
        """Test that suspicious UA patterns are defined."""
        assert len(http_detector.SUSPICIOUS_UA_PATTERNS) > 0
        assert "Python-urllib" in http_detector.SUSPICIOUS_UA_PATTERNS

    def test_analyze_http_session_suspicious(self, http_detector, sample_http_c2_flows):
        """Test analysis of suspicious HTTP session."""
        result = http_detector.analyze_http_session(sample_http_c2_flows)

        assert result["is_suspicious"] is True
        assert result["confidence"] > 0.3
        assert len(result["indicators"]) > 0

    def test_analyze_http_session_normal(self, http_detector, sample_normal_http_flows):
        """Test analysis of normal HTTP session."""
        result = http_detector.analyze_http_session(sample_normal_http_flows)

        assert result["is_suspicious"] is False
        assert result["confidence"] < 0.4

    def test_analyze_http_session_empty(self, http_detector):
        """Test analysis of empty session."""
        result = http_detector.analyze_http_session([])

        assert result["is_suspicious"] is False
        assert result["confidence"] == 0
        assert result["indicators"] == []

    def test_analyze_http_session_cobalt_strike(self, http_detector):
        """Test detection of Cobalt Strike patterns."""
        flows = [
            {
                "uri": "/submit.php?id=1",
                "user_agent": "Mozilla/4.0",
                "timestamp": 1000,
                "response_size": 100,
            },
            {
                "uri": "/__utm.gif",
                "user_agent": "Mozilla/4.0",
                "timestamp": 1060,
                "response_size": 100,
            },
        ]

        result = http_detector.analyze_http_session(flows)

        assert result["c2_profile_match"] == "Cobalt Strike (default profile)"

    def test_analyze_http_session_regular_timing(self, http_detector):
        """Test detection of regular timing patterns."""
        base_time = 1000
        flows = [
            {
                "uri": "/api/check",
                "user_agent": "Custom Agent",
                "timestamp": base_time + i * 60,
                "response_size": 500,
            }
            for i in range(10)
        ]

        result = http_detector.analyze_http_session(flows)

        timing_detected = any("timing pattern" in ind.lower() for ind in result["indicators"])
        assert timing_detected

    def test_analyze_http_session_identical_responses(self, http_detector):
        """Test detection of identical response sizes."""
        flows = [
            {
                "uri": f"/data/{i}",
                "user_agent": "Agent",
                "timestamp": 1000 + i * 100,
                "response_size": 1024,
            }
            for i in range(5)
        ]

        result = http_detector.analyze_http_session(flows)

        identical_detected = any("Identical" in ind for ind in result["indicators"])
        assert identical_detected

    def test_match_c2_profile_cobalt_strike(self, http_detector):
        """Test C2 profile matching for Cobalt Strike."""
        flows = [{"uri": "/submit.php"}, {"uri": "/__utm.gif"}]
        profile = http_detector._match_c2_profile(flows)

        assert profile == "Cobalt Strike (default profile)"

    def test_match_c2_profile_metasploit(self, http_detector):
        """Test C2 profile matching for Metasploit."""
        flows = [{"uri": "/meterpreter/session"}]
        profile = http_detector._match_c2_profile(flows)

        assert profile == "Possible Metasploit"

    def test_match_c2_profile_none(self, http_detector):
        """Test C2 profile matching with no match."""
        flows = [{"uri": "/index.html"}, {"uri": "/styles.css"}]
        profile = http_detector._match_c2_profile(flows)

        assert profile is None

    @pytest.mark.requires_api
    def test_llm_analyze_session(self, http_detector):
        """Test LLM-based session analysis."""
        session = {
            "dst_ip": "185.234.72.19",
            "dst_port": 443,
            "request_count": 50,
            "duration_seconds": 3600,
            "sample_uris": ["/submit.php", "/__utm.gif"],
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
        }

        result = http_detector.llm_analyze_session(session)

        # Should return dict with expected keys or error
        assert isinstance(result, dict)
        assert "error" in result or "is_c2" in result


# =============================================================================
# TLSCertAnalyzer Tests
# =============================================================================


class TestTLSCertAnalyzer:
    """Tests for TLSCertAnalyzer."""

    def test_analyzer_initialization(self, tls_analyzer):
        """Test analyzer initialization."""
        assert tls_analyzer is not None
        assert len(tls_analyzer.FREE_CA_PROVIDERS) > 0

    def test_free_ca_providers(self, tls_analyzer):
        """Test free CA providers list."""
        assert "Let's Encrypt" in tls_analyzer.FREE_CA_PROVIDERS
        assert "ZeroSSL" in tls_analyzer.FREE_CA_PROVIDERS

    def test_analyze_self_signed_cert(self, tls_analyzer, sample_self_signed_cert):
        """Test analysis of self-signed certificate."""
        result = tls_analyzer.analyze_certificate(sample_self_signed_cert)

        assert result["risk_score"] > 0.3
        assert any("Self-signed" in ind for ind in result["indicators"])

    def test_analyze_valid_cert(self, tls_analyzer, sample_valid_cert):
        """Test analysis of valid certificate."""
        result = tls_analyzer.analyze_certificate(sample_valid_cert)

        assert result["risk_score"] < 0.5
        assert "Self-signed" not in str(result["indicators"])

    def test_analyze_short_validity_cert(self, tls_analyzer):
        """Test analysis of certificate with short validity."""
        cert = {
            "subject": "CN=short.example.com",
            "issuer": "CN=Some CA",
            "subject_cn": "short.example.com",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2024-02-15T00:00:00Z",  # 45 days validity
        }

        result = tls_analyzer.analyze_certificate(cert)

        short_validity = any("Short validity" in ind for ind in result["indicators"])
        assert short_validity

    def test_analyze_free_ca_cert(self, tls_analyzer, sample_free_ca_cert):
        """Test analysis of certificate from free CA."""
        result = tls_analyzer.analyze_certificate(sample_free_ca_cert)

        free_ca_detected = any("Free CA" in ind for ind in result["indicators"])
        assert free_ca_detected

    def test_analyze_recently_issued_cert(self, tls_analyzer):
        """Test analysis of recently issued certificate."""
        recent_date = datetime.now().isoformat()
        cert = {
            "subject": "CN=new.example.com",
            "issuer": "CN=Some CA",
            "subject_cn": "new.example.com",
            "not_before": recent_date,
            "not_after": "2025-01-01T00:00:00Z",
        }

        result = tls_analyzer.analyze_certificate(cert)

        recent_detected = any("Recently issued" in ind for ind in result["indicators"])
        assert recent_detected

    def test_analyze_empty_cert(self, tls_analyzer):
        """Test analysis with missing fields."""
        cert = {}

        result = tls_analyzer.analyze_certificate(cert)

        assert "domain" in result
        assert "indicators" in result
        assert "risk_score" in result

    def test_risk_score_capped(self, tls_analyzer):
        """Test that risk score is capped at 1.0."""
        from datetime import timedelta

        # Certificate with many risk factors
        cert = {
            "subject": "CN=evil.com",
            "issuer": "CN=evil.com",  # Self-signed
            "subject_cn": "evil.com",
            "not_before": datetime.now().isoformat(),  # Recent
            "not_after": (datetime.now() + timedelta(days=30)).isoformat(),  # Short validity
        }

        result = tls_analyzer.analyze_certificate(cert)

        assert result["risk_score"] <= 1.0


# =============================================================================
# C2DetectionPipeline Tests
# =============================================================================


class TestC2DetectionPipeline:
    """Tests for C2DetectionPipeline."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = C2DetectionPipeline()

        assert pipeline.beacon_detector is not None
        assert pipeline.dns_detector is not None
        assert pipeline.http_detector is not None
        assert pipeline.tls_analyzer is not None

    def test_analyze_traffic_with_beacons(self, full_traffic_data):
        """Test traffic analysis detecting beacons."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        assert isinstance(report, C2Report)
        assert len(report.beacons) >= 1

    def test_analyze_traffic_with_tunneling(self, full_traffic_data):
        """Test traffic analysis detecting DNS tunneling."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        assert len(report.tunneling) >= 1

    def test_analyze_traffic_with_http_c2(self, full_traffic_data):
        """Test traffic analysis detecting HTTP C2."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        assert len(report.http_c2) >= 1

    def test_analyze_traffic_with_tls_anomalies(self, full_traffic_data):
        """Test traffic analysis detecting TLS anomalies."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        assert len(report.tls_anomalies) >= 1

    def test_analyze_traffic_risk_level_critical(self, full_traffic_data):
        """Test critical risk level determination."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        # With beacons and tunneling, should be critical or high
        assert report.risk_level in ["critical", "high"]

    def test_analyze_traffic_empty(self):
        """Test traffic analysis with empty data."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic({})

        assert report.risk_level == "low"
        assert len(report.beacons) == 0
        assert len(report.tunneling) == 0

    def test_analyze_traffic_normal(self, sample_normal_connections, sample_normal_dns_queries):
        """Test traffic analysis with normal traffic."""
        pipeline = C2DetectionPipeline()

        traffic = {
            "connections": sample_normal_connections,
            "dns": sample_normal_dns_queries,
            "http_sessions": [],
            "tls_certs": [],
        }

        report = pipeline.analyze_traffic(traffic)

        assert report.risk_level in ["low", "medium"]

    def test_report_summary_format(self, full_traffic_data):
        """Test report summary formatting."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        assert isinstance(report.summary, str)
        assert len(report.summary) > 0

    def test_report_timestamp(self, full_traffic_data):
        """Test report timestamp."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)

        # Should be valid ISO timestamp
        timestamp = datetime.fromisoformat(report.timestamp)
        assert timestamp is not None

    def test_generate_detection_rules_snort(self, full_traffic_data):
        """Test Snort rule generation."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)
        rules = pipeline.generate_detection_rules(report)

        assert "snort" in rules
        if report.beacons:
            assert len(rules["snort"]) >= 1

    def test_generate_detection_rules_suricata(self, full_traffic_data):
        """Test Suricata rule generation."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic(full_traffic_data)
        rules = pipeline.generate_detection_rules(report)

        assert "suricata" in rules
        if report.tunneling:
            assert len(rules["suricata"]) >= 1

    def test_generate_detection_rules_empty(self):
        """Test rule generation with no findings."""
        pipeline = C2DetectionPipeline()
        report = pipeline.analyze_traffic({})
        rules = pipeline.generate_detection_rules(report)

        assert rules["snort"] == []
        assert rules["suricata"] == []


# =============================================================================
# DataClass Tests
# =============================================================================


class TestBeaconCandidate:
    """Tests for BeaconCandidate dataclass."""

    def test_beacon_candidate_creation(self):
        """Test BeaconCandidate creation."""
        beacon = BeaconCandidate(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            interval=60.0,
            jitter=0.05,
            confidence=0.95,
        )

        assert beacon.src_ip == "192.168.1.100"
        assert beacon.dst_port == 443
        assert beacon.interval == 60.0
        assert beacon.sample_times == []  # Default

    def test_beacon_candidate_with_sample_times(self):
        """Test BeaconCandidate with sample times."""
        times = [1000, 1060, 1120]
        beacon = BeaconCandidate(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            interval=60.0,
            jitter=0.05,
            confidence=0.95,
            sample_times=times,
        )

        assert beacon.sample_times == times


class TestTunnelingCandidate:
    """Tests for TunnelingCandidate dataclass."""

    def test_tunneling_candidate_creation(self):
        """Test TunnelingCandidate creation."""
        tunnel = TunnelingCandidate(
            domain="evil-tunnel.com", query_count=100, avg_entropy=4.5, avg_length=25.0
        )

        assert tunnel.domain == "evil-tunnel.com"
        assert tunnel.query_count == 100
        assert tunnel.confidence == 0.0  # Default

    def test_tunneling_candidate_with_record_types(self):
        """Test TunnelingCandidate with record types."""
        tunnel = TunnelingCandidate(
            domain="evil-tunnel.com",
            query_count=100,
            avg_entropy=4.5,
            avg_length=25.0,
            record_types=["TXT", "A"],
            confidence=0.8,
        )

        assert "TXT" in tunnel.record_types
        assert tunnel.confidence == 0.8


class TestHTTPFlow:
    """Tests for HTTPFlow dataclass."""

    def test_http_flow_creation(self):
        """Test HTTPFlow creation."""
        flow = HTTPFlow(
            timestamp="2024-01-15T09:00:00Z",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            method="GET",
            uri="/submit.php",
            host="evil.com",
            user_agent="Mozilla/5.0",
            content_type="text/html",
            response_code=200,
            request_size=100,
            response_size=1024,
        )

        assert flow.method == "GET"
        assert flow.uri == "/submit.php"
        assert flow.response_code == 200


class TestC2Report:
    """Tests for C2Report dataclass."""

    def test_c2_report_creation(self):
        """Test C2Report creation."""
        report = C2Report(
            timestamp="2024-01-15T09:00:00Z",
            beacons=[],
            tunneling=[],
            http_c2=[],
            tls_anomalies=[],
            summary="No C2 indicators found",
            risk_level="low",
        )

        assert report.risk_level == "low"
        assert len(report.beacons) == 0

    def test_c2_report_with_findings(self):
        """Test C2Report with findings."""
        beacon = BeaconCandidate(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            interval=60.0,
            jitter=0.05,
            confidence=0.95,
        )

        report = C2Report(
            timestamp="2024-01-15T09:00:00Z",
            beacons=[beacon],
            tunneling=[],
            http_c2=[],
            tls_anomalies=[],
            summary="1 beacon(s) detected",
            risk_level="critical",
        )

        assert len(report.beacons) == 1
        assert report.risk_level == "critical"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_beacon_detector_zero_interval(self):
        """Test beacon detection with zero time intervals."""
        detector = BeaconDetector()
        timings = [1000, 1000, 1000, 1000, 1000]

        result = detector.detect_periodicity(timings)

        assert result["is_beacon"] is False

    def test_dns_detector_very_long_subdomain(self):
        """Test DNS detection with extremely long subdomain."""
        detector = DNSTunnelDetector()
        long_subdomain = "a" * 200 + ".example.com"

        result = detector.analyze_query(long_subdomain)

        assert result["subdomain_length"] == 200
        assert result["is_suspicious"] is True

    def test_http_detector_empty_uris(self):
        """Test HTTP detection with empty URIs."""
        detector = HTTPC2Detector()
        flows = [{"uri": "", "user_agent": "Test", "timestamp": 1000, "response_size": 100}]

        result = detector.analyze_http_session(flows)

        assert isinstance(result, dict)

    def test_tls_analyzer_invalid_dates(self):
        """Test TLS analyzer with invalid date formats."""
        analyzer = TLSCertAnalyzer()
        cert = {
            "subject": "CN=test.com",
            "issuer": "CN=CA",
            "not_before": "invalid-date",
            "not_after": "also-invalid",
        }

        result = analyzer.analyze_certificate(cert)

        # Should handle gracefully without crashing
        assert "risk_score" in result

    def test_pipeline_partial_data(self):
        """Test pipeline with partial traffic data."""
        pipeline = C2DetectionPipeline()

        # Only connections, no other data
        traffic = {
            "connections": [
                {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "dst_port": 443, "timestamp": 1000}
            ]
        }

        report = pipeline.analyze_traffic(traffic)

        assert isinstance(report, C2Report)

    def test_beacon_detector_negative_timestamps(self):
        """Test beacon detection with negative timestamps."""
        detector = BeaconDetector()
        timings = [-1000, -940, -880, -820, -760]

        result = detector.detect_periodicity(timings)

        # Should still work with negative timestamps
        assert "is_beacon" in result

    def test_dns_detector_unicode_domain(self):
        """Test DNS detection with unicode characters."""
        detector = DNSTunnelDetector()

        # IDN domain
        result = detector.analyze_query("xn--e1afmkfd.xn--p1ai")  # Punycode

        assert isinstance(result, dict)

    def test_http_session_with_iso_timestamps(self):
        """Test HTTP session analysis with ISO timestamp strings."""
        detector = HTTPC2Detector()
        flows = [
            {
                "uri": "/test",
                "user_agent": "Test",
                "timestamp": "2024-01-15T09:00:00Z",
                "response_size": 100,
            },
            {
                "uri": "/test",
                "user_agent": "Test",
                "timestamp": "2024-01-15T09:01:00Z",
                "response_size": 100,
            },
            {
                "uri": "/test",
                "user_agent": "Test",
                "timestamp": "2024-01-15T09:02:00Z",
                "response_size": 100,
            },
            {
                "uri": "/test",
                "user_agent": "Test",
                "timestamp": "2024-01-15T09:03:00Z",
                "response_size": 100,
            },
            {
                "uri": "/test",
                "user_agent": "Test",
                "timestamp": "2024-01-15T09:04:00Z",
                "response_size": 100,
            },
        ]

        result = detector.analyze_http_session(flows)

        assert isinstance(result, dict)


# =============================================================================
# Integration Tests with Sample Data Files
# =============================================================================


class TestIntegrationWithSampleData:
    """Integration tests using actual sample data files."""

    @pytest.fixture
    def sample_data_path(self):
        """Get path to sample data directory."""
        return Path(__file__).parent.parent / "labs" / "lab14-c2-traffic-analysis" / "data"

    def test_load_beacon_traffic_data(self, sample_data_path):
        """Test loading beacon traffic data file."""
        data_file = sample_data_path / "beacon_traffic.json"

        if data_file.exists():
            with open(data_file) as f:
                data = json.load(f)

            assert "connections" in data
            assert "dns" in data
            assert "http_sessions" in data
            assert "tls_certs" in data

    def test_full_pipeline_with_sample_data(self, sample_data_path):
        """Test full pipeline with sample data file."""
        data_file = sample_data_path / "beacon_traffic.json"

        if data_file.exists():
            with open(data_file) as f:
                data = json.load(f)

            pipeline = C2DetectionPipeline()
            report = pipeline.analyze_traffic(data)

            assert isinstance(report, C2Report)
            # Sample data should trigger some detections
            assert report.risk_level in ["low", "medium", "high", "critical"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

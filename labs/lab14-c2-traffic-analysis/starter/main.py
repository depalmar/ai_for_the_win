"""
Lab 14: AI-Powered C2 Traffic Analysis - Starter Code

Detect and analyze Command & Control communications using ML and LLMs.
Learn to identify beaconing, DNS tunneling, and covert channels.

Complete the TODOs to build a C2 detection pipeline.
"""

import json
import math
import os
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import numpy as np

# LLM setup - supports multiple providers
def setup_llm(provider: str = "auto"):
    """Initialize LLM client based on available API keys."""
    if provider == "auto":
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("GOOGLE_API_KEY"):
            provider = "google"
        else:
            raise ValueError("No API key found.")

    if provider == "anthropic":
        from anthropic import Anthropic
        return ("anthropic", Anthropic())
    elif provider == "openai":
        from openai import OpenAI
        return ("openai", OpenAI())
    elif provider == "google":
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        return ("google", genai.GenerativeModel("gemini-2.5-pro"))
    else:
        raise ValueError(f"Unknown provider: {provider}")


@dataclass
class BeaconCandidate:
    """A potential beaconing connection."""
    src_ip: str
    dst_ip: str
    dst_port: int
    interval: float
    jitter: float
    confidence: float
    sample_times: List[float]


@dataclass
class TunnelingCandidate:
    """A potential DNS tunneling domain."""
    domain: str
    query_count: int
    avg_entropy: float
    avg_length: float
    record_types: List[str]
    confidence: float


@dataclass
class HTTPFlow:
    """HTTP request/response pair."""
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    host: str
    user_agent: str
    content_type: str
    response_code: int
    request_size: int
    response_size: int


@dataclass
class C2Report:
    """C2 detection report."""
    timestamp: str
    beacons: List[BeaconCandidate]
    tunneling: List[TunnelingCandidate]
    http_c2: List[dict]
    tls_anomalies: List[dict]
    summary: str
    risk_level: str


class BeaconDetector:
    """Detect regular callback patterns indicative of C2."""

    def __init__(self, jitter_tolerance: float = 0.2):
        """
        Initialize beacon detector.

        Args:
            jitter_tolerance: Allowable variance in beacon timing (0.2 = 20%)
        """
        self.jitter_tolerance = jitter_tolerance

    def extract_connection_timings(self, connections: List[dict],
                                   src_ip: str, dst_ip: str) -> List[float]:
        """
        Extract timestamps for connections between two hosts.

        TODO: Implement timing extraction
        - Filter connections by src_ip and dst_ip
        - Extract and sort timestamps
        - Return as list of Unix timestamps

        Args:
            connections: List of connection records
            src_ip: Source IP to filter
            dst_ip: Destination IP to filter

        Returns:
            Sorted list of timestamps
        """
        # TODO: Implement this method
        pass

    def calculate_intervals(self, timings: List[float]) -> List[float]:
        """
        Calculate time intervals between consecutive connections.

        Args:
            timings: Sorted list of timestamps

        Returns:
            List of intervals in seconds
        """
        if len(timings) < 2:
            return []
        return [timings[i+1] - timings[i] for i in range(len(timings)-1)]

    def detect_periodicity(self, timings: List[float]) -> dict:
        """
        Detect periodic patterns in connection timings.

        TODO: Implement periodicity detection using FFT or autocorrelation
        - Calculate intervals between connections
        - Use statistical analysis to detect regularity
        - Account for jitter in beacon intervals

        Args:
            timings: List of connection timestamps

        Returns:
            {
                'is_beacon': bool,
                'interval': float,  # seconds
                'jitter': float,    # variance as percentage
                'confidence': float
            }
        """
        # TODO: Implement this method
        # Hint: Use numpy for statistical analysis
        # Beacons typically have consistent intervals with small variance
        pass

    def analyze_all_pairs(self, connections: List[dict]) -> List[BeaconCandidate]:
        """
        Analyze all src-dst pairs for beaconing behavior.

        TODO: Implement pair analysis
        - Group connections by (src_ip, dst_ip, dst_port)
        - For each group with enough samples, check for periodicity
        - Return list of beacon candidates

        Args:
            connections: All network connections

        Returns:
            List of BeaconCandidate objects
        """
        # TODO: Implement this method
        pass


class DNSTunnelDetector:
    """Identify data exfiltration or C2 over DNS."""

    def __init__(self):
        self.entropy_threshold = 3.5  # Bits per character
        self.length_threshold = 50    # Subdomain length

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def extract_subdomain(self, domain: str) -> str:
        """Extract subdomain from full domain name."""
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[:-2])
        return ''

    def analyze_query(self, query: str) -> dict:
        """
        Analyze single DNS query for tunneling indicators.

        TODO: Implement query analysis
        - Extract subdomain
        - Calculate entropy
        - Check length
        - Identify suspicious patterns

        Args:
            query: DNS query domain

        Returns:
            {
                'domain': str,
                'subdomain': str,
                'subdomain_entropy': float,
                'subdomain_length': int,
                'is_suspicious': bool,
                'indicators': List[str]
            }
        """
        # TODO: Implement this method
        pass

    def detect_tunneling_domain(self, queries: List[dict],
                                min_queries: int = 10) -> List[TunnelingCandidate]:
        """
        Detect domains being used for DNS tunneling.

        TODO: Implement tunneling detection
        - Group queries by base domain
        - Calculate average entropy and length
        - Check for TXT record abuse
        - Identify high-volume suspicious domains

        Args:
            queries: List of DNS query records
            min_queries: Minimum queries to consider

        Returns:
            List of TunnelingCandidate objects
        """
        # TODO: Implement this method
        pass


class HTTPC2Detector:
    """Identify HTTP-based C2 patterns."""

    # Known C2 URI patterns
    C2_URI_PATTERNS = [
        '/submit.php', '/pixel.gif', '/__utm.gif',  # Cobalt Strike defaults
        '/login.php', '/admin.php', '/upload.php',  # Generic suspicious
        '/jquery-', '.js?',  # Malleable C2 common patterns
    ]

    # Suspicious User-Agent patterns
    SUSPICIOUS_UA_PATTERNS = [
        'Mozilla/4.0',  # Old IE, common in malware
        'Mozilla/5.0 (compatible;',  # Generic pattern
    ]

    def __init__(self, llm_provider: str = "auto"):
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def analyze_http_session(self, flows: List[HTTPFlow]) -> dict:
        """
        Analyze HTTP session for C2 indicators.

        TODO: Implement HTTP C2 detection
        - Check URI patterns
        - Analyze timing between requests
        - Look for encoded payloads
        - Check user-agent anomalies
        - Detect cookie-based data transfer

        Args:
            flows: List of HTTP flows in session

        Returns:
            {
                'is_suspicious': bool,
                'indicators': List[str],
                'c2_profile_match': str or None,
                'confidence': float
            }
        """
        # TODO: Implement this method
        pass

    def llm_analyze_session(self, session: dict) -> dict:
        """
        Use LLM to analyze HTTP session for C2 indicators.

        TODO: Implement LLM analysis
        - Build prompt with session details
        - Request structured analysis
        - Parse and return results

        Args:
            session: Session data dict

        Returns:
            LLM analysis result
        """
        # TODO: Implement this method
        pass


class TLSCertAnalyzer:
    """Detect C2 using TLS certificate anomalies."""

    def analyze_certificate(self, cert_data: dict) -> dict:
        """
        Analyze TLS certificate for C2 indicators.

        TODO: Implement certificate analysis
        - Check for self-signed certificates
        - Check certificate age (recently issued)
        - Verify domain matches
        - Look for known C2 certificate patterns

        Args:
            cert_data: Certificate information dict

        Returns:
            {
                'domain': str,
                'indicators': List[str],
                'risk_score': float
            }
        """
        # TODO: Implement this method
        pass


class C2DetectionPipeline:
    """End-to-end C2 detection pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        self.beacon_detector = BeaconDetector()
        self.dns_detector = DNSTunnelDetector()
        self.http_detector = HTTPC2Detector(llm_provider)
        self.tls_analyzer = TLSCertAnalyzer()

    def analyze_traffic(self, traffic_data: dict) -> C2Report:
        """
        Run full C2 detection on network traffic.

        TODO: Implement detection pipeline
        1. Run beacon detection on flows
        2. Check for DNS tunneling
        3. Analyze HTTP sessions
        4. Check TLS certificates
        5. Correlate findings
        6. Generate report

        Args:
            traffic_data: Parsed traffic data with flows, DNS, HTTP, TLS

        Returns:
            C2Report with findings
        """
        # TODO: Implement this method
        pass

    def generate_detection_rules(self, findings: List[dict]) -> dict:
        """
        Generate Snort/Suricata rules from findings.

        TODO: Implement rule generation
        - Create rules for detected beacon intervals
        - Create rules for suspicious domains
        - Create rules for HTTP indicators

        Args:
            findings: Detection findings

        Returns:
            Dict with 'snort' and 'suricata' rule lists
        """
        # TODO: Implement this method
        pass


def main():
    """Main entry point for Lab 14."""
    print("=" * 60)
    print("Lab 14: AI-Powered C2 Traffic Analysis")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')

    try:
        with open(os.path.join(data_dir, 'beacon_traffic.json'), 'r') as f:
            beacon_data = json.load(f)
        print(f"\nLoaded {len(beacon_data.get('connections', []))} connections")
    except FileNotFoundError:
        print("Sample data not found. Using mock data.")
        beacon_data = {'connections': [], 'dns': [], 'http_sessions': []}

    # Task 1: Beacon detection
    print("\n--- Task 1: Beacon Detection ---")
    detector = BeaconDetector()
    beacons = detector.analyze_all_pairs(beacon_data.get('connections', []))
    if beacons:
        print(f"Found {len(beacons)} potential beacons")
        for b in beacons[:3]:
            print(f"  - {b.src_ip} -> {b.dst_ip}:{b.dst_port}")
            print(f"    Interval: {b.interval:.1f}s, Jitter: {b.jitter:.1%}")
    else:
        print("TODO: Implement analyze_all_pairs()")

    # Task 2: DNS tunneling detection
    print("\n--- Task 2: DNS Tunneling Detection ---")
    dns_detector = DNSTunnelDetector()
    tunnels = dns_detector.detect_tunneling_domain(beacon_data.get('dns', []))
    if tunnels:
        print(f"Found {len(tunnels)} potential tunneling domains")
        for t in tunnels:
            print(f"  - {t.domain}: entropy={t.avg_entropy:.2f}, queries={t.query_count}")
    else:
        print("TODO: Implement detect_tunneling_domain()")

    # Task 3: HTTP C2 detection
    print("\n--- Task 3: HTTP C2 Detection ---")
    http_detector = HTTPC2Detector()
    # Convert session data to HTTPFlow objects if available
    http_sessions = beacon_data.get('http_sessions', [])
    if http_sessions:
        for session in http_sessions[:2]:
            result = http_detector.analyze_http_session(session.get('flows', []))
            if result:
                print(f"  Session to {session.get('dst_ip', 'unknown')}:")
                print(f"    Suspicious: {result.get('is_suspicious', 'N/A')}")
            else:
                print("TODO: Implement analyze_http_session()")
                break
    else:
        print("No HTTP sessions in sample data")

    # Task 4: Full pipeline
    print("\n--- Task 4: C2 Detection Pipeline ---")
    pipeline = C2DetectionPipeline()
    report = pipeline.analyze_traffic(beacon_data)
    if report:
        print(f"Risk Level: {report.risk_level}")
        print(f"Summary: {report.summary}")
    else:
        print("TODO: Implement analyze_traffic()")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 14!")
    print("=" * 60)


if __name__ == "__main__":
    main()

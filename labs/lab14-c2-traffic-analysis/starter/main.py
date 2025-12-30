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
from typing import Dict, List, Optional, Tuple

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

    def extract_connection_timings(
        self, connections: List[dict], src_ip: str, dst_ip: str
    ) -> List[float]:
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
        # TODO: Ask your AI assistant:
        # "Write Python code to filter a list of connection dicts by src_ip and dst_ip,
        # extract the 'timestamp' field from each matching connection, convert to Unix
        # timestamps if needed, sort them, and return as a list of floats."
        #
        # Then review and test the generated code.
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
        return [timings[i + 1] - timings[i] for i in range(len(timings) - 1)]

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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect periodic patterns in a list of timestamps using
        # numpy. Calculate intervals between consecutive times, compute mean interval
        # and standard deviation, determine jitter as coefficient of variation, and
        # return a dict with 'is_beacon' (True if jitter < threshold), 'interval',
        # 'jitter', and 'confidence' based on how consistent the timing is."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to group network connections by (src_ip, dst_ip, dst_port)
        # tuples, extract timestamps for each group, call detect_periodicity() on groups
        # with sufficient samples, and return a list of BeaconCandidate objects for
        # connections that show periodic beaconing behavior."
        #
        # Then review and test the generated code.
        pass


class DNSTunnelDetector:
    """Identify data exfiltration or C2 over DNS."""

    def __init__(self):
        self.entropy_threshold = 3.5  # Bits per character
        self.length_threshold = 50  # Subdomain length

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def extract_subdomain(self, domain: str) -> str:
        """Extract subdomain from full domain name."""
        parts = domain.split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

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
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze a DNS query for tunneling indicators: extract
        # the subdomain using extract_subdomain(), calculate its entropy using
        # calculate_entropy(), check if length exceeds threshold, identify suspicious
        # patterns (hex encoding, base64, high entropy), and return a dict with domain,
        # subdomain, entropy, length, is_suspicious flag, and list of indicators."
        #
        # Then review and test the generated code.
        pass

    def detect_tunneling_domain(
        self, queries: List[dict], min_queries: int = 10
    ) -> List[TunnelingCandidate]:
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
        # TODO: Ask your AI assistant:
        # "Write Python code to detect DNS tunneling by grouping queries by base domain,
        # calculating average subdomain entropy and length for each domain, checking for
        # TXT record abuse, filtering domains with query_count >= min_queries, and
        # returning a list of TunnelingCandidate objects for suspicious domains."
        #
        # Then review and test the generated code.
        pass


class HTTPC2Detector:
    """Identify HTTP-based C2 patterns."""

    # Known C2 URI patterns
    C2_URI_PATTERNS = [
        "/submit.php",
        "/pixel.gif",
        "/__utm.gif",  # Cobalt Strike defaults
        "/login.php",
        "/admin.php",
        "/upload.php",  # Generic suspicious
        "/jquery-",
        ".js?",  # Malleable C2 common patterns
    ]

    # Suspicious User-Agent patterns
    SUSPICIOUS_UA_PATTERNS = [
        "Mozilla/4.0",  # Old IE, common in malware
        "Mozilla/5.0 (compatible;",  # Generic pattern
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
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze a list of HTTPFlow objects for C2 indicators:
        # check URIs against C2_URI_PATTERNS, analyze timing regularity between requests,
        # look for base64/encoded payloads in URIs and bodies, check user-agents against
        # SUSPICIOUS_UA_PATTERNS, detect cookie-based data transfer, and return a dict
        # with is_suspicious, indicators list, c2_profile_match, and confidence score."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to use an LLM to analyze HTTP session data for C2 indicators:
        # initialize the LLM with _init_llm(), build a detailed prompt describing the
        # session (URIs, timing, headers, payloads), request structured analysis for
        # C2 patterns like Cobalt Strike or custom frameworks, parse the LLM response,
        # and return a dict with the analysis results."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze a TLS certificate dict for C2 indicators:
        # check if the certificate is self-signed, verify if it was recently issued
        # (within days), check if the subject/CN matches the domain, look for known
        # C2 certificate patterns (short validity, missing fields, suspicious issuers),
        # calculate a risk_score, and return a dict with domain, indicators, and score."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to run a full C2 detection pipeline on traffic_data:
        # 1) Call beacon_detector.analyze_all_pairs() on connections,
        # 2) Call dns_detector.detect_tunneling_domain() on DNS queries,
        # 3) Call http_detector.analyze_http_session() on each HTTP session,
        # 4) Call tls_analyzer.analyze_certificate() on TLS cert data,
        # 5) Correlate findings across detectors,
        # 6) Return a C2Report with beacons, tunneling, http_c2, tls_anomalies,
        #    summary, and risk_level based on the combined findings."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to generate Snort and Suricata IDS rules from C2 findings:
        # create rules for detected beacon intervals (alert on regular timing to IPs),
        # create rules for suspicious DNS domains (alert on queries to tunneling domains),
        # create rules for HTTP C2 indicators (alert on matching URIs and user-agents),
        # and return a dict with 'snort' and 'suricata' keys containing rule string lists."
        #
        # Then review and test the generated code.
        pass


def main():
    """Main entry point for Lab 14."""
    print("=" * 60)
    print("Lab 14: AI-Powered C2 Traffic Analysis")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "beacon_traffic.json"), "r") as f:
            beacon_data = json.load(f)
        print(f"\nLoaded {len(beacon_data.get('connections', []))} connections")
    except FileNotFoundError:
        print("Sample data not found. Using mock data.")
        beacon_data = {"connections": [], "dns": [], "http_sessions": []}

    # Task 1: Beacon detection
    print("\n--- Task 1: Beacon Detection ---")
    detector = BeaconDetector()
    beacons = detector.analyze_all_pairs(beacon_data.get("connections", []))
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
    tunnels = dns_detector.detect_tunneling_domain(beacon_data.get("dns", []))
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
    http_sessions = beacon_data.get("http_sessions", [])
    if http_sessions:
        for session in http_sessions[:2]:
            result = http_detector.analyze_http_session(session.get("flows", []))
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

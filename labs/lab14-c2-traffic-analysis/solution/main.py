"""
Lab 14: AI-Powered C2 Traffic Analysis - Solution

Detect and analyze Command & Control communications using ML and LLMs.
"""

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import numpy as np


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
    src_ip: str
    dst_ip: str
    dst_port: int
    interval: float
    jitter: float
    confidence: float
    sample_times: List[float] = field(default_factory=list)


@dataclass
class TunnelingCandidate:
    domain: str
    query_count: int
    avg_entropy: float
    avg_length: float
    record_types: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class HTTPFlow:
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
        self.jitter_tolerance = jitter_tolerance

    def extract_connection_timings(
        self, connections: List[dict], src_ip: str, dst_ip: str, dst_port: int = None
    ) -> List[float]:
        """Extract timestamps for connections between two hosts."""
        timings = []
        for conn in connections:
            if conn.get("src_ip") == src_ip and conn.get("dst_ip") == dst_ip:
                if dst_port is None or conn.get("dst_port") == dst_port:
                    ts = conn.get("timestamp")
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        ts = dt.timestamp()
                    timings.append(float(ts))
        return sorted(timings)

    def calculate_intervals(self, timings: List[float]) -> List[float]:
        """Calculate time intervals between consecutive connections."""
        if len(timings) < 2:
            return []
        return [timings[i + 1] - timings[i] for i in range(len(timings) - 1)]

    def detect_periodicity(self, timings: List[float]) -> dict:
        """Detect periodic patterns in connection timings."""
        if len(timings) < 5:
            return {"is_beacon": False, "interval": 0, "jitter": 1.0, "confidence": 0}

        intervals = self.calculate_intervals(timings)
        if not intervals:
            return {"is_beacon": False, "interval": 0, "jitter": 1.0, "confidence": 0}

        # Calculate statistics
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        # Jitter as coefficient of variation
        if mean_interval > 0:
            jitter = std_interval / mean_interval
        else:
            jitter = 1.0

        # Determine if this is beacon-like
        is_beacon = jitter <= self.jitter_tolerance and mean_interval > 1

        # Confidence based on sample size and consistency
        confidence = 0.0
        if is_beacon:
            sample_factor = min(len(intervals) / 20, 1.0)
            jitter_factor = 1.0 - (jitter / self.jitter_tolerance)
            confidence = sample_factor * 0.5 + jitter_factor * 0.5

        return {
            "is_beacon": is_beacon,
            "interval": mean_interval,
            "jitter": jitter,
            "confidence": confidence,
        }

    def analyze_all_pairs(self, connections: List[dict]) -> List[BeaconCandidate]:
        """Analyze all src-dst pairs for beaconing behavior."""
        # Group connections by (src, dst, port)
        pairs = defaultdict(list)
        for conn in connections:
            key = (conn.get("src_ip"), conn.get("dst_ip"), conn.get("dst_port"))
            pairs[key].append(conn)

        candidates = []
        for (src, dst, port), conns in pairs.items():
            if len(conns) < 5:
                continue

            timings = self.extract_connection_timings(connections, src, dst, port)
            result = self.detect_periodicity(timings)

            if result["is_beacon"]:
                candidates.append(
                    BeaconCandidate(
                        src_ip=src,
                        dst_ip=dst,
                        dst_port=port,
                        interval=result["interval"],
                        jitter=result["jitter"],
                        confidence=result["confidence"],
                        sample_times=timings[:10],
                    )
                )

        return sorted(candidates, key=lambda x: x.confidence, reverse=True)


class DNSTunnelDetector:
    """Identify data exfiltration or C2 over DNS."""

    def __init__(self):
        self.entropy_threshold = 3.5
        self.length_threshold = 50

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

    def get_base_domain(self, domain: str) -> str:
        """Get base domain (last two parts)."""
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def analyze_query(self, query: str) -> dict:
        """Analyze single DNS query for tunneling indicators."""
        subdomain = self.extract_subdomain(query)
        entropy = self.calculate_entropy(subdomain)
        indicators = []

        if entropy > self.entropy_threshold:
            indicators.append(f"High entropy subdomain: {entropy:.2f}")

        if len(subdomain) > self.length_threshold:
            indicators.append(f"Long subdomain: {len(subdomain)} chars")

        # Check for base64-like patterns (minimum 8 chars to avoid false positives)
        if len(subdomain) >= 8 and all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            for c in subdomain.replace(".", "")
        ):
            indicators.append("Base64-like encoding detected")

        # Check for hex-like patterns (minimum 8 chars to avoid false positives)
        if len(subdomain) >= 8 and all(c in "0123456789abcdefABCDEF." for c in subdomain):
            indicators.append("Hex encoding detected")

        return {
            "domain": query,
            "subdomain": subdomain,
            "subdomain_entropy": entropy,
            "subdomain_length": len(subdomain),
            "is_suspicious": len(indicators) > 0,
            "indicators": indicators,
        }

    def detect_tunneling_domain(
        self, queries: List[dict], min_queries: int = 10
    ) -> List[TunnelingCandidate]:
        """Detect domains being used for DNS tunneling."""
        # Group queries by base domain
        domain_stats = defaultdict(
            lambda: {"queries": [], "entropies": [], "lengths": [], "record_types": set()}
        )

        for query in queries:
            domain = query.get("query", query.get("domain", ""))
            base = self.get_base_domain(domain)
            analysis = self.analyze_query(domain)

            domain_stats[base]["queries"].append(domain)
            domain_stats[base]["entropies"].append(analysis["subdomain_entropy"])
            domain_stats[base]["lengths"].append(analysis["subdomain_length"])
            domain_stats[base]["record_types"].add(query.get("type", "A"))

        candidates = []
        for domain, stats in domain_stats.items():
            if len(stats["queries"]) < min_queries:
                continue

            avg_entropy = np.mean(stats["entropies"]) if stats["entropies"] else 0
            avg_length = np.mean(stats["lengths"]) if stats["lengths"] else 0

            # Calculate confidence
            confidence = 0.0
            if avg_entropy > self.entropy_threshold:
                confidence += 0.4
            if avg_length > self.length_threshold:
                confidence += 0.3
            if "TXT" in stats["record_types"]:
                confidence += 0.2
            if len(stats["queries"]) > 100:
                confidence += 0.1

            if confidence > 0.3:
                candidates.append(
                    TunnelingCandidate(
                        domain=domain,
                        query_count=len(stats["queries"]),
                        avg_entropy=avg_entropy,
                        avg_length=avg_length,
                        record_types=list(stats["record_types"]),
                        confidence=min(confidence, 1.0),
                    )
                )

        return sorted(candidates, key=lambda x: x.confidence, reverse=True)


class HTTPC2Detector:
    """Identify HTTP-based C2 patterns."""

    C2_URI_PATTERNS = [
        "/submit.php",
        "/pixel.gif",
        "/__utm.gif",
        "/login.php",
        "/admin.php",
        "/upload.php",
        "/jquery-",
        ".js?",
        "/api/v1/",
        "/beacon",
    ]

    SUSPICIOUS_UA_PATTERNS = [
        "Mozilla/4.0",
        "Mozilla/5.0 (compatible;",
        "Java/",
        "Python-urllib",
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

    def analyze_http_session(self, flows: List[dict]) -> dict:
        """Analyze HTTP session for C2 indicators."""
        if not flows:
            return {"is_suspicious": False, "indicators": [], "confidence": 0}

        indicators = []
        confidence = 0.0

        # Analyze URIs
        uris = [f.get("uri", "") for f in flows]
        for uri in uris:
            for pattern in self.C2_URI_PATTERNS:
                if pattern in uri.lower():
                    indicators.append(f"Suspicious URI pattern: {pattern}")
                    confidence += 0.2
                    break

        # Analyze User-Agents
        user_agents = set(f.get("user_agent", "") for f in flows)
        for ua in user_agents:
            for pattern in self.SUSPICIOUS_UA_PATTERNS:
                if pattern in ua:
                    indicators.append(f"Suspicious User-Agent: {pattern}")
                    confidence += 0.15
                    break

        # Check for regular timing (beacon-like)
        if len(flows) >= 5:
            timestamps = []
            for f in flows:
                ts = f.get("timestamp")
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        ts = dt.timestamp()
                    timestamps.append(ts)

            if len(timestamps) >= 5:
                timestamps.sort()
                intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
                if intervals:
                    std = np.std(intervals)
                    mean = np.mean(intervals)
                    if mean > 0 and std / mean < 0.2:
                        indicators.append(f"Regular timing pattern: ~{mean:.0f}s interval")
                        confidence += 0.3

        # Check response sizes for patterns
        response_sizes = [f.get("response_size", 0) for f in flows]
        if len(set(response_sizes)) == 1 and response_sizes[0] > 0:
            indicators.append("Identical response sizes (possible C2)")
            confidence += 0.15

        return {
            "is_suspicious": confidence > 0.3,
            "indicators": indicators,
            "c2_profile_match": self._match_c2_profile(flows),
            "confidence": min(confidence, 1.0),
        }

    def _match_c2_profile(self, flows: List[dict]) -> Optional[str]:
        """Match session against known C2 profiles."""
        uris = [f.get("uri", "") for f in flows]

        # Cobalt Strike defaults
        cs_patterns = ["/submit.php", "/__utm.gif", "/pixel.gif"]
        if any(any(p in uri for p in cs_patterns) for uri in uris):
            return "Cobalt Strike (default profile)"

        # Metasploit patterns
        if any("/met" in uri.lower() for uri in uris):
            return "Possible Metasploit"

        return None

    def llm_analyze_session(self, session: dict) -> dict:
        """Use LLM to analyze HTTP session for C2 indicators."""
        self._init_llm()
        if not self.llm:
            return {"error": "LLM not available"}

        provider, client = self.llm
        prompt = f"""Analyze this HTTP session for Command & Control (C2) indicators:

Session Summary:
- Destination: {session.get('dst_ip')}:{session.get('dst_port')}
- Request Count: {session.get('request_count')}
- Duration: {session.get('duration_seconds')}s

Sample URIs: {session.get('sample_uris', [])}
User-Agent: {session.get('user_agent', 'unknown')}

Provide analysis in JSON format:
- is_c2: boolean
- confidence: 0-1
- framework_guess: string or null
- indicators: list of strings
- mitre_techniques: list of technique IDs"""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                result_text = response.content[0].text
            elif provider == "openai":
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                )
                result_text = response.choices[0].message.content
            elif provider == "google":
                response = client.generate_content(prompt)
                result_text = response.text

            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            return json.loads(result_text)
        except Exception as e:
            return {"error": str(e)}


class TLSCertAnalyzer:
    """Detect C2 using TLS certificate anomalies."""

    FREE_CA_PROVIDERS = ["Let's Encrypt", "ZeroSSL", "Buypass"]

    def analyze_certificate(self, cert_data: dict) -> dict:
        """Analyze TLS certificate for C2 indicators."""
        indicators = []
        risk_score = 0.0

        issuer = cert_data.get("issuer", "")
        subject = cert_data.get("subject", "")
        not_before = cert_data.get("not_before", "")
        not_after = cert_data.get("not_after", "")

        # Self-signed check
        if issuer == subject:
            indicators.append("Self-signed certificate")
            risk_score += 0.4

        # Recent issuance
        if not_before:
            try:
                issued = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                age_days = (datetime.now(issued.tzinfo) - issued).days
                if age_days < 30:
                    indicators.append(f"Recently issued: {age_days} days ago")
                    risk_score += 0.2
            except (ValueError, TypeError):
                pass

        # Short validity period
        if not_before and not_after:
            try:
                start = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                end = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                validity_days = (end - start).days
                if validity_days < 90:
                    indicators.append(f"Short validity: {validity_days} days")
                    risk_score += 0.15
            except (ValueError, TypeError):
                pass

        # Free CA for suspicious domain
        for ca in self.FREE_CA_PROVIDERS:
            if ca.lower() in issuer.lower():
                indicators.append(f"Free CA provider: {ca}")
                risk_score += 0.1
                break

        return {
            "domain": cert_data.get("subject_cn", subject),
            "indicators": indicators,
            "risk_score": min(risk_score, 1.0),
        }


class C2DetectionPipeline:
    """End-to-end C2 detection pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        self.beacon_detector = BeaconDetector()
        self.dns_detector = DNSTunnelDetector()
        self.http_detector = HTTPC2Detector(llm_provider)
        self.tls_analyzer = TLSCertAnalyzer()

    def analyze_traffic(self, traffic_data: dict) -> C2Report:
        """Run full C2 detection on network traffic."""
        # 1. Beacon detection
        beacons = self.beacon_detector.analyze_all_pairs(traffic_data.get("connections", []))

        # 2. DNS tunneling
        tunneling = self.dns_detector.detect_tunneling_domain(traffic_data.get("dns", []))

        # 3. HTTP C2 patterns
        http_c2 = []
        for session in traffic_data.get("http_sessions", []):
            result = self.http_detector.analyze_http_session(session.get("flows", []))
            if result.get("is_suspicious"):
                result["dst_ip"] = session.get("dst_ip")
                http_c2.append(result)

        # 4. TLS anomalies
        tls_anomalies = []
        for cert in traffic_data.get("tls_certs", []):
            analysis = self.tls_analyzer.analyze_certificate(cert)
            if analysis["risk_score"] > 0.3:
                tls_anomalies.append(analysis)

        # Determine risk level
        if beacons or any(t.confidence > 0.7 for t in tunneling):
            risk_level = "critical"
        elif http_c2 or tunneling:
            risk_level = "high"
        elif tls_anomalies:
            risk_level = "medium"
        else:
            risk_level = "low"

        summary_parts = []
        if beacons:
            summary_parts.append(f"{len(beacons)} beacon(s) detected")
        if tunneling:
            summary_parts.append(f"{len(tunneling)} DNS tunneling domain(s)")
        if http_c2:
            summary_parts.append(f"{len(http_c2)} suspicious HTTP session(s)")
        if tls_anomalies:
            summary_parts.append(f"{len(tls_anomalies)} TLS anomalies")

        return C2Report(
            timestamp=datetime.now().isoformat(),
            beacons=beacons,
            tunneling=tunneling,
            http_c2=http_c2,
            tls_anomalies=tls_anomalies,
            summary="; ".join(summary_parts) if summary_parts else "No C2 indicators found",
            risk_level=risk_level,
        )

    def generate_detection_rules(self, report: C2Report) -> dict:
        """Generate Snort/Suricata rules from findings."""
        snort_rules = []
        suricata_rules = []

        # Rules for beacons
        for i, beacon in enumerate(report.beacons):
            rule = f'alert tcp any any -> {beacon.dst_ip} {beacon.dst_port} (msg:"Potential C2 Beacon to {beacon.dst_ip}"; sid:100000{i}; rev:1;)'
            snort_rules.append(rule)

        # Rules for DNS tunneling
        for i, tunnel in enumerate(report.tunneling):
            rule = f'alert dns any any -> any any (msg:"Potential DNS Tunnel: {tunnel.domain}"; dns.query; content:"{tunnel.domain}"; sid:100100{i}; rev:1;)'
            suricata_rules.append(rule)

        return {"snort": snort_rules, "suricata": suricata_rules}


def main():
    """Main entry point for Lab 14."""
    print("=" * 60)
    print("Lab 14: AI-Powered C2 Traffic Analysis - Solution")
    print("=" * 60)

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "beacon_traffic.json"), "r") as f:
            traffic_data = json.load(f)
        print(f"\nLoaded traffic data")
    except FileNotFoundError:
        print("Sample data not found. Creating mock data.")
        traffic_data = create_mock_traffic_data()

    # Run pipeline
    print("\n" + "-" * 40)
    print("Running C2 Detection Pipeline")
    print("-" * 40)

    pipeline = C2DetectionPipeline()
    report = pipeline.analyze_traffic(traffic_data)

    # Display results
    print(f"\n{'=' * 60}")
    print("C2 DETECTION REPORT")
    print("=" * 60)
    print(f"Timestamp: {report.timestamp}")
    print(f"Risk Level: {report.risk_level.upper()}")
    print(f"Summary: {report.summary}")

    if report.beacons:
        print(f"\n--- Beacons ({len(report.beacons)}) ---")
        for b in report.beacons:
            print(f"  {b.src_ip} -> {b.dst_ip}:{b.dst_port}")
            print(
                f"    Interval: {b.interval:.1f}s, Jitter: {b.jitter:.1%}, Confidence: {b.confidence:.1%}"
            )

    if report.tunneling:
        print(f"\n--- DNS Tunneling ({len(report.tunneling)}) ---")
        for t in report.tunneling:
            print(f"  {t.domain}")
            print(
                f"    Queries: {t.query_count}, Entropy: {t.avg_entropy:.2f}, Confidence: {t.confidence:.1%}"
            )

    if report.http_c2:
        print(f"\n--- HTTP C2 ({len(report.http_c2)}) ---")
        for h in report.http_c2:
            print(f"  {h.get('dst_ip', 'unknown')}")
            for ind in h.get("indicators", []):
                print(f"    - {ind}")

    # Generate rules
    rules = pipeline.generate_detection_rules(report)
    if rules["snort"] or rules["suricata"]:
        print("\n--- Generated Detection Rules ---")
        for rule in rules["snort"][:3]:
            print(f"  {rule}")

    print("\n" + "=" * 60)


def create_mock_traffic_data():
    """Create mock traffic data for demo."""
    base_time = datetime(2024, 1, 15, 9, 0, 0)

    # Create beacon-like traffic
    connections = []
    for i in range(30):
        connections.append(
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "185.234.72.19",
                "dst_port": 443,
                "timestamp": (base_time.timestamp() + i * 60 + np.random.uniform(-5, 5)),
                "protocol": "TCP",
            }
        )

    # Normal traffic
    for i in range(50):
        connections.append(
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "timestamp": (base_time.timestamp() + np.random.uniform(0, 3600)),
                "protocol": "UDP",
            }
        )

    # DNS tunneling queries
    dns_queries = []
    tunnel_domain = "evil-tunnel.com"
    for i in range(50):
        encoded_data = "".join(np.random.choice(list("abcdef0123456789"), 32))
        dns_queries.append(
            {
                "query": f"{encoded_data}.{tunnel_domain}",
                "type": "TXT" if i % 3 == 0 else "A",
                "timestamp": base_time.timestamp() + i * 10,
            }
        )

    # Normal DNS
    for domain in ["google.com", "microsoft.com", "github.com"]:
        for i in range(10):
            dns_queries.append(
                {
                    "query": domain,
                    "type": "A",
                    "timestamp": base_time.timestamp() + np.random.uniform(0, 3600),
                }
            )

    # HTTP sessions
    http_sessions = [
        {
            "dst_ip": "185.234.72.19",
            "dst_port": 443,
            "flows": [
                {
                    "timestamp": (base_time.timestamp() + i * 60),
                    "method": "GET",
                    "uri": "/submit.php?id=" + str(i),
                    "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
                    "response_code": 200,
                    "response_size": 1024,
                }
                for i in range(10)
            ],
        }
    ]

    # TLS certificates
    tls_certs = [
        {
            "subject": "CN=malicious.example.com",
            "issuer": "CN=malicious.example.com",
            "subject_cn": "malicious.example.com",
            "not_before": datetime.now().isoformat(),
            "not_after": (datetime.now().replace(year=datetime.now().year + 1)).isoformat(),
        }
    ]

    return {
        "connections": connections,
        "dns": dns_queries,
        "http_sessions": http_sessions,
        "tls_certs": tls_certs,
    }


if __name__ == "__main__":
    main()

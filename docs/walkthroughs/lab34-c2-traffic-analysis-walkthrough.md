# Lab 14: C2 Traffic Analysis - Solution Walkthrough

## Overview

Build an AI-powered C2 (Command & Control) traffic detection system for identifying beaconing, DNS tunneling, and encrypted C2 channels.

**Time:** 3-4 hours
**Difficulty:** Advanced

---

## Task 1: Beaconing Detection

### Identifying Periodic C2 Communication

```python
import numpy as np
from scipy import stats
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

@dataclass
class NetworkFlow:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float

class BeaconDetector:
    def __init__(self):
        # Detection thresholds
        self.min_connections = 10  # Minimum connections to analyze
        self.jitter_threshold = 0.3  # Max 30% jitter for beacon detection
        self.regularity_threshold = 0.7  # Minimum regularity score

    def detect_beacons(self, flows: list[NetworkFlow]) -> list[dict]:
        """Detect beaconing behavior in network flows."""

        # Group flows by destination
        dest_flows = defaultdict(list)
        for flow in flows:
            key = (flow.dst_ip, flow.dst_port)
            dest_flows[key].append(flow)

        beacons = []

        for (dst_ip, dst_port), flow_list in dest_flows.items():
            if len(flow_list) < self.min_connections:
                continue

            analysis = self._analyze_timing(flow_list)

            if analysis['is_beacon']:
                beacons.append({
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'connection_count': len(flow_list),
                    'interval_mean': analysis['interval_mean'],
                    'interval_std': analysis['interval_std'],
                    'jitter': analysis['jitter'],
                    'regularity_score': analysis['regularity_score'],
                    'first_seen': min(f.timestamp for f in flow_list).isoformat(),
                    'last_seen': max(f.timestamp for f in flow_list).isoformat()
                })

        return sorted(beacons, key=lambda x: x['regularity_score'], reverse=True)

    def _analyze_timing(self, flows: list[NetworkFlow]) -> dict:
        """Analyze timing patterns in flows."""

        # Sort by timestamp
        sorted_flows = sorted(flows, key=lambda f: f.timestamp)

        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(sorted_flows)):
            delta = (sorted_flows[i].timestamp - sorted_flows[i-1].timestamp).total_seconds()
            intervals.append(delta)

        if not intervals:
            return {'is_beacon': False}

        # Statistical analysis
        intervals = np.array(intervals)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        # Calculate jitter (coefficient of variation)
        jitter = std_interval / mean_interval if mean_interval > 0 else 1.0

        # Calculate regularity score using FFT
        regularity_score = self._calculate_regularity(intervals)

        is_beacon = (
            jitter <= self.jitter_threshold and
            regularity_score >= self.regularity_threshold
        )

        return {
            'is_beacon': is_beacon,
            'interval_mean': round(mean_interval, 2),
            'interval_std': round(std_interval, 2),
            'jitter': round(jitter, 4),
            'regularity_score': round(regularity_score, 4)
        }

    def _calculate_regularity(self, intervals: np.ndarray) -> float:
        """Calculate regularity score using FFT analysis."""

        if len(intervals) < 4:
            return 0.0

        # Normalize intervals
        normalized = (intervals - np.mean(intervals)) / (np.std(intervals) + 1e-10)

        # Apply FFT
        fft_result = np.abs(np.fft.fft(normalized))

        # Find dominant frequency
        dominant_freq_power = np.max(fft_result[1:len(fft_result)//2])
        total_power = np.sum(fft_result[1:len(fft_result)//2])

        # Regularity is ratio of dominant to total
        regularity = dominant_freq_power / (total_power + 1e-10)

        return min(regularity, 1.0)

# Detect beacons
beacon_detector = BeaconDetector()

# Sample flows (in production, load from PCAP/Zeek/etc.)
flows = [
    NetworkFlow(datetime(2024, 12, 23, 10, 0, 0), "192.168.1.100", "10.0.0.50", 443, "TCP", 1024, 2048, 0.5),
    NetworkFlow(datetime(2024, 12, 23, 10, 5, 0), "192.168.1.100", "10.0.0.50", 443, "TCP", 1024, 2048, 0.5),
    NetworkFlow(datetime(2024, 12, 23, 10, 10, 0), "192.168.1.100", "10.0.0.50", 443, "TCP", 1024, 2048, 0.5),
    # ... more flows
]

beacons = beacon_detector.detect_beacons(flows)
for beacon in beacons:
    print(f"Beacon detected: {beacon['dst_ip']}:{beacon['dst_port']}")
    print(f"  Interval: {beacon['interval_mean']}s (jitter: {beacon['jitter']})")
```

---

## Task 2: DNS Tunneling Detection

### Identifying Data Exfiltration via DNS

```python
import re
import math
from collections import Counter

class DNSTunnelingDetector:
    def __init__(self):
        self.entropy_threshold = 3.5  # High entropy indicates encoding
        self.length_threshold = 50  # Long subdomain names
        self.query_rate_threshold = 100  # Queries per minute

    def analyze_dns_query(self, query: str) -> dict:
        """Analyze a single DNS query for tunneling indicators."""

        # Extract subdomain
        parts = query.lower().split('.')
        subdomain = parts[0] if len(parts) > 2 else ''

        analysis = {
            'query': query,
            'subdomain': subdomain,
            'subdomain_length': len(subdomain),
            'entropy': self._calculate_entropy(subdomain),
            'has_encoded_data': False,
            'suspicious_patterns': [],
            'risk_score': 0
        }

        # Check for Base64/Hex patterns
        if re.match(r'^[A-Za-z0-9+/=]+$', subdomain) and len(subdomain) > 20:
            analysis['has_encoded_data'] = True
            analysis['suspicious_patterns'].append('base64_like')

        if re.match(r'^[0-9a-fA-F]+$', subdomain) and len(subdomain) > 20:
            analysis['has_encoded_data'] = True
            analysis['suspicious_patterns'].append('hex_encoded')

        # Check for unusual TLD patterns
        if parts[-1] in ['xyz', 'top', 'tk', 'ml', 'ga', 'cf']:
            analysis['suspicious_patterns'].append('suspicious_tld')

        # Calculate risk score
        risk = 0
        if analysis['entropy'] > self.entropy_threshold:
            risk += 30
        if analysis['subdomain_length'] > self.length_threshold:
            risk += 30
        if analysis['has_encoded_data']:
            risk += 25
        if analysis['suspicious_patterns']:
            risk += 15

        analysis['risk_score'] = min(risk, 100)

        return analysis

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 3)

    def detect_tunneling_domain(self, queries: list[dict]) -> list[dict]:
        """Detect DNS tunneling by analyzing query patterns per domain."""

        # Group by domain
        domain_stats = defaultdict(lambda: {
            'queries': [],
            'total_subdomain_bytes': 0,
            'unique_subdomains': set()
        })

        for query in queries:
            parts = query['name'].split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
                subdomain = parts[0] if len(parts) > 2 else ''

                domain_stats[domain]['queries'].append(query)
                domain_stats[domain]['total_subdomain_bytes'] += len(subdomain)
                domain_stats[domain]['unique_subdomains'].add(subdomain)

        # Analyze each domain
        tunneling_candidates = []

        for domain, stats in domain_stats.items():
            if len(stats['queries']) < 10:
                continue

            # Calculate metrics
            query_count = len(stats['queries'])
            unique_ratio = len(stats['unique_subdomains']) / query_count
            avg_subdomain_len = stats['total_subdomain_bytes'] / query_count

            # Analyze individual queries
            high_entropy_count = 0
            for query in stats['queries']:
                analysis = self.analyze_dns_query(query['name'])
                if analysis['entropy'] > self.entropy_threshold:
                    high_entropy_count += 1

            entropy_ratio = high_entropy_count / query_count

            # Determine if likely tunneling
            is_tunneling = (
                unique_ratio > 0.9 and  # Almost all unique subdomains
                avg_subdomain_len > 30 and  # Long subdomains
                entropy_ratio > 0.5  # High entropy queries
            )

            if is_tunneling or entropy_ratio > 0.3:
                tunneling_candidates.append({
                    'domain': domain,
                    'query_count': query_count,
                    'unique_subdomain_ratio': round(unique_ratio, 3),
                    'avg_subdomain_length': round(avg_subdomain_len, 1),
                    'high_entropy_ratio': round(entropy_ratio, 3),
                    'estimated_data_bytes': stats['total_subdomain_bytes'],
                    'is_likely_tunneling': is_tunneling,
                    'risk_score': min(100, int(entropy_ratio * 50 + unique_ratio * 30 + (avg_subdomain_len / 2)))
                })

        return sorted(tunneling_candidates, key=lambda x: x['risk_score'], reverse=True)

# Detect DNS tunneling
dns_detector = DNSTunnelingDetector()

# Sample DNS queries
dns_queries = [
    {'name': 'dGhpcyBpcyBhIHRlc3Q.evil.com', 'type': 'A'},
    {'name': 'YW5vdGhlciB0ZXN0.evil.com', 'type': 'A'},
    {'name': 'www.google.com', 'type': 'A'},
    # ... more queries
]

tunneling = dns_detector.detect_tunneling_domain(dns_queries)
for candidate in tunneling:
    print(f"Potential DNS tunneling: {candidate['domain']}")
    print(f"  Risk Score: {candidate['risk_score']}/100")
```

---

## Task 3: Encrypted C2 Detection

### Analyzing TLS/SSL Traffic Patterns

```python
import hashlib

@dataclass
class TLSConnection:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    ja3_hash: str
    ja3s_hash: str
    server_name: str
    cert_issuer: str
    cert_subject: str
    cert_validity_days: int

class EncryptedC2Detector:
    def __init__(self):
        # Known malicious JA3 hashes
        self.malicious_ja3 = {
            'e7d705a3286e19ea42f587b344ee6865': 'Cobalt Strike',
            'a0e9f5d64349fb13191bc781f81f42e1': 'Metasploit',
            '72a589da586844d7f0818ce684948eea': 'Empire',
            # Add more from threat intel
        }

        # Suspicious certificate patterns
        self.suspicious_cert_patterns = [
            r'let\'s encrypt',  # Often abused
            r'self.signed',
            r'cloudflare',  # Check context
        ]

    def analyze_tls_connection(self, conn: TLSConnection) -> dict:
        """Analyze TLS connection for C2 indicators."""

        analysis = {
            'connection': {
                'dst_ip': conn.dst_ip,
                'dst_port': conn.dst_port,
                'server_name': conn.server_name
            },
            'indicators': [],
            'risk_score': 0
        }

        # Check JA3 hash
        if conn.ja3_hash in self.malicious_ja3:
            analysis['indicators'].append({
                'type': 'malicious_ja3',
                'value': conn.ja3_hash,
                'matched': self.malicious_ja3[conn.ja3_hash]
            })
            analysis['risk_score'] += 50

        # Check certificate
        if conn.cert_validity_days and conn.cert_validity_days < 30:
            analysis['indicators'].append({
                'type': 'short_cert_validity',
                'value': conn.cert_validity_days
            })
            analysis['risk_score'] += 20

        # Check for self-signed or suspicious issuers
        if conn.cert_issuer:
            issuer_lower = conn.cert_issuer.lower()
            if 'self' in issuer_lower or conn.cert_issuer == conn.cert_subject:
                analysis['indicators'].append({
                    'type': 'self_signed_cert',
                    'value': conn.cert_issuer
                })
                analysis['risk_score'] += 30

        # Check for IP-based server name (no SNI)
        if not conn.server_name or re.match(r'^\d+\.\d+\.\d+\.\d+$', conn.server_name):
            analysis['indicators'].append({
                'type': 'no_sni_or_ip_based',
                'value': conn.server_name or 'No SNI'
            })
            analysis['risk_score'] += 25

        # Check unusual port
        if conn.dst_port not in [443, 8443]:
            analysis['indicators'].append({
                'type': 'unusual_tls_port',
                'value': conn.dst_port
            })
            analysis['risk_score'] += 15

        analysis['risk_score'] = min(analysis['risk_score'], 100)

        return analysis

    def correlate_with_beacons(self, tls_connections: list[TLSConnection],
                               beacon_results: list[dict]) -> list[dict]:
        """Correlate encrypted traffic with beacon detection."""

        correlated = []
        beacon_dests = {(b['dst_ip'], b['dst_port']) for b in beacon_results}

        for conn in tls_connections:
            tls_analysis = self.analyze_tls_connection(conn)

            # Check if destination matches beacon
            if (conn.dst_ip, conn.dst_port) in beacon_dests:
                tls_analysis['beacon_correlation'] = True
                tls_analysis['risk_score'] = min(100, tls_analysis['risk_score'] + 30)

                # Find matching beacon
                for beacon in beacon_results:
                    if beacon['dst_ip'] == conn.dst_ip and beacon['dst_port'] == conn.dst_port:
                        tls_analysis['beacon_info'] = beacon
                        break

                correlated.append(tls_analysis)

        return correlated

# Analyze encrypted traffic
encrypted_detector = EncryptedC2Detector()

tls_conn = TLSConnection(
    timestamp=datetime.now(),
    src_ip="192.168.1.100",
    dst_ip="185.123.45.67",
    dst_port=443,
    ja3_hash="e7d705a3286e19ea42f587b344ee6865",
    ja3s_hash="abc123",
    server_name="",
    cert_issuer="Self-Signed",
    cert_subject="Self-Signed",
    cert_validity_days=7
)

analysis = encrypted_detector.analyze_tls_connection(tls_conn)
print(f"Risk Score: {analysis['risk_score']}/100")
print(f"Indicators: {analysis['indicators']}")
```

---

## Task 4: AI-Powered Traffic Analysis

### LLM Integration for C2 Detection

```python
import anthropic

class AIC2Analyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def analyze_suspicious_traffic(self, traffic_data: dict) -> str:
        """AI analysis of suspicious network traffic."""

        prompt = f"""Analyze this network traffic for C2 (Command & Control) indicators:

## Traffic Summary
{json.dumps(traffic_data, indent=2, default=str)}

Analyze for:
1. **C2 Protocol Identification** - What type of C2 might this be?
2. **Malware Family** - Any indicators of specific malware?
3. **Attack Stage** - What phase of attack does this represent?
4. **Data Exfiltration** - Signs of data leaving the network?
5. **Lateral Movement** - Internal reconnaissance or spreading?

Provide:
- Risk assessment (Critical/High/Medium/Low)
- Confidence level in your assessment
- Recommended immediate actions
- IOCs to block
- MITRE ATT&CK techniques observed"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def classify_c2_type(self, indicators: list[dict]) -> dict:
        """Classify the type of C2 based on indicators."""

        prompt = f"""Based on these network indicators, classify the C2 type:

## Indicators
{json.dumps(indicators, indent=2)}

Classify into one of these C2 types:
1. HTTP/HTTPS Beacon (e.g., Cobalt Strike, Metasploit)
2. DNS Tunneling (e.g., DNScat, Iodine)
3. Custom Protocol (proprietary C2)
4. Cloud-based C2 (using legitimate services)
5. Social Media C2 (Twitter, Telegram, etc.)
6. P2P C2 (peer-to-peer communication)

Return JSON with:
- "c2_type": Most likely type
- "confidence": 0.0-1.0
- "alternative_types": Other possible types
- "key_indicators": What led to this classification
- "recommended_detection": How to detect this C2 type"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except json.JSONDecodeError:
            return {'raw': response.content[0].text}

    def generate_detection_rules(self, c2_analysis: dict) -> str:
        """Generate detection rules for identified C2."""

        prompt = f"""Generate detection rules for this C2 traffic pattern:

## C2 Analysis
{json.dumps(c2_analysis, indent=2, default=str)}

Generate:
1. Suricata/Snort rule
2. Zeek script snippet
3. Sigma rule for SIEM
4. YARA rule for network traffic
5. Firewall block rule (generic format)

Include comments explaining each rule."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# AI analysis
ai_analyzer = AIC2Analyzer()

# Combine all findings
combined_findings = {
    'beacons': beacons,
    'dns_tunneling': tunneling,
    'encrypted_c2': [analysis],
    'timestamp': datetime.now().isoformat()
}

# Get AI analysis
ai_analysis = ai_analyzer.analyze_suspicious_traffic(combined_findings)
print("AI Analysis:")
print(ai_analysis)
```

---

## Task 5: Complete Detection Pipeline

### Integrated C2 Detection System

```python
class C2DetectionPipeline:
    def __init__(self):
        self.beacon_detector = BeaconDetector()
        self.dns_detector = DNSTunnelingDetector()
        self.encrypted_detector = EncryptedC2Detector()
        self.ai_analyzer = AIC2Analyzer()

    def analyze_traffic(self, network_flows: list[NetworkFlow],
                       dns_queries: list[dict],
                       tls_connections: list[TLSConnection]) -> dict:
        """Complete C2 traffic analysis."""

        results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'findings': {}
        }

        # Beacon detection
        print("[1/4] Detecting beacons...")
        beacons = self.beacon_detector.detect_beacons(network_flows)
        results['findings']['beacons'] = beacons

        # DNS tunneling detection
        print("[2/4] Detecting DNS tunneling...")
        dns_tunneling = self.dns_detector.detect_tunneling_domain(dns_queries)
        results['findings']['dns_tunneling'] = dns_tunneling

        # Encrypted C2 detection
        print("[3/4] Analyzing encrypted traffic...")
        encrypted_c2 = []
        for conn in tls_connections:
            analysis = self.encrypted_detector.analyze_tls_connection(conn)
            if analysis['risk_score'] > 30:
                encrypted_c2.append(analysis)
        results['findings']['encrypted_c2'] = encrypted_c2

        # Correlation
        print("[4/4] Correlating findings...")
        correlated = self.encrypted_detector.correlate_with_beacons(
            tls_connections, beacons
        )
        results['findings']['correlated'] = correlated

        # Summary
        results['summary'] = {
            'beacon_count': len(beacons),
            'dns_tunneling_domains': len(dns_tunneling),
            'suspicious_tls': len(encrypted_c2),
            'correlated_threats': len(correlated),
            'risk_level': self._calculate_risk_level(results['findings'])
        }

        return results

    def _calculate_risk_level(self, findings: dict) -> str:
        """Calculate overall risk level."""
        score = 0

        if findings['beacons']:
            score += 30
        if findings['dns_tunneling']:
            score += 40
        if findings['encrypted_c2']:
            score += 20
        if findings['correlated']:
            score += 40

        if score >= 70:
            return 'CRITICAL'
        elif score >= 40:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        return 'LOW'

    def generate_report(self, results: dict) -> str:
        """Generate comprehensive C2 detection report."""
        return self.ai_analyzer.analyze_suspicious_traffic(results)

# Run detection pipeline
pipeline = C2DetectionPipeline()

# Analyze (with sample data)
results = pipeline.analyze_traffic(flows, dns_queries, [tls_conn])

print(f"\nRisk Level: {results['summary']['risk_level']}")
print(f"Beacons: {results['summary']['beacon_count']}")
print(f"DNS Tunneling: {results['summary']['dns_tunneling_domains']}")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| High false positives | Tune thresholds, add whitelists |
| Missed beacons | Lower jitter threshold, check time ranges |
| DNS analysis slow | Use sampling, limit domain analysis |
| JA3 hash misses | Update threat intel, use JA3S too |
| Encrypted traffic | Focus on metadata, not content |

---

## Next Steps

- Add real-time streaming analysis
- Integrate threat intelligence feeds
- Build ML model for C2 classification
- Add protocol-specific detectors (HTTP, DNS, ICMP)
- Create automated blocking integration

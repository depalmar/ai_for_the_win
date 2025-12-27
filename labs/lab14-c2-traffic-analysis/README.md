# Lab 14: AI-Powered C2 Traffic Analysis

Detect and analyze Command & Control (C2) communications using machine learning and LLMs. Learn to identify beaconing, data exfiltration, and covert channels.

## Learning Objectives

1. Understand C2 frameworks and communication patterns
2. Build ML models to detect beaconing behavior
3. Identify DNS tunneling and HTTP covert channels
4. Use LLMs to analyze suspicious traffic patterns
5. Generate detection rules from C2 traffic analysis

## Estimated Time

3-4 hours

## Prerequisites

- Completed Labs 03 (Anomaly Detection), 04 (Log Analysis)
- Basic understanding of network protocols (HTTP, DNS, TLS)
- Familiarity with PCAP analysis concepts

## Background

### Command & Control Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          C2 COMMUNICATION FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   COMPROMISED HOST                              C2 SERVER                   │
│   ┌──────────────┐                             ┌──────────────┐            │
│   │              │  ① Beacon (check-in)        │              │            │
│   │   Implant/   │ ─────────────────────────►  │   Attacker   │            │
│   │   Backdoor   │                             │   Control    │            │
│   │              │  ② Commands                 │   Panel      │            │
│   │              │ ◄─────────────────────────  │              │            │
│   │              │                             │              │            │
│   │              │  ③ Results/Exfil            │              │            │
│   │              │ ─────────────────────────►  │              │            │
│   └──────────────┘                             └──────────────┘            │
│                                                                             │
│   DETECTION OPPORTUNITIES:                                                  │
│   • Beaconing patterns (regular intervals)                                  │
│   • Unusual protocols or ports                                              │
│   • Encoded/encrypted payloads                                              │
│   • DNS tunneling (long queries, TXT records)                               │
│   • Certificate anomalies                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Common C2 Frameworks

| Framework | Typical Indicators |
|-----------|-------------------|
| Cobalt Strike | Malleable C2 profiles, HTTPS beacons, named pipes |
| Metasploit | Meterpreter sessions, staged payloads |
| Empire/Starkiller | PowerShell, HTTP(S) with jitter |
| Sliver | mTLS, DNS, HTTP(S), WireGuard |
| Havoc | Custom protocols, Sleep obfuscation |

### MITRE ATT&CK Techniques

| Technique | ID | Description |
|-----------|-----|-------------|
| Application Layer Protocol | T1071 | HTTP, DNS, HTTPS C2 |
| Encrypted Channel | T1573 | TLS/SSL C2 communications |
| Protocol Tunneling | T1572 | DNS tunneling, ICMP tunneling |
| Data Encoding | T1132 | Base64, custom encoding |
| Exfiltration Over C2 | T1041 | Data theft via C2 channel |

---

## Tasks

### Task 1: Beaconing Detection

Detect regular callback patterns indicative of C2.

```python
# TODO: Implement beaconing detection
class BeaconDetector:
    def __init__(self, jitter_tolerance: float = 0.2):
        """
        Initialize beacon detector.

        Args:
            jitter_tolerance: Allowable variance in beacon timing (0.2 = 20%)
        """
        self.jitter_tolerance = jitter_tolerance

    def extract_connection_timings(
        self,
        connections: List[dict],
        src_ip: str,
        dst_ip: str
    ) -> List[float]:
        """Extract timestamps for connections between two hosts."""
        pass

    def detect_periodicity(self, timings: List[float]) -> dict:
        """
        Detect periodic patterns in connection timings.

        Returns:
            {
                'is_beacon': bool,
                'interval': float,  # seconds
                'jitter': float,    # variance
                'confidence': float
            }
        """
        # Use FFT or autocorrelation to detect periodicity
        pass

    def analyze_all_pairs(self, connections: List[dict]) -> List[BeaconCandidate]:
        """Analyze all src-dst pairs for beaconing."""
        pass
```

### Task 2: DNS Tunneling Detection

Identify data exfiltration or C2 over DNS.

```python
# TODO: Implement DNS tunneling detection
class DNSTunnelDetector:
    def __init__(self):
        self.entropy_threshold = 3.5  # Bits per character
        self.length_threshold = 50    # Subdomain length

    def analyze_query(self, query: str) -> dict:
        """
        Analyze single DNS query for tunneling indicators.

        Returns:
            {
                'domain': str,
                'subdomain_entropy': float,
                'subdomain_length': int,
                'is_suspicious': bool,
                'indicators': List[str]
            }
        """
        pass

    def detect_tunneling_domain(
        self,
        queries: List[dict],
        min_queries: int = 10
    ) -> List[TunnelingCandidate]:
        """
        Detect domains being used for DNS tunneling.

        Indicators:
        - High entropy subdomains
        - Unusually long queries
        - High query volume
        - TXT record responses
        - Unusual query patterns
        """
        pass

    def extract_tunneled_data(self, queries: List[dict], domain: str) -> bytes:
        """Attempt to extract tunneled data from DNS queries."""
        # Decode base32/base64/hex from subdomains
        pass
```

### Task 3: HTTP C2 Pattern Detection

Identify HTTP-based C2 patterns.

```python
# TODO: Implement HTTP C2 detection
class HTTPC2Detector:
    def __init__(self, llm_provider: str = "auto"):
        self.llm = setup_llm(provider=llm_provider)
        self.known_profiles = self._load_c2_profiles()

    def analyze_http_session(self, flows: List[HTTPFlow]) -> dict:
        """
        Analyze HTTP session for C2 indicators.

        Checks:
        - URI patterns (staging, tasking endpoints)
        - Cookie/header anomalies
        - Response timing patterns
        - Payload encoding
        - User-agent strings
        """
        pass

    def match_c2_profile(self, session: dict) -> List[ProfileMatch]:
        """Match session against known C2 profiles (Malleable C2, etc.)."""
        pass

    def llm_analyze_session(self, session: dict) -> dict:
        """Use LLM to analyze HTTP session for C2 indicators."""

        prompt = f"""
        Analyze this HTTP session for Command & Control (C2) indicators:

        Destination: {session['dst_ip']}:{session['dst_port']}
        Request Count: {session['request_count']}
        Time Span: {session['duration_seconds']}s

        Sample Requests:
        {self._format_requests(session['requests'][:5])}

        Sample Responses:
        {self._format_responses(session['responses'][:5])}

        Timing Pattern: {session.get('timing_analysis', {})}

        Analyze for:
        1. C2 framework identification (Cobalt Strike, Metasploit, etc.)
        2. Beaconing patterns
        3. Data encoding/encryption
        4. Suspicious headers or URIs
        5. MITRE ATT&CK techniques

        Return JSON with threat assessment and confidence score.
        """
        pass
```

### Task 4: TLS Certificate Analysis

Detect C2 using certificate anomalies.

```python
# TODO: Implement TLS certificate analysis
class TLSCertAnalyzer:
    def analyze_certificate(self, cert_data: dict) -> dict:
        """
        Analyze TLS certificate for C2 indicators.

        Checks:
        - Self-signed certificates
        - Recently issued (< 30 days)
        - Free CA providers (Let's Encrypt for suspicious domains)
        - Certificate/domain mismatch
        - Unusual validity periods
        - Known C2 certificate patterns
        """
        indicators = []

        # Self-signed check
        if cert_data['issuer'] == cert_data['subject']:
            indicators.append('self_signed')

        # Recent issuance
        issued = parse_date(cert_data['not_before'])
        if (datetime.now() - issued).days < 30:
            indicators.append('recently_issued')

        # Add more checks...

        return {
            'domain': cert_data['subject_cn'],
            'indicators': indicators,
            'risk_score': self._calculate_risk(indicators)
        }
```

### Task 5: C2 Detection Pipeline

Build end-to-end C2 detection.

```python
# TODO: Implement C2 detection pipeline
class C2DetectionPipeline:
    def __init__(self, llm_provider: str = "auto"):
        self.beacon_detector = BeaconDetector()
        self.dns_detector = DNSTunnelDetector()
        self.http_detector = HTTPC2Detector(llm_provider)
        self.tls_analyzer = TLSCertAnalyzer()

    def analyze_traffic(self, pcap_data: dict) -> C2Report:
        """
        Run full C2 detection on network traffic.

        Args:
            pcap_data: Parsed PCAP data with flows, DNS, HTTP, TLS

        Returns:
            C2Report with findings, confidence, and recommendations
        """
        findings = []

        # 1. Beacon detection
        beacons = self.beacon_detector.analyze_all_pairs(pcap_data['flows'])
        findings.extend(beacons)

        # 2. DNS tunneling
        tunnels = self.dns_detector.detect_tunneling_domain(pcap_data['dns'])
        findings.extend(tunnels)

        # 3. HTTP C2 patterns
        for session in pcap_data['http_sessions']:
            http_findings = self.http_detector.analyze_http_session(session)
            if http_findings['is_suspicious']:
                findings.append(http_findings)

        # 4. TLS anomalies
        for cert in pcap_data['tls_certs']:
            cert_analysis = self.tls_analyzer.analyze_certificate(cert)
            if cert_analysis['risk_score'] > 0.7:
                findings.append(cert_analysis)

        # 5. Correlate and report
        return self._generate_report(findings)

    def generate_detection_rules(self, findings: List[dict]) -> dict:
        """Generate Snort/Suricata rules from findings."""
        pass
```

---

## Sample Data

The `data/` directory contains:
- `beacon_traffic.json` - Simulated Cobalt Strike beacon traffic
- `dns_tunnel.json` - DNS tunneling samples (iodine, dnscat2 patterns)
- `http_c2_sessions.json` - HTTP C2 session data
- `tls_certificates.json` - Certificate data including suspicious certs
- `normal_traffic.json` - Baseline normal traffic for comparison

---

## Hints

<details>
<summary>Hint 1: FFT for Beacon Detection</summary>

Use Fast Fourier Transform to detect periodic signals:
```python
from scipy.fft import fft
import numpy as np

def detect_periodicity(intervals):
    # Remove mean and compute FFT
    centered = intervals - np.mean(intervals)
    spectrum = np.abs(fft(centered))
    # Find dominant frequency
    freqs = np.fft.fftfreq(len(intervals))
    peak_idx = np.argmax(spectrum[1:len(spectrum)//2]) + 1
    return 1 / freqs[peak_idx]  # Period in seconds
```
</details>

<details>
<summary>Hint 2: DNS Entropy Calculation</summary>

High entropy subdomains often indicate encoded data:
```python
def subdomain_entropy(domain):
    subdomain = domain.split('.')[0]
    if len(subdomain) == 0:
        return 0
    prob = [subdomain.count(c)/len(subdomain) for c in set(subdomain)]
    return -sum(p * math.log2(p) for p in prob)
```
</details>

<details>
<summary>Hint 3: Cobalt Strike Patterns</summary>

Look for these Cobalt Strike indicators:
- Default URIs: `/submit.php`, `/pixel.gif`, `/__utm.gif`
- Malleable C2 profile headers
- Cookie-based data encoding
- Predictable jitter patterns
</details>

---

## Bonus Challenges

1. **JA3/JA3S Fingerprinting**: Implement TLS fingerprinting for C2 detection
2. **Encrypted Traffic Analysis**: Detect C2 in encrypted traffic using flow metadata
3. **Real-time Detection**: Build streaming detection with sliding windows
4. **C2 Infrastructure Mapping**: Identify related C2 infrastructure

---

## Resources

- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [Cobalt Strike Detection Guide](https://www.cobaltstrike.com/blog/)
- [Detecting DNS Tunneling](https://www.sans.org/white-papers/)
- [JA3 TLS Fingerprinting](https://github.com/salesforce/ja3)

---

> **Stuck?** See the [Lab 14 Walkthrough](../../docs/walkthroughs/lab14-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 15 - AI-Powered Lateral Movement Detection](../lab15-lateral-movement-detection/)
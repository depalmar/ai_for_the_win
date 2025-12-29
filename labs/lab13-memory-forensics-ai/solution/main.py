"""
Lab 13: AI-Powered Memory Forensics - Solution

Analyze memory dumps using AI to detect malware, process injection,
and hidden threats that evade disk-based detection.
"""

import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
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
            raise ValueError(
                "No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY"
            )

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


# Data classes for memory artifacts
@dataclass
class ProcessInfo:
    """Information about a process extracted from memory."""

    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    create_time: str
    threads: int = 0
    handles: int = 0
    memory_regions: List[dict] = field(default_factory=list)


@dataclass
class NetworkConnection:
    """Network connection from memory."""

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int
    protocol: str = "TCP"


@dataclass
class DLLInfo:
    """DLL loaded by a process."""

    name: str
    path: str
    base_address: str
    size: int
    pid: int


@dataclass
class InjectionIndicator:
    """Indicator of potential code injection."""

    pid: int
    process_name: str
    indicator_type: str
    description: str
    memory_address: str
    confidence: float


@dataclass
class TriageReport:
    """Memory triage report."""

    timestamp: str
    findings: List[dict]
    iocs: dict
    summary: str
    risk_level: str


class MemoryAnalyzer:
    """Extract and analyze artifacts from memory dumps."""

    def __init__(self, memory_data: dict = None):
        """
        Initialize memory analyzer.

        Args:
            memory_data: Parsed memory dump data (JSON format for simulation)
        """
        self.memory_data = memory_data or {}

    def load_from_file(self, filepath: str):
        """Load memory data from JSON file."""
        with open(filepath, "r") as f:
            self.memory_data = json.load(f)

    def extract_processes(self) -> List[ProcessInfo]:
        """Extract running processes from memory dump."""
        processes = []
        for proc in self.memory_data.get("processes", []):
            processes.append(
                ProcessInfo(
                    pid=proc.get("pid", 0),
                    ppid=proc.get("ppid", 0),
                    name=proc.get("name", "unknown"),
                    path=proc.get("path", ""),
                    cmdline=proc.get("cmdline", ""),
                    create_time=proc.get("create_time", ""),
                    threads=proc.get("threads", 0),
                    handles=proc.get("handles", 0),
                    memory_regions=proc.get("memory_regions", []),
                )
            )
        return processes

    def extract_network_connections(self) -> List[NetworkConnection]:
        """Extract active network connections from memory."""
        connections = []
        for conn in self.memory_data.get("connections", []):
            connections.append(
                NetworkConnection(
                    local_ip=conn.get("local_ip", "0.0.0.0"),  # nosec B104 - default for parsing
                    local_port=conn.get("local_port", 0),
                    remote_ip=conn.get("remote_ip", "0.0.0.0"),  # nosec B104 - default for parsing
                    remote_port=conn.get("remote_port", 0),
                    state=conn.get("state", "UNKNOWN"),
                    pid=conn.get("pid", 0),
                    protocol=conn.get("protocol", "TCP"),
                )
            )
        return connections

    def extract_loaded_dlls(self, pid: int) -> List[DLLInfo]:
        """Extract DLLs loaded by a specific process."""
        dlls = []
        for dll in self.memory_data.get("dlls", []):
            if dll.get("pid") == pid:
                dlls.append(
                    DLLInfo(
                        name=dll.get("name", ""),
                        path=dll.get("path", ""),
                        base_address=dll.get("base_address", "0x0"),
                        size=dll.get("size", 0),
                        pid=pid,
                    )
                )
        return dlls

    def detect_injected_code(self) -> List[InjectionIndicator]:
        """Detect potential code injection artifacts."""
        indicators = []
        for finding in self.memory_data.get("malfind", []):
            indicators.append(
                InjectionIndicator(
                    pid=finding.get("pid", 0),
                    process_name=finding.get("process_name", "unknown"),
                    indicator_type=finding.get("type", "unknown"),
                    description=finding.get("description", ""),
                    memory_address=finding.get("address", "0x0"),
                    confidence=finding.get("confidence", 0.5),
                )
            )
        return indicators


class ProcessAnomalyDetector:
    """Detect anomalous processes using ML and heuristics."""

    SUSPICIOUS_RELATIONSHIPS = {
        "outlook.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
        "excel.exe": ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"],
        "word.exe": ["powershell.exe", "cmd.exe"],
        "winword.exe": ["powershell.exe", "cmd.exe", "mshta.exe"],
        "powerpnt.exe": ["powershell.exe", "cmd.exe"],
        "acrobat.exe": ["powershell.exe", "cmd.exe"],
        "acrord32.exe": ["powershell.exe", "cmd.exe"],
    }

    STRICT_PARENT_RULES = {
        "svchost.exe": ["services.exe"],
        "smss.exe": ["System"],
        "csrss.exe": ["smss.exe"],
        "wininit.exe": ["smss.exe"],
        "lsass.exe": ["wininit.exe"],
        "services.exe": ["wininit.exe"],
    }

    SYSTEM_PATHS = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows",
    ]

    def __init__(self, baseline_path: str = None):
        """Initialize detector with optional baseline data."""
        self.baseline = {}
        if baseline_path and os.path.exists(baseline_path):
            with open(baseline_path, "r") as f:
                self.baseline = json.load(f)

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def extract_features(self, process: ProcessInfo) -> np.ndarray:
        """Extract features from a process for anomaly detection."""
        features = []

        # Feature 1: Command line entropy
        cmdline_entropy = self.calculate_entropy(process.cmdline)
        features.append(cmdline_entropy)

        # Feature 2: Path depth
        path_depth = process.path.count("\\") if process.path else 0
        features.append(path_depth)

        # Feature 3: Is in system directory (binary)
        is_system = (
            any(process.path.lower().startswith(sp) for sp in self.SYSTEM_PATHS)
            if process.path
            else False
        )
        features.append(1.0 if is_system else 0.0)

        # Feature 4: Process name length
        features.append(len(process.name))

        # Feature 5: Has encoded content in cmdline
        has_encoded = any(
            pattern in process.cmdline.lower()
            for pattern in ["-enc", "-encodedcommand", "base64", "-e "]
        )
        features.append(1.0 if has_encoded else 0.0)

        # Feature 6: Has suspicious flags
        suspicious_flags = [
            "-nop",
            "-w hidden",
            "-windowstyle hidden",
            "-noni",
            "-ep bypass",
            "-executionpolicy bypass",
        ]
        has_suspicious = any(flag in process.cmdline.lower() for flag in suspicious_flags)
        features.append(1.0 if has_suspicious else 0.0)

        # Feature 7: Thread count anomaly (very high or very low)
        thread_anomaly = 1.0 if process.threads > 100 or process.threads == 0 else 0.0
        features.append(thread_anomaly)

        return np.array(features)

    def check_parent_child_anomaly(
        self, process: ProcessInfo, processes: List[ProcessInfo]
    ) -> List[str]:
        """Check for suspicious parent-child relationships."""
        anomalies = []

        # Find parent process
        parent = None
        for p in processes:
            if p.pid == process.ppid:
                parent = p
                break

        if not parent:
            return anomalies

        parent_name = parent.name.lower()
        process_name = process.name.lower()

        # Check suspicious relationships
        for parent_pattern, child_patterns in self.SUSPICIOUS_RELATIONSHIPS.items():
            if parent_pattern in parent_name:
                if any(child in process_name for child in child_patterns):
                    anomalies.append(f"Suspicious spawn: {parent.name} -> {process.name}")

        # Check strict parent rules
        for child_pattern, allowed_parents in self.STRICT_PARENT_RULES.items():
            if child_pattern in process_name:
                if not any(ap.lower() in parent_name for ap in allowed_parents):
                    anomalies.append(
                        f"Invalid parent for {process.name}: expected {allowed_parents}, got {parent.name}"
                    )

        return anomalies

    def score_process(self, process: ProcessInfo, all_processes: List[ProcessInfo]) -> dict:
        """Calculate anomaly score for a process."""
        risk_factors = []
        score = 0.0

        # Feature-based scoring
        features = self.extract_features(process)

        # High entropy command line
        if features[0] > 4.5:
            risk_factors.append(f"High command line entropy: {features[0]:.2f}")
            score += 0.2

        # Encoded commands
        if features[4] > 0:
            risk_factors.append("Contains encoded command indicators")
            score += 0.3

        # Suspicious execution flags
        if features[5] > 0:
            risk_factors.append("Uses suspicious PowerShell flags")
            score += 0.2

        # Parent-child anomalies
        parent_anomalies = self.check_parent_child_anomaly(process, all_processes)
        for anomaly in parent_anomalies:
            risk_factors.append(anomaly)
            score += 0.3

        # Not in system path but pretending to be system process
        system_process_names = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe"]
        if process.name.lower() in system_process_names:
            if not features[2]:  # Not in system directory
                risk_factors.append(f"System process {process.name} outside system directory")
                score += 0.4

        # Check against baseline
        if self.baseline:
            baseline_entry = self.baseline.get(process.name.lower())
            if baseline_entry:
                expected_paths = baseline_entry.get("expected_paths", [])
                if process.path and not any(
                    ep.lower() in process.path.lower() for ep in expected_paths
                ):
                    risk_factors.append(f"Unusual path for {process.name}")
                    score += 0.2

        return {
            "anomaly_score": min(score, 1.0),
            "risk_factors": risk_factors,
            "features": features.tolist(),
        }

    def detect_process_hollowing(self, process: ProcessInfo) -> dict:
        """Detect signs of process hollowing."""
        indicators = []

        # Check memory regions for hollowing signs
        for region in process.memory_regions:
            protection = region.get("protection", "")
            # Look for RWX regions (Read-Write-Execute)
            if "RWX" in protection or ("EXECUTE" in protection and "WRITE" in protection):
                indicators.append(
                    {
                        "type": "rwx_memory",
                        "address": region.get("address", "unknown"),
                        "description": "Memory region with Read-Write-Execute permissions",
                    }
                )

            # Check for private executable memory (potential hollowed section)
            if region.get("type") == "PRIVATE" and "EXECUTE" in protection:
                indicators.append(
                    {
                        "type": "private_executable",
                        "address": region.get("address", "unknown"),
                        "description": "Private memory region with execute permissions",
                    }
                )

        return {
            "is_hollowed": len(indicators) > 0,
            "confidence": min(len(indicators) * 0.3, 1.0),
            "indicators": indicators,
        }


def analyze_suspicious_process(process: ProcessInfo, context: dict, llm_client) -> dict:
    """Use LLM to analyze a suspicious process."""
    provider, client = llm_client

    prompt = f"""Analyze this potentially malicious process from a memory dump:

Process: {process.name} (PID: {process.pid})
Parent PID: {process.ppid}
Path: {process.path}
Command Line: {process.cmdline}
Creation Time: {process.create_time}
Threads: {process.threads}

Suspicious Indicators:
{json.dumps(context.get('indicators', []), indent=2)}

Network Connections:
{json.dumps(context.get('connections', []), indent=2)}

Provide analysis in JSON format with:
- threat_level: "benign", "suspicious", or "malicious"
- assessment: brief explanation
- malware_family: suspected family name or null
- mitre_techniques: list of technique IDs (e.g., ["T1055", "T1059.001"])
- response_actions: recommended actions
- investigate_next: what to look at next"""

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

        # Parse JSON from response
        # Handle markdown code blocks
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0]
        elif "```" in result_text:
            result_text = result_text.split("```")[1].split("```")[0]

        return json.loads(result_text)

    except Exception as e:
        return {
            "threat_level": "unknown",
            "assessment": f"Analysis failed: {str(e)}",
            "malware_family": None,
            "mitre_techniques": [],
            "response_actions": ["Manual review required"],
            "investigate_next": [],
        }


class MemoryTriagePipeline:
    """End-to-end automated memory triage."""

    def __init__(self, llm_provider: str = "auto"):
        """Initialize triage pipeline."""
        self.analyzer = MemoryAnalyzer()
        self.detector = ProcessAnomalyDetector()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        """Lazy initialization of LLM."""
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def triage(self, memory_data: dict) -> TriageReport:
        """Run full automated triage on memory dump."""
        self._init_llm()
        self.analyzer.memory_data = memory_data

        # 1. Extract all artifacts
        processes = self.analyzer.extract_processes()
        connections = self.analyzer.extract_network_connections()
        injections = self.analyzer.detect_injected_code()

        print(f"  Extracted {len(processes)} processes")
        print(f"  Found {len(connections)} connections")
        print(f"  Detected {len(injections)} injection indicators")

        # 2. Score all processes
        scored_processes = []
        for proc in processes:
            score_result = self.detector.score_process(proc, processes)
            scored_processes.append((proc, score_result))

        # 3. Identify suspicious processes
        suspicious = [(p, s) for p, s in scored_processes if s["anomaly_score"] > 0.5]
        print(f"  Found {len(suspicious)} suspicious processes")

        # 4. Deep analysis on suspicious processes
        findings = []
        for process, score in suspicious:
            finding = {
                "process_name": process.name,
                "pid": process.pid,
                "anomaly_score": score["anomaly_score"],
                "risk_factors": score["risk_factors"],
            }

            # Check for process hollowing
            hollowing = self.detector.detect_process_hollowing(process)
            if hollowing["is_hollowed"]:
                finding["hollowing_detected"] = hollowing

            # Get related connections
            proc_connections = self._get_process_connections(process, connections)
            if proc_connections:
                finding["network_connections"] = proc_connections

            # Get related injections
            proc_injections = [i for i in injections if i.pid == process.pid]
            if proc_injections:
                finding["injection_indicators"] = [
                    {"type": i.indicator_type, "description": i.description}
                    for i in proc_injections
                ]

            # LLM analysis if available
            if self.llm:
                context = {"indicators": score["risk_factors"], "connections": proc_connections}
                llm_analysis = analyze_suspicious_process(process, context, self.llm)
                finding.update(llm_analysis)

            findings.append(finding)

        # 5. Generate report
        return self._generate_report(findings)

    def _get_process_connections(
        self, process: ProcessInfo, connections: List[NetworkConnection]
    ) -> List[dict]:
        """Get network connections for a specific process."""
        return [
            {
                "local": f"{c.local_ip}:{c.local_port}",
                "remote": f"{c.remote_ip}:{c.remote_port}",
                "state": c.state,
                "protocol": c.protocol,
            }
            for c in connections
            if c.pid == process.pid
        ]

    def _generate_report(self, findings: List[dict]) -> TriageReport:
        """Generate final triage report."""
        risk_levels = [f.get("threat_level", "unknown") for f in findings]

        if "malicious" in risk_levels:
            overall_risk = "critical"
        elif "suspicious" in risk_levels:
            overall_risk = "high"
        elif any(f.get("anomaly_score", 0) > 0.7 for f in findings):
            overall_risk = "high"
        elif any(f.get("anomaly_score", 0) > 0.5 for f in findings):
            overall_risk = "medium"
        else:
            overall_risk = "low"

        summary_parts = [f"Analyzed memory dump at {datetime.now().isoformat()}"]
        summary_parts.append(f"Found {len(findings)} suspicious processes")

        malicious = [f for f in findings if f.get("threat_level") == "malicious"]
        if malicious:
            summary_parts.append(f"ALERT: {len(malicious)} confirmed malicious")

        return TriageReport(
            timestamp=datetime.now().isoformat(),
            findings=findings,
            iocs=self._extract_iocs(findings),
            summary=". ".join(summary_parts),
            risk_level=overall_risk,
        )

    def _extract_iocs(self, findings: List[dict]) -> dict:
        """Extract IOCs from findings."""
        iocs = {
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "mitre_techniques": set(),
            "process_names": set(),
        }

        for finding in findings:
            # Extract MITRE techniques
            for technique in finding.get("mitre_techniques", []):
                iocs["mitre_techniques"].add(technique)

            # Extract suspicious process names
            if finding.get("threat_level") in ["suspicious", "malicious"]:
                iocs["process_names"].add(finding.get("process_name", ""))

            # Extract IPs from connections
            for conn in finding.get("network_connections", []):
                remote = conn.get("remote", "")
                if remote:
                    ip = remote.split(":")[0]
                    if ip and not ip.startswith(("10.", "192.168.", "172.")):
                        iocs["ips"].add(ip)

        return {k: list(v) for k, v in iocs.items()}


def main():
    """Main entry point for Lab 13."""
    print("=" * 60)
    print("Lab 13: AI-Powered Memory Forensics - Solution")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "sample_process_list.json"), "r") as f:
            memory_data = json.load(f)
        print(f"\nLoaded memory data with {len(memory_data.get('processes', []))} processes")
    except FileNotFoundError:
        print("Sample data not found. Creating mock data for demo.")
        memory_data = create_mock_memory_data()

    # Initialize pipeline
    print("\n" + "-" * 40)
    print("Initializing Memory Triage Pipeline")
    print("-" * 40)

    pipeline = MemoryTriagePipeline()

    # Run triage
    print("\nRunning automated triage...")
    report = pipeline.triage(memory_data)

    # Display results
    print("\n" + "=" * 60)
    print("TRIAGE REPORT")
    print("=" * 60)
    print(f"Timestamp: {report.timestamp}")
    print(f"Risk Level: {report.risk_level.upper()}")
    print(f"Summary: {report.summary}")

    print("\n--- Findings ---")
    for i, finding in enumerate(report.findings, 1):
        print(f"\n{i}. {finding['process_name']} (PID: {finding['pid']})")
        print(f"   Anomaly Score: {finding['anomaly_score']:.2f}")
        if finding.get("risk_factors"):
            print(f"   Risk Factors:")
            for rf in finding["risk_factors"]:
                print(f"     - {rf}")
        if finding.get("threat_level"):
            print(f"   Threat Level: {finding['threat_level']}")
        if finding.get("mitre_techniques"):
            print(f"   MITRE ATT&CK: {', '.join(finding['mitre_techniques'])}")

    print("\n--- IOCs Extracted ---")
    for ioc_type, values in report.iocs.items():
        if values:
            print(f"  {ioc_type}: {', '.join(str(v) for v in values)}")

    print("\n" + "=" * 60)


def create_mock_memory_data():
    """Create mock memory data for demo purposes."""
    return {
        "processes": [
            {
                "pid": 4,
                "ppid": 0,
                "name": "System",
                "path": "",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:00",
                "threads": 150,
                "handles": 2000,
            },
            {
                "pid": 632,
                "ppid": 4,
                "name": "smss.exe",
                "path": "C:\\Windows\\System32\\smss.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:01",
                "threads": 2,
                "handles": 50,
            },
            {
                "pid": 780,
                "ppid": 632,
                "name": "csrss.exe",
                "path": "C:\\Windows\\System32\\csrss.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:02",
                "threads": 12,
                "handles": 500,
            },
            {
                "pid": 1234,
                "ppid": 780,
                "name": "services.exe",
                "path": "C:\\Windows\\System32\\services.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:03",
                "threads": 5,
                "handles": 300,
            },
            {
                "pid": 2048,
                "ppid": 1234,
                "name": "svchost.exe",
                "path": "C:\\Windows\\System32\\svchost.exe",
                "cmdline": "-k netsvcs",
                "create_time": "2024-01-15T08:00:10",
                "threads": 20,
                "handles": 800,
            },
            {
                "pid": 3456,
                "ppid": 5678,
                "name": "outlook.exe",
                "path": "C:\\Program Files\\Microsoft Office\\Office16\\outlook.exe",
                "cmdline": "",
                "create_time": "2024-01-15T09:00:00",
                "threads": 30,
                "handles": 400,
            },
            {
                "pid": 4567,
                "ppid": 3456,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQ=",
                "create_time": "2024-01-15T09:05:00",
                "threads": 8,
                "handles": 200,
                "memory_regions": [
                    {"address": "0x7FFE0000", "protection": "RWX", "type": "PRIVATE", "size": 4096}
                ],
            },
            {
                "pid": 5678,
                "ppid": 1234,
                "name": "explorer.exe",
                "path": "C:\\Windows\\explorer.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:01:00",
                "threads": 40,
                "handles": 1500,
            },
            {
                "pid": 7890,
                "ppid": 4567,
                "name": "cmd.exe",
                "path": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "cmd.exe /c whoami && net user",
                "create_time": "2024-01-15T09:06:00",
                "threads": 1,
                "handles": 50,
            },
            {
                "pid": 9999,
                "ppid": 1,
                "name": "svchost.exe",
                "path": "C:\\Users\\Public\\svchost.exe",
                "cmdline": "-k malware",
                "create_time": "2024-01-15T09:10:00",
                "threads": 3,
                "handles": 100,
                "memory_regions": [
                    {"address": "0x10000000", "protection": "RWX", "type": "PRIVATE", "size": 65536}
                ],
            },
        ],
        "connections": [
            {
                "local_ip": "192.168.1.100",
                "local_port": 49152,
                "remote_ip": "185.234.72.19",
                "remote_port": 443,
                "state": "ESTABLISHED",
                "pid": 4567,
                "protocol": "TCP",
            },
            {
                "local_ip": "192.168.1.100",
                "local_port": 49153,
                "remote_ip": "10.0.0.1",
                "remote_port": 445,
                "state": "ESTABLISHED",
                "pid": 2048,
                "protocol": "TCP",
            },
            {
                "local_ip": "192.168.1.100",
                "local_port": 49154,
                "remote_ip": "91.234.56.78",
                "remote_port": 8080,
                "state": "ESTABLISHED",
                "pid": 9999,
                "protocol": "TCP",
            },
        ],
        "malfind": [
            {
                "pid": 4567,
                "process_name": "powershell.exe",
                "type": "MZ_HEADER_IN_PRIVATE_MEMORY",
                "description": "PE header found in private memory region",
                "address": "0x7FFE0000",
                "confidence": 0.85,
            },
            {
                "pid": 9999,
                "process_name": "svchost.exe",
                "type": "EXECUTABLE_MEMORY",
                "description": "Executable code in non-image memory",
                "address": "0x10000000",
                "confidence": 0.9,
            },
        ],
        "dlls": [
            {
                "pid": 4567,
                "name": "ntdll.dll",
                "path": "C:\\Windows\\System32\\ntdll.dll",
                "base_address": "0x77000000",
                "size": 1900544,
            },
            {
                "pid": 4567,
                "name": "kernel32.dll",
                "path": "C:\\Windows\\System32\\kernel32.dll",
                "base_address": "0x75000000",
                "size": 1200128,
            },
        ],
    }


if __name__ == "__main__":
    main()

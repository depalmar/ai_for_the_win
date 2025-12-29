"""
Lab 13: AI-Powered Memory Forensics - Starter Code

Analyze memory dumps using AI to detect malware, process injection,
and hidden threats that evade disk-based detection.

Complete the TODOs to build a memory forensics analysis pipeline.
"""

import json
import math
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

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

        return Anthropic()
    elif provider == "openai":
        from openai import OpenAI

        return OpenAI()
    elif provider == "google":
        import google.generativeai as genai

        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        return genai.GenerativeModel("gemini-2.5-pro")
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
    memory_regions: List[dict] = None


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
        """
        Extract running processes from memory dump.

        TODO: Implement process extraction
        - Parse process list from memory data
        - Create ProcessInfo objects for each process
        - Include metadata: PID, PPID, name, path, cmdline, creation time

        Returns:
            List of ProcessInfo objects
        """
        # TODO: Implement this method
        # Hint: Access self.memory_data['processes']
        pass

    def extract_network_connections(self) -> List[NetworkConnection]:
        """
        Extract active network connections from memory.

        TODO: Implement network connection extraction
        - Parse network connections from memory data
        - Create NetworkConnection objects
        - Include: local/remote IP, ports, state, owning process

        Returns:
            List of NetworkConnection objects
        """
        # TODO: Implement this method
        # Hint: Access self.memory_data['connections']
        pass

    def extract_loaded_dlls(self, pid: int) -> List[DLLInfo]:
        """
        Extract DLLs loaded by a specific process.

        TODO: Implement DLL extraction
        - Get loaded modules for the specified PID
        - Return list of DLLInfo objects

        Args:
            pid: Process ID to get DLLs for

        Returns:
            List of DLLInfo objects
        """
        # TODO: Implement this method
        # Hint: Access self.memory_data['dlls'] and filter by pid
        pass

    def detect_injected_code(self) -> List[InjectionIndicator]:
        """
        Detect potential code injection artifacts.

        TODO: Implement injection detection
        - Look for RWX (Read-Write-Execute) memory regions
        - Check for unmapped executable code
        - Identify suspicious memory patterns

        Returns:
            List of InjectionIndicator objects
        """
        # TODO: Implement this method
        # Hint: Access self.memory_data['malfind'] for injection indicators
        pass


class ProcessAnomalyDetector:
    """Detect anomalous processes using ML and heuristics."""

    # Known suspicious parent-child relationships
    SUSPICIOUS_RELATIONSHIPS = {
        "outlook.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
        "excel.exe": ["powershell.exe", "cmd.exe", "mshta.exe"],
        "word.exe": ["powershell.exe", "cmd.exe"],
        "winword.exe": ["powershell.exe", "cmd.exe"],
    }

    # Processes that should only be spawned by specific parents
    STRICT_PARENT_RULES = {
        "svchost.exe": ["services.exe"],
        "smss.exe": ["System"],
        "csrss.exe": ["smss.exe"],
        "wininit.exe": ["smss.exe"],
    }

    def __init__(self, baseline_path: str = None):
        """
        Initialize detector with optional baseline data.

        Args:
            baseline_path: Path to baseline process data JSON
        """
        self.baseline = {}
        if baseline_path and os.path.exists(baseline_path):
            with open(baseline_path, "r") as f:
                self.baseline = json.load(f)

    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        High entropy in command lines often indicates encoded/obfuscated commands.

        Args:
            text: String to calculate entropy for

        Returns:
            Entropy value (bits per character)
        """
        if not text:
            return 0.0
        prob = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def extract_features(self, process: ProcessInfo) -> np.ndarray:
        """
        Extract features from a process for anomaly detection.

        TODO: Implement feature extraction
        Features to extract:
        - Command line entropy
        - Path depth (number of directories)
        - Is path in system directories
        - Parent-child relationship anomaly
        - Name length
        - Has suspicious extensions in cmdline

        Args:
            process: ProcessInfo object

        Returns:
            Feature vector as numpy array
        """
        # TODO: Implement this method
        # Return a numpy array of features
        pass

    def check_parent_child_anomaly(
        self, process: ProcessInfo, processes: List[ProcessInfo]
    ) -> bool:
        """
        Check for suspicious parent-child relationships.

        TODO: Implement parent-child checking
        - Find parent process by PPID
        - Check against SUSPICIOUS_RELATIONSHIPS
        - Check against STRICT_PARENT_RULES

        Args:
            process: Process to check
            processes: All processes (to find parent)

        Returns:
            True if relationship is suspicious
        """
        # TODO: Implement this method
        pass

    def score_process(self, process: ProcessInfo, all_processes: List[ProcessInfo]) -> dict:
        """
        Calculate anomaly score for a process.

        TODO: Implement process scoring
        - Calculate feature-based anomaly score
        - Check parent-child relationships
        - Check against baseline
        - Aggregate into final score

        Args:
            process: Process to score
            all_processes: All processes for context

        Returns:
            Dict with score and risk factors
        """
        # TODO: Implement this method
        # Return: {'anomaly_score': float, 'risk_factors': list}
        pass

    def detect_process_hollowing(self, process: ProcessInfo) -> dict:
        """
        Detect signs of process hollowing.

        Process hollowing replaces legitimate process memory with malicious code.

        TODO: Implement hollowing detection
        - Check if image base in memory differs from disk
        - Look for mismatched section permissions

        Args:
            process: Process to check

        Returns:
            Dict with detection result and evidence
        """
        # TODO: Implement this method
        pass


def analyze_suspicious_process(process: ProcessInfo, context: dict, llm_client) -> dict:
    """
    Use LLM to analyze a suspicious process.

    TODO: Implement LLM analysis
    - Build prompt with process details
    - Include suspicious indicators from context
    - Request structured analysis

    Args:
        process: ProcessInfo object
        context: Additional context (indicators, connections, etc.)
        llm_client: LLM client instance

    Returns:
        Analysis result as dict
    """
    prompt = f"""
Analyze this potentially malicious process from a memory dump:

Process: {process.name} (PID: {process.pid})
Parent PID: {process.ppid}
Path: {process.path}
Command Line: {process.cmdline}
Creation Time: {process.create_time}

Suspicious Indicators:
{json.dumps(context.get('indicators', []), indent=2)}

Network Connections:
{json.dumps(context.get('connections', []), indent=2)}

Provide:
1. Threat assessment (benign/suspicious/malicious)
2. Likely malware family or technique if malicious
3. MITRE ATT&CK techniques observed
4. Recommended response actions
5. Additional artifacts to investigate

Return response as JSON with keys:
- threat_level: string
- assessment: string
- malware_family: string or null
- mitre_techniques: list of strings
- response_actions: list of strings
- investigate_next: list of strings
"""

    # TODO: Implement LLM call based on client type
    # Handle different providers (anthropic, openai, google)
    pass


class MemoryTriagePipeline:
    """End-to-end automated memory triage."""

    def __init__(self, llm_provider: str = "auto"):
        """
        Initialize triage pipeline.

        Args:
            llm_provider: LLM provider to use
        """
        self.analyzer = MemoryAnalyzer()
        self.detector = ProcessAnomalyDetector()
        self.llm = setup_llm(provider=llm_provider)

    def triage(self, memory_data: dict) -> TriageReport:
        """
        Run full automated triage on memory dump.

        TODO: Implement triage pipeline
        1. Load and parse memory data
        2. Extract all artifacts (processes, connections, injections)
        3. Score all processes for anomalies
        4. Perform deep analysis on suspicious processes
        5. Extract IOCs
        6. Generate report

        Args:
            memory_data: Parsed memory dump data

        Returns:
            TriageReport with findings
        """
        # TODO: Implement this method
        pass

    def _get_process_connections(
        self, process: ProcessInfo, connections: List[NetworkConnection]
    ) -> List[dict]:
        """Get network connections for a specific process."""
        return [
            {
                "local": f"{c.local_ip}:{c.local_port}",
                "remote": f"{c.remote_ip}:{c.remote_port}",
                "state": c.state,
            }
            for c in connections
            if c.pid == process.pid
        ]

    def _generate_report(self, findings: List[dict]) -> TriageReport:
        """Generate final triage report."""
        # Determine overall risk level
        risk_levels = [f.get("threat_level", "unknown") for f in findings]
        if "critical" in risk_levels or "malicious" in risk_levels:
            overall_risk = "critical"
        elif "high" in risk_levels or "suspicious" in risk_levels:
            overall_risk = "high"
        elif "medium" in risk_levels:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        return TriageReport(
            timestamp=datetime.now().isoformat(),
            findings=findings,
            iocs=self._extract_iocs(findings),
            summary=f"Found {len(findings)} suspicious items",
            risk_level=overall_risk,
        )

    def _extract_iocs(self, findings: List[dict]) -> dict:
        """Extract IOCs from findings."""
        iocs = {"ips": set(), "domains": set(), "hashes": set(), "mitre_techniques": set()}

        for finding in findings:
            for technique in finding.get("mitre_techniques", []):
                iocs["mitre_techniques"].add(technique)

        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in iocs.items()}


def main():
    """Main entry point for Lab 13."""
    print("=" * 60)
    print("Lab 13: AI-Powered Memory Forensics")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "sample_process_list.json"), "r") as f:
            process_data = json.load(f)
        print(f"\nLoaded {len(process_data.get('processes', []))} processes")
    except FileNotFoundError:
        print("Sample data not found. Using mock data.")
        process_data = {"processes": [], "connections": [], "malfind": []}

    # Initialize analyzer
    analyzer = MemoryAnalyzer(process_data)

    # Task 1: Extract processes
    print("\n--- Task 1: Process Extraction ---")
    processes = analyzer.extract_processes()
    if processes:
        print(f"Extracted {len(processes)} processes")
        for p in processes[:5]:
            print(f"  - {p.name} (PID: {p.pid})")
    else:
        print("TODO: Implement extract_processes()")

    # Task 2: Extract network connections
    print("\n--- Task 2: Network Connection Extraction ---")
    connections = analyzer.extract_network_connections()
    if connections:
        print(f"Found {len(connections)} connections")
        for c in connections[:5]:
            print(f"  - {c.local_ip}:{c.local_port} -> {c.remote_ip}:{c.remote_port}")
    else:
        print("TODO: Implement extract_network_connections()")

    # Task 3: Detect code injection
    print("\n--- Task 3: Code Injection Detection ---")
    injections = analyzer.detect_injected_code()
    if injections:
        print(f"Found {len(injections)} potential injections")
        for inj in injections:
            print(f"  - {inj.process_name}: {inj.indicator_type}")
    else:
        print("TODO: Implement detect_injected_code()")

    # Task 4: Process anomaly detection
    print("\n--- Task 4: Process Anomaly Detection ---")
    detector = ProcessAnomalyDetector(os.path.join(data_dir, "baseline_processes.json"))

    if processes:
        for process in processes[:3]:
            score = detector.score_process(process, processes)
            if score:
                print(f"  {process.name}: score={score.get('anomaly_score', 'N/A')}")
            else:
                print("TODO: Implement score_process()")
                break

    # Task 5: LLM Analysis (requires API key)
    print("\n--- Task 5: LLM-Powered Analysis ---")
    api_key = (
        os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    )

    if api_key and processes:
        try:
            llm = setup_llm()
            # Analyze first suspicious process
            suspicious = [p for p in processes if "powershell" in p.name.lower()]
            if suspicious:
                result = analyze_suspicious_process(
                    suspicious[0], {"indicators": [], "connections": []}, llm
                )
                if result:
                    print(f"Analysis result: {json.dumps(result, indent=2)}")
                else:
                    print("TODO: Implement analyze_suspicious_process()")
        except Exception as e:
            print(f"LLM analysis skipped: {e}")
    else:
        print("Skipped - Set API key to enable LLM analysis")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 13!")
    print("=" * 60)


if __name__ == "__main__":
    main()

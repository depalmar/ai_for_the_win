"""
Lab 15: AI-Powered Lateral Movement Detection - Starter Code

Detect lateral movement attacks using Windows authentication events,
remote execution patterns, and graph analysis.

Complete the TODOs to build a lateral movement detection pipeline.
"""

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

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


@dataclass
class AuthEvent:
    """Windows authentication event (4624/4625)."""

    timestamp: str
    event_id: int  # 4624 = success, 4625 = failure
    source_ip: str
    target_host: str
    username: str
    domain: str
    logon_type: int
    status: str
    workstation_name: str = ""
    process_name: str = ""


@dataclass
class RemoteExecEvent:
    """Remote execution event (PsExec, WMI, WinRM, etc.)."""

    timestamp: str
    source_host: str
    target_host: str
    exec_type: str  # psexec, wmi, winrm, ssh, rdp
    username: str
    command: str = ""
    success: bool = True


@dataclass
class AttackPath:
    """Detected attack path through the network."""

    path: List[str]  # List of hosts in order
    start_time: str
    end_time: str
    techniques: List[str]
    confidence: float
    risk_score: float


@dataclass
class LateralMovementAlert:
    """Alert for detected lateral movement."""

    timestamp: str
    alert_type: str
    source_host: str
    target_host: str
    username: str
    indicators: List[str]
    severity: str
    mitre_techniques: List[str]


class AuthAnomalyDetector:
    """Detect anomalies in Windows authentication events."""

    # Windows logon types
    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive",
        11: "CachedInteractive",
    }

    # Suspicious logon type combinations
    SUSPICIOUS_LOGON_TYPES = [3, 10]  # Network, RemoteInteractive

    def __init__(self, baseline_hours: int = 24):
        """
        Initialize the auth anomaly detector.

        Args:
            baseline_hours: Hours of data to use for baseline
        """
        self.baseline_hours = baseline_hours
        self.user_patterns = defaultdict(lambda: {"hosts": set(), "times": [], "source_ips": set()})

    def build_baseline(self, events: List[AuthEvent]):
        """
        Build baseline of normal authentication patterns.

        TODO: Implement baseline building
        - Track which hosts each user normally accesses
        - Track normal working hours for each user
        - Track normal source IPs for each user
        - Calculate statistical baselines

        Args:
            events: Historical authentication events
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to build a baseline of normal authentication patterns by iterating
        # through historical AuthEvent objects and populating self.user_patterns with:
        # - The set of hosts each user normally accesses
        # - The login times for each user (to establish normal working hours)
        # - The set of source IPs each user authenticates from
        # Calculate statistical baselines for anomaly detection."
        #
        # Then review and test the generated code.
        pass

    def detect_anomalies(self, event: AuthEvent) -> List[dict]:
        """
        Detect anomalies in a single authentication event.

        TODO: Implement anomaly detection
        - Check if user is accessing new/unusual hosts
        - Check for unusual authentication times
        - Check for unusual source IPs
        - Check for suspicious logon types
        - Check for multiple failed attempts

        Args:
            event: Authentication event to analyze

        Returns:
            List of detected anomalies with details
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to detect anomalies in a single AuthEvent by comparing it against
        # self.user_patterns baseline. Check for: unusual/new hosts for the user, authentication
        # outside normal working hours, unusual source IPs, suspicious logon types (3 or 10),
        # and multiple failed attempts. Return a list of dicts with keys: type, description,
        # severity, and confidence."
        #
        # Then review and test the generated code.
        pass

    def detect_credential_abuse(self, events: List[AuthEvent]) -> List[dict]:
        """
        Detect potential credential abuse patterns.

        TODO: Implement credential abuse detection
        - Password spraying: same password against many accounts
        - Credential stuffing: many usernames from single IP
        - Pass-the-hash: NTLM network logons without prior interactive

        Args:
            events: Window of authentication events

        Returns:
            List of credential abuse indicators
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to detect credential abuse patterns in a list of AuthEvents.
        # Detect: password spraying (same password against many accounts from one source),
        # credential stuffing (many usernames from a single IP in a short time window),
        # and pass-the-hash attacks (NTLM network logons without prior interactive logon).
        # Return a list of dicts describing each detected abuse pattern."
        #
        # Then review and test the generated code.
        pass

    def calculate_risk_score(self, event: AuthEvent, anomalies: List[dict]) -> float:
        """
        Calculate risk score for an authentication event.

        TODO: Implement risk scoring
        - Base score on anomaly count and severity
        - Factor in logon type risk
        - Factor in time of day
        - Factor in user privilege level

        Args:
            event: The authentication event
            anomalies: Detected anomalies

        Returns:
            Risk score between 0 and 1
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate a risk score (0 to 1) for an AuthEvent based on:
        # the number and severity of detected anomalies, the logon type risk level
        # (network and remote interactive are higher risk), time of day (off-hours is riskier),
        # and user privilege level if available. Combine these factors into a normalized score."
        #
        # Then review and test the generated code.
        pass


class RemoteExecutionDetector:
    """Detect suspicious remote execution patterns."""

    # PsExec service names
    PSEXEC_SERVICES = ["psexesvc", "paexec", "csexec", "remcom"]

    # WMI suspicious classes
    WMI_SUSPICIOUS = ["Win32_Process", "Win32_ScheduledJob", "StdRegProv"]

    def __init__(self):
        self.known_admin_tools = set()
        self.exec_history = defaultdict(list)

    def detect_psexec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """
        Detect PsExec or similar SMB-based execution.

        TODO: Implement PsExec detection
        - Look for service creation events (7045)
        - Check for ADMIN$ share access
        - Identify PSEXESVC or variants
        - Track source and target hosts

        Args:
            events: Windows event log entries

        Returns:
            List of detected PsExec executions
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to detect PsExec or similar SMB-based remote execution from
        # Windows event log entries. Look for: service creation events (Event ID 7045),
        # ADMIN$ share access, service names matching PSEXESVC or variants in
        # self.PSEXEC_SERVICES. Extract source and target hosts, username, and command.
        # Return a list of RemoteExecEvent objects with exec_type='psexec'."
        #
        # Then review and test the generated code.
        pass

    def detect_wmi_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """
        Detect WMI-based remote execution.

        TODO: Implement WMI execution detection
        - Look for WmiPrvSE.exe spawning processes
        - Check for Win32_Process Create method calls
        - Track WMI connections (event 5857, 5858)

        Args:
            events: Windows event log entries

        Returns:
            List of detected WMI executions
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to detect WMI-based remote execution from Windows event logs.
        # Look for: WmiPrvSE.exe spawning child processes, Win32_Process Create method calls,
        # WMI connection events (Event ID 5857, 5858), and suspicious WMI classes from
        # self.WMI_SUSPICIOUS. Return a list of RemoteExecEvent objects with exec_type='wmi'."
        #
        # Then review and test the generated code.
        pass

    def detect_winrm_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """
        Detect WinRM/PowerShell Remoting execution.

        TODO: Implement WinRM detection
        - Look for WSMan connection events
        - Check for remote PowerShell sessions
        - Track Enter-PSSession / Invoke-Command usage

        Args:
            events: Windows event log entries

        Returns:
            List of detected WinRM executions
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to detect WinRM/PowerShell Remoting execution from Windows event logs.
        # Look for: WSMan connection events, remote PowerShell session creation,
        # Enter-PSSession and Invoke-Command usage patterns. Extract source and target hosts.
        # Return a list of RemoteExecEvent objects with exec_type='winrm'."
        #
        # Then review and test the generated code.
        pass

    def detect_all_remote_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """
        Run all remote execution detectors.

        TODO: Implement combined detection
        - Call all detection methods
        - Merge and deduplicate results
        - Sort by timestamp

        Args:
            events: Windows event log entries

        Returns:
            Combined list of all remote executions detected
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to run all remote execution detection methods (detect_psexec,
        # detect_wmi_exec, detect_winrm_exec), combine their results, deduplicate based on
        # timestamp and hosts, and return a sorted list of RemoteExecEvent objects by timestamp."
        #
        # Then review and test the generated code.
        pass


class AttackPathAnalyzer:
    """Analyze lateral movement paths using graph analysis."""

    def __init__(self):
        self.graph = defaultdict(lambda: defaultdict(list))  # src -> dst -> [events]
        self.host_risk = {}

    def build_graph(self, events: List[RemoteExecEvent]):
        """
        Build graph of host connections from events.

        TODO: Implement graph building
        - Create nodes for each host
        - Create directed edges for each remote execution
        - Track edge metadata (timestamps, techniques, users)

        Args:
            events: Remote execution events
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to build a directed graph from RemoteExecEvent objects.
        # Populate self.graph as a nested dict where self.graph[source_host][target_host]
        # contains a list of events between those hosts. Track edge metadata including
        # timestamps, execution techniques, and usernames for each connection."
        #
        # Then review and test the generated code.
        pass

    def find_attack_paths(self, start_host: str = None, max_depth: int = 10) -> List[AttackPath]:
        """
        Find potential attack paths through the network.

        TODO: Implement path finding
        - Use BFS/DFS to find paths from compromised hosts
        - Score paths based on techniques used
        - Identify paths leading to high-value targets

        Args:
            start_host: Optional starting host (compromised machine)
            max_depth: Maximum path length to consider

        Returns:
            List of potential attack paths
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to find attack paths through self.graph using BFS or DFS.
        # If start_host is provided, find all paths from that host; otherwise find paths
        # from all nodes. Limit path length to max_depth. For each path, create an AttackPath
        # object with the host sequence, time range, techniques used, and calculate
        # confidence and risk scores."
        #
        # Then review and test the generated code.
        pass

    def identify_pivot_points(self) -> List[dict]:
        """
        Identify hosts being used as pivot points.

        TODO: Implement pivot point detection
        - Find hosts with many incoming AND outgoing connections
        - Calculate centrality metrics
        - Identify unusual connection patterns

        Returns:
            List of potential pivot points with metrics
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to identify hosts being used as pivot points in self.graph.
        # Find hosts with both incoming AND outgoing connections. Calculate centrality
        # metrics (degree centrality, betweenness if feasible). Identify unusual patterns
        # like many connections in short time windows. Return a list of dicts with host,
        # incoming_count, outgoing_count, and centrality score."
        #
        # Then review and test the generated code.
        pass

    def calculate_path_risk(self, path: List[str]) -> float:
        """
        Calculate risk score for an attack path.

        TODO: Implement path risk calculation
        - Consider path length
        - Consider techniques used on path
        - Consider target host value

        Args:
            path: List of hosts in path

        Returns:
            Risk score between 0 and 1
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate a risk score (0 to 1) for an attack path.
        # Consider: path length (longer paths may indicate more sophisticated attacks),
        # techniques used on each hop (PsExec, WMI, WinRM have different risk levels),
        # and target host value from self.host_risk if available. Normalize the final score."
        #
        # Then review and test the generated code.
        pass

    def visualize_graph(self) -> dict:
        """
        Generate graph visualization data.

        TODO: Implement visualization data generation
        - Create nodes list with metadata
        - Create edges list with metadata
        - Format for visualization library

        Returns:
            Dict with 'nodes' and 'edges' for visualization
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate graph visualization data from self.graph.
        # Create a 'nodes' list with dicts containing id, label, and metadata (risk score,
        # connection count). Create an 'edges' list with dicts containing source, target,
        # and metadata (techniques, timestamps). Format for common visualization libraries
        # like D3.js or vis.js."
        #
        # Then review and test the generated code.
        pass


class LateralMovementPipeline:
    """End-to-end lateral movement detection pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        """Initialize the pipeline."""
        self.auth_detector = AuthAnomalyDetector()
        self.exec_detector = RemoteExecutionDetector()
        self.path_analyzer = AttackPathAnalyzer()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        """Lazy initialization of LLM."""
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def analyze(self, auth_events: List[dict], system_events: List[dict]) -> dict:
        """
        Run full lateral movement analysis.

        TODO: Implement analysis pipeline
        1. Parse authentication events
        2. Build baseline from historical data
        3. Detect authentication anomalies
        4. Detect remote execution
        5. Build attack graph
        6. Find attack paths
        7. Generate alerts
        8. Use LLM for enrichment

        Args:
            auth_events: Windows authentication events
            system_events: Windows system events

        Returns:
            Analysis results with alerts and paths
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to run the full lateral movement analysis pipeline:
        # 1. Parse auth_events into AuthEvent objects using parse_auth_events()
        # 2. Build baseline from historical data using self.auth_detector.build_baseline()
        # 3. Detect auth anomalies for recent events using self.auth_detector.detect_anomalies()
        # 4. Detect remote execution using self.exec_detector.detect_all_remote_exec()
        # 5. Build attack graph using self.path_analyzer.build_graph()
        # 6. Find attack paths using self.path_analyzer.find_attack_paths()
        # 7. Generate LateralMovementAlert objects for high-risk findings
        # 8. Optionally use LLM for enrichment via self.llm_analyze_attack_path()
        # Return a dict with keys: alerts, attack_paths, anomalies, remote_execs, graph_data."
        #
        # Then review and test the generated code.
        pass

    def llm_analyze_attack_path(self, path: AttackPath) -> dict:
        """
        Use LLM to analyze and describe an attack path.

        TODO: Implement LLM analysis
        - Build prompt with path details
        - Request threat assessment
        - Get remediation recommendations

        Args:
            path: Detected attack path

        Returns:
            LLM analysis results
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze an AttackPath using an LLM. Initialize the LLM
        # with self._init_llm(). Build a prompt containing: the path hosts, techniques used,
        # timestamps, and risk score. Request a threat assessment, likely attack objectives,
        # and remediation recommendations. Handle the response based on self.llm provider
        # type (anthropic, openai, or google). Return a dict with assessment and recommendations."
        #
        # Then review and test the generated code.
        pass

    def generate_report(self, results: dict) -> str:
        """
        Generate human-readable report.

        TODO: Implement report generation
        - Summarize findings
        - List attack paths
        - Provide recommendations

        Args:
            results: Analysis results

        Returns:
            Formatted report string
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate a human-readable security report from analysis results.
        # Include: executive summary of findings, list of detected attack paths with risk scores,
        # authentication anomalies summary, remote execution events summary, identified pivot
        # points, and prioritized remediation recommendations. Format as a multi-line string
        # with clear section headers."
        #
        # Then review and test the generated code.
        pass


def parse_auth_events(raw_events: List[dict]) -> List[AuthEvent]:
    """Parse raw event data into AuthEvent objects."""
    events = []
    for e in raw_events:
        try:
            events.append(
                AuthEvent(
                    timestamp=e.get("timestamp", ""),
                    event_id=e.get("event_id", 0),
                    source_ip=e.get("source_ip", ""),
                    target_host=e.get("target_host", ""),
                    username=e.get("username", ""),
                    domain=e.get("domain", ""),
                    logon_type=e.get("logon_type", 0),
                    status=e.get("status", ""),
                    workstation_name=e.get("workstation_name", ""),
                    process_name=e.get("process_name", ""),
                )
            )
        except Exception:
            continue
    return events


def main():
    """Main entry point for Lab 15."""
    print("=" * 60)
    print("Lab 15: AI-Powered Lateral Movement Detection")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "auth_events.json"), "r") as f:
            data = json.load(f)
        print(f"\nLoaded {len(data.get('auth_events', []))} auth events")
        print(f"Loaded {len(data.get('system_events', []))} system events")
    except FileNotFoundError:
        print("Sample data not found. Using mock data.")
        data = {"auth_events": [], "system_events": []}

    # Task 1: Parse and analyze auth events
    print("\n--- Task 1: Authentication Anomaly Detection ---")
    auth_events = parse_auth_events(data.get("auth_events", []))
    detector = AuthAnomalyDetector()
    detector.build_baseline(auth_events[:50])  # Use first 50 as baseline

    if auth_events:
        for event in auth_events[50:55]:  # Check next 5
            anomalies = detector.detect_anomalies(event)
            if anomalies:
                print(f"  Anomalies for {event.username}@{event.target_host}:")
                for a in anomalies:
                    print(f"    - {a.get('type', 'unknown')}: {a.get('description', 'N/A')}")
            elif anomalies is None:
                print("TODO: Implement detect_anomalies()")
                break

    # Task 2: Remote execution detection
    print("\n--- Task 2: Remote Execution Detection ---")
    exec_detector = RemoteExecutionDetector()
    remote_execs = exec_detector.detect_all_remote_exec(data.get("system_events", []))
    if remote_execs:
        print(f"Found {len(remote_execs)} remote executions")
        for r in remote_execs[:5]:
            print(f"  - {r.exec_type}: {r.source_host} -> {r.target_host}")
    elif remote_execs is None:
        print("TODO: Implement detect_all_remote_exec()")

    # Task 3: Attack path analysis
    print("\n--- Task 3: Attack Path Analysis ---")
    path_analyzer = AttackPathAnalyzer()
    if remote_execs:
        path_analyzer.build_graph(remote_execs)
        paths = path_analyzer.find_attack_paths()
        if paths:
            print(f"Found {len(paths)} potential attack paths")
            for p in paths[:3]:
                print(f"  - Path: {' -> '.join(p.path)}")
                print(f"    Risk: {p.risk_score:.2f}")
        elif paths is None:
            print("TODO: Implement find_attack_paths()")
    else:
        print("No remote executions to build graph from")

    # Task 4: Full pipeline
    print("\n--- Task 4: Full Pipeline ---")
    pipeline = LateralMovementPipeline()
    results = pipeline.analyze(data.get("auth_events", []), data.get("system_events", []))
    if results:
        print(f"Analysis complete")
        if results.get("alerts"):
            print(f"  Alerts: {len(results['alerts'])}")
        if results.get("attack_paths"):
            print(f"  Attack paths: {len(results['attack_paths'])}")
    else:
        print("TODO: Implement analyze()")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 15!")
    print("=" * 60)


if __name__ == "__main__":
    main()

"""
Lab 15: AI-Powered Lateral Movement Detection - Solution

Detect lateral movement attacks using Windows authentication events,
remote execution patterns, and graph analysis.
"""

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

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
class AuthEvent:
    """Windows authentication event (4624/4625)."""

    timestamp: str
    event_id: int
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
    """Remote execution event."""

    timestamp: str
    source_host: str
    target_host: str
    exec_type: str
    username: str
    command: str = ""
    success: bool = True


@dataclass
class AttackPath:
    """Detected attack path through the network."""

    path: List[str]
    start_time: str
    end_time: str
    techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    risk_score: float = 0.0


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

    SUSPICIOUS_LOGON_TYPES = [3, 10]

    def __init__(self, baseline_hours: int = 24):
        self.baseline_hours = baseline_hours
        self.user_patterns = defaultdict(
            lambda: {"hosts": set(), "times": [], "source_ips": set(), "logon_types": set()}
        )
        self.baseline_built = False

    def build_baseline(self, events: List[AuthEvent]):
        """Build baseline of normal authentication patterns."""
        for event in events:
            if event.event_id == 4624:  # Successful logon
                user_key = f"{event.domain}\\{event.username}".lower()
                self.user_patterns[user_key]["hosts"].add(event.target_host.lower())
                self.user_patterns[user_key]["source_ips"].add(event.source_ip)
                self.user_patterns[user_key]["logon_types"].add(event.logon_type)

                # Parse timestamp for time pattern
                try:
                    dt = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                    self.user_patterns[user_key]["times"].append(dt.hour)
                except (ValueError, AttributeError):
                    pass

        self.baseline_built = True
        print(f"  Built baseline for {len(self.user_patterns)} users")

    def detect_anomalies(self, event: AuthEvent) -> List[dict]:
        """Detect anomalies in a single authentication event."""
        anomalies = []
        user_key = f"{event.domain}\\{event.username}".lower()
        pattern = self.user_patterns.get(user_key)

        # New user (no baseline)
        if not pattern and self.baseline_built:
            anomalies.append(
                {
                    "type": "new_user",
                    "description": f"First time seeing user {event.username}",
                    "severity": "medium",
                    "confidence": 0.7,
                }
            )
            return anomalies

        if pattern:
            # Check for new host access
            if event.target_host.lower() not in pattern["hosts"]:
                anomalies.append(
                    {
                        "type": "new_host",
                        "description": f"User {event.username} accessing new host {event.target_host}",
                        "severity": "medium",
                        "confidence": 0.8,
                    }
                )

            # Check for new source IP
            if event.source_ip and event.source_ip not in pattern["source_ips"]:
                anomalies.append(
                    {
                        "type": "new_source_ip",
                        "description": f"User {event.username} authenticating from new IP {event.source_ip}",
                        "severity": "medium",
                        "confidence": 0.75,
                    }
                )

            # Check for unusual time
            try:
                dt = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                avg_hour = np.mean(pattern["times"]) if pattern["times"] else 12
                if abs(dt.hour - avg_hour) > 6:  # More than 6 hours from average
                    anomalies.append(
                        {
                            "type": "unusual_time",
                            "description": f"User {event.username} authenticating at unusual hour {dt.hour}",
                            "severity": "low",
                            "confidence": 0.6,
                        }
                    )
            except (ValueError, AttributeError):
                pass

        # Check for suspicious logon types
        if event.logon_type in self.SUSPICIOUS_LOGON_TYPES:
            anomalies.append(
                {
                    "type": "suspicious_logon_type",
                    "description": f"Logon type {self.LOGON_TYPES.get(event.logon_type, event.logon_type)} to {event.target_host}",
                    "severity": "low",
                    "confidence": 0.5,
                }
            )

        # Failed logon
        if event.event_id == 4625:
            anomalies.append(
                {
                    "type": "failed_logon",
                    "description": f"Failed logon for {event.username} to {event.target_host}",
                    "severity": "medium",
                    "confidence": 0.9,
                }
            )

        return anomalies

    def detect_credential_abuse(self, events: List[AuthEvent]) -> List[dict]:
        """Detect potential credential abuse patterns."""
        abuse_indicators = []

        # Group by source IP
        by_source = defaultdict(list)
        for e in events:
            if e.source_ip:
                by_source[e.source_ip].append(e)

        # Password spraying detection (single IP, many users, failures)
        for source_ip, ip_events in by_source.items():
            failed = [e for e in ip_events if e.event_id == 4625]
            unique_users = len(set(e.username for e in failed))
            if len(failed) > 5 and unique_users > 3:
                abuse_indicators.append(
                    {
                        "type": "password_spraying",
                        "description": f"Possible password spraying from {source_ip}: {unique_users} users, {len(failed)} failures",
                        "severity": "high",
                        "source_ip": source_ip,
                        "affected_users": list(set(e.username for e in failed))[:10],
                    }
                )

        # Credential stuffing (single IP, many rapid attempts)
        for source_ip, ip_events in by_source.items():
            if len(ip_events) > 10:
                timestamps = []
                for e in ip_events:
                    try:
                        dt = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                        timestamps.append(dt)
                    except (ValueError, AttributeError):
                        continue

                if len(timestamps) > 1:
                    timestamps.sort()
                    duration = (timestamps[-1] - timestamps[0]).total_seconds()
                    if (
                        duration > 0 and len(ip_events) / duration > 0.5
                    ):  # More than 1 per 2 seconds
                        abuse_indicators.append(
                            {
                                "type": "credential_stuffing",
                                "description": f"Rapid authentication attempts from {source_ip}: {len(ip_events)} in {duration:.0f}s",
                                "severity": "high",
                                "source_ip": source_ip,
                            }
                        )

        return abuse_indicators

    def calculate_risk_score(self, event: AuthEvent, anomalies: List[dict]) -> float:
        """Calculate risk score for an authentication event."""
        score = 0.0

        # Base score from anomalies
        severity_weights = {"low": 0.1, "medium": 0.25, "high": 0.4, "critical": 0.6}
        for anomaly in anomalies:
            weight = severity_weights.get(anomaly.get("severity", "low"), 0.1)
            confidence = anomaly.get("confidence", 0.5)
            score += weight * confidence

        # Logon type risk
        if event.logon_type == 3:  # Network logon
            score += 0.1
        elif event.logon_type == 10:  # RDP
            score += 0.15

        # Failed logon additional risk
        if event.event_id == 4625:
            score += 0.2

        # Admin account risk
        admin_keywords = ["admin", "administrator", "root", "system"]
        if any(kw in event.username.lower() for kw in admin_keywords):
            score += 0.15

        return min(score, 1.0)


class RemoteExecutionDetector:
    """Detect suspicious remote execution patterns."""

    PSEXEC_SERVICES = ["psexesvc", "paexec", "csexec", "remcom", "smbexec"]
    WMI_SUSPICIOUS = ["Win32_Process", "Win32_ScheduledJob", "StdRegProv"]

    def __init__(self):
        self.known_admin_tools = set()
        self.exec_history = defaultdict(list)

    def detect_psexec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """Detect PsExec or similar SMB-based execution."""
        detections = []

        for event in events:
            event_id = event.get("event_id", 0)

            # Service creation (7045)
            if event_id == 7045:
                service_name = event.get("service_name", "").lower()
                if any(ps in service_name for ps in self.PSEXEC_SERVICES):
                    detections.append(
                        RemoteExecEvent(
                            timestamp=event.get("timestamp", ""),
                            source_host=event.get("source_host", "unknown"),
                            target_host=event.get("target_host", event.get("computer_name", "")),
                            exec_type="psexec",
                            username=event.get("username", ""),
                            command=event.get("service_file_name", ""),
                            success=True,
                        )
                    )

            # SMB share access (5140) - ADMIN$
            if event_id == 5140:
                share_name = event.get("share_name", "")
                if share_name in ["\\\\*\\ADMIN$", "\\\\*\\C$", "ADMIN$", "C$"]:
                    detections.append(
                        RemoteExecEvent(
                            timestamp=event.get("timestamp", ""),
                            source_host=event.get("source_ip", "unknown"),
                            target_host=event.get("target_host", event.get("computer_name", "")),
                            exec_type="smb_admin_share",
                            username=event.get("username", ""),
                            success=True,
                        )
                    )

        return detections

    def detect_wmi_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """Detect WMI-based remote execution."""
        detections = []

        for event in events:
            event_id = event.get("event_id", 0)

            # WMI activity
            if event_id in [5857, 5858, 5859, 5860, 5861]:
                operation = event.get("operation", "")
                if "Win32_Process" in operation or "Create" in operation:
                    detections.append(
                        RemoteExecEvent(
                            timestamp=event.get("timestamp", ""),
                            source_host=event.get(
                                "source_host", event.get("client_machine", "unknown")
                            ),
                            target_host=event.get("target_host", event.get("computer_name", "")),
                            exec_type="wmi",
                            username=event.get("username", ""),
                            command=event.get("commandline", operation),
                            success=True,
                        )
                    )

            # Process creation from WmiPrvSE.exe (4688)
            if event_id == 4688:
                parent = event.get("parent_process_name", "").lower()
                if "wmiprvse" in parent:
                    detections.append(
                        RemoteExecEvent(
                            timestamp=event.get("timestamp", ""),
                            source_host=event.get("source_host", "unknown"),
                            target_host=event.get("target_host", event.get("computer_name", "")),
                            exec_type="wmi_process",
                            username=event.get("username", ""),
                            command=event.get("commandline", ""),
                            success=True,
                        )
                    )

        return detections

    def detect_winrm_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """Detect WinRM/PowerShell Remoting execution."""
        detections = []

        for event in events:
            event_id = event.get("event_id", 0)

            # PowerShell remoting (4103, 4104)
            if event_id in [4103, 4104]:
                script = event.get("script_block", event.get("payload", ""))
                if any(
                    kw in script.lower()
                    for kw in ["invoke-command", "enter-pssession", "new-pssession"]
                ):
                    detections.append(
                        RemoteExecEvent(
                            timestamp=event.get("timestamp", ""),
                            source_host=event.get("source_host", "unknown"),
                            target_host=event.get("target_host", event.get("computer_name", "")),
                            exec_type="winrm",
                            username=event.get("username", ""),
                            command=script[:500],
                            success=True,
                        )
                    )

            # WinRM connection (91, 168)
            if event_id in [91, 168]:
                detections.append(
                    RemoteExecEvent(
                        timestamp=event.get("timestamp", ""),
                        source_host=event.get("source_ip", "unknown"),
                        target_host=event.get("target_host", event.get("computer_name", "")),
                        exec_type="winrm",
                        username=event.get("username", ""),
                        success=True,
                    )
                )

        return detections

    def detect_all_remote_exec(self, events: List[dict]) -> List[RemoteExecEvent]:
        """Run all remote execution detectors."""
        all_detections = []

        all_detections.extend(self.detect_psexec(events))
        all_detections.extend(self.detect_wmi_exec(events))
        all_detections.extend(self.detect_winrm_exec(events))

        # Sort by timestamp
        all_detections.sort(key=lambda x: x.timestamp)

        return all_detections


class AttackPathAnalyzer:
    """Analyze lateral movement paths using graph analysis."""

    def __init__(self):
        self.graph = defaultdict(lambda: defaultdict(list))
        self.host_risk = {}
        self.high_value_targets = {"dc01", "dc02", "sql01", "fileserver", "exchange"}

    def build_graph(self, events: List[RemoteExecEvent]):
        """Build graph of host connections from events."""
        for event in events:
            src = event.source_host.lower()
            dst = event.target_host.lower()
            self.graph[src][dst].append(
                {
                    "timestamp": event.timestamp,
                    "technique": event.exec_type,
                    "username": event.username,
                    "command": event.command,
                }
            )

        print(f"  Built graph with {len(self.graph)} source hosts")

    def find_attack_paths(self, start_host: str = None, max_depth: int = 10) -> List[AttackPath]:
        """Find potential attack paths through the network."""
        paths = []

        # If no start host, find hosts with only outgoing connections
        start_hosts = []
        if start_host:
            start_hosts = [start_host.lower()]
        else:
            all_dsts = set()
            for src in self.graph:
                for dst in self.graph[src]:
                    all_dsts.add(dst)

            for src in self.graph:
                if src not in all_dsts:
                    start_hosts.append(src)

            if not start_hosts:
                start_hosts = list(self.graph.keys())[:5]

        # BFS from each start host
        for start in start_hosts:
            visited = set()
            queue = [(start, [start], [])]

            while queue:
                current, path, techniques = queue.pop(0)

                if len(path) > max_depth:
                    continue

                if current in visited:
                    continue
                visited.add(current)

                # Check if this path leads to high-value target
                if any(hvt in current for hvt in self.high_value_targets):
                    timestamps = []
                    for i, host in enumerate(path[:-1]):
                        next_host = path[i + 1]
                        edges = self.graph[host].get(next_host, [])
                        if edges:
                            timestamps.append(edges[0]["timestamp"])

                    if timestamps:
                        paths.append(
                            AttackPath(
                                path=path,
                                start_time=min(timestamps) if timestamps else "",
                                end_time=max(timestamps) if timestamps else "",
                                techniques=list(set(techniques)),
                                confidence=0.7,
                                risk_score=self.calculate_path_risk(path),
                            )
                        )

                # Explore neighbors
                for neighbor in self.graph[current]:
                    if neighbor not in visited:
                        edges = self.graph[current][neighbor]
                        new_techniques = techniques + [e["technique"] for e in edges]
                        queue.append((neighbor, path + [neighbor], new_techniques))

        # Sort by risk score
        paths.sort(key=lambda x: x.risk_score, reverse=True)
        return paths

    def identify_pivot_points(self) -> List[dict]:
        """Identify hosts being used as pivot points."""
        pivot_points = []

        for host in self.graph:
            incoming = sum(1 for src in self.graph if host in self.graph[src])
            outgoing = len(self.graph[host])

            if incoming > 0 and outgoing > 0:
                # Calculate centrality (simplified betweenness)
                centrality = incoming * outgoing
                pivot_points.append(
                    {
                        "host": host,
                        "incoming": incoming,
                        "outgoing": outgoing,
                        "centrality": centrality,
                        "is_pivot": incoming >= 2 and outgoing >= 2,
                    }
                )

        pivot_points.sort(key=lambda x: x["centrality"], reverse=True)
        return pivot_points

    def calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for an attack path."""
        score = 0.0

        # Path length factor (longer paths = higher risk of persistent attacker)
        score += min(len(path) * 0.1, 0.4)

        # High-value target factor
        for host in path:
            if any(hvt in host.lower() for hvt in self.high_value_targets):
                score += 0.3
                break

        # Techniques used
        techniques = set()
        for i, host in enumerate(path[:-1]):
            next_host = path[i + 1]
            for edge in self.graph[host].get(next_host, []):
                techniques.add(edge["technique"])

        technique_risk = {"psexec": 0.2, "wmi": 0.15, "winrm": 0.15, "smb_admin_share": 0.25}
        for tech in techniques:
            score += technique_risk.get(tech, 0.1)

        return min(score, 1.0)

    def visualize_graph(self) -> dict:
        """Generate graph visualization data."""
        nodes = []
        edges = []
        node_set = set()

        for src in self.graph:
            if src not in node_set:
                node_set.add(src)
                nodes.append(
                    {
                        "id": src,
                        "label": src,
                        "type": (
                            "high_value"
                            if any(hvt in src for hvt in self.high_value_targets)
                            else "normal"
                        ),
                    }
                )

            for dst in self.graph[src]:
                if dst not in node_set:
                    node_set.add(dst)
                    nodes.append(
                        {
                            "id": dst,
                            "label": dst,
                            "type": (
                                "high_value"
                                if any(hvt in dst for hvt in self.high_value_targets)
                                else "normal"
                            ),
                        }
                    )

                edge_data = self.graph[src][dst]
                edges.append(
                    {
                        "source": src,
                        "target": dst,
                        "techniques": list(set(e["technique"] for e in edge_data)),
                        "count": len(edge_data),
                    }
                )

        return {"nodes": nodes, "edges": edges}


class LateralMovementPipeline:
    """End-to-end lateral movement detection pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        self.auth_detector = AuthAnomalyDetector()
        self.exec_detector = RemoteExecutionDetector()
        self.path_analyzer = AttackPathAnalyzer()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def analyze(self, auth_events: List[dict], system_events: List[dict]) -> dict:
        """Run full lateral movement analysis."""
        results = {
            "alerts": [],
            "attack_paths": [],
            "pivot_points": [],
            "auth_anomalies": [],
            "credential_abuse": [],
            "remote_executions": [],
        }

        # 1. Parse authentication events
        parsed_auth = []
        for e in auth_events:
            try:
                parsed_auth.append(
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

        print(f"  Parsed {len(parsed_auth)} authentication events")

        # 2. Build baseline
        baseline_count = min(len(parsed_auth) // 2, 100)
        self.auth_detector.build_baseline(parsed_auth[:baseline_count])

        # 3. Detect auth anomalies
        for event in parsed_auth[baseline_count:]:
            anomalies = self.auth_detector.detect_anomalies(event)
            if anomalies:
                risk_score = self.auth_detector.calculate_risk_score(event, anomalies)
                if risk_score > 0.3:
                    results["auth_anomalies"].append(
                        {
                            "event": {
                                "timestamp": event.timestamp,
                                "username": event.username,
                                "target_host": event.target_host,
                                "source_ip": event.source_ip,
                            },
                            "anomalies": anomalies,
                            "risk_score": risk_score,
                        }
                    )

        # 4. Detect credential abuse
        results["credential_abuse"] = self.auth_detector.detect_credential_abuse(parsed_auth)

        # 5. Detect remote execution
        results["remote_executions"] = self.exec_detector.detect_all_remote_exec(system_events)
        print(f"  Detected {len(results['remote_executions'])} remote executions")

        # 6. Build attack graph
        self.path_analyzer.build_graph(results["remote_executions"])

        # 7. Find attack paths
        results["attack_paths"] = self.path_analyzer.find_attack_paths()

        # 8. Find pivot points
        results["pivot_points"] = self.path_analyzer.identify_pivot_points()

        # 9. Generate alerts
        for anomaly in results["auth_anomalies"]:
            if anomaly["risk_score"] > 0.5:
                results["alerts"].append(
                    LateralMovementAlert(
                        timestamp=anomaly["event"]["timestamp"],
                        alert_type="auth_anomaly",
                        source_host=anomaly["event"]["source_ip"],
                        target_host=anomaly["event"]["target_host"],
                        username=anomaly["event"]["username"],
                        indicators=[a["description"] for a in anomaly["anomalies"]],
                        severity="high" if anomaly["risk_score"] > 0.7 else "medium",
                        mitre_techniques=["T1078", "T1021"],
                    )
                )

        for abuse in results["credential_abuse"]:
            results["alerts"].append(
                LateralMovementAlert(
                    timestamp=datetime.now().isoformat(),
                    alert_type=abuse["type"],
                    source_host=abuse.get("source_ip", "unknown"),
                    target_host="multiple",
                    username="multiple",
                    indicators=[abuse["description"]],
                    severity="high",
                    mitre_techniques=["T1110"],
                )
            )

        for path in results["attack_paths"]:
            if path.risk_score > 0.5:
                results["alerts"].append(
                    LateralMovementAlert(
                        timestamp=path.start_time,
                        alert_type="attack_path",
                        source_host=path.path[0],
                        target_host=path.path[-1],
                        username="unknown",
                        indicators=[f"Path: {' -> '.join(path.path)}"],
                        severity="critical" if path.risk_score > 0.7 else "high",
                        mitre_techniques=["T1021", "T1570"],
                    )
                )

        return results

    def llm_analyze_attack_path(self, path: AttackPath) -> dict:
        """Use LLM to analyze and describe an attack path."""
        self._init_llm()
        if not self.llm:
            return {"error": "LLM not available"}

        provider, client = self.llm

        prompt = f"""Analyze this potential lateral movement attack path:

Path: {' -> '.join(path.path)}
Start Time: {path.start_time}
End Time: {path.end_time}
Techniques Used: {', '.join(path.techniques)}
Risk Score: {path.risk_score:.2f}

Provide analysis in JSON format:
- attack_description: Brief description of the attack
- threat_actor_profile: Likely attacker sophistication level
- mitre_techniques: List of MITRE ATT&CK technique IDs
- impact_assessment: Potential impact
- remediation_steps: List of immediate actions
- detection_gaps: What detection might have been missed"""

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
                    model="gpt-5",
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

    def generate_report(self, results: dict) -> str:
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 60)
        lines.append("LATERAL MOVEMENT DETECTION REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")

        # Summary
        lines.append("--- SUMMARY ---")
        lines.append(f"Authentication Anomalies: {len(results.get('auth_anomalies', []))}")
        lines.append(f"Credential Abuse Indicators: {len(results.get('credential_abuse', []))}")
        lines.append(f"Remote Executions: {len(results.get('remote_executions', []))}")
        lines.append(f"Attack Paths: {len(results.get('attack_paths', []))}")
        lines.append(f"Total Alerts: {len(results.get('alerts', []))}")
        lines.append("")

        # Critical Alerts
        critical_alerts = [
            a
            for a in results.get("alerts", [])
            if isinstance(a, LateralMovementAlert) and a.severity == "critical"
        ]
        if critical_alerts:
            lines.append("--- CRITICAL ALERTS ---")
            for alert in critical_alerts:
                lines.append(f"  [{alert.alert_type}] {alert.source_host} -> {alert.target_host}")
                for ind in alert.indicators:
                    lines.append(f"    - {ind}")
            lines.append("")

        # Attack Paths
        if results.get("attack_paths"):
            lines.append("--- ATTACK PATHS ---")
            for path in results["attack_paths"][:5]:
                lines.append(f"  Path: {' -> '.join(path.path)}")
                lines.append(
                    f"  Risk: {path.risk_score:.2f}, Techniques: {', '.join(path.techniques)}"
                )
                lines.append("")

        # Pivot Points
        pivots = [p for p in results.get("pivot_points", []) if p.get("is_pivot")]
        if pivots:
            lines.append("--- PIVOT POINTS ---")
            for pivot in pivots[:5]:
                lines.append(f"  {pivot['host']}: {pivot['incoming']} in, {pivot['outgoing']} out")
            lines.append("")

        return "\n".join(lines)


def main():
    """Main entry point for Lab 15."""
    print("=" * 60)
    print("Lab 15: AI-Powered Lateral Movement Detection - Solution")
    print("=" * 60)

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "auth_events.json"), "r") as f:
            data = json.load(f)
        print(f"\nLoaded {len(data.get('auth_events', []))} auth events")
        print(f"Loaded {len(data.get('system_events', []))} system events")
    except FileNotFoundError:
        print("Sample data not found. Creating mock data.")
        data = create_mock_data()

    # Run pipeline
    print("\n" + "-" * 40)
    print("Running Lateral Movement Detection Pipeline")
    print("-" * 40)

    pipeline = LateralMovementPipeline()
    results = pipeline.analyze(data.get("auth_events", []), data.get("system_events", []))

    # Generate and print report
    report = pipeline.generate_report(results)
    print("\n" + report)

    # Graph visualization data
    graph_data = pipeline.path_analyzer.visualize_graph()
    print(f"\nGraph: {len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges")


def create_mock_data():
    """Create mock data for demo."""
    base_time = datetime(2024, 1, 15, 9, 0, 0)

    auth_events = []
    # Normal baseline events
    for i in range(50):
        auth_events.append(
            {
                "timestamp": (base_time + timedelta(hours=i // 10, minutes=i % 60)).isoformat(),
                "event_id": 4624,
                "source_ip": "192.168.1.10",
                "target_host": "workstation01",
                "username": "jsmith",
                "domain": "CORP",
                "logon_type": 2,
                "status": "success",
            }
        )

    # Suspicious events
    for i in range(10):
        auth_events.append(
            {
                "timestamp": (base_time + timedelta(hours=10, minutes=i * 5)).isoformat(),
                "event_id": 4624,
                "source_ip": "192.168.1.50",
                "target_host": f"server0{i%3+1}",
                "username": "admin",
                "domain": "CORP",
                "logon_type": 3,
                "status": "success",
            }
        )

    # Failed attempts (password spraying)
    for i in range(15):
        auth_events.append(
            {
                "timestamp": (base_time + timedelta(hours=11, minutes=i)).isoformat(),
                "event_id": 4625,
                "source_ip": "192.168.1.99",
                "target_host": "dc01",
                "username": f"user{i}",
                "domain": "CORP",
                "logon_type": 3,
                "status": "failure",
            }
        )

    system_events = []
    # PsExec activity
    system_events.append(
        {
            "timestamp": (base_time + timedelta(hours=10, minutes=30)).isoformat(),
            "event_id": 7045,
            "service_name": "PSEXESVC",
            "source_host": "workstation01",
            "target_host": "server01",
            "computer_name": "server01",
            "username": "admin",
            "service_file_name": "%SystemRoot%\\PSEXESVC.exe",
        }
    )

    # SMB share access
    system_events.append(
        {
            "timestamp": (base_time + timedelta(hours=10, minutes=31)).isoformat(),
            "event_id": 5140,
            "share_name": "ADMIN$",
            "source_ip": "192.168.1.10",
            "target_host": "server02",
            "computer_name": "server02",
            "username": "admin",
        }
    )

    # WMI execution
    system_events.append(
        {
            "timestamp": (base_time + timedelta(hours=10, minutes=35)).isoformat(),
            "event_id": 5857,
            "operation": "Win32_Process::Create",
            "source_host": "server01",
            "target_host": "dc01",
            "computer_name": "dc01",
            "username": "admin",
            "commandline": "cmd.exe /c whoami",
        }
    )

    # More lateral movement
    system_events.append(
        {
            "timestamp": (base_time + timedelta(hours=10, minutes=40)).isoformat(),
            "event_id": 7045,
            "service_name": "PSEXESVC",
            "source_host": "server02",
            "target_host": "fileserver",
            "computer_name": "fileserver",
            "username": "admin",
            "service_file_name": "%SystemRoot%\\PSEXESVC.exe",
        }
    )

    return {"auth_events": auth_events, "system_events": system_events}


if __name__ == "__main__":
    main()

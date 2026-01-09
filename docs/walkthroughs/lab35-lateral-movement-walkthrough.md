# Lab 15: Lateral Movement Detection - Solution Walkthrough

## Overview

Build an AI-powered lateral movement detection system for identifying authentication anomalies, remote execution, and attack path analysis.

**Time:** 3-4 hours
**Difficulty:** Advanced

---

## Task 1: Authentication Anomaly Detection

### Analyzing Login Patterns

```python
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class AuthenticationEvent:
    timestamp: datetime
    username: str
    src_ip: str
    dst_host: str
    auth_type: str  # kerberos, ntlm, rdp, ssh
    success: bool
    logon_type: int  # Windows logon types (2, 3, 10, etc.)

class AuthAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.user_baselines = defaultdict(lambda: {
            'normal_hours': set(),
            'normal_sources': set(),
            'normal_destinations': set(),
            'auth_types': set()
        })
        self.is_trained = False

    def build_baseline(self, events: list[AuthenticationEvent], days: int = 30):
        """Build user behavior baselines."""

        for event in events:
            if not event.success:
                continue

            baseline = self.user_baselines[event.username]
            baseline['normal_hours'].add(event.timestamp.hour)
            baseline['normal_sources'].add(event.src_ip)
            baseline['normal_destinations'].add(event.dst_host)
            baseline['auth_types'].add(event.auth_type)

    def extract_features(self, event: AuthenticationEvent) -> np.ndarray:
        """Extract features for anomaly detection."""

        baseline = self.user_baselines.get(event.username, {})

        features = {
            # Temporal features
            'hour': event.timestamp.hour,
            'is_weekend': 1 if event.timestamp.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= event.timestamp.hour <= 17 else 0,

            # Baseline deviations
            'new_source': 0 if event.src_ip in baseline.get('normal_sources', set()) else 1,
            'new_destination': 0 if event.dst_host in baseline.get('normal_destinations', set()) else 1,
            'unusual_hour': 0 if event.timestamp.hour in baseline.get('normal_hours', set()) else 1,
            'new_auth_type': 0 if event.auth_type in baseline.get('auth_types', set()) else 1,

            # Logon type encoding
            'is_network_logon': 1 if event.logon_type == 3 else 0,
            'is_remote_logon': 1 if event.logon_type == 10 else 0,
            'is_service_logon': 1 if event.logon_type == 5 else 0,

            # Authentication type
            'is_ntlm': 1 if event.auth_type == 'ntlm' else 0,
            'is_kerberos': 1 if event.auth_type == 'kerberos' else 0,
        }

        return np.array(list(features.values())).reshape(1, -1)

    def train(self, events: list[AuthenticationEvent]):
        """Train anomaly detection model."""

        # Build baselines first
        self.build_baseline(events)

        # Extract features
        X = []
        for event in events:
            if event.success:
                features = self.extract_features(event)
                X.append(features.flatten())

        X = np.array(X)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

    def detect_anomaly(self, event: AuthenticationEvent) -> dict:
        """Detect if authentication event is anomalous."""

        features = self.extract_features(event)
        features_scaled = self.scaler.transform(features)

        score = self.model.decision_function(features_scaled)[0]
        is_anomaly = self.model.predict(features_scaled)[0] == -1

        # Calculate specific anomaly reasons
        reasons = []
        baseline = self.user_baselines.get(event.username, {})

        if event.src_ip not in baseline.get('normal_sources', set()):
            reasons.append(f"New source IP: {event.src_ip}")
        if event.dst_host not in baseline.get('normal_destinations', set()):
            reasons.append(f"New destination: {event.dst_host}")
        if event.timestamp.hour not in baseline.get('normal_hours', set()):
            reasons.append(f"Unusual hour: {event.timestamp.hour}")
        if event.auth_type not in baseline.get('auth_types', set()):
            reasons.append(f"New auth type: {event.auth_type}")

        return {
            'event': {
                'username': event.username,
                'src_ip': event.src_ip,
                'dst_host': event.dst_host,
                'timestamp': event.timestamp.isoformat()
            },
            'is_anomaly': is_anomaly,
            'anomaly_score': round(float(score), 4),
            'reasons': reasons,
            'risk_level': 'HIGH' if is_anomaly and len(reasons) >= 2 else 'MEDIUM' if is_anomaly else 'LOW'
        }

# Train detector
auth_detector = AuthAnomalyDetector()

# Historical events for baseline
historical_events = [
    AuthenticationEvent(datetime(2024, 12, 1, 9, 0), "jsmith", "192.168.1.100", "DC01", "kerberos", True, 3),
    AuthenticationEvent(datetime(2024, 12, 1, 10, 0), "jsmith", "192.168.1.100", "FILE01", "kerberos", True, 3),
    # ... more historical data
]

auth_detector.train(historical_events)

# Detect anomaly
new_event = AuthenticationEvent(
    datetime(2024, 12, 23, 3, 0),  # 3 AM
    "jsmith",
    "10.0.0.50",  # New source
    "DC01",
    "ntlm",  # Different auth type
    True,
    10  # Remote logon
)

result = auth_detector.detect_anomaly(new_event)
print(f"Anomaly: {result['is_anomaly']}")
print(f"Reasons: {result['reasons']}")
```

---

## Task 2: Remote Execution Detection

### Monitoring PsExec, WMI, WinRM

```python
from enum import Enum

class RemoteExecutionType(Enum):
    PSEXEC = "psexec"
    WMI = "wmi"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    DCOM = "dcom"
    SCHEDULED_TASK = "scheduled_task"

@dataclass
class RemoteExecutionEvent:
    timestamp: datetime
    src_host: str
    dst_host: str
    username: str
    execution_type: RemoteExecutionType
    command: str
    process_name: str
    parent_process: str

class RemoteExecutionDetector:
    def __init__(self):
        # Suspicious patterns
        self.suspicious_commands = [
            r'powershell.*-enc',
            r'cmd.*\/c.*whoami',
            r'net\s+(user|group|localgroup)',
            r'nltest',
            r'mimikatz',
            r'procdump.*lsass',
            r'reg.*save.*sam',
            r'wmic.*process.*call.*create',
        ]

        # Suspicious parent-child relationships
        self.suspicious_parents = {
            'services.exe': ['cmd.exe', 'powershell.exe'],
            'wmiprvse.exe': ['cmd.exe', 'powershell.exe'],
            'wsmprovhost.exe': ['cmd.exe', 'powershell.exe'],
        }

    def analyze_event(self, event: RemoteExecutionEvent) -> dict:
        """Analyze remote execution event for lateral movement."""

        analysis = {
            'event': {
                'src_host': event.src_host,
                'dst_host': event.dst_host,
                'username': event.username,
                'execution_type': event.execution_type.value,
                'command': event.command[:200]
            },
            'indicators': [],
            'risk_score': 0
        }

        # Check execution type risk
        high_risk_types = [RemoteExecutionType.PSEXEC, RemoteExecutionType.WMI, RemoteExecutionType.DCOM]
        if event.execution_type in high_risk_types:
            analysis['indicators'].append({
                'type': 'high_risk_execution_method',
                'value': event.execution_type.value
            })
            analysis['risk_score'] += 20

        # Check for suspicious commands
        import re
        for pattern in self.suspicious_commands:
            if re.search(pattern, event.command, re.IGNORECASE):
                analysis['indicators'].append({
                    'type': 'suspicious_command',
                    'pattern': pattern,
                    'matched': True
                })
                analysis['risk_score'] += 30

        # Check parent-child relationship
        parent_lower = event.parent_process.lower()
        process_lower = event.process_name.lower()

        for parent, children in self.suspicious_parents.items():
            if parent in parent_lower:
                if any(child in process_lower for child in children):
                    analysis['indicators'].append({
                        'type': 'suspicious_parent_child',
                        'parent': event.parent_process,
                        'child': event.process_name
                    })
                    analysis['risk_score'] += 25

        # Check if targeting sensitive systems
        sensitive_hosts = ['dc', 'domain', 'admin', 'backup', 'sql']
        if any(sens in event.dst_host.lower() for sens in sensitive_hosts):
            analysis['indicators'].append({
                'type': 'sensitive_target',
                'host': event.dst_host
            })
            analysis['risk_score'] += 20

        analysis['risk_score'] = min(analysis['risk_score'], 100)
        analysis['risk_level'] = (
            'CRITICAL' if analysis['risk_score'] >= 70 else
            'HIGH' if analysis['risk_score'] >= 50 else
            'MEDIUM' if analysis['risk_score'] >= 30 else 'LOW'
        )

        return analysis

    def detect_lateral_chain(self, events: list[RemoteExecutionEvent],
                            time_window: timedelta = timedelta(hours=1)) -> list[dict]:
        """Detect chains of lateral movement."""

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        chains = []
        current_chain = []

        for i, event in enumerate(sorted_events):
            if not current_chain:
                current_chain = [event]
                continue

            # Check if continues chain
            last_event = current_chain[-1]

            # Same source as previous destination
            is_continuation = (
                event.src_host == last_event.dst_host and
                event.timestamp - last_event.timestamp <= time_window
            )

            if is_continuation:
                current_chain.append(event)
            else:
                # Save chain if significant
                if len(current_chain) >= 2:
                    chains.append(self._analyze_chain(current_chain))
                current_chain = [event]

        # Don't forget last chain
        if len(current_chain) >= 2:
            chains.append(self._analyze_chain(current_chain))

        return chains

    def _analyze_chain(self, chain: list[RemoteExecutionEvent]) -> dict:
        """Analyze a lateral movement chain."""

        hosts_visited = [chain[0].src_host]
        hosts_visited.extend(e.dst_host for e in chain)

        return {
            'chain_length': len(chain),
            'hosts_visited': hosts_visited,
            'users_involved': list(set(e.username for e in chain)),
            'execution_types': list(set(e.execution_type.value for e in chain)),
            'start_time': chain[0].timestamp.isoformat(),
            'end_time': chain[-1].timestamp.isoformat(),
            'duration_seconds': (chain[-1].timestamp - chain[0].timestamp).total_seconds(),
            'risk_level': 'CRITICAL' if len(chain) >= 3 else 'HIGH'
        }

# Detect remote execution
remote_detector = RemoteExecutionDetector()

event = RemoteExecutionEvent(
    timestamp=datetime.now(),
    src_host="WS01",
    dst_host="DC01",
    username="admin",
    execution_type=RemoteExecutionType.PSEXEC,
    command="cmd.exe /c whoami && net user",
    process_name="cmd.exe",
    parent_process="PSEXESVC.exe"
)

analysis = remote_detector.analyze_event(event)
print(f"Risk Level: {analysis['risk_level']}")
print(f"Indicators: {analysis['indicators']}")
```

---

## Task 3: Attack Path Analysis

### Graph-Based Attack Path Detection

```python
import networkx as nx
from typing import Set

class AttackPathAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.high_value_targets = set()

    def add_authentication(self, src: str, dst: str, username: str,
                          timestamp: datetime, success: bool):
        """Add authentication edge to graph."""

        if not self.graph.has_node(src):
            self.graph.add_node(src, type='host')
        if not self.graph.has_node(dst):
            self.graph.add_node(dst, type='host')

        # Add or update edge
        if self.graph.has_edge(src, dst):
            # Update existing edge
            self.graph[src][dst]['count'] += 1
            self.graph[src][dst]['users'].add(username)
            self.graph[src][dst]['last_seen'] = timestamp
        else:
            self.graph.add_edge(
                src, dst,
                count=1,
                users={username},
                first_seen=timestamp,
                last_seen=timestamp,
                success_rate=1.0 if success else 0.0
            )

    def set_high_value_targets(self, targets: Set[str]):
        """Define high-value targets (DCs, databases, etc.)."""
        self.high_value_targets = targets
        for target in targets:
            if self.graph.has_node(target):
                self.graph.nodes[target]['is_hvt'] = True

    def find_attack_paths(self, compromised_host: str,
                         max_hops: int = 5) -> list[dict]:
        """Find potential attack paths from compromised host to HVTs."""

        paths = []

        for target in self.high_value_targets:
            if not self.graph.has_node(target):
                continue

            try:
                # Find all simple paths
                all_paths = nx.all_simple_paths(
                    self.graph, compromised_host, target,
                    cutoff=max_hops
                )

                for path in all_paths:
                    path_info = self._analyze_path(path)
                    paths.append(path_info)

            except nx.NetworkXNoPath:
                continue

        return sorted(paths, key=lambda p: p['risk_score'], reverse=True)

    def _analyze_path(self, path: list[str]) -> dict:
        """Analyze an attack path."""

        hops = []
        total_connections = 0
        unique_users = set()

        for i in range(len(path) - 1):
            src, dst = path[i], path[i+1]
            edge_data = self.graph[src][dst]

            hops.append({
                'from': src,
                'to': dst,
                'connections': edge_data['count'],
                'users': list(edge_data['users'])
            })

            total_connections += edge_data['count']
            unique_users.update(edge_data['users'])

        # Calculate risk score
        risk_score = 50  # Base score for valid path
        risk_score += min(30, total_connections * 2)  # More traffic = higher risk
        risk_score -= len(path) * 5  # Longer paths slightly lower risk

        return {
            'path': path,
            'path_length': len(path) - 1,
            'hops': hops,
            'unique_users': list(unique_users),
            'total_connections': total_connections,
            'risk_score': min(100, max(0, risk_score)),
            'target': path[-1]
        }

    def detect_anomalous_paths(self, baseline_paths: Set[tuple],
                               current_events: list) -> list[dict]:
        """Detect new paths not seen in baseline."""

        new_paths = []

        for event in current_events:
            path_tuple = (event.src_host, event.dst_host)

            if path_tuple not in baseline_paths:
                new_paths.append({
                    'path': path_tuple,
                    'event': event,
                    'reason': 'New connection path not in baseline'
                })

        return new_paths

    def visualize_graph(self, output_file: str = "attack_graph.png"):
        """Generate visualization of attack graph."""
        import matplotlib.pyplot as plt

        pos = nx.spring_layout(self.graph)

        # Color nodes
        colors = []
        for node in self.graph.nodes():
            if node in self.high_value_targets:
                colors.append('red')
            else:
                colors.append('lightblue')

        plt.figure(figsize=(12, 8))
        nx.draw(
            self.graph, pos,
            node_color=colors,
            with_labels=True,
            node_size=500,
            font_size=8,
            arrows=True
        )
        plt.savefig(output_file)
        plt.close()

# Build attack graph
path_analyzer = AttackPathAnalyzer()

# Add authentication events
path_analyzer.add_authentication("WS01", "WS02", "user1", datetime.now(), True)
path_analyzer.add_authentication("WS02", "SRV01", "user1", datetime.now(), True)
path_analyzer.add_authentication("SRV01", "DC01", "admin", datetime.now(), True)

# Set high-value targets
path_analyzer.set_high_value_targets({"DC01", "SQL01", "BACKUP01"})

# Find attack paths
paths = path_analyzer.find_attack_paths("WS01")
for path in paths:
    print(f"Path to {path['target']}: {' -> '.join(path['path'])}")
    print(f"  Risk Score: {path['risk_score']}")
```

---

## Task 4: AI-Powered Analysis

### LLM Integration for Lateral Movement Detection

```python
import anthropic

class AILateralMovementAnalyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def analyze_lateral_movement(self, findings: dict) -> str:
        """AI analysis of lateral movement indicators."""

        prompt = f"""Analyze these lateral movement detection findings:

## Authentication Anomalies
{json.dumps(findings.get('auth_anomalies', []), indent=2, default=str)}

## Remote Execution Events
{json.dumps(findings.get('remote_execution', []), indent=2, default=str)}

## Attack Paths Detected
{json.dumps(findings.get('attack_paths', []), indent=2, default=str)}

Provide:
1. **Attack Assessment** - What type of attack is this?
2. **Attack Stage** - Where in the kill chain?
3. **Threat Actor Assessment** - Sophistication level
4. **Compromised Assets** - List of likely compromised systems
5. **MITRE ATT&CK Techniques** - Relevant technique IDs
6. **Immediate Actions** - What to do right now
7. **Containment Strategy** - How to stop the spread
8. **Evidence to Preserve** - What to collect for forensics"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def generate_containment_plan(self, compromised_hosts: list[str],
                                  attack_paths: list[dict]) -> str:
        """Generate containment plan for lateral movement."""

        prompt = f"""Generate a containment plan for this lateral movement attack:

## Compromised Hosts
{json.dumps(compromised_hosts, indent=2)}

## Active Attack Paths
{json.dumps(attack_paths, indent=2, default=str)}

Create a prioritized containment plan with:
1. **Immediate Isolation** - Hosts to isolate immediately
2. **Network Segmentation** - Firewall rules to implement
3. **Credential Reset** - Accounts to reset
4. **Monitoring Enhancement** - What to watch for
5. **Verification Steps** - How to confirm containment

Format as actionable checklist."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# AI analysis
ai_analyzer = AILateralMovementAnalyzer()

findings = {
    'auth_anomalies': [result],
    'remote_execution': [analysis],
    'attack_paths': paths
}

ai_analysis = ai_analyzer.analyze_lateral_movement(findings)
print(ai_analysis)
```

---

## Task 5: Complete Detection Pipeline

### Integrated Lateral Movement Detection

```python
class LateralMovementDetectionPipeline:
    def __init__(self):
        self.auth_detector = AuthAnomalyDetector()
        self.remote_detector = RemoteExecutionDetector()
        self.path_analyzer = AttackPathAnalyzer()
        self.ai_analyzer = AILateralMovementAnalyzer()

    def analyze(self, auth_events: list[AuthenticationEvent],
                exec_events: list[RemoteExecutionEvent],
                high_value_targets: Set[str]) -> dict:
        """Complete lateral movement analysis."""

        results = {
            'timestamp': datetime.now().isoformat(),
            'findings': {},
            'summary': {}
        }

        # Train/update auth baseline
        self.auth_detector.train(auth_events)

        # Detect auth anomalies
        auth_anomalies = []
        for event in auth_events[-100:]:  # Recent events
            anomaly = self.auth_detector.detect_anomaly(event)
            if anomaly['is_anomaly']:
                auth_anomalies.append(anomaly)
        results['findings']['auth_anomalies'] = auth_anomalies

        # Analyze remote execution
        exec_analysis = []
        for event in exec_events:
            analysis = self.remote_detector.analyze_event(event)
            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                exec_analysis.append(analysis)
        results['findings']['remote_execution'] = exec_analysis

        # Detect lateral chains
        chains = self.remote_detector.detect_lateral_chain(exec_events)
        results['findings']['lateral_chains'] = chains

        # Build and analyze attack graph
        self.path_analyzer.set_high_value_targets(high_value_targets)
        for event in auth_events:
            self.path_analyzer.add_authentication(
                event.src_ip, event.dst_host,
                event.username, event.timestamp, event.success
            )

        # Find paths from anomalous sources
        attack_paths = []
        for anomaly in auth_anomalies:
            paths = self.path_analyzer.find_attack_paths(anomaly['event']['src_ip'])
            attack_paths.extend(paths)
        results['findings']['attack_paths'] = attack_paths

        # Summary
        results['summary'] = {
            'auth_anomalies': len(auth_anomalies),
            'high_risk_executions': len(exec_analysis),
            'lateral_chains': len(chains),
            'attack_paths_to_hvt': len(attack_paths),
            'risk_level': self._calculate_risk(results['findings'])
        }

        return results

    def _calculate_risk(self, findings: dict) -> str:
        score = 0
        if findings['auth_anomalies']:
            score += 20
        if findings['remote_execution']:
            score += 30
        if findings['lateral_chains']:
            score += 40
        if findings['attack_paths']:
            score += 30

        return (
            'CRITICAL' if score >= 70 else
            'HIGH' if score >= 50 else
            'MEDIUM' if score >= 30 else 'LOW'
        )

# Run pipeline
pipeline = LateralMovementDetectionPipeline()
results = pipeline.analyze(
    historical_events + [new_event],
    [event],
    {"DC01", "SQL01"}
)

print(f"Risk Level: {results['summary']['risk_level']}")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Baseline too small | Collect more historical data |
| Too many anomalies | Tune thresholds, add whitelist |
| Missed lateral movement | Add more event sources |
| Graph too large | Prune old edges, use time windows |
| Slow analysis | Use incremental updates |

---

## Next Steps

- Add real-time streaming analysis
- Integrate with EDR for process data
- Build honeypot integration
- Add user behavior analytics (UBA)
- Create automated response playbooks

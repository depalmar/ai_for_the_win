# Lab 15: AI-Powered Lateral Movement Detection

Detect adversary lateral movement techniques using ML and LLMs. Learn to identify credential abuse, remote execution, and network pivoting in enterprise environments.

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand lateral movement TTPs and detection opportunities
2. Build ML models for authentication anomaly detection
3. Detect remote execution techniques (PsExec, WMI, WinRM)
4. Use graph analysis to identify attack paths
5. Apply LLMs for alert triage and investigation

---

## ⏱️ Estimated Time

1.5-2 hours (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 03 (Anomaly Detection), 09 (Detection Pipeline)
- Understanding of Windows authentication (NTLM, Kerberos)
- Familiarity with Active Directory concepts

---

## 📖 Background

### Lateral Movement Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      LATERAL MOVEMENT ATTACK FLOW                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Initial          Credential        Lateral           Target              │
│   Foothold    ──►  Harvesting   ──►  Movement    ──►   Access              │
│                                                                             │
│   ┌─────────┐     ┌─────────────┐   ┌────────────┐   ┌─────────────┐       │
│   │Phishing │     │ Mimikatz    │   │ PsExec     │   │ Domain      │       │
│   │Exploit  │     │ DCSync      │   │ WMI        │   │ Controller  │       │
│   │VPN      │     │ Kerberoast  │   │ WinRM      │   │ File Server │       │
│   └─────────┘     │ LSASS dump  │   │ RDP        │   │ Database    │       │
│                   └─────────────┘   │ SSH        │   └─────────────┘       │
│                                     │ SMB        │                         │
│                                     └────────────┘                         │
│                                                                             │
│   DETECTION OPPORTUNITIES:                                                  │
│   ───────────────────────                                                   │
│   • Unusual authentication patterns                                         │
│   • First-time host access                                                  │
│   • Service account misuse                                                  │
│   • Credential type anomalies                                               │
│   • Process execution chains                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Lateral Movement Techniques

| Technique | ID | Key Indicators |
|-----------|-----|----------------|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | ADMIN$, C$ access |
| Remote Services: RDP | T1021.001 | 3389/tcp, NLA events |
| Windows Remote Management | T1021.006 | 5985/tcp, 5986/tcp |
| Remote Services: SSH | T1021.004 | 22/tcp, key-based auth |
| Lateral Tool Transfer | T1570 | File copies via SMB |
| Pass the Hash | T1550.002 | NTLM auth without password |
| Pass the Ticket | T1550.003 | Kerberos ticket reuse |

### Key Windows Events

| Event ID | Source | Indicator |
|----------|--------|-----------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential use |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket |
| 4776 | Security | NTLM authentication |
| 7045 | System | Service installation |

---

## Tasks

### Task 1: Authentication Anomaly Detection

Build ML models to detect unusual authentication patterns.

```python
# TODO: Implement authentication anomaly detection
class AuthAnomalyDetector:
    def __init__(self):
        self.user_baselines = {}
        self.model = IsolationForest(contamination=0.05)

    def build_user_baseline(self, auth_events: List[dict], user: str) -> dict:
        """
        Build baseline for a user's normal authentication behavior.

        Features:
        - Typical source hosts
        - Typical destination hosts
        - Working hours
        - Authentication types used
        - Success/failure ratios
        """
        pass

    def extract_features(self, event: dict) -> np.ndarray:
        """
        Extract features from authentication event.

        Features:
        - Hour of day (one-hot or cyclical)
        - Is weekend
        - Source host familiarity score
        - Dest host familiarity score
        - Auth type (NTLM=0, Kerberos=1)
        - Is first time src->dst
        - Days since last auth to dest
        - Failed attempts in last hour
        """
        pass

    def score_event(self, event: dict) -> dict:
        """
        Score authentication event for anomaly.

        Returns:
            {
                'event_id': str,
                'user': str,
                'anomaly_score': float,
                'risk_factors': List[str],
                'baseline_comparison': dict
            }
        """
        pass
```

### Task 2: Remote Execution Detection

Detect remote code execution techniques.

```python
# TODO: Implement remote execution detection
class RemoteExecutionDetector:
    def __init__(self):
        self.execution_signatures = self._load_signatures()

    def detect_psexec(self, events: List[dict]) -> List[dict]:
        """
        Detect PsExec-style execution.

        Indicators:
        - Service creation (7045) with PSEXESVC pattern
        - Named pipe creation
        - ADMIN$ access followed by service start
        """
        pass

    def detect_wmi_exec(self, events: List[dict]) -> List[dict]:
        """
        Detect WMI-based remote execution.

        Indicators:
        - WmiPrvSE.exe spawning processes
        - Event 5857, 5860, 5861
        - Remote WMI connections
        """
        pass

    def detect_winrm_exec(self, events: List[dict]) -> List[dict]:
        """
        Detect WinRM/PowerShell remoting.

        Indicators:
        - wsmprovhost.exe process
        - Port 5985/5986 connections
        - Event 4656 with WinRM
        """
        pass

    def detect_dcom_exec(self, events: List[dict]) -> List[dict]:
        """
        Detect DCOM-based execution.

        Indicators:
        - MMC20.Application, ShellWindows, ShellBrowserWindow
        - DCOMLaunch events
        """
        pass

    def correlate_execution_chain(
        self,
        events: List[dict],
        time_window: int = 300
    ) -> List[ExecutionChain]:
        """
        Correlate events into execution chains.

        Links: auth -> file copy -> service install -> process create
        """
        pass
```

### Task 3: Graph-Based Attack Path Analysis

Use graph analysis to detect attack paths.

```python
# TODO: Implement graph-based analysis
class AttackPathAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_auth_graph(self, auth_events: List[dict]) -> nx.DiGraph:
        """
        Build graph of authentication relationships.

        Nodes: Hosts, Users
        Edges: Authentication events with metadata
        """
        for event in auth_events:
            self.graph.add_edge(
                event['source_host'],
                event['dest_host'],
                user=event['user'],
                timestamp=event['timestamp'],
                auth_type=event['auth_type']
            )
        return self.graph

    def detect_pivoting(self, compromised_host: str) -> List[dict]:
        """
        Detect potential pivoting from compromised host.

        Looks for:
        - New outbound authentications after compromise
        - Authentication to sensitive hosts
        - Unusual authentication patterns
        """
        pass

    def find_attack_paths(
        self,
        source: str,
        target: str,
        max_hops: int = 5
    ) -> List[List[str]]:
        """Find potential attack paths from source to target."""
        return list(nx.all_simple_paths(
            self.graph, source, target, cutoff=max_hops
        ))

    def calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for an attack path."""
        pass
```

### Task 4: LLM-Powered Alert Triage

Use LLMs to analyze and prioritize alerts.

```python
# TODO: Implement LLM triage
class LateralMovementTriager:
    def __init__(self, llm_provider: str = "auto"):
        self.llm = setup_llm(provider=llm_provider)

    def triage_alert(self, alert: dict, context: dict) -> dict:
        """
        Use LLM to triage lateral movement alert.

        Args:
            alert: The detection alert
            context: Additional context (user history, host info, etc.)

        Returns:
            Triage result with priority, analysis, and recommendations
        """
        prompt = f"""
        Triage this lateral movement alert:

        ALERT:
        Type: {alert['type']}
        User: {alert['user']}
        Source: {alert['source_host']}
        Destination: {alert['dest_host']}
        Time: {alert['timestamp']}
        Technique: {alert.get('technique', 'Unknown')}

        CONTEXT:
        User Role: {context.get('user_role', 'Unknown')}
        User Department: {context.get('department', 'Unknown')}
        Is Admin: {context.get('is_admin', False)}
        Source Host Type: {context.get('source_type', 'Unknown')}
        Dest Host Type: {context.get('dest_type', 'Unknown')}
        Previous Access History: {context.get('access_history', [])}

        RELATED EVENTS:
        {self._format_related_events(context.get('related_events', []))}

        Analyze and provide:
        1. Priority (Critical/High/Medium/Low)
        2. Likelihood of true positive (0-100%)
        3. Likely attack scenario if malicious
        4. MITRE ATT&CK techniques
        5. Recommended investigation steps
        6. Recommended response actions

        Return as JSON.
        """
        pass

    def investigate_user(self, user: str, events: List[dict]) -> dict:
        """Use LLM to investigate suspicious user activity."""
        pass
```

### Task 5: Detection Pipeline Integration

Build end-to-end detection pipeline.

```python
# TODO: Implement detection pipeline
class LateralMovementPipeline:
    def __init__(self, llm_provider: str = "auto"):
        self.auth_detector = AuthAnomalyDetector()
        self.exec_detector = RemoteExecutionDetector()
        self.path_analyzer = AttackPathAnalyzer()
        self.triager = LateralMovementTriager(llm_provider)

    def process_events(self, events: List[dict]) -> List[Alert]:
        """
        Process security events and detect lateral movement.

        Args:
            events: Stream of Windows security events

        Returns:
            List of prioritized alerts
        """
        alerts = []

        # 1. Authentication anomalies
        auth_events = [e for e in events if e['event_id'] in [4624, 4625, 4648]]
        for event in auth_events:
            score = self.auth_detector.score_event(event)
            if score['anomaly_score'] > 0.7:
                alerts.append(self._create_alert('auth_anomaly', event, score))

        # 2. Remote execution
        exec_events = self.exec_detector.correlate_execution_chain(events)
        for chain in exec_events:
            alerts.append(self._create_alert('remote_exec', chain))

        # 3. Graph analysis
        self.path_analyzer.build_auth_graph(auth_events)
        # Analyze paths to sensitive hosts...

        # 4. LLM triage
        for alert in alerts:
            context = self._gather_context(alert)
            triage = self.triager.triage_alert(alert, context)
            alert['triage'] = triage

        return sorted(alerts, key=lambda a: a['triage']['priority'])
```

---

## Sample Data

The `data/` directory contains:
- `auth_events.json` - Windows authentication events (4624, 4625, etc.)
- `process_events.json` - Process creation events (4688)
- `service_events.json` - Service installation events (7045)
- `lateral_movement_scenario.json` - Full attack scenario with labeled data
- `user_baselines.json` - Normal user authentication baselines

---

## Hints

<details>
<summary>Hint 1: Detecting First-Time Access</summary>

Track historical access patterns to detect first-time access:
```python
def is_first_access(user, src, dst, history):
    key = f"{user}:{src}:{dst}"
    return key not in history
```
</details>

<details>
<summary>Hint 2: Service Account Abuse</summary>

Service accounts should have predictable behavior:
```python
SERVICE_ACCOUNT_PATTERNS = [
    r'^svc[-_]',
    r'[-_]svc$',
    r'^sa[-_]',
]
def is_service_account(user):
    return any(re.match(p, user, re.I) for p in SERVICE_ACCOUNT_PATTERNS)
```
</details>

<details>
<summary>Hint 3: Sensitive Host Detection</summary>

Identify authentication to high-value targets:
```python
SENSITIVE_PATTERNS = [
    r'dc\d*\.',  # Domain controllers
    r'sql',      # Database servers
    r'backup',   # Backup servers
    r'admin',    # Admin workstations
]
```
</details>

---

## Sigma Rules for Lateral Movement

### PsExec Detection

```yaml
title: PsExec Service Installation
status: stable
description: Detects PsExec service installation on target host
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXE'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002
```

### WMI Remote Execution

```yaml
title: Remote WMI Process Creation
status: experimental
description: Detects WMI spawning processes remotely
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\WmiPrvSE.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1047
```

### Pass-the-Hash Detection

```yaml
title: Pass the Hash Activity
status: experimental
description: Detects PtH by monitoring for NTLM auth type 3 logons
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        WorkstationName|not endswith: '$'  # Exclude machine accounts
    filter:
        TargetUserName|endswith: '$'  # Exclude machine accounts
    condition: selection and not filter
level: medium
tags:
    - attack.lateral_movement
    - attack.t1550.002
```

---

## Bonus Challenges

1. **Kerberoasting Detection**: Detect service ticket requests for crackable accounts
2. **DCSync Detection**: Identify replication requests from non-DC hosts
3. **Golden Ticket Detection**: Detect Kerberos tickets with anomalous lifetimes
4. **Real-time Detection**: Implement streaming detection with Kafka/Redis

---

## Resources

- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Windows Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Sigma Rules - Lateral Movement](https://github.com/SigmaHQ/sigma)

---

> **Stuck?** See the [Lab 15 Walkthrough](../../docs/walkthroughs/lab15-lateral-movement-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 16 - AI-Powered Threat Actor Profiling](../lab16-threat-actor-profiling/)
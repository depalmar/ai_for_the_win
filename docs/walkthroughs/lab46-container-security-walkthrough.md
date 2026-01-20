# Lab 46: Container Security Analysis Walkthrough

Step-by-step guide to analyzing container security threats and building detection rules.

## Overview

This walkthrough guides you through:
1. Analyzing container images for vulnerabilities
2. Detecting runtime container attacks
3. Investigating container escape attempts
4. Building detection rules for container threats

**Difficulty:** Intermediate
**Time:** 90-120 minutes
**Prerequisites:** Lab 44-45, Docker/Kubernetes basics

---

## Container Threat Landscape

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| Vulnerable Base Images | Unpatched vulnerabilities | Initial access |
| Misconfigured Containers | Privileged mode, host mounts | Container escape |
| Runtime Attacks | Cryptomining, reverse shells | Resource abuse |
| Kubernetes Misconfig | RBAC issues, exposed APIs | Cluster compromise |

---

## Exercise 1: Image Vulnerability Analysis

### Parse Trivy Scan Results

```python
import json
import pandas as pd
from typing import Dict, List

def parse_trivy_results(scan_file: str) -> pd.DataFrame:
    """Parse Trivy JSON scan results."""
    with open(scan_file) as f:
        data = json.load(f)

    vulnerabilities = []

    for result in data.get('Results', []):
        target = result.get('Target', 'unknown')

        for vuln in result.get('Vulnerabilities', []):
            vulnerabilities.append({
                'target': target,
                'vuln_id': vuln.get('VulnerabilityID'),
                'pkg_name': vuln.get('PkgName'),
                'installed_version': vuln.get('InstalledVersion'),
                'fixed_version': vuln.get('FixedVersion'),
                'severity': vuln.get('Severity'),
                'title': vuln.get('Title'),
                'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score')
            })

    return pd.DataFrame(vulnerabilities)

def calculate_image_risk_score(vulnerabilities_df: pd.DataFrame) -> Dict:
    """Calculate risk score based on vulnerabilities."""
    severity_weights = {
        'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1, 'UNKNOWN': 2
    }

    scores = vulnerabilities_df['severity'].map(severity_weights)
    base_score = scores.sum()

    # Factor in fixable vs unfixable
    fixable = vulnerabilities_df['fixed_version'].notna().sum()
    total = len(vulnerabilities_df)

    # Penalize unfixed critical vulns
    critical_unfixed = vulnerabilities_df[
        (vulnerabilities_df['severity'] == 'CRITICAL') &
        (vulnerabilities_df['fixed_version'].isna())
    ]

    risk_score = base_score
    if len(critical_unfixed) > 0:
        risk_score *= 1.5

    return {
        'total_vulns': total,
        'critical': len(vulnerabilities_df[vulnerabilities_df['severity'] == 'CRITICAL']),
        'high': len(vulnerabilities_df[vulnerabilities_df['severity'] == 'HIGH']),
        'fixable': fixable,
        'risk_score': round(risk_score, 2)
    }
```

---

## Exercise 2: Runtime Attack Detection

### Suspicious Process Detection

```python
from sklearn.ensemble import IsolationForest

SUSPICIOUS_CONTAINER_PROCESSES = [
    'nc', 'ncat', 'netcat',          # Netcat variants
    'nmap', 'masscan',               # Network scanning
    'curl', 'wget',                  # Downloads in runtime
    'gcc', 'make',                   # Compilation tools
    'mount', 'umount',               # Mount operations
    'insmod', 'modprobe',            # Kernel modules
]

def detect_process_anomalies(container_logs_df: pd.DataFrame) -> pd.DataFrame:
    """Detect anomalous processes in containers."""
    profiles = container_logs_df.groupby('container_id').agg({
        'process_name': 'nunique',
        'network_connections': 'sum',
        'file_writes': 'sum'
    }).reset_index()

    features = ['process_name', 'network_connections', 'file_writes']
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    profiles['anomaly_score'] = iso_forest.fit_predict(profiles[features])

    return profiles[profiles['anomaly_score'] == -1]

def flag_suspicious_processes(processes_df: pd.DataFrame) -> pd.DataFrame:
    """Flag known suspicious processes."""
    return processes_df[
        processes_df['process_name'].str.lower().isin(
            [p.lower() for p in SUSPICIOUS_CONTAINER_PROCESSES]
        )
    ]
```

### Container Escape Detection

```python
def detect_container_escape_attempts(events_df: pd.DataFrame) -> tuple:
    """Detect potential container escape attempts."""

    escape_indicators = {
        'privileged_container': events_df['privileged'] == True,
        'docker_socket_mount': events_df['mounts'].str.contains('/var/run/docker.sock', na=False),
        'host_path_mount': events_df['mounts'].str.contains('hostPath', na=False),
        'sys_admin_cap': events_df['capabilities'].str.contains('SYS_ADMIN', na=False),
        'sys_ptrace_cap': events_df['capabilities'].str.contains('SYS_PTRACE', na=False),
        'host_pid': events_df['host_pid'] == True,
        'host_network': events_df['host_network'] == True,
        'cgroup_write': events_df['file_path'].str.contains('/sys/fs/cgroup', na=False),
    }

    events_df['escape_score'] = sum(
        indicator.astype(int) for indicator in escape_indicators.values()
    )

    high_risk = events_df[events_df['escape_score'] >= 2]
    return high_risk, escape_indicators
```

### Cryptomining Detection

```python
def detect_cryptomining(network_df: pd.DataFrame, process_df: pd.DataFrame) -> Dict:
    """Detect cryptomining activity in containers."""

    mining_patterns = [
        r'stratum\+tcp://', r'mining\.pool', r'minexmr\.com',
        r'nanopool\.org', r'2miners\.com', r'f2pool\.com',
    ]

    mining_processes = [
        'xmrig', 'ccminer', 'cgminer', 'bfgminer',
        'minerd', 'cpuminer', 'ethminer'
    ]

    # Check network connections
    network_indicators = network_df[
        network_df['destination'].str.contains('|'.join(mining_patterns), case=False, na=False)
    ]

    # Check processes
    process_indicators = process_df[
        process_df['process_name'].str.lower().isin(mining_processes)
    ]

    # Check for high CPU usage
    high_cpu = process_df[process_df['cpu_percent'] > 80]

    return {
        'network_indicators': network_indicators,
        'process_indicators': process_indicators,
        'high_cpu_containers': high_cpu['container_id'].unique().tolist()
    }
```

---

## Exercise 3: Kubernetes Security Analysis

### Parse Kubernetes Audit Logs

```python
def parse_k8s_audit_logs(audit_log_path: str) -> pd.DataFrame:
    """Parse Kubernetes audit logs."""
    events = []

    with open(audit_log_path) as f:
        for line in f:
            try:
                event = json.loads(line)
                events.append({
                    'timestamp': event.get('requestReceivedTimestamp'),
                    'verb': event.get('verb'),
                    'user': event.get('user', {}).get('username'),
                    'resource': event.get('objectRef', {}).get('resource'),
                    'name': event.get('objectRef', {}).get('name'),
                    'namespace': event.get('objectRef', {}).get('namespace'),
                    'response_code': event.get('responseStatus', {}).get('code'),
                    'source_ip': event.get('sourceIPs', [None])[0],
                })
            except json.JSONDecodeError:
                continue

    return pd.DataFrame(events)

def detect_rbac_violations(audit_df: pd.DataFrame) -> Dict:
    """Detect potential RBAC violations and privilege escalation."""

    # Failed authorization attempts
    auth_failures = audit_df[audit_df['response_code'] == 403]

    # Repeated failures from same user
    repeat_failures = auth_failures.groupby('user').size()
    suspicious_users = repeat_failures[repeat_failures > 5]

    # Sensitive resource access
    sensitive_resources = ['secrets', 'configmaps', 'serviceaccounts', 'clusterroles']
    sensitive_access = audit_df[
        (audit_df['resource'].isin(sensitive_resources)) &
        (audit_df['verb'].isin(['create', 'update', 'patch', 'delete']))
    ]

    # Privilege escalation attempts
    priv_esc = audit_df[
        (audit_df['resource'].isin(['clusterroles', 'clusterrolebindings'])) &
        (audit_df['verb'].isin(['create', 'update', 'patch']))
    ]

    return {
        'auth_failures': auth_failures,
        'suspicious_users': suspicious_users.to_dict(),
        'sensitive_access': sensitive_access,
        'privilege_escalation': priv_esc
    }
```

---

## Exercise 4: Falco Detection Rules

### Custom Falco Rules

```yaml
# Container escape via Docker socket
- rule: Container Escape via Docker Socket
  desc: Detect container accessing Docker socket
  condition: >
    container and
    (fd.name startswith /var/run/docker.sock)
  output: >
    Container accessing Docker socket
    (container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape]

# Reverse shell detection
- rule: Reverse Shell in Container
  desc: Detect reverse shell execution
  condition: >
    container and spawned_process and
    (proc.name in (nc, ncat, netcat) and proc.args contains "-e")
  output: >
    Reverse shell detected (container=%container.name command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, network, shell]

# Cryptominer detection
- rule: Cryptocurrency Miner Started
  desc: Detect cryptocurrency mining software
  condition: >
    container and spawned_process and
    (proc.name in (xmrig, ccminer, minerd, cpuminer))
  output: >
    Cryptominer detected (container=%container.name command=%proc.cmdline)
  priority: HIGH
  tags: [container, cryptomining]
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           CONTAINER SECURITY REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Images Scanned: 47
Containers Monitored: 156

━━━━━ IMAGE VULNERABILITIES ━━━━━
🔴 CRITICAL: nginx:1.19 - 3 critical CVEs
   CVE-2021-23017 (CVSS 9.8) - Fix available

🟠 HIGH: redis:6.0 - 5 high CVEs
   Risk Score: 78.5

━━━━━ RUNTIME ALERTS ━━━━━
🔴 CRITICAL: Container escape attempt
   Container: app-backend-7d4f8
   Indicator: Docker socket mount detected

🔴 CRITICAL: Cryptominer detected
   Container: data-processor-2c8a1
   Process: xmrig (CPU: 98%)

━━━━━ KUBERNETES RBAC ━━━━━
🟠 HIGH: Privilege escalation attempt
   User: service-account-compromised
   Action: ClusterRole creation attempted

━━━━━ RECOMMENDATIONS ━━━━━
1. Update nginx:1.19 to fix critical CVEs
2. Isolate container app-backend-7d4f8
3. Terminate cryptominer and investigate source
```

---

## Resources

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Falco Documentation](https://falco.org/docs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

---

*Next: Lab 47 - Serverless Security Walkthrough*

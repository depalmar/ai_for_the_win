# Lab 46: Container Security Analysis

## Overview

Analyze container security threats including image vulnerabilities, runtime attacks, container escapes, and Kubernetes-specific threats.

**Difficulty**: Intermediate
**Duration**: 90-120 minutes
**Prerequisites**: Lab 45 (Cloud Fundamentals), basic Docker/Kubernetes knowledge

## Learning Objectives

By the end of this lab, you will be able to:
1. Analyze container images for vulnerabilities and misconfigurations
2. Detect runtime container attacks and anomalies
3. Investigate container escape attempts
4. Analyze Kubernetes audit logs for security events
5. Build detection rules for container-based threats

## Background

### Container Threat Landscape

Containers introduce unique security challenges:

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| Vulnerable Base Images | Unpatched OS/application vulnerabilities | Initial access, privilege escalation |
| Misconfigured Containers | Privileged mode, host mounts | Container escape |
| Supply Chain Attacks | Compromised images in registries | Backdoor deployment |
| Runtime Attacks | Cryptomining, reverse shells | Resource abuse, data theft |
| Kubernetes Misconfig | RBAC issues, exposed APIs | Cluster compromise |

### Key Data Sources

| Source | What It Contains |
|--------|------------------|
| Container Runtime Logs | Process execution, file access, network |
| Kubernetes Audit Logs | API server requests, RBAC decisions |
| Image Scan Results | CVE findings, misconfigurations |
| Network Flow Logs | Container-to-container, egress traffic |
| Falco/Runtime Security | Real-time behavioral alerts |

## Part 1: Image Vulnerability Analysis

### Exercise 1.1: Parsing Trivy Scan Results

```python
import json
import pandas as pd
from collections import defaultdict

def parse_trivy_results(scan_file):
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

# Example usage
# df_vulns = parse_trivy_results('scan_results.json')
```

### Exercise 1.2: Risk Scoring for Images

```python
def calculate_image_risk_score(vulnerabilities_df):
    """Calculate risk score based on vulnerabilities."""
    severity_weights = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 1,
        'UNKNOWN': 2
    }

    # Base score from vulnerability counts
    scores = vulnerabilities_df['severity'].map(severity_weights)
    base_score = scores.sum()

    # Factor in fixable vs unfixable
    fixable = vulnerabilities_df['fixed_version'].notna().sum()
    total = len(vulnerabilities_df)
    fixable_ratio = fixable / total if total > 0 else 1.0

    # Penalize images with unfixed critical vulns
    critical_unfixed = vulnerabilities_df[
        (vulnerabilities_df['severity'] == 'CRITICAL') &
        (vulnerabilities_df['fixed_version'].isna())
    ]

    risk_score = base_score * (2 - fixable_ratio)
    if len(critical_unfixed) > 0:
        risk_score *= 1.5  # 50% penalty for unfixed criticals

    return {
        'total_vulns': total,
        'critical': len(vulnerabilities_df[vulnerabilities_df['severity'] == 'CRITICAL']),
        'high': len(vulnerabilities_df[vulnerabilities_df['severity'] == 'HIGH']),
        'fixable': fixable,
        'risk_score': round(risk_score, 2)
    }
```

### Exercise 1.3: Supply Chain Analysis

```python
def analyze_image_layers(image_history):
    """Analyze image build layers for suspicious patterns."""
    suspicious_patterns = [
        r'curl.*\|.*sh',           # Piping curl to shell
        r'wget.*\|.*bash',         # Piping wget to bash
        r'chmod\s+777',            # World-writable permissions
        r'--allow-root',           # Running as root
        r'PASSWORD|SECRET|KEY',    # Hardcoded secrets
        r'apt-get.*--force-yes',   # Bypassing package verification
    ]

    findings = []
    for idx, layer in enumerate(image_history):
        command = layer.get('CreatedBy', '')

        for pattern in suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                findings.append({
                    'layer': idx,
                    'pattern': pattern,
                    'command': command[:200],
                    'risk': 'high' if 'SECRET' in pattern else 'medium'
                })

    return findings
```

## Part 2: Runtime Attack Detection

### Exercise 2.1: Container Process Anomaly Detection

```python
import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_process_anomalies(container_logs_df):
    """Detect anomalous processes in containers."""

    # Create process execution profile per container
    profiles = container_logs_df.groupby('container_id').agg({
        'process_name': 'nunique',
        'process_count': 'sum',
        'unique_parents': 'nunique',
        'network_connections': 'sum',
        'file_writes': 'sum'
    }).reset_index()

    # Fit isolation forest
    features = ['process_name', 'process_count', 'unique_parents',
                'network_connections', 'file_writes']

    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    profiles['anomaly_score'] = iso_forest.fit_predict(profiles[features])

    # Anomalies have score -1
    anomalies = profiles[profiles['anomaly_score'] == -1]

    return anomalies

# Suspicious process patterns for containers
SUSPICIOUS_CONTAINER_PROCESSES = [
    'nc', 'ncat', 'netcat',          # Netcat variants
    'nmap', 'masscan',               # Network scanning
    'tcpdump', 'wireshark',          # Packet capture
    'curl', 'wget',                  # Download tools (in runtime)
    'python', 'perl', 'ruby',        # Scripting (if not expected)
    'gcc', 'make', 'ld',             # Compilation tools
    'mount', 'umount',               # Mount operations
    'insmod', 'modprobe',            # Kernel module loading
]

def flag_suspicious_processes(processes_df):
    """Flag known suspicious processes."""
    return processes_df[
        processes_df['process_name'].str.lower().isin(
            [p.lower() for p in SUSPICIOUS_CONTAINER_PROCESSES]
        )
    ]
```

### Exercise 2.2: Container Escape Detection

```python
def detect_container_escape_attempts(events_df):
    """Detect potential container escape attempts."""

    escape_indicators = {
        # Privileged operations
        'privileged_container': events_df['privileged'] == True,

        # Sensitive mounts
        'docker_socket_mount': events_df['mounts'].str.contains(
            '/var/run/docker.sock', na=False
        ),
        'host_path_mount': events_df['mounts'].str.contains(
            'hostPath', na=False
        ),
        'proc_mount': events_df['mounts'].str.contains(
            '/proc', na=False
        ),

        # Capability abuse
        'sys_admin_cap': events_df['capabilities'].str.contains(
            'SYS_ADMIN', na=False
        ),
        'sys_ptrace_cap': events_df['capabilities'].str.contains(
            'SYS_PTRACE', na=False
        ),

        # Namespace manipulation
        'host_pid': events_df['host_pid'] == True,
        'host_network': events_df['host_network'] == True,

        # Process injection
        'ptrace_attach': events_df['syscall'] == 'ptrace',

        # cgroup escape
        'cgroup_write': events_df['file_path'].str.contains(
            '/sys/fs/cgroup', na=False
        ) & (events_df['operation'] == 'write')
    }

    # Score each event
    events_df['escape_score'] = sum(
        indicator.astype(int) for indicator in escape_indicators.values()
    )

    # Flag high-risk events
    high_risk = events_df[events_df['escape_score'] >= 2]

    return high_risk, escape_indicators
```

### Exercise 2.3: Cryptomining Detection

```python
def detect_cryptomining(network_df, process_df):
    """Detect cryptomining activity in containers."""

    # Known mining pool patterns
    mining_patterns = [
        r'stratum\+tcp://',
        r'mining\.pool',
        r'minexmr\.com',
        r'nanopool\.org',
        r'2miners\.com',
        r'f2pool\.com',
        r'pool\.supportxmr',
    ]

    # Mining-related process names
    mining_processes = [
        'xmrig', 'ccminer', 'cgminer', 'bfgminer',
        'minerd', 'cpuminer', 'ethminer', 'phoenixminer'
    ]

    # Check network connections
    network_indicators = network_df[
        network_df['destination'].str.contains(
            '|'.join(mining_patterns),
            case=False,
            na=False
        )
    ]

    # Check processes
    process_indicators = process_df[
        process_df['process_name'].str.lower().isin(mining_processes)
    ]

    # Check for high CPU usage pattern
    high_cpu = process_df[process_df['cpu_percent'] > 80]
    sustained_high_cpu = high_cpu.groupby('container_id').filter(
        lambda x: len(x) > 10  # Sustained over multiple samples
    )

    return {
        'network_indicators': network_indicators,
        'process_indicators': process_indicators,
        'high_cpu_containers': sustained_high_cpu['container_id'].unique()
    }
```

## Part 3: Kubernetes Security Analysis

### Exercise 3.1: Parsing Kubernetes Audit Logs

```python
def parse_k8s_audit_logs(audit_log_path):
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
                    'groups': event.get('user', {}).get('groups', []),
                    'resource': event.get('objectRef', {}).get('resource'),
                    'name': event.get('objectRef', {}).get('name'),
                    'namespace': event.get('objectRef', {}).get('namespace'),
                    'response_code': event.get('responseStatus', {}).get('code'),
                    'source_ip': event.get('sourceIPs', [None])[0],
                    'user_agent': event.get('userAgent'),
                    'stage': event.get('stage'),
                })
            except json.JSONDecodeError:
                continue

    return pd.DataFrame(events)
```

### Exercise 3.2: RBAC Violation Detection

```python
def detect_rbac_violations(audit_df):
    """Detect potential RBAC violations and privilege escalation."""

    # Failed authorization attempts
    auth_failures = audit_df[audit_df['response_code'] == 403]

    # Repeated failures from same user
    repeat_failures = auth_failures.groupby('user').size()
    suspicious_users = repeat_failures[repeat_failures > 5]

    # Sensitive resource access
    sensitive_resources = ['secrets', 'configmaps', 'serviceaccounts',
                          'clusterroles', 'clusterrolebindings']

    sensitive_access = audit_df[
        (audit_df['resource'].isin(sensitive_resources)) &
        (audit_df['verb'].isin(['create', 'update', 'patch', 'delete']))
    ]

    # Service account token access
    token_access = audit_df[
        (audit_df['resource'] == 'secrets') &
        (audit_df['name'].str.contains('token', na=False))
    ]

    # Privilege escalation attempts
    priv_esc = audit_df[
        (audit_df['resource'].isin(['clusterroles', 'clusterrolebindings', 'roles', 'rolebindings'])) &
        (audit_df['verb'].isin(['create', 'update', 'patch']))
    ]

    return {
        'auth_failures': auth_failures,
        'suspicious_users': suspicious_users.to_dict(),
        'sensitive_access': sensitive_access,
        'token_access': token_access,
        'privilege_escalation': priv_esc
    }
```

### Exercise 3.3: Detecting Malicious Workloads

```python
def analyze_pod_security(pods_df):
    """Analyze pods for security issues."""

    security_issues = []

    for _, pod in pods_df.iterrows():
        issues = []

        # Check for privileged containers
        if pod.get('privileged'):
            issues.append({
                'severity': 'CRITICAL',
                'issue': 'Privileged container',
                'risk': 'Full host access'
            })

        # Check for host namespaces
        if pod.get('host_network'):
            issues.append({
                'severity': 'HIGH',
                'issue': 'Host network enabled',
                'risk': 'Network sniffing, bypass network policies'
            })

        if pod.get('host_pid'):
            issues.append({
                'severity': 'HIGH',
                'issue': 'Host PID namespace',
                'risk': 'Process visibility and manipulation'
            })

        # Check for dangerous capabilities
        dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE',
                         'NET_RAW', 'SYS_MODULE']
        for cap in dangerous_caps:
            if cap in pod.get('capabilities', []):
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Dangerous capability: {cap}',
                    'risk': f'Capability abuse for {cap}'
                })

        # Check for writable root filesystem
        if not pod.get('read_only_root_fs'):
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Writable root filesystem',
                'risk': 'Persistence, malware installation'
            })

        # Check for running as root
        if pod.get('run_as_root', True):  # Default is root
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Running as root',
                'risk': 'Increased attack surface'
            })

        if issues:
            security_issues.append({
                'pod_name': pod['name'],
                'namespace': pod['namespace'],
                'issues': issues,
                'total_issues': len(issues),
                'max_severity': max(i['severity'] for i in issues)
            })

    return security_issues
```

## Part 4: Building Container Detection Rules

### Exercise 4.1: Falco Rules for Container Threats

```yaml
# Custom Falco rules for container security

- rule: Container Escape via Docker Socket
  desc: Detect container accessing Docker socket
  condition: >
    container and
    (fd.name startswith /var/run/docker.sock or
     fd.name startswith /run/docker.sock)
  output: >
    Container accessing Docker socket
    (user=%user.name container=%container.name
     image=%container.image.repository command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape]

- rule: Reverse Shell in Container
  desc: Detect reverse shell execution in container
  condition: >
    container and
    spawned_process and
    ((proc.name in (nc, ncat, netcat) and
      proc.args contains "-e") or
     (proc.name = bash and
      fd.type = ipv4 and
      fd.l4proto = tcp))
  output: >
    Reverse shell detected in container
    (user=%user.name container=%container.name command=%proc.cmdline
     connection=%fd.name)
  priority: CRITICAL
  tags: [container, network, shell]

- rule: Cryptocurrency Miner Started
  desc: Detect cryptocurrency mining software
  condition: >
    container and
    spawned_process and
    (proc.name in (xmrig, ccminer, minerd, cpuminer) or
     proc.args contains "stratum+tcp")
  output: >
    Cryptominer detected (container=%container.name
     image=%container.image.repository command=%proc.cmdline)
  priority: HIGH
  tags: [container, cryptomining]

- rule: Sensitive File Access in Container
  desc: Detect access to sensitive files
  condition: >
    container and
    open_read and
    (fd.name startswith /etc/shadow or
     fd.name startswith /etc/passwd or
     fd.name startswith /proc/1/ or
     fd.name contains /.ssh/)
  output: >
    Sensitive file access in container
    (file=%fd.name container=%container.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, filesystem]
```

## Part 5: Incident Response Scenario

### Scenario: Compromised Container Investigation

Your Kubernetes cluster has triggered alerts for unusual activity. Investigate the incident.

#### Step 1: Initial Triage

```python
def investigate_container_incident(container_id, timeframe_hours=24):
    """Initial triage for container incident."""

    investigation = {
        'container_id': container_id,
        'timestamp': datetime.now().isoformat(),
        'findings': []
    }

    # Get container metadata
    container_info = get_container_info(container_id)
    investigation['container_info'] = container_info

    # Check process history
    processes = get_container_processes(container_id, timeframe_hours)
    suspicious = flag_suspicious_processes(processes)
    if len(suspicious) > 0:
        investigation['findings'].append({
            'type': 'suspicious_processes',
            'count': len(suspicious),
            'details': suspicious.to_dict('records')
        })

    # Check network connections
    network = get_container_network(container_id, timeframe_hours)
    external = network[~network['destination'].str.startswith('10.')]
    investigation['findings'].append({
        'type': 'external_connections',
        'count': len(external),
        'destinations': external['destination'].unique().tolist()
    })

    # Check file modifications
    files = get_container_file_changes(container_id, timeframe_hours)
    sensitive_paths = ['/etc/', '/root/', '/bin/', '/usr/bin/']
    sensitive_changes = files[
        files['path'].apply(lambda p: any(p.startswith(sp) for sp in sensitive_paths))
    ]
    if len(sensitive_changes) > 0:
        investigation['findings'].append({
            'type': 'sensitive_file_changes',
            'count': len(sensitive_changes),
            'files': sensitive_changes['path'].tolist()
        })

    return investigation
```

#### Step 2: Build Investigation Timeline

```python
def build_container_timeline(container_id, events_df):
    """Build investigation timeline for container."""

    timeline = events_df[
        events_df['container_id'] == container_id
    ].sort_values('timestamp')

    # Enrich with threat context
    timeline['threat_indicator'] = timeline.apply(
        lambda row: classify_event_threat(row), axis=1
    )

    # Identify key events
    timeline['is_key_event'] = (
        (timeline['threat_indicator'] != 'benign') |
        (timeline['event_type'].isin(['process_start', 'network_connect', 'file_write']))
    )

    key_events = timeline[timeline['is_key_event']]

    return key_events[[
        'timestamp', 'event_type', 'details',
        'threat_indicator', 'source'
    ]]
```

## Exercises

### Exercise 1: Image Analysis
Analyze the provided container image scan results:
1. Calculate the risk score
2. Identify exploitable vulnerabilities
3. Recommend remediation priorities

### Exercise 2: Runtime Detection
Using the provided container logs:
1. Identify any cryptomining activity
2. Detect container escape attempts
3. Build a behavioral baseline

### Exercise 3: Kubernetes Audit Analysis
Analyze the audit logs to:
1. Find RBAC violations
2. Identify suspicious service account usage
3. Detect privilege escalation attempts

### Exercise 4: Detection Engineering
Write detection rules for:
1. Container using host network namespace
2. Kubectl exec into sensitive namespaces
3. Secret enumeration attempts

## Challenge Questions

1. How would you detect a container that has been compromised through a vulnerable base image?
2. What are the limitations of container runtime security tools?
3. How can attackers evade container escape detection?
4. Design a detection strategy for supply chain attacks through container images.

## Resources

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Falco Documentation](https://falco.org/docs/)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

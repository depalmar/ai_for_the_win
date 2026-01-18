# Lab 47: Serverless Security Analysis Walkthrough

Step-by-step guide to analyzing security threats in serverless environments.

## Overview

This walkthrough guides you through:
1. Analyzing serverless function logs for security events
2. Detecting event injection and data poisoning
3. Investigating IAM permission misconfigurations
4. Building detection rules for serverless threats

**Difficulty:** Intermediate
**Time:** 90-120 minutes
**Prerequisites:** Lab 44, Lab 46, serverless basics

---

## Serverless Threat Landscape

| Threat Vector | Description | Example |
|--------------|-------------|---------|
| Event Injection | Malicious payloads in triggers | SQLi in API Gateway events |
| Permission Creep | Over-privileged function roles | Function with admin access |
| Dependency Attacks | Vulnerable packages | Compromised npm packages |
| Data Exposure | Secrets in env variables | Hardcoded API keys |
| Cold Start Attacks | Exploiting initialization | Race conditions |

---

## Exercise 1: Function Log Analysis

### Parse Lambda Logs

```python
import json
import re
import pandas as pd
from datetime import datetime
from typing import Dict, List

def parse_lambda_logs(log_events: List[Dict]) -> pd.DataFrame:
    """Parse CloudWatch logs from Lambda functions."""
    parsed = []

    for event in log_events:
        message = event.get('message', '')
        timestamp = datetime.fromtimestamp(event.get('timestamp', 0) / 1000)

        log_entry = {
            'timestamp': timestamp,
            'raw_message': message,
            'log_type': classify_log_type(message)
        }

        # Extract request ID
        request_id_match = re.search(r'RequestId:\s*([a-f0-9-]+)', message)
        if request_id_match:
            log_entry['request_id'] = request_id_match.group(1)

        # Parse START/END/REPORT lines
        if message.startswith('START'):
            log_entry['event'] = 'invocation_start'
        elif message.startswith('END'):
            log_entry['event'] = 'invocation_end'
        elif message.startswith('REPORT'):
            log_entry['event'] = 'invocation_report'
            log_entry.update(parse_report_line(message))
        else:
            log_entry['event'] = 'application_log'

        parsed.append(log_entry)

    return pd.DataFrame(parsed)

def parse_report_line(message: str) -> Dict:
    """Extract metrics from REPORT line."""
    metrics = {}
    patterns = {
        'duration': r'Duration:\s*([\d.]+)\s*ms',
        'billed_duration': r'Billed Duration:\s*(\d+)\s*ms',
        'memory_size': r'Memory Size:\s*(\d+)\s*MB',
        'memory_used': r'Max Memory Used:\s*(\d+)\s*MB',
        'init_duration': r'Init Duration:\s*([\d.]+)\s*ms'
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, message)
        if match:
            metrics[key] = float(match.group(1))

    return metrics

def classify_log_type(message: str) -> str:
    """Classify log message type."""
    if message.startswith(('START', 'END', 'REPORT')):
        return 'platform'
    elif 'ERROR' in message or 'Exception' in message:
        return 'error'
    return 'application'
```

### Detect Invocation Anomalies

```python
from sklearn.ensemble import IsolationForest
import numpy as np

def detect_invocation_anomalies(logs_df: pd.DataFrame) -> pd.DataFrame:
    """Detect anomalous function invocations."""
    logs_df['hour'] = logs_df['timestamp'].dt.floor('H')

    hourly_stats = logs_df[logs_df['event'] == 'invocation_report'].groupby('hour').agg({
        'duration': ['mean', 'std', 'max'],
        'memory_used': ['mean', 'max'],
        'request_id': 'count'
    }).reset_index()

    hourly_stats.columns = [
        'hour', 'duration_mean', 'duration_std', 'duration_max',
        'memory_mean', 'memory_max', 'invocation_count'
    ]

    features = ['duration_mean', 'duration_max', 'memory_mean', 'invocation_count']
    iso = IsolationForest(contamination=0.05, random_state=42)
    hourly_stats['anomaly'] = iso.fit_predict(hourly_stats[features].fillna(0))

    return hourly_stats[hourly_stats['anomaly'] == -1]
```

---

## Exercise 2: Event Injection Detection

### Input Validation Analysis

```python
def analyze_event_payloads(events_df: pd.DataFrame) -> pd.DataFrame:
    """Analyze incoming events for injection patterns."""

    injection_patterns = {
        'sql_injection': [
            r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\b(FROM|INTO)\b)",
            r"(?i)('\s*(OR|AND)\s*'?\d+'\s*=\s*'?\d+)",
        ],
        'command_injection': [
            r"[;&|`$]",
            r"(?i)\$\(.*\)",
            r"(?i)\b(cat|ls|whoami|curl)\b\s",
        ],
        'path_traversal': [
            r"\.\./",
            r"\.\.\\",
        ],
        'ssrf': [
            r"(?i)(localhost|127\.0\.0\.1)",
            r"(?i)169\.254\.169\.254",  # AWS metadata
        ]
    }

    findings = []

    for _, event in events_df.iterrows():
        payload = json.dumps(event.get('body', {}))

        for attack_type, patterns in injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload):
                    findings.append({
                        'timestamp': event.get('timestamp'),
                        'request_id': event.get('request_id'),
                        'attack_type': attack_type,
                        'pattern': pattern,
                        'payload_preview': payload[:200]
                    })
                    break

    return pd.DataFrame(findings)

def detect_enumeration_attempts(logs_df: pd.DataFrame,
                                window_minutes: int = 5,
                                threshold: int = 20) -> pd.DataFrame:
    """Detect path/parameter enumeration attempts."""
    logs_df['window'] = logs_df['timestamp'].dt.floor(f'{window_minutes}T')

    grouped = logs_df.groupby(['source_ip', 'window']).agg({
        'path': 'nunique',
        'request_id': 'count',
        'status': lambda x: (x == 404).sum()
    }).reset_index()

    grouped.columns = ['source_ip', 'window', 'unique_paths', 'request_count', '404_count']

    enumeration = grouped[
        (grouped['unique_paths'] > threshold) |
        (grouped['404_count'] > threshold)
    ]

    return enumeration
```

---

## Exercise 3: Permission Analysis

### Function Role Analysis

```python
def analyze_function_permissions(functions_df: pd.DataFrame,
                                 roles_df: pd.DataFrame) -> pd.DataFrame:
    """Analyze Lambda function IAM role permissions."""

    sensitive_permissions = {
        'critical': ['iam:*', '*:*', 'sts:AssumeRole', 'kms:Decrypt'],
        'high': ['s3:*', 'dynamodb:*', 'secretsmanager:GetSecretValue', 'lambda:InvokeFunction'],
        'medium': ['s3:GetObject', 's3:PutObject', 'logs:*']
    }

    findings = []

    for _, func in functions_df.iterrows():
        role_name = func['role_name']
        role = roles_df[roles_df['role_name'] == role_name]

        if role.empty:
            continue

        policies = role.iloc[0].get('policies', [])

        func_findings = {
            'function_name': func['function_name'],
            'role_name': role_name,
            'critical_permissions': [],
            'high_permissions': [],
            'is_overprivileged': False
        }

        for policy in policies:
            for statement in policy.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    for severity, patterns in sensitive_permissions.items():
                        if any(re.match(p.replace('*', '.*'), action) for p in patterns):
                            func_findings[f'{severity}_permissions'].append(action)

        if func_findings['critical_permissions'] or len(func_findings['high_permissions']) > 5:
            func_findings['is_overprivileged'] = True

        findings.append(func_findings)

    return pd.DataFrame(findings)
```

### Secret Access Monitoring

```python
def monitor_secret_access(cloudtrail_df: pd.DataFrame,
                          function_names: List[str]) -> pd.DataFrame:
    """Monitor how functions access secrets."""

    secret_access_events = [
        'GetSecretValue', 'GetParameter', 'GetParameters', 'Decrypt'
    ]

    secret_events = cloudtrail_df[
        cloudtrail_df['event_name'].isin(secret_access_events)
    ]

    function_secret_access = []

    for func_name in function_names:
        func_events = secret_events[
            secret_events['userIdentity'].apply(lambda x: func_name in str(x))
        ]

        if not func_events.empty:
            secrets_accessed = func_events.apply(
                lambda x: x.get('requestParameters', {}).get('name') or
                         x.get('requestParameters', {}).get('secretId'),
                axis=1
            ).dropna().unique()

            function_secret_access.append({
                'function_name': func_name,
                'secrets_accessed': list(secrets_accessed),
                'access_count': len(func_events)
            })

    return pd.DataFrame(function_secret_access)
```

---

## Exercise 4: Detection Rules

### Event Poisoning Detection

```python
def detect_event_poisoning(events_df: pd.DataFrame,
                           baseline_schema: Dict) -> pd.DataFrame:
    """Detect event poisoning attempts."""

    poisoning_indicators = []

    for _, event in events_df.iterrows():
        payload = event.get('body', {})
        indicators = []

        # Check for unexpected fields
        expected_fields = set(baseline_schema.get('expected_fields', []))
        actual_fields = set(payload.keys()) if isinstance(payload, dict) else set()
        unexpected = actual_fields - expected_fields

        if unexpected:
            indicators.append({'type': 'unexpected_fields', 'fields': list(unexpected)})

        # Check for type mismatches
        for field, expected_type in baseline_schema.get('field_types', {}).items():
            if field in payload:
                actual_type = type(payload[field]).__name__
                if actual_type != expected_type:
                    indicators.append({
                        'type': 'type_mismatch',
                        'field': field,
                        'expected': expected_type,
                        'actual': actual_type
                    })

        if indicators:
            poisoning_indicators.append({
                'timestamp': event.get('timestamp'),
                'request_id': event.get('request_id'),
                'indicators': indicators
            })

    return pd.DataFrame(poisoning_indicators)
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           SERVERLESS SECURITY REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Functions Monitored: 23
Invocations Analyzed: 45,231

━━━━━ EVENT INJECTION ━━━━━
🔴 CRITICAL: SQL injection detected
   Function: api-handler
   Pattern: SELECT * FROM users WHERE...
   Source IP: 1.2.3.4

🟠 HIGH: SSRF attempt detected
   Function: data-fetcher
   Target: 169.254.169.254 (AWS metadata)

━━━━━ PERMISSIONS ━━━━━
🔴 CRITICAL: Overprivileged function
   Function: admin-utility
   Permissions: iam:*, s3:*, dynamodb:*
   Risk: Full admin access

━━━━━ ANOMALIES ━━━━━
🟠 HIGH: Cold start spike detected
   Function: api-handler
   Rate: 85% (normal: 12%)
   Possible: Function probing

━━━━━ RECOMMENDATIONS ━━━━━
1. Apply input validation to api-handler
2. Restrict admin-utility permissions
3. Investigate cold start anomaly
```

---

## Resources

- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [Azure Functions Security](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts)

---

*Next: Lab 48 - Cloud IR Automation Walkthrough*

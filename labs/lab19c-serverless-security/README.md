# Lab 19c: Serverless Security Analysis

## Overview

Analyze security threats unique to serverless environments including function vulnerabilities, event injection, permission misconfigurations, and cold start attacks.

**Difficulty**: Intermediate
**Duration**: 90-120 minutes
**Prerequisites**: Lab 19 (Cloud Fundamentals), basic serverless knowledge

## Learning Objectives

By the end of this lab, you will be able to:
1. Analyze serverless function logs for security events
2. Detect event injection and data poisoning attacks
3. Investigate IAM permission misconfigurations
4. Identify cold start exploitation attempts
5. Build detection rules for serverless-specific threats

## Background

### Serverless Threat Landscape

Serverless introduces unique security challenges:

| Threat Vector | Description | Example |
|--------------|-------------|---------|
| Event Injection | Malicious payloads in triggers | SQLi in API Gateway events |
| Permission Creep | Over-privileged function roles | Function with admin access |
| Dependency Attacks | Vulnerable packages in functions | Compromised npm packages |
| Data Exposure | Secrets in environment variables | Hardcoded API keys |
| Cold Start Attacks | Exploiting initialization phase | Race conditions |
| Invocation Abuse | Unauthorized function execution | Exposed function URLs |

### Key Data Sources

| Source | What It Captures |
|--------|------------------|
| CloudWatch/Cloud Logging | Function invocations, errors |
| CloudTrail/Activity Logs | API calls, IAM events |
| X-Ray/Tracing | Request flows, latencies |
| VPC Flow Logs | Network traffic (if VPC-enabled) |
| Application Logs | Custom function logging |

## Part 1: Function Log Analysis

### Exercise 1.1: Parsing Lambda Logs

```python
import json
import re
import pandas as pd
from datetime import datetime

def parse_lambda_logs(log_events):
    """Parse CloudWatch logs from Lambda functions."""
    parsed = []

    for event in log_events:
        message = event.get('message', '')
        timestamp = datetime.fromtimestamp(
            event.get('timestamp', 0) / 1000
        )

        # Parse different log types
        log_entry = {
            'timestamp': timestamp,
            'raw_message': message,
            'log_type': classify_log_type(message)
        }

        # Extract request ID
        request_id_match = re.search(
            r'RequestId:\s*([a-f0-9-]+)',
            message
        )
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

def parse_report_line(message):
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

def classify_log_type(message):
    """Classify log message type."""
    if message.startswith(('START', 'END', 'REPORT')):
        return 'platform'
    elif re.match(r'\d{4}-\d{2}-\d{2}', message):
        return 'application'
    elif 'ERROR' in message or 'Exception' in message:
        return 'error'
    else:
        return 'other'
```

### Exercise 1.2: Detecting Invocation Anomalies

```python
from sklearn.ensemble import IsolationForest
import numpy as np

def detect_invocation_anomalies(logs_df):
    """Detect anomalous function invocations."""

    # Aggregate metrics per time window
    logs_df['hour'] = logs_df['timestamp'].dt.floor('H')

    hourly_stats = logs_df[logs_df['event'] == 'invocation_report'].groupby(
        'hour'
    ).agg({
        'duration': ['mean', 'std', 'max'],
        'memory_used': ['mean', 'max'],
        'request_id': 'count'
    }).reset_index()

    hourly_stats.columns = [
        'hour', 'duration_mean', 'duration_std', 'duration_max',
        'memory_mean', 'memory_max', 'invocation_count'
    ]

    # Prepare features
    features = hourly_stats[[
        'duration_mean', 'duration_max',
        'memory_mean', 'invocation_count'
    ]].fillna(0)

    # Detect anomalies
    iso = IsolationForest(contamination=0.05, random_state=42)
    hourly_stats['anomaly'] = iso.fit_predict(features)

    anomalies = hourly_stats[hourly_stats['anomaly'] == -1]

    return anomalies

def detect_error_spikes(logs_df, threshold=10):
    """Detect sudden increases in error rates."""

    errors = logs_df[logs_df['log_type'] == 'error']
    errors['hour'] = errors['timestamp'].dt.floor('H')

    error_counts = errors.groupby('hour').size().reset_index(name='error_count')

    # Calculate rolling average
    error_counts['rolling_avg'] = error_counts['error_count'].rolling(
        window=24, min_periods=1
    ).mean()

    # Find spikes
    error_counts['is_spike'] = (
        error_counts['error_count'] >
        error_counts['rolling_avg'] * threshold
    )

    return error_counts[error_counts['is_spike']]
```

### Exercise 1.3: Cold Start Analysis

```python
def analyze_cold_starts(logs_df):
    """Analyze cold start patterns for security implications."""

    # Identify cold starts (have init_duration)
    invocations = logs_df[logs_df['event'] == 'invocation_report'].copy()
    invocations['is_cold_start'] = invocations['init_duration'].notna()

    # Calculate cold start statistics
    stats = {
        'total_invocations': len(invocations),
        'cold_starts': invocations['is_cold_start'].sum(),
        'cold_start_rate': invocations['is_cold_start'].mean(),
        'avg_cold_start_duration': invocations[
            invocations['is_cold_start']
        ]['init_duration'].mean(),
        'avg_warm_duration': invocations[
            ~invocations['is_cold_start']
        ]['duration'].mean()
    }

    # Detect unusual cold start patterns
    # High frequency cold starts might indicate probing
    invocations['hour'] = invocations['timestamp'].dt.floor('H')
    hourly_cold = invocations.groupby('hour').agg({
        'is_cold_start': ['sum', 'mean']
    }).reset_index()
    hourly_cold.columns = ['hour', 'cold_count', 'cold_rate']

    # Flag hours with unusually high cold start rates
    avg_cold_rate = hourly_cold['cold_rate'].mean()
    suspicious_hours = hourly_cold[
        hourly_cold['cold_rate'] > avg_cold_rate * 3
    ]

    return stats, suspicious_hours
```

## Part 2: Event Injection Detection

### Exercise 2.1: Input Validation Analysis

```python
def analyze_event_payloads(events_df):
    """Analyze incoming events for injection patterns."""

    injection_patterns = {
        'sql_injection': [
            r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|SET|TABLE)\b)",
            r"(?i)('\s*(OR|AND)\s*'?\d+'\s*=\s*'?\d+)",
            r"(?i)(--\s*$|;\s*--)",
        ],
        'command_injection': [
            r"[;&|`$]",
            r"(?i)\$\(.*\)",
            r"(?i)\b(cat|ls|pwd|whoami|id|wget|curl)\b\s",
        ],
        'path_traversal': [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[/\\]",
        ],
        'xss': [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
        ],
        'xxe': [
            r"<!ENTITY",
            r"<!DOCTYPE.*\[",
            r"SYSTEM\s+[\"']",
        ],
        'ssrf': [
            r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)",
            r"(?i)169\.254\.169\.254",  # AWS metadata
            r"(?i)metadata\.google",     # GCP metadata
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
```

### Exercise 2.2: API Gateway Log Analysis

```python
def analyze_api_gateway_logs(logs_df):
    """Analyze API Gateway logs for security events."""

    # Parse API Gateway access logs
    security_events = []

    for _, log in logs_df.iterrows():
        event = {
            'timestamp': log['timestamp'],
            'request_id': log['request_id'],
            'source_ip': log['source_ip'],
            'http_method': log['http_method'],
            'path': log['path'],
            'status': log['status'],
            'response_length': log.get('response_length', 0)
        }

        # Check for security indicators
        indicators = []

        # 4xx/5xx errors
        if log['status'] >= 400:
            indicators.append(f"error_status_{log['status']}")

        # Unusual HTTP methods
        if log['http_method'] not in ['GET', 'POST', 'PUT', 'DELETE']:
            indicators.append(f"unusual_method_{log['http_method']}")

        # Suspicious paths
        suspicious_paths = ['/admin', '/.env', '/config', '/debug', '/actuator']
        if any(sp in log['path'] for sp in suspicious_paths):
            indicators.append('suspicious_path')

        # Large request/response
        if log.get('request_length', 0) > 1000000:  # 1MB
            indicators.append('large_request')

        if indicators:
            event['indicators'] = indicators
            security_events.append(event)

    return pd.DataFrame(security_events)

def detect_enumeration_attempts(logs_df, window_minutes=5, threshold=20):
    """Detect path/parameter enumeration attempts."""

    logs_df['window'] = logs_df['timestamp'].dt.floor(f'{window_minutes}T')

    # Group by source IP and time window
    grouped = logs_df.groupby(['source_ip', 'window']).agg({
        'path': 'nunique',
        'request_id': 'count',
        'status': lambda x: (x == 404).sum()
    }).reset_index()

    grouped.columns = ['source_ip', 'window', 'unique_paths',
                       'request_count', '404_count']

    # Detect enumeration: many unique paths or many 404s
    enumeration = grouped[
        (grouped['unique_paths'] > threshold) |
        (grouped['404_count'] > threshold)
    ]

    return enumeration
```

### Exercise 2.3: Event Source Validation

```python
def validate_event_sources(events_df, allowed_sources):
    """Validate that events come from expected sources."""

    validation_results = []

    for _, event in events_df.iterrows():
        source = event.get('eventSource', 'unknown')
        source_arn = event.get('eventSourceARN', '')

        is_valid = source in allowed_sources.get('sources', [])
        arn_valid = any(
            re.match(pattern, source_arn)
            for pattern in allowed_sources.get('arn_patterns', [])
        )

        if not is_valid or not arn_valid:
            validation_results.append({
                'timestamp': event.get('timestamp'),
                'request_id': event.get('request_id'),
                'source': source,
                'source_arn': source_arn,
                'is_valid_source': is_valid,
                'is_valid_arn': arn_valid
            })

    return pd.DataFrame(validation_results)

# Example allowed sources configuration
ALLOWED_SOURCES = {
    'sources': ['aws:s3', 'aws:sqs', 'aws:apigateway', 'aws:dynamodb'],
    'arn_patterns': [
        r'arn:aws:s3:::my-trusted-bucket',
        r'arn:aws:sqs:us-east-1:123456789012:my-queue',
        r'arn:aws:execute-api:.*'
    ]
}
```

## Part 3: Permission Analysis

### Exercise 3.1: Function Role Analysis

```python
def analyze_function_permissions(functions_df, roles_df):
    """Analyze Lambda function IAM role permissions."""

    # Define sensitive permissions
    sensitive_permissions = {
        'critical': [
            'iam:*',
            '*:*',
            'sts:AssumeRole',
            'organizations:*',
            'kms:Decrypt',
        ],
        'high': [
            's3:*',
            'dynamodb:*',
            'secretsmanager:GetSecretValue',
            'ssm:GetParameter*',
            'lambda:InvokeFunction',
            'ec2:*',
        ],
        'medium': [
            's3:GetObject',
            's3:PutObject',
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'logs:*',
            'xray:*',
        ]
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
            'medium_permissions': [],
            'is_overprivileged': False
        }

        for policy in policies:
            for statement in policy.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                for action in actions:
                    for severity, patterns in sensitive_permissions.items():
                        if any(re.match(p.replace('*', '.*'), action)
                               for p in patterns):
                            func_findings[f'{severity}_permissions'].append(action)

        # Flag if overprivileged
        if (func_findings['critical_permissions'] or
            len(func_findings['high_permissions']) > 5):
            func_findings['is_overprivileged'] = True

        findings.append(func_findings)

    return pd.DataFrame(findings)
```

### Exercise 3.2: Cross-Account Access Detection

```python
def detect_cross_account_access(cloudtrail_df, account_id):
    """Detect Lambda invoking resources in other accounts."""

    cross_account_events = []

    for _, event in cloudtrail_df.iterrows():
        # Check if the target resource is in a different account
        resources = event.get('resources', [])

        for resource in resources:
            resource_arn = resource.get('ARN', '')

            # Extract account ID from ARN
            arn_match = re.match(
                r'arn:aws:[^:]+:[^:]*:(\d+):',
                resource_arn
            )

            if arn_match:
                target_account = arn_match.group(1)

                if target_account != account_id:
                    cross_account_events.append({
                        'timestamp': event['timestamp'],
                        'event_name': event['event_name'],
                        'source_function': event.get('userIdentity', {}).get(
                            'sessionContext', {}
                        ).get('sessionIssuer', {}).get('arn'),
                        'target_resource': resource_arn,
                        'target_account': target_account
                    })

    return pd.DataFrame(cross_account_events)
```

### Exercise 3.3: Secret Access Monitoring

```python
def monitor_secret_access(cloudtrail_df, function_names):
    """Monitor how functions access secrets."""

    secret_access_events = [
        'GetSecretValue',
        'GetParameter',
        'GetParameters',
        'GetParametersByPath',
        'Decrypt'
    ]

    # Filter for secret access events
    secret_events = cloudtrail_df[
        cloudtrail_df['event_name'].isin(secret_access_events)
    ]

    # Group by function
    function_secret_access = []

    for func_name in function_names:
        func_events = secret_events[
            secret_events['userIdentity'].apply(
                lambda x: func_name in str(x)
            )
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
                'access_count': len(func_events),
                'unique_secrets': len(secrets_accessed)
            })

    return pd.DataFrame(function_secret_access)
```

## Part 4: Attack Scenarios

### Scenario 1: Dependency Confusion Attack

```python
def detect_dependency_confusion(function_config, package_registry):
    """Detect potential dependency confusion in function packages."""

    findings = []

    for func in function_config:
        dependencies = func.get('dependencies', {})

        for pkg_name, version in dependencies.items():
            # Check if internal package exists in public registry
            if package_registry.exists_public(pkg_name):
                public_info = package_registry.get_public_info(pkg_name)

                # Check version discrepancy
                if public_info and public_info['latest_version'] != version:
                    findings.append({
                        'function': func['name'],
                        'package': pkg_name,
                        'installed_version': version,
                        'public_version': public_info['latest_version'],
                        'risk': 'dependency_confusion',
                        'severity': 'HIGH'
                    })

            # Check for typosquatting
            similar = package_registry.find_similar_names(pkg_name)
            if similar:
                findings.append({
                    'function': func['name'],
                    'package': pkg_name,
                    'similar_packages': similar,
                    'risk': 'typosquatting',
                    'severity': 'MEDIUM'
                })

    return findings
```

### Scenario 2: Event Poisoning Attack

```python
def detect_event_poisoning(events_df, baseline_schema):
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
            indicators.append({
                'type': 'unexpected_fields',
                'fields': list(unexpected)
            })

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

        # Check payload size
        payload_size = len(json.dumps(payload))
        max_size = baseline_schema.get('max_payload_size', 10000)

        if payload_size > max_size:
            indicators.append({
                'type': 'oversized_payload',
                'size': payload_size,
                'max_allowed': max_size
            })

        if indicators:
            poisoning_indicators.append({
                'timestamp': event.get('timestamp'),
                'request_id': event.get('request_id'),
                'indicators': indicators
            })

    return pd.DataFrame(poisoning_indicators)
```

## Part 5: Detection Engineering

### XQL Detection Rules for Serverless

```xql
config case_sensitive = false

// Detect excessive Lambda errors
| preset = cloud_audit
| filter provider = "aws" and service = "lambda"
| filter operation_status = "failure"
| comp count() as error_count by function_name, _time = bin(1h)
| filter error_count > 100
| sort desc error_count
| limit 100
```

```xql
config case_sensitive = false

// Detect Lambda accessing secrets at unusual times
| preset = cloud_audit
| filter provider = "aws"
| filter service in ("secretsmanager", "ssm")
| filter operation_name in ("GetSecretValue", "GetParameter")
| filter user_identity_type = "AssumedRole"
| filter timestamp_extract("HOUR", _time) not between 6 and 22
| fields _time, function_name, secret_name, source_ip
| sort desc _time
| limit 100
```

```xql
config case_sensitive = false

// Detect potential SSRF attempts via Lambda
| preset = cloud_audit
| filter provider = "aws" and service = "ec2"
| filter operation_name = "DescribeInstances"
| filter user_identity_type = "AssumedRole"
| filter user_identity_arn contains ":function:"
| comp count() as api_count by user_identity_arn, _time = bin(1h)
| filter api_count > 50
| sort desc api_count
| limit 100
```

## Exercises

### Exercise 1: Log Analysis
Using the provided Lambda logs:
1. Identify cold start patterns
2. Detect error rate anomalies
3. Find potential timeout issues

### Exercise 2: Event Injection
Analyze the API Gateway logs to:
1. Detect SQL injection attempts
2. Find path traversal attacks
3. Identify enumeration behavior

### Exercise 3: Permission Audit
Review the function configurations to:
1. Find overprivileged functions
2. Identify cross-account access
3. Map secret access patterns

### Exercise 4: Detection Rules
Write detection rules for:
1. Function invocation from unusual IP ranges
2. Excessive secret rotation
3. New function deployment by unauthorized user

## Challenge Questions

1. How would you detect data exfiltration through Lambda function responses?
2. What are the blind spots in serverless security monitoring?
3. Design a detection strategy for serverless cryptojacking.
4. How can attackers abuse Lambda function URLs?

## Resources

- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [Azure Functions Security](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [GCP Cloud Functions Security](https://cloud.google.com/functions/docs/securing)

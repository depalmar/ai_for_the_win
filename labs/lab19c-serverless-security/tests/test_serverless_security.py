#!/usr/bin/env python3
"""Tests for Lab 19c: Serverless Security Analysis.

This module tests serverless security concepts including function log analysis,
event injection detection, permission analysis, and cold start exploitation.
"""

import pytest
import json
import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


# =============================================================================
# Sample Data for Testing
# =============================================================================

SAMPLE_LAMBDA_LOGS = [
    "START RequestId: abc-123 Version: $LATEST",
    "2024-01-15T10:30:00.000Z abc-123 INFO Processing request",
    "END RequestId: abc-123",
    "REPORT RequestId: abc-123 Duration: 150.25 ms Billed Duration: 200 ms Memory Size: 128 MB Max Memory Used: 64 MB Init Duration: 250.50 ms",
]

INJECTION_PATTERNS = {
    "sql_injection": [
        r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|SET|TABLE)\b)",
        r"(?i)('\s*(OR|AND)\s*'?\d+'\s*=\s*'?\d+)",
    ],
    "command_injection": [
        r"[;&|`$]",
        r"(?i)\$\(.*\)",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
    ],
    "ssrf": [
        r"(?i)(localhost|127\.0\.0\.1)",
        r"(?i)169\.254\.169\.254",
    ],
}

SENSITIVE_PERMISSIONS = {
    "critical": ["iam:*", "*:*", "sts:AssumeRole"],
    "high": ["s3:*", "dynamodb:*", "secretsmanager:GetSecretValue"],
    "medium": ["s3:GetObject", "logs:*"],
}


# =============================================================================
# Lambda Log Parsing Tests
# =============================================================================


class TestLambdaLogParsing:
    """Test Lambda log parsing functionality."""

    def test_start_event_detection(self):
        """Test detection of START log events."""
        log_message = "START RequestId: abc-123 Version: $LATEST"

        is_start = log_message.startswith("START")
        request_id_match = re.search(r"RequestId:\s*([a-f0-9-]+)", log_message)

        assert is_start is True
        assert request_id_match is not None
        assert request_id_match.group(1) == "abc-123"

    def test_end_event_detection(self):
        """Test detection of END log events."""
        log_message = "END RequestId: abc-123"

        is_end = log_message.startswith("END")
        assert is_end is True

    def test_report_line_parsing(self):
        """Test parsing of REPORT log lines."""
        log_message = "REPORT RequestId: abc-123 Duration: 150.25 ms Billed Duration: 200 ms Memory Size: 128 MB Max Memory Used: 64 MB Init Duration: 250.50 ms"

        patterns = {
            "duration": r"Duration:\s*([\d.]+)\s*ms",
            "billed_duration": r"Billed Duration:\s*(\d+)\s*ms",
            "memory_size": r"Memory Size:\s*(\d+)\s*MB",
            "memory_used": r"Max Memory Used:\s*(\d+)\s*MB",
            "init_duration": r"Init Duration:\s*([\d.]+)\s*ms",
        }

        metrics = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, log_message)
            if match:
                metrics[key] = float(match.group(1))

        assert metrics["duration"] == 150.25
        assert metrics["billed_duration"] == 200
        assert metrics["memory_size"] == 128
        assert metrics["memory_used"] == 64
        assert metrics["init_duration"] == 250.50

    def test_log_type_classification(self):
        """Test classification of log message types."""

        def classify_log_type(message):
            if message.startswith(("START", "END", "REPORT")):
                return "platform"
            elif re.match(r"\d{4}-\d{2}-\d{2}", message):
                return "application"
            elif "ERROR" in message or "Exception" in message:
                return "error"
            else:
                return "other"

        assert classify_log_type("START RequestId: abc") == "platform"
        assert classify_log_type("REPORT RequestId: abc") == "platform"
        assert classify_log_type("2024-01-15T10:30:00.000Z INFO test") == "application"
        assert classify_log_type("ERROR: Something went wrong") == "error"


class TestInvocationAnomalyDetection:
    """Test invocation anomaly detection."""

    def test_error_spike_detection(self):
        """Test detection of error rate spikes."""
        error_counts = [5, 3, 4, 6, 50, 4, 3]  # Spike at index 4

        rolling_avg = sum(error_counts[:4]) / 4
        threshold_multiplier = 5

        spikes = [
            i for i, count in enumerate(error_counts)
            if count > rolling_avg * threshold_multiplier
        ]

        assert len(spikes) == 1
        assert spikes[0] == 4

    def test_duration_anomaly_detection(self):
        """Test detection of duration anomalies."""
        durations = [100, 105, 98, 102, 500, 99, 103]  # Anomaly at index 4

        mean_duration = np.mean(durations)
        std_duration = np.std(durations)

        anomalies = [
            i for i, d in enumerate(durations)
            if abs(d - mean_duration) > 2 * std_duration
        ]

        assert len(anomalies) >= 1
        assert 4 in anomalies

    def test_invocation_count_aggregation(self):
        """Test aggregation of invocation counts."""
        logs = pd.DataFrame({
            "hour": [datetime(2024, 1, 15, 10), datetime(2024, 1, 15, 10), datetime(2024, 1, 15, 11)],
            "request_id": ["req1", "req2", "req3"],
            "duration": [100, 150, 200],
        })

        hourly_stats = logs.groupby("hour").agg({
            "duration": ["mean", "max"],
            "request_id": "count",
        })

        assert hourly_stats.loc[datetime(2024, 1, 15, 10), ("request_id", "count")] == 2
        assert hourly_stats.loc[datetime(2024, 1, 15, 11), ("request_id", "count")] == 1


class TestColdStartAnalysis:
    """Test cold start analysis."""

    def test_cold_start_identification(self):
        """Test identification of cold starts."""
        invocations = [
            {"request_id": "req1", "init_duration": 250.5},  # Cold start
            {"request_id": "req2", "init_duration": None},  # Warm
            {"request_id": "req3", "init_duration": 300.0},  # Cold start
            {"request_id": "req4", "init_duration": None},  # Warm
        ]

        cold_starts = [i for i in invocations if i["init_duration"] is not None]
        warm_invocations = [i for i in invocations if i["init_duration"] is None]

        assert len(cold_starts) == 2
        assert len(warm_invocations) == 2

    def test_cold_start_rate_calculation(self):
        """Test calculation of cold start rate."""
        invocations = [
            {"is_cold_start": True},
            {"is_cold_start": False},
            {"is_cold_start": False},
            {"is_cold_start": True},
            {"is_cold_start": False},
        ]

        cold_start_count = sum(1 for i in invocations if i["is_cold_start"])
        cold_start_rate = cold_start_count / len(invocations)

        assert cold_start_rate == 0.4

    def test_unusual_cold_start_pattern_detection(self):
        """Test detection of unusual cold start patterns."""
        hourly_cold_rates = [0.1, 0.12, 0.08, 0.5, 0.11, 0.09]  # Unusual at index 3

        avg_rate = np.mean(hourly_cold_rates)
        suspicious_hours = [
            i for i, rate in enumerate(hourly_cold_rates)
            if rate > avg_rate * 3
        ]

        assert len(suspicious_hours) >= 1
        assert 3 in suspicious_hours


# =============================================================================
# Event Injection Detection Tests
# =============================================================================


class TestEventInjectionDetection:
    """Test event injection detection."""

    def test_sql_injection_detection(self):
        """Test detection of SQL injection patterns."""
        payloads = [
            "SELECT * FROM users",
            "1' OR '1'='1",
            "'; DROP TABLE users; --",
            "normal input",
        ]

        sql_patterns = INJECTION_PATTERNS["sql_injection"]

        injections_found = []
        for payload in payloads:
            for pattern in sql_patterns:
                if re.search(pattern, payload):
                    injections_found.append(payload)
                    break

        assert len(injections_found) >= 2
        assert "normal input" not in injections_found

    def test_command_injection_detection(self):
        """Test detection of command injection patterns."""
        payloads = [
            "; rm -rf /",
            "$(cat /etc/passwd)",
            "normal input",
            "| ls -la",
        ]

        cmd_patterns = INJECTION_PATTERNS["command_injection"]

        injections_found = []
        for payload in payloads:
            for pattern in cmd_patterns:
                if re.search(pattern, payload):
                    injections_found.append(payload)
                    break

        assert len(injections_found) >= 3
        assert "normal input" not in injections_found

    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/normal/path/file.txt",
        ]

        path_patterns = INJECTION_PATTERNS["path_traversal"]

        traversal_found = []
        for payload in payloads:
            for pattern in path_patterns:
                if re.search(pattern, payload):
                    traversal_found.append(payload)
                    break

        assert len(traversal_found) == 2
        assert "/normal/path/file.txt" not in traversal_found

    def test_ssrf_detection(self):
        """Test detection of SSRF attempts."""
        payloads = [
            "http://localhost:8080/admin",
            "http://169.254.169.254/latest/meta-data",
            "http://example.com/api",
        ]

        ssrf_patterns = INJECTION_PATTERNS["ssrf"]

        ssrf_found = []
        for payload in payloads:
            for pattern in ssrf_patterns:
                if re.search(pattern, payload):
                    ssrf_found.append(payload)
                    break

        assert len(ssrf_found) == 2
        assert "http://example.com/api" not in ssrf_found


class TestAPIGatewayLogAnalysis:
    """Test API Gateway log analysis."""

    def test_security_indicator_detection(self):
        """Test detection of security indicators in API logs."""
        log = {
            "status": 403,
            "http_method": "TRACE",
            "path": "/admin/config",
            "request_length": 2000000,
        }

        indicators = []

        if log["status"] >= 400:
            indicators.append(f"error_status_{log['status']}")

        if log["http_method"] not in ["GET", "POST", "PUT", "DELETE"]:
            indicators.append(f"unusual_method_{log['http_method']}")

        suspicious_paths = ["/admin", "/.env", "/config"]
        if any(sp in log["path"] for sp in suspicious_paths):
            indicators.append("suspicious_path")

        if log.get("request_length", 0) > 1000000:
            indicators.append("large_request")

        assert "error_status_403" in indicators
        assert "unusual_method_TRACE" in indicators
        assert "suspicious_path" in indicators
        assert "large_request" in indicators

    def test_enumeration_attempt_detection(self):
        """Test detection of path enumeration attempts."""
        logs = pd.DataFrame({
            "source_ip": ["1.2.3.4"] * 25 + ["5.6.7.8"] * 5,
            "path": [f"/path/{i}" for i in range(25)] + ["/api/v1"] * 5,
            "status": [404] * 20 + [200] * 10,
        })

        # Group by source IP
        grouped = logs.groupby("source_ip").agg({
            "path": "nunique",
            "status": lambda x: (x == 404).sum(),
        })

        threshold = 15
        enumeration_ips = grouped[
            (grouped["path"] > threshold) | (grouped["status"] > threshold)
        ].index.tolist()

        assert "1.2.3.4" in enumeration_ips


class TestEventSourceValidation:
    """Test event source validation."""

    def test_valid_source_check(self):
        """Test validation of allowed event sources."""
        allowed_sources = ["aws:s3", "aws:sqs", "aws:apigateway"]

        events = [
            {"eventSource": "aws:s3"},
            {"eventSource": "aws:sqs"},
            {"eventSource": "unknown:source"},
        ]

        invalid_sources = [
            e for e in events
            if e["eventSource"] not in allowed_sources
        ]

        assert len(invalid_sources) == 1
        assert invalid_sources[0]["eventSource"] == "unknown:source"

    def test_arn_pattern_validation(self):
        """Test validation of source ARN patterns."""
        allowed_patterns = [
            r"arn:aws:s3:::my-trusted-bucket",
            r"arn:aws:sqs:us-east-1:\d+:my-queue",
        ]

        events = [
            {"sourceARN": "arn:aws:s3:::my-trusted-bucket"},
            {"sourceARN": "arn:aws:sqs:us-east-1:123456789:my-queue"},
            {"sourceARN": "arn:aws:s3:::malicious-bucket"},
        ]

        invalid_arns = []
        for event in events:
            arn = event["sourceARN"]
            is_valid = any(re.match(pattern, arn) for pattern in allowed_patterns)
            if not is_valid:
                invalid_arns.append(arn)

        assert len(invalid_arns) == 1
        assert "malicious-bucket" in invalid_arns[0]


# =============================================================================
# Permission Analysis Tests
# =============================================================================


class TestFunctionPermissionAnalysis:
    """Test function IAM permission analysis."""

    def test_critical_permission_detection(self):
        """Test detection of critical permissions."""
        function_permissions = ["s3:GetObject", "iam:*", "logs:PutLogEvents"]

        critical_patterns = SENSITIVE_PERMISSIONS["critical"]

        critical_found = []
        for perm in function_permissions:
            for pattern in critical_patterns:
                if pattern.replace("*", ".*") == perm or pattern == perm:
                    critical_found.append(perm)
                elif "*" in pattern:
                    regex = pattern.replace("*", ".*")
                    if re.match(regex, perm):
                        critical_found.append(perm)

        # iam:* should be found as it's in critical permissions
        assert "iam:*" in critical_found

    def test_overprivileged_function_detection(self):
        """Test detection of overprivileged functions."""
        function = {
            "name": "my-function",
            "permissions": ["s3:*", "dynamodb:*", "iam:CreateUser", "ec2:*", "lambda:*", "kms:Decrypt"],
        }

        high_permissions = SENSITIVE_PERMISSIONS["high"]
        critical_permissions = SENSITIVE_PERMISSIONS["critical"]

        high_count = 0
        has_critical = False

        for perm in function["permissions"]:
            if perm in critical_permissions:
                has_critical = True
            if perm in high_permissions or any(hp.replace("*", "") in perm for hp in high_permissions):
                high_count += 1

        is_overprivileged = has_critical or high_count > 5

        assert is_overprivileged is True

    def test_permission_categorization(self):
        """Test categorization of permissions by sensitivity."""
        permissions = ["s3:GetObject", "iam:*", "logs:PutLogEvents", "secretsmanager:GetSecretValue"]

        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "other": [],
        }

        for perm in permissions:
            found = False
            for category in ["critical", "high", "medium"]:
                patterns = SENSITIVE_PERMISSIONS.get(category, [])
                for pattern in patterns:
                    if perm == pattern or (pattern.endswith("*") and perm.startswith(pattern[:-1])):
                        categorized[category].append(perm)
                        found = True
                        break
                if found:
                    break
            if not found:
                categorized["other"].append(perm)

        assert "iam:*" in categorized["critical"]


class TestCrossAccountAccessDetection:
    """Test cross-account access detection."""

    def test_cross_account_resource_detection(self):
        """Test detection of cross-account resource access."""
        our_account = "123456789012"

        events = [
            {"resourceARN": "arn:aws:s3:::bucket-123456789012-data"},
            {"resourceARN": "arn:aws:dynamodb:us-east-1:987654321098:table/foreign-table"},
            {"resourceARN": "arn:aws:sqs:us-east-1:123456789012:our-queue"},
        ]

        cross_account = []
        for event in events:
            arn = event["resourceARN"]
            match = re.search(r"arn:aws:[^:]+:[^:]*:(\d+):", arn)
            if match:
                target_account = match.group(1)
                if target_account != our_account:
                    cross_account.append({
                        "arn": arn,
                        "target_account": target_account,
                    })

        assert len(cross_account) == 1
        assert cross_account[0]["target_account"] == "987654321098"


class TestSecretAccessMonitoring:
    """Test secret access monitoring."""

    def test_secret_access_event_filtering(self):
        """Test filtering of secret access events."""
        secret_access_events = ["GetSecretValue", "GetParameter", "Decrypt"]

        events = [
            {"event_name": "GetSecretValue", "function": "func1"},
            {"event_name": "PutObject", "function": "func1"},
            {"event_name": "GetParameter", "function": "func2"},
            {"event_name": "ListBuckets", "function": "func3"},
        ]

        secret_events = [
            e for e in events
            if e["event_name"] in secret_access_events
        ]

        assert len(secret_events) == 2
        assert all(e["event_name"] in secret_access_events for e in secret_events)

    def test_function_secret_access_summary(self):
        """Test summarization of function secret access."""
        events = [
            {"function": "func1", "secret_name": "secret1"},
            {"function": "func1", "secret_name": "secret2"},
            {"function": "func1", "secret_name": "secret1"},
            {"function": "func2", "secret_name": "secret3"},
        ]

        df = pd.DataFrame(events)
        summary = df.groupby("function").agg({
            "secret_name": ["count", "nunique"],
        })

        assert summary.loc["func1", ("secret_name", "count")] == 3
        assert summary.loc["func1", ("secret_name", "nunique")] == 2


# =============================================================================
# Attack Scenario Tests
# =============================================================================


class TestEventPoisoningDetection:
    """Test event poisoning attack detection."""

    def test_unexpected_field_detection(self):
        """Test detection of unexpected fields in event payloads."""
        expected_fields = {"name", "email", "message"}

        payload = {
            "name": "John",
            "email": "john@example.com",
            "message": "Hello",
            "admin": True,  # Unexpected
            "__proto__": {},  # Unexpected
        }

        actual_fields = set(payload.keys())
        unexpected = actual_fields - expected_fields

        assert "admin" in unexpected
        assert "__proto__" in unexpected

    def test_type_mismatch_detection(self):
        """Test detection of type mismatches in payloads."""
        field_types = {
            "name": "str",
            "age": "int",
            "active": "bool",
        }

        payload = {
            "name": "John",
            "age": "25",  # Should be int
            "active": True,
        }

        mismatches = []
        for field, expected_type in field_types.items():
            if field in payload:
                actual_type = type(payload[field]).__name__
                if actual_type != expected_type:
                    mismatches.append({
                        "field": field,
                        "expected": expected_type,
                        "actual": actual_type,
                    })

        assert len(mismatches) == 1
        assert mismatches[0]["field"] == "age"

    def test_oversized_payload_detection(self):
        """Test detection of oversized payloads."""
        max_size = 10000

        payloads = [
            {"data": "x" * 100},
            {"data": "x" * 50000},
        ]

        oversized = [
            p for p in payloads
            if len(json.dumps(p)) > max_size
        ]

        assert len(oversized) == 1


class TestDependencyConfusionDetection:
    """Test dependency confusion attack detection."""

    def test_version_discrepancy_detection(self):
        """Test detection of version discrepancies."""
        internal_packages = {
            "my-internal-lib": "1.0.0",
            "company-utils": "2.3.1",
        }

        public_registry = {
            "my-internal-lib": "3.0.0",  # Higher version in public registry
        }

        findings = []
        for pkg, internal_version in internal_packages.items():
            if pkg in public_registry:
                public_version = public_registry[pkg]
                if public_version != internal_version:
                    findings.append({
                        "package": pkg,
                        "internal_version": internal_version,
                        "public_version": public_version,
                        "risk": "dependency_confusion",
                    })

        assert len(findings) == 1
        assert findings[0]["package"] == "my-internal-lib"


# =============================================================================
# Detection Rule Tests
# =============================================================================


class TestServerlessDetectionRules:
    """Test serverless detection rules."""

    def test_excessive_error_rule(self):
        """Test rule for excessive Lambda errors."""
        error_counts = [
            {"function": "func1", "hour": "2024-01-15T10:00", "errors": 150},
            {"function": "func2", "hour": "2024-01-15T10:00", "errors": 50},
            {"function": "func3", "hour": "2024-01-15T10:00", "errors": 200},
        ]

        threshold = 100
        excessive = [e for e in error_counts if e["errors"] > threshold]

        assert len(excessive) == 2
        assert all(e["errors"] > threshold for e in excessive)

    def test_unusual_time_access_rule(self):
        """Test rule for unusual time secret access."""
        events = [
            {"hour": 10, "event": "GetSecretValue"},
            {"hour": 3, "event": "GetSecretValue"},  # Unusual
            {"hour": 14, "event": "GetSecretValue"},
            {"hour": 2, "event": "GetSecretValue"},  # Unusual
        ]

        business_hours = range(6, 23)
        unusual = [e for e in events if e["hour"] not in business_hours]

        assert len(unusual) == 2

    def test_high_api_call_rate_rule(self):
        """Test rule for high API call rate detection."""
        api_calls = [
            {"function": "func1", "hour": "10:00", "count": 60},
            {"function": "func1", "hour": "11:00", "count": 55},
            {"function": "func1", "hour": "12:00", "count": 150},  # Spike
        ]

        threshold = 100
        high_rate = [c for c in api_calls if c["count"] > threshold]

        assert len(high_rate) == 1
        assert high_rate[0]["hour"] == "12:00"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

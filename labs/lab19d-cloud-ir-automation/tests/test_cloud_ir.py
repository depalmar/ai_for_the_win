#!/usr/bin/env python3
"""Tests for Lab 19d: Cloud Incident Response Automation.

This module tests cloud IR automation concepts including containment actions,
evidence collection, workflow orchestration, and multi-cloud response.
"""

import pytest
import json
import hashlib
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


# =============================================================================
# Sample Data for Testing
# =============================================================================

SAMPLE_ALERT = {
    "id": "alert-123",
    "type": "unauthorized_api_call",
    "severity": "CRITICAL",
    "source_ip": "1.2.3.4",
    "user": "compromised-user",
    "resource_id": "i-1234567890abcdef0",
    "timestamp": "2024-01-15T10:30:00Z",
}

SAMPLE_INSTANCE = {
    "InstanceId": "i-1234567890abcdef0",
    "SecurityGroups": [
        {"GroupId": "sg-original-123"},
        {"GroupId": "sg-original-456"},
    ],
    "BlockDeviceMappings": [
        {"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-abc123"}},
        {"DeviceName": "/dev/sdb", "Ebs": {"VolumeId": "vol-def456"}},
    ],
}

SAMPLE_IAM_USER = {
    "UserName": "compromised-user",
    "AccessKeys": [
        {"AccessKeyId": "AKIAEXAMPLE1", "Status": "Active"},
        {"AccessKeyId": "AKIAEXAMPLE2", "Status": "Active"},
    ],
}


# =============================================================================
# Containment Action Tests
# =============================================================================


class TestEC2Isolation:
    """Test EC2 instance isolation functionality."""

    def test_isolation_metadata_structure(self):
        """Test structure of isolation metadata tags."""
        instance_id = "i-1234567890abcdef0"
        original_sgs = ["sg-original-123", "sg-original-456"]
        reason = "Suspicious activity detected"

        tags = [
            {"Key": "IR_Isolated", "Value": "true"},
            {"Key": "IR_IsolationTime", "Value": datetime.utcnow().isoformat()},
            {"Key": "IR_OriginalSGs", "Value": json.dumps(original_sgs)},
            {"Key": "IR_IsolationReason", "Value": reason},
        ]

        assert len(tags) == 4
        assert any(t["Key"] == "IR_Isolated" for t in tags)
        assert any(t["Key"] == "IR_OriginalSGs" for t in tags)

        # Verify original SGs can be recovered
        original_sgs_tag = next(t for t in tags if t["Key"] == "IR_OriginalSGs")
        recovered_sgs = json.loads(original_sgs_tag["Value"])
        assert recovered_sgs == original_sgs

    def test_isolation_result_structure(self):
        """Test structure of isolation result."""
        result = {
            "status": "isolated",
            "instance_id": "i-1234567890abcdef0",
            "original_security_groups": ["sg-original-123"],
            "isolation_sg": "sg-isolation-789",
            "timestamp": datetime.utcnow().isoformat(),
        }

        required_fields = [
            "status",
            "instance_id",
            "original_security_groups",
            "isolation_sg",
            "timestamp",
        ]
        for field in required_fields:
            assert field in result

        assert result["status"] == "isolated"

    def test_isolation_security_group_rules(self):
        """Test isolation security group rule structure."""
        # Isolation SG should block all traffic except forensics access
        forensics_cidr = "10.0.100.0/24"

        ingress_rules = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": forensics_cidr}],
            }
        ]

        egress_rules = []  # Empty = no outbound allowed

        # Verify only SSH from forensics subnet is allowed
        assert len(ingress_rules) == 1
        assert ingress_rules[0]["FromPort"] == 22
        assert ingress_rules[0]["IpRanges"][0]["CidrIp"] == forensics_cidr
        assert len(egress_rules) == 0


class TestIAMCredentialRevocation:
    """Test IAM credential revocation functionality."""

    def test_access_key_disable_action(self):
        """Test access key disable action structure."""
        user_name = "compromised-user"
        access_keys = SAMPLE_IAM_USER["AccessKeys"]

        actions_taken = []
        for key in access_keys:
            action = {
                "action": "disable_access_key",
                "user": user_name,
                "key_id": key["AccessKeyId"],
                "original_status": key["Status"],
            }
            actions_taken.append(action)

        assert len(actions_taken) == 2
        assert all(a["action"] == "disable_access_key" for a in actions_taken)

    def test_deny_all_policy_structure(self):
        """Test deny-all policy structure."""
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

        assert deny_policy["Statement"][0]["Effect"] == "Deny"
        assert deny_policy["Statement"][0]["Action"] == "*"
        assert deny_policy["Statement"][0]["Resource"] == "*"

    def test_revocation_result_structure(self):
        """Test credential revocation result structure."""
        result = {
            "status": "revoked",
            "user": "compromised-user",
            "actions_taken": [
                "Disabled access key AKIAEXAMPLE1",
                "Disabled access key AKIAEXAMPLE2",
                "Removed console access",
                "Attached deny-all policy",
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        assert result["status"] == "revoked"
        assert len(result["actions_taken"]) >= 3

    def test_session_invalidation_policy(self):
        """Test session invalidation policy structure."""
        current_time = datetime.utcnow().isoformat()

        invalidation_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": current_time,
                        }
                    },
                }
            ],
        }

        condition = invalidation_policy["Statement"][0]["Condition"]
        assert "DateLessThan" in condition
        assert "aws:TokenIssueTime" in condition["DateLessThan"]


class TestNetworkContainment:
    """Test network containment functionality."""

    def test_ip_block_waf_entry(self):
        """Test WAF IP block entry structure."""
        ip_address = "1.2.3.4"
        ip_cidr = f"{ip_address}/32"

        waf_entry = {
            "ip_set_name": "IR-BlockedIPs",
            "addresses": [ip_cidr],
            "reason": "Incident response block",
        }

        assert waf_entry["addresses"][0] == "1.2.3.4/32"

    def test_nacl_deny_rule_structure(self):
        """Test Network ACL deny rule structure."""
        ip_address = "1.2.3.4"

        nacl_entry = {
            "RuleNumber": 100,
            "Protocol": "-1",  # All protocols
            "RuleAction": "deny",
            "Egress": False,  # Inbound
            "CidrBlock": f"{ip_address}/32",
        }

        assert nacl_entry["RuleAction"] == "deny"
        assert nacl_entry["Protocol"] == "-1"
        assert nacl_entry["Egress"] is False

    def test_block_result_structure(self):
        """Test IP block result structure."""
        result = {
            "status": "blocked",
            "ip_address": "1.2.3.4",
            "reason": "Suspicious activity",
            "actions": [
                "Added 1.2.3.4 to WAF block list",
                "Added NACL rule 100 to block 1.2.3.4",
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        assert result["status"] == "blocked"
        assert len(result["actions"]) >= 1


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestDiskSnapshotCollection:
    """Test disk snapshot evidence collection."""

    def test_snapshot_metadata_tags(self):
        """Test snapshot metadata tag structure."""
        case_id = "IR-2024-001"
        instance_id = "i-1234567890abcdef0"
        device_name = "/dev/sda1"

        tags = [
            {"Key": "IR_CaseId", "Value": case_id},
            {"Key": "IR_InstanceId", "Value": instance_id},
            {"Key": "IR_DeviceName", "Value": device_name},
            {"Key": "IR_CreatedAt", "Value": datetime.utcnow().isoformat()},
            {"Key": "IR_Type", "Value": "forensic_evidence"},
        ]

        assert any(t["Key"] == "IR_CaseId" for t in tags)
        assert any(t["Key"] == "IR_Type" and t["Value"] == "forensic_evidence" for t in tags)

    def test_snapshot_result_structure(self):
        """Test snapshot creation result structure."""
        result = {
            "status": "snapshots_created",
            "instance_id": "i-1234567890abcdef0",
            "case_id": "IR-2024-001",
            "snapshots": [
                {
                    "snapshot_id": "snap-abc123",
                    "volume_id": "vol-abc123",
                    "device_name": "/dev/sda1",
                },
                {
                    "snapshot_id": "snap-def456",
                    "volume_id": "vol-def456",
                    "device_name": "/dev/sdb",
                },
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        assert result["status"] == "snapshots_created"
        assert len(result["snapshots"]) == 2
        assert all("snapshot_id" in s for s in result["snapshots"])


class TestLogCollection:
    """Test log evidence collection."""

    def test_cloudtrail_evidence_structure(self):
        """Test CloudTrail evidence collection structure."""
        case_id = "IR-2024-001"
        time_range = {
            "start": datetime.now() - timedelta(hours=24),
            "end": datetime.now(),
        }

        evidence = {
            "case_id": case_id,
            "collection_time": datetime.utcnow().isoformat(),
            "time_range": {
                "start": time_range["start"].isoformat(),
                "end": time_range["end"].isoformat(),
            },
            "event_count": 150,
            "events": [],  # Would contain actual events
        }

        assert evidence["case_id"] == case_id
        assert "time_range" in evidence
        assert "event_count" in evidence

    def test_evidence_s3_path_structure(self):
        """Test evidence S3 path structure."""
        bucket = "forensic-evidence-bucket"
        case_id = "IR-2024-001"
        evidence_type = "cloudtrail"

        s3_path = f"s3://{bucket}/cases/{case_id}/{evidence_type}/events.json"

        assert case_id in s3_path
        assert evidence_type in s3_path
        assert s3_path.startswith("s3://")


class TestEvidenceIntegrity:
    """Test evidence integrity verification."""

    def test_hash_calculation(self):
        """Test evidence hash calculation."""
        content = b"This is test evidence content"

        hashes = {
            "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha512": hashlib.sha512(content).hexdigest(),
        }

        assert len(hashes["md5"]) == 32
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128

    def test_hash_file_structure(self):
        """Test hash file structure for evidence."""
        s3_key = "cases/IR-2024-001/cloudtrail/events.json"
        file_size = 1024

        hash_record = {
            "original_file": s3_key,
            "file_size": file_size,
            "hashes": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "hash_time": datetime.utcnow().isoformat(),
        }

        assert hash_record["original_file"] == s3_key
        assert "md5" in hash_record["hashes"]
        assert "sha256" in hash_record["hashes"]

    def test_chain_of_custody_structure(self):
        """Test chain of custody record structure."""
        case_id = "IR-2024-001"

        custody_record = {
            "case_id": case_id,
            "created_at": datetime.utcnow().isoformat(),
            "created_by": "arn:aws:iam::123456789012:user/investigator",
            "evidence_items": [
                {
                    "item_id": str(uuid.uuid4()),
                    "description": "CloudTrail logs",
                    "s3_path": "s3://bucket/cases/IR-2024-001/cloudtrail/events.json",
                    "hashes": {"sha256": "abc123..."},
                    "collected_at": datetime.utcnow().isoformat(),
                }
            ],
            "custody_chain": [
                {
                    "action": "created",
                    "timestamp": datetime.utcnow().isoformat(),
                    "actor": "arn:aws:iam::123456789012:user/investigator",
                    "notes": "Initial evidence collection",
                }
            ],
        }

        assert custody_record["case_id"] == case_id
        assert len(custody_record["evidence_items"]) >= 1
        assert len(custody_record["custody_chain"]) >= 1


# =============================================================================
# Orchestration Workflow Tests
# =============================================================================


class TestWorkflowStates:
    """Test workflow state definitions."""

    def test_severity_routing_logic(self):
        """Test severity-based routing logic."""

        def route_by_severity(severity):
            if severity == "CRITICAL":
                return "CriticalResponse"
            elif severity == "HIGH":
                return "HighResponse"
            else:
                return "StandardResponse"

        assert route_by_severity("CRITICAL") == "CriticalResponse"
        assert route_by_severity("HIGH") == "HighResponse"
        assert route_by_severity("MEDIUM") == "StandardResponse"
        assert route_by_severity("LOW") == "StandardResponse"

    def test_parallel_response_actions(self):
        """Test parallel response action definition."""
        parallel_actions = [
            {"action": "isolate_instance", "target": "i-123"},
            {"action": "revoke_credentials", "target": "user1"},
            {"action": "create_snapshots", "target": "i-123"},
            {"action": "notify_team", "target": "security-team"},
        ]

        assert len(parallel_actions) == 4
        assert any(a["action"] == "isolate_instance" for a in parallel_actions)
        assert any(a["action"] == "notify_team" for a in parallel_actions)

    def test_workflow_execution_order(self):
        """Test workflow execution order for dependencies."""
        workflow_steps = [
            {"name": "TriageAlert", "order": 1},
            {"name": "SeverityCheck", "order": 2},
            {"name": "ContainmentActions", "order": 3},
            {"name": "CollectEvidence", "order": 4},
            {"name": "CreateTicket", "order": 5},
        ]

        # Sort by order
        sorted_steps = sorted(workflow_steps, key=lambda x: x["order"])

        assert sorted_steps[0]["name"] == "TriageAlert"
        assert sorted_steps[-1]["name"] == "CreateTicket"


class TestEventBridgeIntegration:
    """Test EventBridge integration for detection automation."""

    def test_guardduty_event_pattern(self):
        """Test GuardDuty event pattern structure."""
        event_pattern = {
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"],
            "detail": {
                "severity": [{"numeric": [">=", 7]}],
            },
        }

        assert "aws.guardduty" in event_pattern["source"]
        assert event_pattern["detail"]["severity"][0]["numeric"] == [">=", 7]

    def test_event_input_transformation(self):
        """Test event input transformation structure."""
        input_transformer = {
            "InputPathsMap": {
                "findingId": "$.detail.id",
                "severity": "$.detail.severity",
                "type": "$.detail.type",
            },
            "InputTemplate": json.dumps(
                {
                    "alert_id": "<findingId>",
                    "severity": "<severity>",
                    "alert_type": "<type>",
                }
            ),
        }

        assert "findingId" in input_transformer["InputPathsMap"]
        assert "<findingId>" in input_transformer["InputTemplate"]


# =============================================================================
# Multi-Cloud Response Tests
# =============================================================================


class TestMultiCloudOrchestration:
    """Test multi-cloud IR orchestration."""

    def test_cloud_resource_identification(self):
        """Test identification of resource cloud provider."""

        def identify_cloud(resource_id):
            if resource_id.startswith("i-") or resource_id.startswith("arn:aws:"):
                return "aws"
            elif resource_id.startswith("projects/"):
                return "gcp"
            elif resource_id.startswith("/subscriptions/"):
                return "azure"
            else:
                return "unknown"

        assert identify_cloud("i-1234567890abcdef0") == "aws"
        assert identify_cloud("projects/my-project/zones/us-central1-a/instances/vm1") == "gcp"
        assert (
            identify_cloud(
                "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
            )
            == "azure"
        )

    def test_parallel_containment_result(self):
        """Test parallel containment result structure."""
        results = [
            {
                "target": {"cloud": "aws", "resource_id": "i-123", "resource_type": "ec2"},
                "status": "success",
                "result": {"status": "isolated"},
            },
            {
                "target": {"cloud": "gcp", "resource_id": "vm-456", "resource_type": "compute"},
                "status": "success",
                "result": {"status": "isolated"},
            },
            {
                "target": {"cloud": "azure", "resource_id": "vm-789", "resource_type": "vm"},
                "status": "failed",
                "error": "Permission denied",
            },
        ]

        successful = [r for r in results if r["status"] == "success"]
        failed = [r for r in results if r["status"] == "failed"]

        assert len(successful) == 2
        assert len(failed) == 1


# =============================================================================
# Detection-to-Response Pipeline Tests
# =============================================================================


class TestAlertHandling:
    """Test alert handling and response selection."""

    def test_response_action_selection(self):
        """Test selection of response actions based on alert."""

        def select_response_actions(action_count):
            response_actions = []

            if action_count > 50:
                response_actions.append({"action": "revoke_credentials", "priority": "immediate"})
                response_actions.append({"action": "block_ip", "priority": "immediate"})
            elif action_count > 20:
                response_actions.append({"action": "revoke_credentials", "priority": "high"})
                response_actions.append({"action": "notify", "priority": "high"})
            else:
                response_actions.append({"action": "create_investigation", "priority": "medium"})

            return response_actions

        # Critical case
        critical_actions = select_response_actions(60)
        assert len(critical_actions) == 2
        assert any(a["action"] == "block_ip" for a in critical_actions)

        # High case
        high_actions = select_response_actions(30)
        assert len(high_actions) == 2
        assert any(a["action"] == "notify" for a in high_actions)

        # Medium case
        medium_actions = select_response_actions(10)
        assert len(medium_actions) == 1
        assert medium_actions[0]["action"] == "create_investigation"

    def test_playbook_selection(self):
        """Test playbook selection based on alert type."""
        playbook_map = {
            "unauthorized_api_call": "cloud-credential-compromise",
            "data_exfiltration": "cloud-data-breach",
            "cryptomining": "cloud-cryptojacking",
            "privilege_escalation": "cloud-privilege-escalation",
        }

        alert_type = "unauthorized_api_call"
        selected_playbook = playbook_map.get(alert_type, "cloud-generic-investigation")

        assert selected_playbook == "cloud-credential-compromise"

        # Unknown type should get generic playbook
        unknown_playbook = playbook_map.get("unknown_type", "cloud-generic-investigation")
        assert unknown_playbook == "cloud-generic-investigation"


class TestOrchestrationPlatformIntegration:
    """Test orchestration platform integration."""

    def test_incident_creation_structure(self):
        """Test incident creation structure for orchestration platform."""
        alert_data = SAMPLE_ALERT

        incident = {
            "title": f"Cloud Security Alert - {alert_data['type']}",
            "severity": alert_data["severity"],
            "source": "cloud-ir-automation",
            "artifacts": [
                {"type": "ip", "value": alert_data["source_ip"], "context": "source"},
                {"type": "user", "value": alert_data["user"], "context": "affected"},
                {"type": "resource", "value": alert_data["resource_id"], "context": "target"},
            ],
            "playbook": "cloud-credential-compromise",
        }

        assert incident["severity"] == "CRITICAL"
        assert len(incident["artifacts"]) == 3
        assert incident["source"] == "cloud-ir-automation"


# =============================================================================
# Testing and Validation Tests
# =============================================================================


class TestIRAutomationValidation:
    """Test IR automation testing and validation."""

    def test_isolation_verification(self):
        """Test verification of isolation success."""
        result = {
            "status": "isolated",
            "instance_id": "i-123",
            "original_security_groups": ["sg-original"],
            "isolation_sg": "sg-isolation",
        }

        assert result["status"] == "isolated"
        assert result["isolation_sg"] != result["original_security_groups"][0]

    def test_credential_revocation_verification(self):
        """Test verification of credential revocation."""
        result = {
            "status": "revoked",
            "user": "compromised-user",
            "actions_taken": [
                "Disabled access key AKIAEXAMPLE1",
                "Disabled access key AKIAEXAMPLE2",
            ],
        }

        assert result["status"] == "revoked"
        assert len(result["actions_taken"]) >= 1

    def test_workflow_completion_verification(self):
        """Test verification of complete workflow execution."""
        result = {
            "containment": {"status": "success"},
            "evidence_collection": {"status": "success"},
            "notification": {"status": "success"},
        }

        all_successful = all(step["status"] == "success" for step in result.values())
        assert all_successful is True

    def test_rollback_capability(self):
        """Test rollback capability structure."""
        isolation_record = {
            "instance_id": "i-123",
            "original_security_groups": ["sg-original-1", "sg-original-2"],
            "isolation_time": datetime.utcnow().isoformat(),
        }

        # Rollback would restore original SGs
        rollback_action = {
            "action": "restore_security_groups",
            "instance_id": isolation_record["instance_id"],
            "groups": isolation_record["original_security_groups"],
        }

        assert rollback_action["groups"] == ["sg-original-1", "sg-original-2"]


class TestAlertValidation:
    """Test alert validation and processing."""

    def test_alert_required_fields(self):
        """Test that alerts contain required fields."""
        alert = SAMPLE_ALERT

        required_fields = ["id", "type", "severity", "timestamp"]
        for field in required_fields:
            assert field in alert, f"Alert should contain {field}"

    def test_severity_validation(self):
        """Test severity value validation."""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        alert = SAMPLE_ALERT
        assert alert["severity"] in valid_severities

    def test_resource_id_format_validation(self):
        """Test resource ID format validation."""
        ec2_pattern = r"^i-[a-f0-9]{8,17}$"
        resource_id = "i-1234567890abcdef0"

        import re

        assert re.match(ec2_pattern, resource_id) is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""Tests for Lab 10a: DFIR Fundamentals."""

import pytest

# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Test evidence collection concepts."""

    def test_volatility_order(self):
        """Test order of volatility understanding."""
        # Order of volatility - most volatile to least
        volatility_order = [
            "registers",
            "memory",
            "network_state",
            "running_processes",
            "disk",
            "archival_media",
        ]

        # Memory is more volatile than disk
        memory_index = volatility_order.index("memory")
        disk_index = volatility_order.index("disk")
        assert memory_index < disk_index

    def test_evidence_integrity(self):
        """Test evidence integrity concepts."""
        # Hash for evidence integrity
        original_hash = "a1b2c3d4e5f6"
        collected_hash = "a1b2c3d4e5f6"

        assert original_hash == collected_hash  # Integrity verified


class TestTimelineAnalysis:
    """Test timeline analysis concepts."""

    def test_timestamp_formats(self):
        """Test various timestamp formats."""
        timestamps = {
            "unix_epoch": 1704672000,
            "iso8601": "2025-01-08T00:00:00Z",
            "windows_filetime": 133496160000000000,
        }

        assert isinstance(timestamps["unix_epoch"], int)
        assert "T" in timestamps["iso8601"]

    def test_timeline_event_structure(self):
        """Test timeline event structure."""
        event = {
            "timestamp": "2025-01-08T14:30:00Z",
            "source": "Windows Event Log",
            "event_type": "Process Creation",
            "details": "powershell.exe -enc ...",
            "artifact": "Security.evtx",
        }

        required_fields = ["timestamp", "source", "event_type", "details"]
        for field in required_fields:
            assert field in event


class TestArtifactAnalysis:
    """Test artifact analysis concepts."""

    def test_windows_artifacts(self):
        """Test Windows artifact locations."""
        windows_artifacts = {
            "prefetch": "C:\\Windows\\Prefetch\\",
            "event_logs": "C:\\Windows\\System32\\winevt\\Logs\\",
            "registry": "C:\\Windows\\System32\\config\\",
            "amcache": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
            "shimcache": "SYSTEM registry hive",
            "mft": "$MFT",
            "usnjrnl": "$UsnJrnl",
        }

        assert "Prefetch" in windows_artifacts["prefetch"]
        assert "winevt" in windows_artifacts["event_logs"]

    def test_linux_artifacts(self):
        """Test Linux artifact locations."""
        linux_artifacts = {
            "auth_log": "/var/log/auth.log",
            "syslog": "/var/log/syslog",
            "bash_history": "~/.bash_history",
            "wtmp": "/var/log/wtmp",
            "cron": "/var/log/cron.log",
        }

        assert "/var/log" in linux_artifacts["auth_log"]


class TestMemoryForensics:
    """Test memory forensics concepts."""

    def test_memory_artifacts(self):
        """Test types of memory artifacts."""
        memory_artifacts = [
            "running_processes",
            "loaded_dlls",
            "network_connections",
            "registry_hives",
            "encryption_keys",
            "command_history",
            "injected_code",
        ]

        # All are volatile - only available in memory
        assert "running_processes" in memory_artifacts
        assert "encryption_keys" in memory_artifacts

    def test_volatility_plugins(self):
        """Test common Volatility plugins."""
        volatility_plugins = {
            "pslist": "List running processes",
            "psscan": "Scan for hidden processes",
            "netscan": "Network connections",
            "dlllist": "Loaded DLLs",
            "cmdline": "Command line arguments",
            "malfind": "Find injected code",
            "hashdump": "Extract password hashes",
        }

        assert "pslist" in volatility_plugins
        assert "malfind" in volatility_plugins


class TestNetworkForensics:
    """Test network forensics concepts."""

    def test_pcap_analysis_fields(self):
        """Test PCAP analysis key fields."""
        pcap_fields = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "payload": b"encrypted_data",
            "timestamp": "2025-01-08T14:30:00Z",
        }

        assert "src_ip" in pcap_fields
        assert "payload" in pcap_fields

    def test_network_iocs(self):
        """Test network IOC types."""
        network_iocs = {
            "ip_addresses": ["185.143.223.47"],
            "domains": ["evil.com"],
            "urls": ["http://evil.com/malware.exe"],
            "user_agents": ["PowerShell/5.0"],
            "ja3_hashes": ["abc123..."],
        }

        assert len(network_iocs["ip_addresses"]) > 0


class TestIncidentResponse:
    """Test incident response concepts."""

    def test_ir_phases(self):
        """Test IR lifecycle phases."""
        ir_phases = [
            "preparation",
            "identification",
            "containment",
            "eradication",
            "recovery",
            "lessons_learned",
        ]

        assert ir_phases[0] == "preparation"
        assert ir_phases[-1] == "lessons_learned"
        assert "containment" in ir_phases

    def test_containment_strategies(self):
        """Test containment strategies."""
        containment_actions = {
            "network": ["isolate_host", "block_ip", "sinkhole_domain"],
            "endpoint": ["disable_account", "kill_process", "quarantine_file"],
            "data": ["revoke_tokens", "reset_credentials"],
        }

        assert "isolate_host" in containment_actions["network"]
        assert "kill_process" in containment_actions["endpoint"]


class TestChainOfCustody:
    """Test chain of custody concepts."""

    def test_custody_record(self):
        """Test chain of custody record structure."""
        custody_record = {
            "evidence_id": "EV-2025-001",
            "description": "Disk image of workstation",
            "collected_by": "Analyst A",
            "collected_date": "2025-01-08T10:00:00Z",
            "hash_md5": "abc123...",
            "hash_sha256": "def456...",
            "transfers": [
                {
                    "from": "Analyst A",
                    "to": "Lab B",
                    "date": "2025-01-08T14:00:00Z",
                    "reason": "Analysis",
                }
            ],
        }

        assert "hash_sha256" in custody_record
        assert len(custody_record["transfers"]) > 0


class TestIOCManagement:
    """Test IOC management concepts."""

    def test_ioc_types(self):
        """Test IOC categorization."""
        ioc_types = {
            "atomic": ["ip", "domain", "hash", "email"],
            "computed": ["yara_rule", "sigma_rule", "snort_rule"],
            "behavioral": ["ttps", "attack_patterns"],
        }

        assert "ip" in ioc_types["atomic"]
        assert "yara_rule" in ioc_types["computed"]

    def test_ioc_confidence_levels(self):
        """Test IOC confidence scoring."""
        confidence_levels = {"high": 3, "medium": 2, "low": 1}

        # Higher is more confident
        assert confidence_levels["high"] > confidence_levels["low"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

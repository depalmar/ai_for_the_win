#!/usr/bin/env python3
"""
Lab 00a: Python for Security Fundamentals - Test Suite

Run tests with: pytest tests/test_exercises.py -v
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "starter"))
sys.path.insert(0, str(Path(__file__).parent.parent / "solution"))

# Try to import from solution (for reference tests)
try:
    from main import (
        analyze_failed_logins,
        generate_blocklist,
        is_private_ip,
        is_valid_ip,
        monitor_logs,
        parse_log_line,
    )

    SOLUTION_AVAILABLE = True
except ImportError:
    SOLUTION_AVAILABLE = False


# Get the data directory
DATA_DIR = Path(__file__).parent.parent / "data"


# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================


class TestIsValidIP:
    """Tests for the is_valid_ip helper function."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses should return True."""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("0.0.0.0") is True  # nosec B104
        assert is_valid_ip("255.255.255.255") is True

    def test_invalid_octet_range(self):
        """Octets outside 0-255 should return False."""
        assert is_valid_ip("256.1.2.3") is False
        assert is_valid_ip("192.168.1.256") is False
        assert is_valid_ip("-1.0.0.1") is False

    def test_incomplete_ip(self):
        """Incomplete IPs should return False."""
        assert is_valid_ip("192.168.1") is False
        assert is_valid_ip("192.168") is False
        assert is_valid_ip("192") is False

    def test_empty_and_invalid(self):
        """Empty strings and non-IP strings should return False."""
        assert is_valid_ip("") is False
        assert is_valid_ip("not_an_ip") is False
        assert is_valid_ip("hello.world.foo.bar") is False

    def test_whitespace_handling(self):
        """IPs with whitespace should be handled."""
        assert is_valid_ip("  192.168.1.1  ") is True
        assert is_valid_ip("\n10.0.0.1\n") is True


class TestIsPrivateIP:
    """Tests for the is_private_ip helper function."""

    def test_class_a_private(self):
        """10.0.0.0/8 range should be private."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_class_b_private(self):
        """172.16.0.0/12 range should be private."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True
        assert is_private_ip("172.15.0.1") is False  # Outside range
        assert is_private_ip("172.32.0.1") is False  # Outside range

    def test_class_c_private(self):
        """192.168.0.0/16 range should be private."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_public_ips(self):
        """Public IPs should return False."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("45.33.32.156") is False

    def test_invalid_ip_returns_false(self):
        """Invalid IPs should return False."""
        assert is_private_ip("256.1.2.3") is False
        assert is_private_ip("not_an_ip") is False


class TestParseLogLine:
    """Tests for the parse_log_line helper function."""

    def test_valid_log_line(self):
        """Valid log lines should be parsed correctly."""
        result = parse_log_line("2024-01-15 10:00:00 ERROR Database timeout")
        assert result is not None
        assert result["timestamp"] == "2024-01-15 10:00:00"
        assert result["level"] == "ERROR"
        assert result["message"] == "Database timeout"

    def test_different_levels(self):
        """Different log levels should be parsed."""
        for level in ["INFO", "WARN", "ERROR", "DEBUG"]:
            result = parse_log_line(f"2024-01-15 10:00:00 {level} Test message")
            assert result is not None
            assert result["level"] == level

    def test_invalid_format(self):
        """Invalid log lines should return None."""
        assert parse_log_line("This is not a log line") is None
        assert parse_log_line("") is None
        assert parse_log_line("2024-01-15 ERROR Missing timestamp") is None


# ============================================================================
# EXERCISE 1 TESTS
# ============================================================================


@pytest.mark.skipif(not SOLUTION_AVAILABLE, reason="Solution not available")
class TestFailedLoginAnalyzer:
    """Tests for Exercise 1: Failed Login Analyzer."""

    def test_returns_dict_with_required_keys(self):
        """Function should return dict with required keys."""
        result = analyze_failed_logins(str(DATA_DIR / "login_events.txt"))
        assert isinstance(result, dict)
        assert "failed_by_user" in result
        assert "flagged_users" in result
        assert "total_failures" in result

    def test_counts_failures_correctly(self):
        """Should count failed logins per user."""
        result = analyze_failed_logins(str(DATA_DIR / "login_events.txt"))
        assert result["failed_by_user"]["admin"] >= 6  # At least 6 admin failures

    def test_flags_users_with_many_failures(self):
        """Should flag users with >3 failures."""
        result = analyze_failed_logins(str(DATA_DIR / "login_events.txt"))
        assert "admin" in result["flagged_users"]

    def test_total_failures_count(self):
        """Should count total failures."""
        result = analyze_failed_logins(str(DATA_DIR / "login_events.txt"))
        assert result["total_failures"] > 0

    def test_with_custom_data(self):
        """Test with custom login data."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Test data\n")
            f.write("2024-01-15T10:00:00,testuser,FAILED,1.2.3.4\n")
            f.write("2024-01-15T10:00:01,testuser,FAILED,1.2.3.4\n")
            f.write("2024-01-15T10:00:02,testuser,FAILED,1.2.3.4\n")
            f.write("2024-01-15T10:00:03,testuser,FAILED,1.2.3.4\n")
            f.write("2024-01-15T10:00:04,testuser,SUCCESS,1.2.3.4\n")
            temp_path = f.name

        try:
            result = analyze_failed_logins(temp_path)
            assert result["failed_by_user"]["testuser"] == 4
            assert "testuser" in result["flagged_users"]
            assert result["total_failures"] == 4
        finally:
            os.unlink(temp_path)


# ============================================================================
# EXERCISE 2 TESTS
# ============================================================================


@pytest.mark.skipif(not SOLUTION_AVAILABLE, reason="Solution not available")
class TestBlocklistGenerator:
    """Tests for Exercise 2: IOC Blocklist Generator."""

    def test_returns_dict_with_required_keys(self):
        """Function should return dict with required keys."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            result = generate_blocklist(str(DATA_DIR / "iocs.txt"), output_path)
            assert isinstance(result, dict)
            assert "valid_public" in result
            assert "valid_private" in result
            assert "invalid" in result
            assert "total_processed" in result
        finally:
            os.unlink(output_path)

    def test_identifies_valid_public_ips(self):
        """Should identify valid public IPs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            result = generate_blocklist(str(DATA_DIR / "iocs.txt"), output_path)
            assert "45.33.32.156" in result["valid_public"]
            assert "185.143.223.47" in result["valid_public"]
        finally:
            os.unlink(output_path)

    def test_identifies_private_ips(self):
        """Should identify private IPs separately."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            result = generate_blocklist(str(DATA_DIR / "iocs.txt"), output_path)
            assert any("192.168" in ip for ip in result["valid_private"])
        finally:
            os.unlink(output_path)

    def test_writes_blocklist_file(self):
        """Should write blocklist to output file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            generate_blocklist(str(DATA_DIR / "iocs.txt"), output_path)
            assert os.path.exists(output_path)
            with open(output_path, "r") as f:
                content = f.read()
                assert "45.33.32.156" in content
        finally:
            os.unlink(output_path)


# ============================================================================
# EXERCISE 3 TESTS
# ============================================================================


@pytest.mark.skipif(not SOLUTION_AVAILABLE, reason="Solution not available")
class TestLogMonitor:
    """Tests for Exercise 3: Simple Log Monitor."""

    def test_returns_dict_with_required_keys(self):
        """Function should return dict with required keys."""
        result = monitor_logs(str(DATA_DIR / "server.log"))
        assert isinstance(result, dict)
        assert "by_hour" in result
        assert "total_errors" in result
        assert "total_warnings" in result
        assert "critical_hours" in result

    def test_counts_errors_and_warnings(self):
        """Should count ERROR and WARN messages."""
        result = monitor_logs(str(DATA_DIR / "server.log"))
        assert result["total_errors"] > 0
        assert result["total_warnings"] > 0

    def test_groups_by_hour(self):
        """Should group messages by hour."""
        result = monitor_logs(str(DATA_DIR / "server.log"))
        assert len(result["by_hour"]) > 0
        for hour, counts in result["by_hour"].items():
            assert "ERROR" in counts
            assert "WARN" in counts

    def test_identifies_critical_hours(self):
        """Should identify hours with >2 errors."""
        result = monitor_logs(str(DATA_DIR / "server.log"))
        # Based on our data, hours 09 and 11 should be critical
        assert len(result["critical_hours"]) > 0

    def test_with_custom_data(self):
        """Test with custom log data."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("2024-01-15 10:00:00 ERROR Error 1\n")
            f.write("2024-01-15 10:00:01 ERROR Error 2\n")
            f.write("2024-01-15 10:00:02 ERROR Error 3\n")
            f.write("2024-01-15 10:00:03 WARN Warning 1\n")
            f.write("2024-01-15 11:00:00 ERROR Error 4\n")
            temp_path = f.name

        try:
            result = monitor_logs(temp_path)
            assert result["total_errors"] == 4
            assert result["total_warnings"] == 1
            assert "10" in result["critical_hours"]
            assert result["by_hour"]["10"]["ERROR"] == 3
        finally:
            os.unlink(temp_path)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


@pytest.mark.skipif(not SOLUTION_AVAILABLE, reason="Solution not available")
class TestIntegration:
    """Integration tests that verify all exercises work together."""

    def test_all_data_files_exist(self):
        """All required data files should exist."""
        required_files = [
            "access.log",
            "login_events.txt",
            "iocs.txt",
            "server.log",
            "alerts.csv",
            "config.json",
        ]
        for filename in required_files:
            assert (DATA_DIR / filename).exists(), f"Missing: {filename}"

    def test_full_pipeline(self):
        """Run all exercises in sequence."""
        # Exercise 1
        login_result = analyze_failed_logins(str(DATA_DIR / "login_events.txt"))
        assert login_result["total_failures"] > 0

        # Exercise 2
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name
        try:
            blocklist_result = generate_blocklist(str(DATA_DIR / "iocs.txt"), output_path)
            assert len(blocklist_result["valid_public"]) > 0
        finally:
            os.unlink(output_path)

        # Exercise 3
        log_result = monitor_logs(str(DATA_DIR / "server.log"))
        assert log_result["total_errors"] > 0

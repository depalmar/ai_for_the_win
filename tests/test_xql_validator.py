"""Tests for XQL Query Validator."""

import pytest
import sys
from pathlib import Path

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.xql_validator import XQLValidator, validate_query, validate_file
from tools.xql_validator.validator import Severity, ValidationIssue


class TestXQLValidator:
    """Test XQL validation functionality."""

    def test_valid_query(self):
        """Test that a valid query passes validation."""
        query = """
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter actor_process_image_name = "powershell.exe"
| fields _time, agent_hostname, actor_process_command_line
| sort desc _time
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_missing_dataset(self):
        """Test detection of missing dataset declaration."""
        query = """
| filter event_type = ENUM.PROCESS
| limit 100
        """
        is_valid, issues = validate_query(query)
        codes = [i.code for i in issues]
        assert "W002" in codes

    def test_missing_limit(self):
        """Test detection of missing limit clause."""
        query = """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
        """
        is_valid, issues = validate_query(query)
        codes = [i.code for i in issues]
        assert "I002" in codes

    def test_wrong_function_length(self):
        """Test detection of wrong function name (length vs strlen)."""
        query = """
| dataset = xdr_data
| filter length(actor_process_command_line) > 100
| limit 100
        """
        is_valid, issues = validate_query(query)
        messages = [i.message for i in issues]
        assert any("strlen" in m for m in messages)

    def test_wrong_function_array_length(self):
        """Test detection of wrong function name (array_length vs arraylen)."""
        query = """
| dataset = xdr_data
| filter array_length(some_array) > 5
| limit 100
        """
        is_valid, issues = validate_query(query)
        messages = [i.message for i in issues]
        assert any("arraylen" in m for m in messages)

    def test_wrong_field_agent_ip(self):
        """Test detection of wrong field name (agent_ip vs agent_ip_addresses)."""
        query = """
| dataset = xdr_data
| fields agent_ip
| limit 100
        """
        is_valid, issues = validate_query(query)
        messages = [i.message for i in issues]
        assert any("agent_ip_addresses" in m for m in messages)

    def test_quoted_event_type(self):
        """Test detection of quoted event_type instead of ENUM."""
        query = """
| dataset = xdr_data
| filter event_type = "PROCESS"
| limit 100
        """
        is_valid, issues = validate_query(query)
        messages = [i.message for i in issues]
        assert any("ENUM" in m for m in messages)

    def test_invalid_stage(self):
        """Test detection of invalid stage name."""
        query = """
| dataset = xdr_data
| invalidstage something
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        assert len(errors) > 0
        assert any("invalidstage" in i.message.lower() for i in errors)

    def test_unclosed_parenthesis(self):
        """Test detection of unclosed parenthesis."""
        query = """
| dataset = xdr_data
| filter strlen(actor_process_command_line > 100
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        assert len(errors) > 0
        assert any("parenthes" in i.message.lower() for i in errors)

    def test_unclosed_quote(self):
        """Test detection of unclosed string quote."""
        query = """
| dataset = xdr_data
| filter actor_process_image_name = "powershell.exe
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        assert len(errors) > 0
        assert any("quote" in i.message.lower() for i in errors)

    def test_time_filter_detection(self):
        """Test detection of missing time filter."""
        query = """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100
        """
        is_valid, issues = validate_query(query)
        codes = [i.code for i in issues]
        assert "I001" in codes

    def test_time_filter_present_timestamp_diff(self):
        """Test that timestamp_diff is recognized as time filtering."""
        query = """
| dataset = xdr_data
| alter days_ago = timestamp_diff(current_time(), _time, "DAY")
| filter days_ago <= 7
| limit 100
        """
        is_valid, issues = validate_query(query)
        codes = [i.code for i in issues]
        assert "I001" not in codes

    def test_time_filter_present_now(self):
        """Test that now() is recognized as time filtering."""
        query = """
| dataset = xdr_data
| filter _time >= now() - duration("7d")
| limit 100
        """
        is_valid, issues = validate_query(query)
        codes = [i.code for i in issues]
        assert "I001" not in codes

    def test_comments_ignored(self):
        """Test that comments are ignored."""
        query = """
// This is a comment about length()
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100
        """
        is_valid, issues = validate_query(query)
        # Should not flag the length() in the comment
        wrong_function_issues = [i for i in issues if "strlen" in i.message]
        assert len(wrong_function_issues) == 0

    def test_format_issues_empty(self):
        """Test formatting when no issues."""
        validator = XQLValidator()
        validator.issues = []
        output = validator.format_issues()
        assert "No issues found" in output

    def test_format_issues_with_errors(self):
        """Test formatting with issues."""
        validator = XQLValidator()
        validator.issues = [
            ValidationIssue(
                line=1,
                column=0,
                severity=Severity.ERROR,
                code="E001",
                message="Test error",
                suggestion="Fix it",
            )
        ]
        output = validator.format_issues()
        assert "E001" in output
        assert "Test error" in output
        assert "Fix it" in output


class TestValidateFile:
    """Test file validation functionality."""

    def test_file_not_found(self, tmp_path):
        """Test handling of non-existent file."""
        is_valid, issues = validate_file(tmp_path / "nonexistent.xql")
        assert not is_valid
        assert any(i.code == "E999" for i in issues)

    def test_valid_file(self, tmp_path):
        """Test validation of a valid XQL file."""
        xql_file = tmp_path / "valid.xql"
        xql_file.write_text(
            """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100
        """
        )
        is_valid, issues = validate_file(xql_file)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_multiple_queries_in_file(self, tmp_path):
        """Test validation of file with multiple queries."""
        xql_file = tmp_path / "multi.xql"
        xql_file.write_text(
            """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100

| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| limit 50
        """
        )
        is_valid, issues = validate_file(xql_file)
        # Should validate both queries
        assert is_valid or len(issues) > 0


class TestValidateQuery:
    """Test the validate_query function."""

    def test_returns_tuple(self):
        """Test that validate_query returns a tuple."""
        result = validate_query("| dataset = xdr_data | limit 100")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_is_valid_boolean(self):
        """Test that is_valid is a boolean."""
        is_valid, _ = validate_query("| dataset = xdr_data | limit 100")
        assert isinstance(is_valid, bool)

    def test_issues_is_list(self):
        """Test that issues is a list."""
        _, issues = validate_query("| dataset = xdr_data | limit 100")
        assert isinstance(issues, list)

    def test_error_makes_invalid(self):
        """Test that an error makes the query invalid."""
        # Query with unclosed parenthesis should be invalid
        is_valid, issues = validate_query("| dataset = xdr_data | filter strlen(x")
        assert not is_valid
        assert any(i.severity == Severity.ERROR for i in issues)

    def test_warning_still_valid(self):
        """Test that warnings don't make query invalid."""
        # Query missing limit (info) should still be valid
        query = """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
        """
        is_valid, issues = validate_query(query)
        assert is_valid  # Warnings and info don't make it invalid

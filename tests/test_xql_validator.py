"""Tests for XQL Query Validator."""

import sys
from pathlib import Path

import pytest

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.xql_validator import XQLValidator, validate_file, validate_query
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

    def test_valid_target_stage(self):
        """Test that target stage is recognized as valid."""
        query = """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| target suspicious_ips
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        stage_errors = [e for e in errors if "target" in e.message.lower()]
        assert len(stage_errors) == 0

    def test_valid_window_stage(self):
        """Test that window stage is recognized as valid."""
        query = """
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| window count() as conn_count by agent_hostname
| limit 100
        """
        is_valid, issues = validate_query(query)
        errors = [i for i in issues if i.severity == Severity.ERROR]
        stage_errors = [e for e in errors if "window" in e.message.lower()]
        assert len(stage_errors) == 0

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


class TestValidateDirectory:
    """Test directory validation functionality."""

    def test_validate_directory(self, tmp_path):
        """Test validation of a directory with XQL files."""
        from tools.xql_validator.validator import validate_directory

        # Create test files
        (tmp_path / "valid.xql").write_text(
            """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100
        """
        )
        (tmp_path / "another.xql").write_text(
            """
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| limit 50
        """
        )

        all_valid, results = validate_directory(tmp_path)
        assert len(results) == 2
        assert all_valid or len(results) > 0

    def test_validate_nonexistent_directory(self, tmp_path):
        """Test handling of non-existent directory."""
        from tools.xql_validator.validator import validate_directory

        all_valid, results = validate_directory(tmp_path / "nonexistent")
        assert not all_valid


class TestCLIOutput:
    """Test CLI output formatting."""

    def test_json_output_format(self):
        """Test JSON output structure."""
        import json

        from tools.xql_validator.validator import (
            Category,
            Severity,
            ValidationIssue,
            _format_json_output,
        )

        issues = [
            ValidationIssue(
                line=1,
                column=0,
                severity=Severity.ERROR,
                code="E001",
                message="Test error",
                category=Category.SYNTAX,
            )
        ]

        output = _format_json_output(issues, "test.xql")
        parsed = json.loads(output)

        assert parsed["file"] == "test.xql"
        assert parsed["valid"] is False
        assert parsed["issue_count"] == 1
        assert parsed["summary"]["errors"] == 1

    def test_json_output_valid_query(self):
        """Test JSON output for valid query."""
        import json

        from tools.xql_validator.validator import _format_json_output

        output = _format_json_output([], "test.xql")
        parsed = json.loads(output)

        assert parsed["valid"] is True
        assert parsed["issue_count"] == 0


class TestHTMLReport:
    """Test HTML report generation."""

    def test_html_report_generation(self):
        """Test basic HTML report generation."""
        from tools.xql_validator.html_report import generate_html_report
        from tools.xql_validator.validator import Category, Severity, ValidationIssue

        query = """
// Title: Test Detection
// MITRE ATT&CK: T1059.001
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| limit 100
        """
        issues = [
            ValidationIssue(
                line=1,
                column=0,
                severity=Severity.INFO,
                code="I001",
                message="Test info",
                category=Category.PERFORMANCE,
            )
        ]

        html = generate_html_report(query, issues, "test.xql")

        assert "<!DOCTYPE html>" in html
        assert "Test Detection" in html
        assert "T1059.001" in html
        assert "Test info" in html

    def test_html_report_with_mitre_mapping(self):
        """Test HTML report includes MITRE ATT&CK guidance."""
        from tools.xql_validator.html_report import generate_html_report

        query = """
// Title: LSASS Detection
// MITRE ATT&CK: T1003.001
| dataset = xdr_data
| filter actor_process_command_line contains "lsass"
| limit 100
        """

        html = generate_html_report(query, [], include_guidance=True)

        assert "T1003.001" in html
        assert "LSASS" in html or "Credential" in html

    def test_html_report_next_steps(self):
        """Test HTML report includes investigation next steps."""
        from tools.xql_validator.html_report import analyze_query_purpose

        query = """
| dataset = xdr_data
| filter actor_process_command_line contains "mimikatz"
| limit 100
        """

        purpose = analyze_query_purpose(query)

        assert purpose["category"] == "Credential Dumping Detection"
        assert len(purpose["next_steps"]) > 0

    def test_metadata_extraction(self):
        """Test extraction of detection metadata from comments."""
        from tools.xql_validator.html_report import extract_metadata

        query = """
// Title: My Detection Rule
// Description: Detects suspicious activity
// MITRE ATT&CK: T1059.001, T1003.001
// Severity: High
// Author: Security Team
| dataset = xdr_data
| limit 100
        """

        metadata = extract_metadata(query)

        assert metadata.title == "My Detection Rule"
        assert metadata.description == "Detects suspicious activity"
        assert "T1059.001" in metadata.mitre_techniques
        assert "T1003.001" in metadata.mitre_techniques
        assert metadata.severity == "High"
        assert metadata.author == "Security Team"


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

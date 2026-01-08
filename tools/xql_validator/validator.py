"""
XQL Query Validator
Validates Cortex XDR XQL query syntax and best practices.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """Validation issue severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a query."""

    line: int
    column: int
    severity: Severity
    code: str
    message: str
    suggestion: Optional[str] = None


class XQLValidator:
    """Validates XQL query syntax and best practices."""

    # Valid XQL stages
    VALID_STAGES = {
        "dataset",
        "filter",
        "fields",
        "alter",
        "comp",
        "sort",
        "limit",
        "dedup",
        "join",
        "union",
        "config",
        "preset",
        "call",
        "arrayexpand",
        "bin",
        "iploc",
    }

    # Valid datasets
    VALID_DATASETS = {
        "xdr_data",
        "process_event_data",
        "file_event_data",
        "network_story",
        "endpoints",
        "host_inventory",
        "cloud_audit_logs",
        "alerts",
        "incidents",
        # XSIAM datasets
        "panw_ngfw_traffic_raw",
        "panw_ngfw_threat_raw",
        "panw_ngfw_url_raw",
        "panw_ngfw_system_raw",
    }

    # Valid functions
    VALID_FUNCTIONS = {
        # String functions
        "lowercase",
        "uppercase",
        "trim",
        "ltrim",
        "rtrim",
        "strlen",
        "substring",
        "split",
        "replace",
        "concat",
        "format_string",
        "contains",
        "extract",
        "coalesce",
        "json_extract",
        "json_extract_scalar",
        "parse_timestamp",
        "to_string",
        "incidr",
        # Array functions
        "arrayfilter",
        "arraymap",
        "arraycreate",
        "arrayconcat",
        "arraymerge",
        "arraylen",
        "arrayindex",
        "arraydistinct",
        # Math functions
        "add",
        "subtract",
        "multiply",
        "divide",
        "floor",
        "ceil",
        "round",
        "pow",
        "abs",
        "mod",
        # Aggregate functions
        "count",
        "count_distinct",
        "sum",
        "avg",
        "min",
        "max",
        "values",
        "first",
        "last",
        # Time functions
        "now",
        "current_time",
        "timestamp_diff",
        "timestamp_seconds",
        "timestamp_extract",
        "duration",
        "bin",
        "format_timestamp",
        # IP functions
        "incidr",
        "iploc",
    }

    # Common mistakes to check
    COMMON_MISTAKES = {
        r"\blength\s*\(": ("strlen", "Use strlen() instead of length()"),
        r"\barray_length\s*\(": ("arraylen", "Use arraylen() instead of array_length()"),
        r"\barrayconcat\s*\(": (
            "arraymerge",
            "Consider using arraymerge() for combining arrays",
        ),
        r"\bextract_time\s*\(": (
            "timestamp_extract",
            "Use timestamp_extract() instead of extract_time()",
        ),
        r'event_type\s*=\s*["\']': (
            "ENUM",
            "Use ENUM.PROCESS syntax instead of quoted strings for event_type",
        ),
        r"\bagent_ip\b(?!_addresses)": (
            "agent_ip_addresses",
            "Use agent_ip_addresses instead of agent_ip",
        ),
        r"\baction_dns_query_name\b": (
            "dns_query_name",
            "Use dns_query_name instead of action_dns_query_name",
        ),
    }

    def __init__(self):
        self.issues: list[ValidationIssue] = []

    def validate(self, query: str) -> list[ValidationIssue]:
        """Validate an XQL query and return any issues found."""
        self.issues = []
        lines = query.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            self._check_line(line_num, line)

        self._check_query_structure(query)
        return self.issues

    def _check_line(self, line_num: int, line: str):
        """Check a single line for issues."""
        # Check for common mistakes
        for pattern, (correct, message) in self.COMMON_MISTAKES.items():
            if re.search(pattern, line, re.IGNORECASE):
                match = re.search(pattern, line, re.IGNORECASE)
                self.issues.append(
                    ValidationIssue(
                        line=line_num,
                        column=match.start() if match else 0,
                        severity=Severity.WARNING,
                        code="W001",
                        message=message,
                        suggestion=f"Use {correct} instead",
                    )
                )

        # Check for invalid stage names
        stage_match = re.match(r"\|\s*(\w+)", line.strip())
        if stage_match:
            stage = stage_match.group(1).lower()
            if stage not in self.VALID_STAGES:
                self.issues.append(
                    ValidationIssue(
                        line=line_num,
                        column=line.find(stage),
                        severity=Severity.ERROR,
                        code="E001",
                        message=f"Unknown stage: {stage}",
                        suggestion=f"Valid stages: {', '.join(sorted(self.VALID_STAGES))}",
                    )
                )

        # Check for unclosed parentheses
        if line.count("(") != line.count(")"):
            self.issues.append(
                ValidationIssue(
                    line=line_num,
                    column=0,
                    severity=Severity.ERROR,
                    code="E002",
                    message="Mismatched parentheses",
                )
            )

        # Check for unclosed quotes
        single_quotes = line.count("'") - line.count("\\'")
        double_quotes = line.count('"') - line.count('\\"')
        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            self.issues.append(
                ValidationIssue(
                    line=line_num,
                    column=0,
                    severity=Severity.ERROR,
                    code="E003",
                    message="Unclosed string quote",
                )
            )

    def _check_query_structure(self, query: str):
        """Check overall query structure."""
        # Check for dataset declaration
        if "dataset" not in query.lower() and "preset" not in query.lower():
            self.issues.append(
                ValidationIssue(
                    line=1,
                    column=0,
                    severity=Severity.WARNING,
                    code="W002",
                    message="Query missing dataset or preset declaration",
                    suggestion="Add '| dataset = xdr_data' or use a preset",
                )
            )

        # Check for time filtering
        time_patterns = [
            r"_time\s*[><=]",
            r"timestamp_diff",
            r"now\s*\(\)",
            r"duration\s*\(",
            r"config\s+timeframe",
            r"days_ago",
        ]
        has_time_filter = any(re.search(p, query, re.IGNORECASE) for p in time_patterns)
        if not has_time_filter:
            self.issues.append(
                ValidationIssue(
                    line=1,
                    column=0,
                    severity=Severity.INFO,
                    code="I001",
                    message="Query may benefit from time filtering",
                    suggestion="Add time filter to improve performance",
                )
            )

        # Check for limit clause
        if "limit" not in query.lower():
            self.issues.append(
                ValidationIssue(
                    line=1,
                    column=0,
                    severity=Severity.INFO,
                    code="I002",
                    message="Query missing LIMIT clause",
                    suggestion="Add '| limit N' to prevent large result sets",
                )
            )

    def format_issues(self) -> str:
        """Format issues for display."""
        if not self.issues:
            return "No issues found."

        output = []
        for issue in sorted(self.issues, key=lambda x: (x.line, x.column)):
            icon = {"error": "X", "warning": "!", "info": "i"}[issue.severity.value]
            output.append(f"[{icon}] Line {issue.line}: [{issue.code}] {issue.message}")
            if issue.suggestion:
                output.append(f"    Suggestion: {issue.suggestion}")

        return "\n".join(output)


def validate_query(query: str) -> tuple[bool, list[ValidationIssue]]:
    """
    Validate an XQL query.

    Args:
        query: The XQL query string to validate

    Returns:
        Tuple of (is_valid, issues)
        is_valid is False if any errors were found
    """
    validator = XQLValidator()
    issues = validator.validate(query)
    has_errors = any(i.severity == Severity.ERROR for i in issues)
    return not has_errors, issues


def validate_file(file_path: str | Path) -> tuple[bool, list[ValidationIssue]]:
    """
    Validate XQL queries in a file.

    Args:
        file_path: Path to file containing XQL queries

    Returns:
        Tuple of (is_valid, issues)
    """
    path = Path(file_path)
    if not path.exists():
        return False, [
            ValidationIssue(
                line=0,
                column=0,
                severity=Severity.ERROR,
                code="E999",
                message=f"File not found: {file_path}",
            )
        ]

    content = path.read_text(encoding="utf-8")

    # Split by query separator (blank lines between queries)
    queries = re.split(r"\n\s*\n", content)

    all_issues = []
    validator = XQLValidator()

    for i, query in enumerate(queries, 1):
        if query.strip():
            issues = validator.validate(query)
            # Adjust line numbers for multi-query files
            for issue in issues:
                issue.message = f"[Query {i}] {issue.message}"
            all_issues.extend(issues)

    has_errors = any(i.severity == Severity.ERROR for i in all_issues)
    return not has_errors, all_issues


if __name__ == "__main__":
    # Example usage
    test_query = """
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter actor_process_image_name = "powershell.exe"
| filter length(actor_process_command_line) > 100
| fields _time, agent_hostname, actor_process_command_line
| sort desc _time
| limit 100
    """

    is_valid, issues = validate_query(test_query)
    print(f"Valid: {is_valid}")
    validator = XQLValidator()
    validator.issues = issues
    print(validator.format_issues())

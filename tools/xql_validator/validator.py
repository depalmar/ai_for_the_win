"""
XQL Query Validator
Validates Cortex XDR XQL query syntax and best practices.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """Validation issue severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    STYLE = "style"


class Category(Enum):
    """Issue categories for filtering."""

    SYNTAX = "syntax"
    PERFORMANCE = "performance"
    SECURITY = "security"
    BEST_PRACTICE = "best_practice"
    DEPRECATED = "deprecated"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a query."""

    line: int
    column: int
    severity: Severity
    code: str
    message: str
    suggestion: Optional[str] = None
    category: Category = Category.SYNTAX


@dataclass
class ValidationResult:
    """Complete validation result."""

    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


class XQLValidator:
    """Validates XQL query syntax and best practices."""

    # Pre-compiled regex patterns for performance (avoid recompilation in loops)
    # See: Architectural Review Section 2.1.2 - Regex Compilation Optimization
    STAGE_PATTERN: re.Pattern[str] = re.compile(r"\|\s*(?P<stage>[a-z_]+)", re.IGNORECASE)
    FUNCTION_PATTERN: re.Pattern[str] = re.compile(
        r"(?P<func>[a-zA-Z_][\w\.]*)\s*\(", re.IGNORECASE
    )
    LIMIT_PATTERN: re.Pattern[str] = re.compile(r"limit\s+(\d+)", re.IGNORECASE)

    # Valid XQL stages (including target, window for materialization/windowing)
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
        "view",
        # Added per architectural review - essential for detection chaining
        "target",  # Materialize results into dataset
        "window",  # Windowed aggregations
        "getrole",  # User role enrichment
    }

    # Valid datasets
    VALID_DATASETS = {
        # Core XDR datasets
        "xdr_data",
        "process_event_data",
        "file_event_data",
        "network_story",
        "endpoints",
        "host_inventory",
        "cloud_audit_logs",
        "alerts",
        "incidents",
        # XSIAM/NGFW datasets
        "panw_ngfw_traffic_raw",
        "panw_ngfw_threat_raw",
        "panw_ngfw_url_raw",
        "panw_ngfw_system_raw",
        "panw_ngfw_auth_raw",
        "panw_ngfw_decryption_raw",
        "panw_ngfw_globalprotect_raw",
        "panw_ngfw_hip_match_raw",
        "panw_ngfw_iptag_raw",
        "panw_ngfw_userid_raw",
        # Additional datasets
        "xdr_agent_event",
        "xdr_network_event",
    }

    # Valid functions organized by category
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
        "json_extract_array",
        "parse_timestamp",
        "to_string",
        "to_number",
        "to_boolean",
        "base64_decode",
        "base64_encode",
        "url_decode",
        "url_encode",
        "regex_match",
        "regex_replace",
        # Array functions
        "arrayfilter",
        "arraymap",
        "arraycreate",
        "arrayconcat",
        "arraymerge",
        "arraylen",
        "arrayindex",
        "arraydistinct",
        "arraysort",
        "arrayreverse",
        "arrayslice",
        # Added per architectural review - essential for multi-value field handling
        "array_contains",  # Check membership in array fields
        "array_distinct",  # Get unique values from array
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
        "log",
        "sqrt",
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
        "stddev",
        "variance",
        "percentile",
        # Time functions
        "now",
        "current_time",
        "timestamp_diff",
        "timestamp_seconds",
        "timestamp_extract",
        "duration",
        "bin",
        "format_timestamp",
        "parse_timestamp",
        # IP/Network functions
        "incidr",
        "iploc",
        "ip_to_int",
        "int_to_ip",
        # Conditional functions
        "if",
        "case",
        "coalesce",
        # Type functions
        "typeof",
        "to_string",
        "to_number",
        "to_timestamp",
    }

    # Common XDR fields for validation
    COMMON_FIELDS = {
        "_time",
        "agent_hostname",
        "agent_ip_addresses",
        "agent_id",
        "agent_os_type",
        "agent_os_version",
        "event_type",
        "event_sub_type",
        "action_type",
        # Process fields
        "actor_process_image_name",
        "actor_process_image_path",
        "actor_process_image_sha256",
        "actor_process_command_line",
        "actor_process_pid",
        "action_process_image_name",
        "action_process_image_path",
        "action_process_image_sha256",
        "action_process_command_line",
        "causality_actor_process_image_name",
        "causality_actor_process_command_line",
        # Network fields
        "action_remote_ip",
        "action_remote_port",
        "action_local_ip",
        "action_local_port",
        "dns_query_name",
        "dns_query_type",
        # File fields
        "action_file_name",
        "action_file_path",
        "action_file_sha256",
        # Registry fields
        "action_registry_key_name",
        "action_registry_value_name",
        "action_registry_data",
    }

    # Common mistakes to check
    COMMON_MISTAKES = {
        r"\blength\s*\(": {
            "correct": "strlen",
            "message": "Use strlen() instead of length()",
            "category": Category.DEPRECATED,
        },
        r"\barray_length\s*\(": {
            "correct": "arraylen",
            "message": "Use arraylen() instead of array_length()",
            "category": Category.DEPRECATED,
        },
        r"\bextract_time\s*\(": {
            "correct": "timestamp_extract",
            "message": "Use timestamp_extract() instead of extract_time()",
            "category": Category.DEPRECATED,
        },
        r'event_type\s*=\s*["\']': {
            "correct": "ENUM.TYPE",
            "message": "Use ENUM.PROCESS syntax instead of quoted strings",
            "category": Category.SYNTAX,
        },
        r"\bagent_ip\b(?!_addresses)": {
            "correct": "agent_ip_addresses",
            "message": "Use agent_ip_addresses instead of agent_ip",
            "category": Category.DEPRECATED,
        },
        r"\baction_dns_query_name\b": {
            "correct": "dns_query_name",
            "message": "Use dns_query_name instead of action_dns_query_name",
            "category": Category.DEPRECATED,
        },
        r"\btarget_process_": {
            "correct": "action_process_",
            "message": "Use action_process_* fields instead of target_process_*",
            "category": Category.DEPRECATED,
        },
        r"\bsrc_ip\b": {
            "correct": "action_local_ip",
            "message": "Use action_local_ip or action_remote_ip instead of src_ip",
            "category": Category.DEPRECATED,
        },
        r"\bdst_ip\b": {
            "correct": "action_remote_ip",
            "message": "Use action_remote_ip instead of dst_ip",
            "category": Category.DEPRECATED,
        },
    }

    # Security-sensitive patterns
    SECURITY_PATTERNS = {
        r"['\"].*\$\{.*\}.*['\"]": {
            "message": "Potential template injection in string literal",
            "severity": Severity.WARNING,
        },
        r"contains\s*\(\s*['\"]select\s": {
            "message": "SQL keyword in filter - verify this is intentional",
            "severity": Severity.INFO,
        },
    }

    # Performance anti-patterns
    PERFORMANCE_PATTERNS = {
        r"\|\s*filter.*\|\s*filter.*\|\s*filter": {
            "message": "Multiple consecutive filters - consider combining with AND",
            "suggestion": "Combine filters: filter A and B and C",
        },
        r"~=\s*['\"]\.": {
            "message": "Regex starting with wildcard is expensive",
            "suggestion": "Use contains() or restructure regex to avoid leading wildcard",
        },
        r"\*\s+from": {
            "message": "SELECT * pattern - specify needed fields for better performance",
            "suggestion": "Use | fields to select only required columns",
        },
    }

    def __init__(self, strict: bool = False):
        """
        Initialize validator.

        Args:
            strict: If True, treat warnings as errors
        """
        self.issues: list[ValidationIssue] = []
        self.strict = strict
        self._line_count = 0
        self._stage_count = 0

    def validate(self, query: str) -> list[ValidationIssue]:
        """Validate an XQL query and return any issues found."""
        self.issues = []
        self._current_query = query  # Store for use in _check_line
        lines = query.split("\n")
        self._line_count = len(lines)
        self._stage_count = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            self._check_line(line_num, line)
            if stripped.startswith("|"):
                self._stage_count += 1

        self._check_query_structure(query)
        self._check_security_patterns(query)
        self._check_performance_patterns(query)

        return self.issues

    def _check_line(self, line_num: int, line: str):
        """Check a single line for issues."""
        # Check for common mistakes
        for pattern, info in self.COMMON_MISTAKES.items():
            if re.search(pattern, line, re.IGNORECASE):
                match = re.search(pattern, line, re.IGNORECASE)
                self.issues.append(
                    ValidationIssue(
                        line=line_num,
                        column=match.start() if match else 0,
                        severity=Severity.WARNING,
                        code="W001",
                        message=info["message"],
                        suggestion=f"Use {info['correct']} instead",
                        category=info["category"],
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
                        category=Category.SYNTAX,
                    )
                )

        # Check for unclosed parentheses
        open_parens = line.count("(") - line.count("\\(")
        close_parens = line.count(")") - line.count("\\)")
        if open_parens != close_parens:
            self.issues.append(
                ValidationIssue(
                    line=line_num,
                    column=0,
                    severity=Severity.ERROR,
                    code="E002",
                    message="Mismatched parentheses",
                    category=Category.SYNTAX,
                )
            )

        # Check for unclosed quotes (improved detection)
        in_string = False
        quote_char = None
        for i, char in enumerate(line):
            if char in ('"', "'") and (i == 0 or line[i - 1] != "\\"):
                if not in_string:
                    in_string = True
                    quote_char = char
                elif char == quote_char:
                    in_string = False
                    quote_char = None
        if in_string:
            self.issues.append(
                ValidationIssue(
                    line=line_num,
                    column=0,
                    severity=Severity.ERROR,
                    code="E003",
                    message="Unclosed string quote",
                    category=Category.SYNTAX,
                )
            )

        # Check for deprecated regex operators
        if "=~" in line:
            self.issues.append(
                ValidationIssue(
                    line=line_num,
                    column=line.find("=~"),
                    severity=Severity.INFO,
                    code="I003",
                    message="Consider using ~= instead of =~ for consistency",
                    category=Category.STYLE,
                )
            )

        # Check for case sensitivity in filters
        if (
            re.search(r'["\'][A-Z].*["\']', line)
            and "config case_sensitive" not in self._current_query.lower()
        ):
            if "filter" in line.lower() and "~=" in line:
                self.issues.append(
                    ValidationIssue(
                        line=line_num,
                        column=0,
                        severity=Severity.INFO,
                        code="I004",
                        message="Query contains uppercase in regex without case_sensitive config",
                        suggestion="Add 'config case_sensitive = false' for case-insensitive matching",
                        category=Category.BEST_PRACTICE,
                    )
                )

    def _check_query_structure(self, query: str):
        """Check overall query structure."""
        query_lower = query.lower()

        # Check for dataset declaration
        if "dataset" not in query_lower and "preset" not in query_lower:
            self.issues.append(
                ValidationIssue(
                    line=1,
                    column=0,
                    severity=Severity.WARNING,
                    code="W002",
                    message="Query missing dataset or preset declaration",
                    suggestion="Add '| dataset = xdr_data' or use a preset",
                    category=Category.SYNTAX,
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
            r"hours_ago",
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
                    category=Category.PERFORMANCE,
                )
            )

        # Check for limit clause
        if "limit" not in query_lower:
            self.issues.append(
                ValidationIssue(
                    line=1,
                    column=0,
                    severity=Severity.INFO,
                    code="I002",
                    message="Query missing LIMIT clause",
                    suggestion="Add '| limit N' to prevent large result sets",
                    category=Category.PERFORMANCE,
                )
            )

        # Check for very large limits
        limit_match = re.search(r"limit\s+(\d+)", query_lower)
        if limit_match:
            limit_val = int(limit_match.group(1))
            if limit_val > 10000:
                self.issues.append(
                    ValidationIssue(
                        line=1,
                        column=0,
                        severity=Severity.WARNING,
                        code="W003",
                        message=f"Large limit value ({limit_val}) may impact performance",
                        suggestion="Consider reducing limit or using pagination",
                        category=Category.PERFORMANCE,
                    )
                )

        # Check for comp without by clause (aggregation check)
        if re.search(r"\|\s*comp\s+\w+\s*\(", query_lower):
            if " by " not in query_lower:
                self.issues.append(
                    ValidationIssue(
                        line=1,
                        column=0,
                        severity=Severity.INFO,
                        code="I005",
                        message="Aggregation (comp) without GROUP BY clause",
                        suggestion="Add 'by field1, field2' to group results",
                        category=Category.BEST_PRACTICE,
                    )
                )

    def _check_security_patterns(self, query: str):
        """Check for security-sensitive patterns."""
        for pattern, info in self.SECURITY_PATTERNS.items():
            if re.search(pattern, query, re.IGNORECASE):
                self.issues.append(
                    ValidationIssue(
                        line=1,
                        column=0,
                        severity=info["severity"],
                        code="S001",
                        message=info["message"],
                        category=Category.SECURITY,
                    )
                )

    def _check_performance_patterns(self, query: str):
        """Check for performance anti-patterns."""
        for pattern, info in self.PERFORMANCE_PATTERNS.items():
            if re.search(pattern, query, re.IGNORECASE):
                self.issues.append(
                    ValidationIssue(
                        line=1,
                        column=0,
                        severity=Severity.INFO,
                        code="P001",
                        message=info["message"],
                        suggestion=info.get("suggestion"),
                        category=Category.PERFORMANCE,
                    )
                )

    def get_stats(self) -> dict:
        """Get validation statistics."""
        return {
            "line_count": self._line_count,
            "stage_count": self._stage_count,
            "error_count": sum(1 for i in self.issues if i.severity == Severity.ERROR),
            "warning_count": sum(1 for i in self.issues if i.severity == Severity.WARNING),
            "info_count": sum(1 for i in self.issues if i.severity == Severity.INFO),
            "issues_by_category": {
                cat.value: sum(1 for i in self.issues if i.category == cat) for cat in Category
            },
        }

    def format_issues(self, show_category: bool = False) -> str:
        """Format issues for display."""
        if not self.issues:
            return "No issues found."

        output = []
        icons = {"error": "X", "warning": "!", "info": "i", "style": "*"}

        for issue in sorted(self.issues, key=lambda x: (x.severity.value, x.line, x.column)):
            icon = icons.get(issue.severity.value, "?")
            cat = f" [{issue.category.value}]" if show_category else ""
            output.append(f"[{icon}] Line {issue.line}:{cat} [{issue.code}] {issue.message}")
            if issue.suggestion:
                output.append(f"    Suggestion: {issue.suggestion}")

        return "\n".join(output)


def validate_query(query: str, strict: bool = False) -> tuple[bool, list[ValidationIssue]]:
    """
    Validate an XQL query.

    Args:
        query: The XQL query string to validate
        strict: If True, treat warnings as errors

    Returns:
        Tuple of (is_valid, issues)
        is_valid is False if any errors were found (or warnings in strict mode)
    """
    validator = XQLValidator(strict=strict)
    issues = validator.validate(query)

    if strict:
        has_problems = any(i.severity in (Severity.ERROR, Severity.WARNING) for i in issues)
    else:
        has_problems = any(i.severity == Severity.ERROR for i in issues)

    return not has_problems, issues


def validate_file(
    file_path: str | Path, strict: bool = False
) -> tuple[bool, list[ValidationIssue]]:
    """
    Validate XQL queries in a file.

    Args:
        file_path: Path to file containing XQL queries
        strict: If True, treat warnings as errors

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

    # Split by query separator (double newlines or comment headers)
    queries = re.split(r"\n\s*\n(?=//|config|\|)", content)

    all_issues = []
    validator = XQLValidator(strict=strict)

    for i, query in enumerate(queries, 1):
        if query.strip() and not query.strip().startswith("//"):
            issues = validator.validate(query)
            for issue in issues:
                issue.message = f"[Query {i}] {issue.message}"
            all_issues.extend(issues)

    if strict:
        has_problems = any(i.severity in (Severity.ERROR, Severity.WARNING) for i in all_issues)
    else:
        has_problems = any(i.severity == Severity.ERROR for i in all_issues)

    return not has_problems, all_issues


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
    print(validator.format_issues(show_category=True))
    print("\nStats:", validator.get_stats())

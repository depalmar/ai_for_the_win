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
        "json_object",  # Create JSON objects
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
        # Added per architectural review
        "approx_distinct",  # Approximate distinct count for large datasets
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
        # Added per architectural review - essential for network detection
        "incidr6",  # IPv6 CIDR matching
        "incidrlist",  # Check IP against list of CIDRs
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

        # Note: Parentheses balance is checked at query level, not per-line,
        # because XQL queries often span multiple lines with grouped conditions

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

    def _check_parentheses_balance(self, query: str):
        """Check that parentheses are balanced across the entire query."""
        # Remove comments and string literals before checking
        # This prevents false positives from parentheses inside strings/comments
        clean_query = ""
        in_string = False
        quote_char = None
        i = 0
        lines = query.split('\n')

        for line_num, line in enumerate(lines, 1):
            for i, char in enumerate(line):
                # Skip comments
                if not in_string and i < len(line) - 1 and line[i:i+2] == "//":
                    break

                # Track string state
                if char in ('"', "'") and (i == 0 or line[i - 1] != "\\"):
                    if not in_string:
                        in_string = True
                        quote_char = char
                    elif char == quote_char:
                        in_string = False
                        quote_char = None
                    continue

                # Only count parentheses outside strings
                if not in_string and char in "()":
                    clean_query += char

        # Count balance
        paren_count = 0
        first_unmatched_line = None

        for line_num, line in enumerate(lines, 1):
            in_string = False
            quote_char = None

            for i, char in enumerate(line):
                # Skip comments
                if not in_string and i < len(line) - 1 and line[i:i+2] == "//":
                    break

                # Track string state
                if char in ('"', "'") and (i == 0 or line[i - 1] != "\\"):
                    if not in_string:
                        in_string = True
                        quote_char = char
                    elif char == quote_char:
                        in_string = False
                        quote_char = None
                    continue

                if not in_string:
                    if char == "(":
                        paren_count += 1
                        if first_unmatched_line is None:
                            first_unmatched_line = line_num
                    elif char == ")":
                        paren_count -= 1
                        if paren_count == 0:
                            first_unmatched_line = None
                        elif paren_count < 0:
                            # More closing than opening
                            self.issues.append(
                                ValidationIssue(
                                    line=line_num,
                                    column=i,
                                    severity=Severity.ERROR,
                                    code="E002",
                                    message="Unexpected closing parenthesis",
                                    category=Category.SYNTAX,
                                )
                            )
                            return  # Stop after first error

        if paren_count > 0:
            self.issues.append(
                ValidationIssue(
                    line=first_unmatched_line or 1,
                    column=0,
                    severity=Severity.ERROR,
                    code="E002",
                    message=f"Unclosed parenthesis ({paren_count} opening without matching close)",
                    category=Category.SYNTAX,
                )
            )

    def _check_query_structure(self, query: str):
        """Check overall query structure."""
        query_lower = query.lower()

        # Check parentheses balance across entire query (not per-line)
        # This handles multi-line filter conditions correctly
        self._check_parentheses_balance(query)

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
            r"timeframe\s*=",  # config timeframe = 7d
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
                    suggestion="Add 'config timeframe = 7d' (simpler than timestamp_diff)",
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

        # Check for very large limits (uses pre-compiled LIMIT_PATTERN)
        limit_match = self.LIMIT_PATTERN.search(query_lower)
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


def validate_directory(
    dir_path: str | Path, pattern: str = "*.xql", strict: bool = False
) -> tuple[bool, dict[str, list[ValidationIssue]]]:
    """
    Validate all XQL files in a directory.

    Args:
        dir_path: Path to directory containing XQL files
        pattern: Glob pattern for XQL files
        strict: If True, treat warnings as errors

    Returns:
        Tuple of (all_valid, {filename: issues})
    """
    path = Path(dir_path)
    if not path.is_dir():
        return False, {str(dir_path): [ValidationIssue(
            line=0, column=0, severity=Severity.ERROR,
            code="E998", message=f"Not a directory: {dir_path}"
        )]}

    results: dict[str, list[ValidationIssue]] = {}
    all_valid = True

    for xql_file in path.rglob(pattern):
        is_valid, issues = validate_file(xql_file, strict)
        results[str(xql_file)] = issues
        if not is_valid:
            all_valid = False

    return all_valid, results


# =============================================================================
# CLI Interface
# =============================================================================

def _format_rich_output(
    issues: list[ValidationIssue],
    file_path: str | None = None,
    show_stats: bool = True
) -> None:
    """Format and print issues using rich for colored output."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        console = Console()
    except ImportError:
        # Fallback to plain text if rich not available
        validator = XQLValidator()
        validator.issues = issues
        print(validator.format_issues(show_category=True))
        return

    if not issues:
        console.print("[bold green]No issues found.[/bold green]")
        return

    # Create severity icons with colors
    severity_styles = {
        Severity.ERROR: ("[bold red]X[/bold red]", "red"),
        Severity.WARNING: ("[bold yellow]![/bold yellow]", "yellow"),
        Severity.INFO: ("[bold blue]i[/bold blue]", "blue"),
        Severity.STYLE: ("[dim]*[/dim]", "dim"),
    }

    # Group issues by severity for summary
    by_severity = {s: [] for s in Severity}
    for issue in issues:
        by_severity[issue.severity].append(issue)

    # Print header
    title = f"Validation Results: {file_path}" if file_path else "Validation Results"
    console.print(f"\n[bold]{title}[/bold]\n")

    # Create issues table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("", width=3)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Code", width=6)
    table.add_column("Category", width=12)
    table.add_column("Message")
    table.add_column("Suggestion", style="dim")

    for issue in sorted(issues, key=lambda x: (x.severity.value, x.line)):
        icon, style = severity_styles.get(issue.severity, ("?", "white"))
        table.add_row(
            icon,
            str(issue.line),
            f"[{style}]{issue.code}[/{style}]",
            issue.category.value,
            issue.message,
            issue.suggestion or ""
        )

    console.print(table)

    # Print summary
    if show_stats:
        summary_parts = []
        if by_severity[Severity.ERROR]:
            summary_parts.append(f"[bold red]{len(by_severity[Severity.ERROR])} errors[/bold red]")
        if by_severity[Severity.WARNING]:
            summary_parts.append(f"[bold yellow]{len(by_severity[Severity.WARNING])} warnings[/bold yellow]")
        if by_severity[Severity.INFO]:
            summary_parts.append(f"[blue]{len(by_severity[Severity.INFO])} info[/blue]")
        if by_severity[Severity.STYLE]:
            summary_parts.append(f"[dim]{len(by_severity[Severity.STYLE])} style[/dim]")

        console.print(f"\n[bold]Summary:[/bold] {', '.join(summary_parts)}")


def _format_json_output(
    issues: list[ValidationIssue],
    file_path: str | None = None
) -> str:
    """Format issues as JSON for CI/CD integration."""
    import json

    return json.dumps({
        "file": file_path,
        "valid": not any(i.severity == Severity.ERROR for i in issues),
        "issue_count": len(issues),
        "issues": [
            {
                "line": i.line,
                "column": i.column,
                "severity": i.severity.value,
                "code": i.code,
                "category": i.category.value,
                "message": i.message,
                "suggestion": i.suggestion
            }
            for i in issues
        ],
        "summary": {
            "errors": sum(1 for i in issues if i.severity == Severity.ERROR),
            "warnings": sum(1 for i in issues if i.severity == Severity.WARNING),
            "info": sum(1 for i in issues if i.severity == Severity.INFO),
            "style": sum(1 for i in issues if i.severity == Severity.STYLE),
        }
    }, indent=2)


def main() -> int:
    """
    CLI entry point for the XQL validator.

    Returns:
        Exit code: 0=success, 1=errors found, 2=warnings only (strict mode)
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="xql-validator",
        description="Validate Cortex XDR XQL queries for syntax and best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0  All queries valid (no errors)
  1  Errors found (syntax violations)
  2  Warnings found (strict mode only)

Examples:
  %(prog)s query.xql                    Validate a single file
  %(prog)s queries/ --recursive         Validate all .xql files in directory
  %(prog)s -c "| dataset = xdr_data"    Validate inline query
  %(prog)s query.xql --format json      Output as JSON for CI/CD
  %(prog)s query.xql --strict           Treat warnings as errors
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "path",
        nargs="?",
        help="XQL file or directory to validate"
    )
    input_group.add_argument(
        "-c", "--command",
        metavar="QUERY",
        help="Validate an inline XQL query string"
    )

    # Validation options
    parser.add_argument(
        "-s", "--strict",
        action="store_true",
        help="Treat warnings as errors (exit code 2)"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively search directories for .xql files"
    )
    parser.add_argument(
        "--pattern",
        default="*.xql",
        help="Glob pattern for XQL files (default: *.xql)"
    )

    # Output options
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "html", "quiet"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file path (required for html format)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional details including style issues"
    )

    args = parser.parse_args()

    # Handle inline query
    if args.command:
        is_valid, issues = validate_query(args.command, strict=args.strict)

        if args.format == "json":
            print(_format_json_output(issues, "<inline>"))
        elif args.format == "html":
            from .html_report import generate_html_report
            html_content = generate_html_report(args.command, issues, "<inline>")
            if args.output:
                Path(args.output).write_text(html_content, encoding="utf-8")
                print(f"HTML report written to: {args.output}")
            else:
                print(html_content)
        elif args.format == "quiet":
            pass  # No output in quiet mode
        else:
            if args.no_color:
                validator = XQLValidator()
                validator.issues = issues
                print(validator.format_issues(show_category=True))
            else:
                _format_rich_output(issues, "<inline>")

        if not is_valid:
            return 1
        if args.strict and any(i.severity == Severity.WARNING for i in issues):
            return 2
        return 0

    # Handle file/directory input
    path = Path(args.path)

    if path.is_dir():
        if not args.recursive:
            # Only immediate children
            pattern = args.pattern
        else:
            pattern = f"**/{args.pattern}"

        all_valid, results = validate_directory(path, pattern, args.strict)

        if args.format == "json":
            import json
            output = {
                "valid": all_valid,
                "files_checked": len(results),
                "files": {
                    fp: _format_json_output(issues, fp)
                    for fp, issues in results.items()
                }
            }
            print(json.dumps(output, indent=2))
        elif args.format == "quiet":
            pass
        else:
            total_errors = 0
            total_warnings = 0
            for file_path, issues in results.items():
                if issues:
                    if args.no_color:
                        print(f"\n=== {file_path} ===")
                        validator = XQLValidator()
                        validator.issues = issues
                        print(validator.format_issues(show_category=True))
                    else:
                        _format_rich_output(issues, file_path, show_stats=False)
                    total_errors += sum(1 for i in issues if i.severity == Severity.ERROR)
                    total_warnings += sum(1 for i in issues if i.severity == Severity.WARNING)

            # Final summary
            print(f"\n{'='*60}")
            print(f"Checked {len(results)} file(s)")
            if total_errors:
                print(f"  Errors:   {total_errors}")
            if total_warnings:
                print(f"  Warnings: {total_warnings}")
            if not total_errors and not total_warnings:
                print("  All files valid!")

        if not all_valid:
            return 1
        return 0

    elif path.is_file():
        is_valid, issues = validate_file(path, strict=args.strict)

        if args.format == "json":
            print(_format_json_output(issues, str(path)))
        elif args.format == "html":
            from .html_report import generate_html_report
            query_content = path.read_text(encoding="utf-8")
            html_content = generate_html_report(query_content, issues, str(path))
            output_file = args.output or f"{path.stem}_report.html"
            Path(output_file).write_text(html_content, encoding="utf-8")
            print(f"HTML report written to: {output_file}")
        elif args.format == "quiet":
            pass
        else:
            if args.no_color:
                validator = XQLValidator()
                validator.issues = issues
                print(validator.format_issues(show_category=True))
            else:
                _format_rich_output(issues, str(path))

        if not is_valid:
            return 1
        if args.strict and any(i.severity == Severity.WARNING for i in issues):
            return 2
        return 0

    else:
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

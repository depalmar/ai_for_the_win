"""XQL Query Validator - Syntax checker for Cortex XSIAM/XDR XQL queries."""

from .ai_providers import (
    AIProvider,
    AIResponse,
    ClaudeProvider,
    GeminiProvider,
    GPTProvider,
    analyze_with_ai,
    enrich_report_with_ai,
    get_provider,
)
from .html_report import generate_html_report, generate_report_file
from .validator import (
    Category,
    Severity,
    ValidationIssue,
    XQLValidator,
    validate_directory,
    validate_file,
    validate_query,
)

__all__ = [
    # Validator
    "XQLValidator",
    "validate_query",
    "validate_file",
    "validate_directory",
    "ValidationIssue",
    "Severity",
    "Category",
    # HTML Report
    "generate_html_report",
    "generate_report_file",
    # AI Providers
    "AIProvider",
    "AIResponse",
    "get_provider",
    "analyze_with_ai",
    "enrich_report_with_ai",
    "ClaudeProvider",
    "GPTProvider",
    "GeminiProvider",
]
__version__ = "1.2.0"

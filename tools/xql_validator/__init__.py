"""XQL Query Validator - Syntax checker for Cortex XDR XQL queries."""

from .validator import (
    XQLValidator,
    validate_file,
    validate_query,
    validate_directory,
    ValidationIssue,
    Severity,
    Category,
)
from .html_report import generate_html_report, generate_report_file
from .ai_providers import (
    AIProvider,
    AIResponse,
    get_provider,
    analyze_with_ai,
    enrich_report_with_ai,
    ClaudeProvider,
    GPTProvider,
    GeminiProvider,
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

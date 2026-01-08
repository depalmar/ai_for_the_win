"""XQL Query Validator - Syntax checker for Cortex XDR XQL queries."""

from .validator import XQLValidator, validate_query, validate_file

__all__ = ["XQLValidator", "validate_query", "validate_file"]
__version__ = "1.0.0"

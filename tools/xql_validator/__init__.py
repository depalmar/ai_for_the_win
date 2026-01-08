"""XQL Query Validator - Syntax checker for Cortex XSIAM/XDR XQL queries."""

from .validator import XQLValidator, validate_file, validate_query

__all__ = ["XQLValidator", "validate_query", "validate_file"]
__version__ = "1.2.0"

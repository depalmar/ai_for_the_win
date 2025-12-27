"""
Shared utilities for AI for the Win labs.

This module provides common functionality used across labs:
- IOC defanging/refanging for safe handling of malicious indicators
- LLM configuration with optimized token limits
- Data loading utilities
"""

from .ioc_utils import (
    classify_ip_risk,
    defang_all,
    defang_dict,
    defang_domain,
    defang_email,
    defang_ioc,
    defang_ip,
    defang_url,
    is_defanged,
    is_private_ip,
    refang_ioc,
)
from .llm_config import (
    DEFAULT_MAX_TOKENS,
    DETAILED_ANALYSIS_TOKENS,
    PROVIDER_CONFIG,
    TOKEN_LIMITS,
    detect_available_provider,
    get_analysis_llm,
    get_investigation_llm,
    get_llm,
    get_llm_config,
    get_quick_llm,
    get_report_llm,
)

__all__ = [
    # IOC utilities
    "defang_ioc",
    "defang_ip",
    "defang_domain",
    "defang_url",
    "defang_email",
    "refang_ioc",
    "is_defanged",
    "defang_all",
    "defang_dict",
    "is_private_ip",
    "classify_ip_risk",
    # LLM configuration
    "get_llm",
    "get_llm_config",
    "get_quick_llm",
    "get_analysis_llm",
    "get_report_llm",
    "get_investigation_llm",
    "detect_available_provider",
    "DEFAULT_MAX_TOKENS",
    "DETAILED_ANALYSIS_TOKENS",
    "TOKEN_LIMITS",
    "PROVIDER_CONFIG",
]

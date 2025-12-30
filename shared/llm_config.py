"""
LLM Configuration for AI for the Win Labs.

This module provides centralized LLM configuration with optimized token limits
for detailed AI-powered security analysis.

Usage:
    from shared.llm_config import (
        get_llm,
        get_llm_config,
        DEFAULT_MAX_TOKENS,
        DETAILED_ANALYSIS_TOKENS,
        PROVIDER_CONFIG,
    )

    # Get configured LLM instance
    llm = get_llm()

    # Or get raw config for custom setup
    config = get_llm_config(task_type="detailed_analysis")
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

# =============================================================================
# TOKEN LIMITS - Optimized for detailed security analysis
# =============================================================================

# Default token limits for different task types
DEFAULT_MAX_TOKENS = 4096  # Standard analysis tasks
DETAILED_ANALYSIS_TOKENS = 8192  # Comprehensive security reports
QUICK_RESPONSE_TOKENS = 1024  # Fast lookups, classifications
SUMMARY_TOKENS = 2048  # Summarization tasks

# Task-specific token configurations
TOKEN_LIMITS = {
    # Quick operations
    "classification": 512,
    "extraction": 1024,
    "lookup": 512,
    # Standard analysis
    "log_analysis": 4096,
    "ioc_analysis": 4096,
    "detection_rule": 4096,
    "yara_generation": 4096,
    "threat_assessment": 4096,
    # Detailed analysis
    "forensic_report": 8192,
    "incident_report": 8192,
    "threat_intel_report": 8192,
    "attack_chain_analysis": 8192,
    "comprehensive_analysis": 8192,
    # Extended analysis
    "full_investigation": 16384,
    "executive_summary": 4096,
}

# =============================================================================
# PROVIDER CONFIGURATIONS
# =============================================================================


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""

    env_key: str
    default_model: str
    max_tokens_param: str  # API parameter name for max tokens
    supports_extended_tokens: bool = True


PROVIDER_CONFIG = {
    "anthropic": ProviderConfig(
        env_key="ANTHROPIC_API_KEY",
        default_model="claude-sonnet-4-20250514",
        max_tokens_param="max_tokens",
        supports_extended_tokens=True,
    ),
    "openai": ProviderConfig(
        env_key="OPENAI_API_KEY",
        default_model="gpt-4o",
        max_tokens_param="max_tokens",
        supports_extended_tokens=True,
    ),
    "google": ProviderConfig(
        env_key="GOOGLE_API_KEY",
        default_model="gemini-2.5-pro",
        max_tokens_param="max_output_tokens",
        supports_extended_tokens=True,
    ),
    "ollama": ProviderConfig(
        env_key="",  # No API key needed
        default_model="llama3.1:8b",
        max_tokens_param="num_predict",
        supports_extended_tokens=False,
    ),
}

# =============================================================================
# PROVIDER DETECTION
# =============================================================================


def detect_available_provider() -> Optional[str]:
    """
    Detect which LLM provider is available based on environment variables.

    Returns:
        Provider name or None if no provider is configured.
    """
    # Priority order: Anthropic > OpenAI > Google > Ollama
    priority = ["anthropic", "openai", "google", "ollama"]

    for provider in priority:
        config = PROVIDER_CONFIG[provider]
        if config.env_key == "":  # Ollama - always available if installed
            # Could add a check for Ollama server here
            continue
        if os.environ.get(config.env_key):
            return provider

    return None


def get_provider_config(provider: Optional[str] = None) -> tuple[str, ProviderConfig]:
    """
    Get provider configuration.

    Args:
        provider: Provider name, or None to auto-detect.

    Returns:
        Tuple of (provider_name, ProviderConfig)

    Raises:
        ValueError: If no provider is available.
    """
    if provider is None:
        provider = detect_available_provider()

    if provider is None:
        raise ValueError(
            "No LLM provider available. Please set one of: "
            "ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY"
        )

    if provider not in PROVIDER_CONFIG:
        raise ValueError(f"Unknown provider: {provider}")

    return provider, PROVIDER_CONFIG[provider]


# =============================================================================
# LLM CONFIGURATION
# =============================================================================

TaskType = Literal[
    "classification",
    "extraction",
    "lookup",
    "log_analysis",
    "ioc_analysis",
    "detection_rule",
    "yara_generation",
    "threat_assessment",
    "forensic_report",
    "incident_report",
    "threat_intel_report",
    "attack_chain_analysis",
    "comprehensive_analysis",
    "full_investigation",
    "executive_summary",
]


def get_llm_config(
    task_type: TaskType = "log_analysis",
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
    override_max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Get LLM configuration for a specific task type.

    Args:
        task_type: Type of task to configure for.
        provider: LLM provider (auto-detected if None).
        model: Model name (uses provider default if None).
        temperature: Sampling temperature (0.0 for deterministic).
        override_max_tokens: Override the task-specific token limit.

    Returns:
        Dictionary with LLM configuration parameters.
    """
    provider_name, config = get_provider_config(provider)

    # Determine token limit
    if override_max_tokens is not None:
        max_tokens = override_max_tokens
    else:
        max_tokens = TOKEN_LIMITS.get(task_type, DEFAULT_MAX_TOKENS)

    return {
        "provider": provider_name,
        "model": model or config.default_model,
        "temperature": temperature,
        config.max_tokens_param: max_tokens,
    }


def get_llm(
    task_type: TaskType = "log_analysis",
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
    override_max_tokens: Optional[int] = None,
):
    """
    Get a configured LLM instance using LangChain.

    Args:
        task_type: Type of task to configure for.
        provider: LLM provider (auto-detected if None).
        model: Model name (uses provider default if None).
        temperature: Sampling temperature.
        override_max_tokens: Override the task-specific token limit.

    Returns:
        Configured LangChain LLM instance.

    Raises:
        ImportError: If required LangChain packages are not installed.
        ValueError: If no provider is available.
    """
    config = get_llm_config(task_type, provider, model, temperature, override_max_tokens)
    provider_name = config.pop("provider")

    if provider_name == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic

            return ChatAnthropic(**config)
        except ImportError:
            raise ImportError("Please install langchain-anthropic: pip install langchain-anthropic")

    elif provider_name == "openai":
        try:
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(**config)
        except ImportError:
            raise ImportError("Please install langchain-openai: pip install langchain-openai")

    elif provider_name == "google":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI

            return ChatGoogleGenerativeAI(**config)
        except ImportError:
            raise ImportError(
                "Please install langchain-google-genai: pip install langchain-google-genai"
            )

    elif provider_name == "ollama":
        try:
            from langchain_ollama import ChatOllama

            return ChatOllama(**config)
        except ImportError:
            raise ImportError("Please install langchain-ollama: pip install langchain-ollama")

    else:
        raise ValueError(f"Unknown provider: {provider_name}")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def get_quick_llm():
    """Get an LLM configured for quick responses (1024 tokens)."""
    return get_llm(task_type="extraction")


def get_analysis_llm():
    """Get an LLM configured for detailed analysis (4096 tokens)."""
    return get_llm(task_type="log_analysis")


def get_report_llm():
    """Get an LLM configured for comprehensive reports (8192 tokens)."""
    return get_llm(task_type="comprehensive_analysis")


def get_investigation_llm():
    """Get an LLM configured for full investigations (16384 tokens)."""
    return get_llm(task_type="full_investigation")


# =============================================================================
# DEMO
# =============================================================================

if __name__ == "__main__":
    print("=== LLM Configuration Demo ===\n")

    # Show available providers
    print("Checking available providers...")
    provider = detect_available_provider()
    if provider:
        print(f"  Active provider: {provider}")
    else:
        print("  No provider configured - set an API key")

    # Show token limits
    print("\nToken limits by task type:")
    for task, tokens in sorted(TOKEN_LIMITS.items(), key=lambda x: x[1]):
        print(f"  {task}: {tokens:,}")

    # Demo configuration
    if provider:
        print("\nExample configurations:")
        for task_type in ["extraction", "log_analysis", "comprehensive_analysis"]:
            config = get_llm_config(task_type=task_type)
            print(f"  {task_type}: {config}")

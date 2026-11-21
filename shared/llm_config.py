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


# Model defaults verified 2026-11-20 against each provider's deprecation page:
#   https://platform.claude.com/docs/en/about-claude/model-deprecations
#   https://developers.openai.com/api/docs/deprecations
#   https://ai.google.dev/gemini-api/docs/deprecations
# Re-verify with a web search before changing (see CLAUDE.md), then run
# scripts/check_ai_model_freshness.py, which knows the retired/retiring IDs.
PROVIDER_CONFIG = {
    "anthropic": ProviderConfig(
        env_key="ANTHROPIC_API_KEY",
        # Official replacement for claude-sonnet-4-5 (retires 2026-11-30)
        default_model="claude-sonnet-5-5",
        max_tokens_param="max_tokens",
        supports_extended_tokens=True,
    ),
    "openai": ProviderConfig(
        env_key="OPENAI_API_KEY",
        # gpt-5 shuts down 2026-12-11; GPT-6.2 Sol is OpenAI's everyday default
        default_model="gpt-6.2-sol",
        max_tokens_param="max_tokens",
        supports_extended_tokens=True,
    ),
    "google": ProviderConfig(
        env_key="GOOGLE_API_KEY",
        # Stable, no shutdown announced; replacement for gemini-2.5-pro (shuts down 2026-12-01)
        default_model="gemini-3.8-flash",
        max_tokens_param="max_output_tokens",
        supports_extended_tokens=True,
    ),
    "ollama": ProviderConfig(
        env_key="",  # No API key needed
        default_model="llama3.3:70b",  # Latest Llama (Dec 2024)
        max_tokens_param="num_predict",
        supports_extended_tokens=False,
    ),
}

# Claude Sonnet 5.5 runs adaptive thinking by default, so a response can start with a
# thinking block, and Claude 4.7+ models reject non-default temperature/top_p/top_k
# with a 400. These labs were written for models that did not think by default, so for
# Sonnet 5.5 we send its documented thinking-off mode, "between_tools": on requests
# without tools the model does not think and the response is text-only, as on Sonnet 4.x.
# Other Claude models reject "between_tools", so it is only sent to the models listed.
ANTHROPIC_THINKING_OFF = {"claude-sonnet-5-5": {"type": "between_tools"}}


def anthropic_request_params(model: str) -> Dict[str, Any]:
    """Return the extra Messages API params a Claude model needs (may be empty)."""
    thinking = ANTHROPIC_THINKING_OFF.get(model)
    return {"thinking": thinking} if thinking else {}


def extract_text(response: Any) -> str:
    """Join the text blocks of an Anthropic response, skipping thinking blocks."""
    return "".join(block.text for block in response.content if block.type == "text")


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
        temperature: Sampling temperature (0.0 for deterministic). Not sent to
            Anthropic: current Claude models reject non-default sampling params.
        override_max_tokens: Override the task-specific token limit.

    Returns:
        Dictionary with LLM configuration parameters.
    """
    provider_name, config = get_provider_config(provider)
    model_name = model or config.default_model

    # Determine token limit
    if override_max_tokens is not None:
        max_tokens = override_max_tokens
    else:
        max_tokens = TOKEN_LIMITS.get(task_type, DEFAULT_MAX_TOKENS)

    llm_config = {
        "provider": provider_name,
        "model": model_name,
        config.max_tokens_param: max_tokens,
    }
    if provider_name == "anthropic":
        llm_config.update(anthropic_request_params(model_name))
    else:
        llm_config["temperature"] = temperature
    return llm_config


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
# DIRECT API SUPPORT (No LangChain required)
# =============================================================================


def query_llm(
    prompt: str,
    system_prompt: str = "You are a helpful security analyst assistant.",
    task_type: TaskType = "log_analysis",
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
) -> str:
    """
    Query an LLM directly without LangChain.

    Works with Anthropic, OpenAI, or Google APIs directly.
    Auto-detects provider based on available API keys.

    Args:
        prompt: The user prompt to send.
        system_prompt: System instructions for the model.
        task_type: Type of task (affects token limits).
        provider: LLM provider (auto-detected if None).
        model: Model name (uses provider default if None).
        temperature: Sampling temperature.

    Returns:
        The model's response text.

    Example:
        >>> response = query_llm("Analyze this log entry for threats...")
        >>> print(response)
    """
    provider_name, config = get_provider_config(provider)
    model_name = model or config.default_model
    max_tokens = TOKEN_LIMITS.get(task_type, DEFAULT_MAX_TOKENS)

    if provider_name == "anthropic":
        try:
            from anthropic import Anthropic

            client = Anthropic()
            response = client.messages.create(
                model=model_name,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                **anthropic_request_params(model_name),
            )
            return extract_text(response)
        except ImportError:
            raise ImportError("pip install anthropic")

    elif provider_name == "openai":
        try:
            from openai import OpenAI

            client = OpenAI()
            response = client.chat.completions.create(
                model=model_name,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content
        except ImportError:
            raise ImportError("pip install openai")

    elif provider_name == "google":
        try:
            import google.generativeai as genai

            genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
            model_instance = genai.GenerativeModel(model_name)
            response = model_instance.generate_content(
                f"{system_prompt}\n\n{prompt}",
                generation_config={"max_output_tokens": max_tokens, "temperature": temperature},
            )
            return response.text
        except ImportError:
            raise ImportError("pip install google-generativeai")

    else:
        raise ValueError(f"Direct API not supported for provider: {provider_name}")


def get_client(provider: Optional[str] = None):
    """
    Get a raw API client for the detected/specified provider.

    Returns:
        Tuple of (provider_name, client_instance)

    Example:
        >>> provider, client = get_client()
        >>> if provider == "anthropic":
        ...     response = client.messages.create(...)
    """
    provider_name, config = get_provider_config(provider)

    if provider_name == "anthropic":
        from anthropic import Anthropic

        return provider_name, Anthropic()
    elif provider_name == "openai":
        from openai import OpenAI

        return provider_name, OpenAI()
    elif provider_name == "google":
        import google.generativeai as genai

        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        return provider_name, genai
    else:
        raise ValueError(f"Unknown provider: {provider_name}")


# =============================================================================
# COLAB/NOTEBOOK HELPER - Copy this cell to notebooks for standalone use
# =============================================================================

NOTEBOOK_SETUP_CODE = '''
# === LLM Setup (Provider-Agnostic) ===
# This cell auto-detects your LLM provider based on API keys.
# Set ONE of these in Colab secrets or environment:
#   - ANTHROPIC_API_KEY (Claude)
#   - OPENAI_API_KEY (GPT)
#   - GOOGLE_API_KEY (Gemini)

import os

def setup_llm():
    """Detect and configure LLM provider."""
    providers = {
        "anthropic": ("ANTHROPIC_API_KEY", "claude-sonnet-5-5"),
        "openai": ("OPENAI_API_KEY", "gpt-6.2-sol"),
        "google": ("GOOGLE_API_KEY", "gemini-3.8-flash"),
    }

    for name, (key, model) in providers.items():
        if os.environ.get(key):
            print(f"✅ Using {name.title()} ({model})")
            return name, model

    raise ValueError("❌ No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")

def query_llm(prompt, system_prompt="You are a security analyst.", max_tokens=4096):
    """Query the configured LLM provider."""
    provider, model = setup_llm()

    if provider == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()
        response = client.messages.create(
            model=model, max_tokens=max_tokens, system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
            # Sonnet 5.5's thinking-off mode; remove it if you switch to another Claude model
            thinking={"type": "between_tools"},
        )
        return "".join(b.text for b in response.content if b.type == "text")

    elif provider == "openai":
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model=model, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    elif provider == "google":
        import google.generativeai as genai
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        model_instance = genai.GenerativeModel(model)
        response = model_instance.generate_content(f"{system_prompt}\\n\\n{prompt}")
        return response.text

# Test the setup
try:
    provider, model = setup_llm()
except ValueError as e:
    print(e)
'''


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

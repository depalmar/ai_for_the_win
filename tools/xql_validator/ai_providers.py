"""
AI Provider Integration for XQL Validator

Supports multiple AI providers for generating dynamic:
- Query explanations
- Threat context
- Detection tips
- False positive tuning suggestions
- Investigation playbooks

Providers:
- Claude (Anthropic API)
- GPT (OpenAI API)
- Gemini (Google API)
"""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AIProvider(Enum):
    """Supported AI providers."""

    CLAUDE = "claude"
    GPT = "gpt"
    GEMINI = "gemini"


@dataclass
class AIResponse:
    """Response from an AI provider."""

    query_explanation: str = ""
    threat_explanation: str = ""
    detection_tips: list[dict] = None
    fp_tuning: list[dict] = None
    next_steps: list[dict] = None
    related_queries: list[dict] = None
    raw_response: str = ""
    provider: str = ""
    model: str = ""

    def __post_init__(self):
        if self.detection_tips is None:
            self.detection_tips = []
        if self.fp_tuning is None:
            self.fp_tuning = []
        if self.next_steps is None:
            self.next_steps = []
        if self.related_queries is None:
            self.related_queries = []


class BaseAIProvider(ABC):
    """Abstract base class for AI providers."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def analyze_query(self, query: str, metadata: dict) -> AIResponse:
        """Analyze an XQL query and return enriched guidance."""
        pass

    def _build_prompt(self, query: str, metadata: dict) -> str:
        """Build the analysis prompt for the AI."""
        mitre_techniques = metadata.get("mitre_techniques", [])
        title = metadata.get("title", "Unknown Detection")
        severity = metadata.get("severity", "Medium")

        return f"""You are a Cortex XDR security analyst expert. Analyze this XQL detection query and provide comprehensive guidance.

## Query Information
- **Title**: {title}
- **Severity**: {severity}
- **MITRE ATT&CK**: {', '.join(mitre_techniques) if mitre_techniques else 'Not specified'}

## XQL Query
```xql
{query}
```

## XQL Syntax Reference (CRITICAL - Follow These Rules Exactly)

### Query Structure
- Config must be on ONE line: `config case_sensitive = false timeframe = 24h`
- Pipeline starts with: `| dataset = xdr_data`
- Each stage starts with `|` (pipe)

### Valid Stages
dataset, filter, alter, comp, fields, sort, limit, dedup, join, union, target, window, bin

### Filter Operators
- Equality: `=`, `!=`
- Comparison: `>`, `>=`, `<`, `<=`
- Contains: `contains`, `not contains`
- Regex: `~=` (e.g., `~= "(?i)pattern"`)
- List: `in ()`, `not in ()`
- Null check: `= null`, `!= null`

### Time Filtering (Use ONE of these)
1. Config timeframe: `config case_sensitive = false timeframe = 24h`
2. Relative time: `| filter _time >= now() - duration("7d")`

### Event Types (Use ENUM.)
ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY, ENUM.NETWORK, ENUM.LOGIN, ENUM.SCRIPT_EXECUTION

### Functions (Correct Names)
- String length: `strlen()` (NOT length())
- Array length: `arraylen()` (NOT array_length())
- Time binning: `bin(_time, 1h)`
- Aggregation: `count()`, `sum()`, `avg()`, `min()`, `max()`, `first()`, `last()`
- Extract: `extract(field, "regex")`
- Coalesce: `coalesce(field1, field2, "default")`

### Common Fields
- Time: `_time`
- Host: `agent_hostname`
- User: `actor_effective_username`
- Process: `actor_process_image_name`, `actor_process_command_line`
- File: `action_file_path`, `action_file_name`
- Network: `action_remote_ip`, `action_remote_port`
- Registry: `registry_key_name`, `action_registry_data`
- Parent: `causality_actor_process_image_name`

## Required Output (JSON format)
Provide your analysis as a JSON object with these fields:

{{
    "query_explanation": "Detailed explanation of what this query does, step by step. Include what data sources it queries, what filters it applies, and what the output represents.",

    "threat_explanation": "Explain the threat/attack technique this query detects. Include: what the attacker is trying to do, why it's dangerous, common tools used, and real-world examples.",

    "detection_tips": [
        {{
            "tip": "Brief description of detection approach",
            "xql": "// Comment explaining the query\\n// MITRE ATT&CK: https://attack.mitre.org/techniques/TXXXX/\\nconfig case_sensitive = false timeframe = 7d\\n| dataset = xdr_data\\n| filter ..."
        }}
    ],

    "fp_tuning": [
        {{
            "tip": "Description of false positive scenario to exclude",
            "xql": "// Comment explaining exclusion\\n| filter field not contains \\"value\\""
        }}
    ],

    "next_steps": [
        {{
            "step": "Investigation action to take",
            "xql": "// Comment explaining investigation purpose\\n// MITRE ATT&CK: https://attack.mitre.org/techniques/TXXXX/\\nconfig case_sensitive = false timeframe = 1h\\n| dataset = xdr_data\\n| filter agent_hostname = \\"<HOSTNAME>\\"\\n..."
        }}
    ],

    "related_queries": [
        {{
            "name": "Related detection name",
            "xql": "// Comment explaining related detection\\n// MITRE ATT&CK: https://attack.mitre.org/techniques/TXXXX/\\nconfig case_sensitive = false timeframe = 24h\\n| dataset = xdr_data\\n..."
        }}
    ]
}}

## Critical Rules
1. Config MUST be on ONE line: `config case_sensitive = false timeframe = 24h` (NOT two separate config lines)
2. Always include a comment at the start of each XQL explaining its purpose
3. Include MITRE ATT&CK link in comment for investigation/detection queries
4. Use `<HOSTNAME>`, `<USERNAME>`, `<IP_ADDRESS>` as placeholders
5. Use correct function names: `strlen` not `length`, `arraylen` not `array_length`
6. Use `ENUM.` prefix for event_type values

Respond ONLY with the JSON object, no other text."""

    def _parse_response(self, response_text: str, provider: str, model: str) -> AIResponse:
        """Parse the AI response into structured format."""
        try:
            # Try to extract JSON from the response
            # Handle cases where the response might have markdown code blocks
            text = response_text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]

            data = json.loads(text.strip())

            return AIResponse(
                query_explanation=data.get("query_explanation", ""),
                threat_explanation=data.get("threat_explanation", ""),
                detection_tips=data.get("detection_tips", []),
                fp_tuning=data.get("fp_tuning", []),
                next_steps=data.get("next_steps", []),
                related_queries=data.get("related_queries", []),
                raw_response=response_text,
                provider=provider,
                model=model,
            )
        except json.JSONDecodeError:
            # Return partial response with raw text
            return AIResponse(
                query_explanation=response_text,
                raw_response=response_text,
                provider=provider,
                model=model,
            )


class ClaudeProvider(BaseAIProvider):
    """Anthropic Claude API provider."""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            model=model or self.DEFAULT_MODEL,
        )

    def analyze_query(self, query: str, metadata: dict) -> AIResponse:
        """Analyze query using Claude API."""
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required. Install with: pip install anthropic")

        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

        client = anthropic.Anthropic(api_key=self.api_key)
        prompt = self._build_prompt(query, metadata)

        message = client.messages.create(
            model=self.model, max_tokens=4096, messages=[{"role": "user", "content": prompt}]
        )

        response_text = message.content[0].text
        return self._parse_response(response_text, "claude", self.model)


class GPTProvider(BaseAIProvider):
    """OpenAI GPT API provider."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"), model=model or self.DEFAULT_MODEL
        )

    def analyze_query(self, query: str, metadata: dict) -> AIResponse:
        """Analyze query using OpenAI API."""
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required. Install with: pip install openai")

        if not self.api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        client = openai.OpenAI(api_key=self.api_key)
        prompt = self._build_prompt(query, metadata)

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a Cortex XDR security analyst expert. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=4096,
            temperature=0.7,
        )

        response_text = response.choices[0].message.content
        return self._parse_response(response_text, "gpt", self.model)


class GeminiProvider(BaseAIProvider):
    """Google Gemini API provider."""

    DEFAULT_MODEL = "gemini-1.5-pro"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get("GOOGLE_API_KEY"), model=model or self.DEFAULT_MODEL
        )

    def analyze_query(self, query: str, metadata: dict) -> AIResponse:
        """Analyze query using Google Gemini API."""
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "google-generativeai package required. Install with: pip install google-generativeai"
            )

        if not self.api_key:
            raise ValueError(
                "Google API key required. Set GOOGLE_API_KEY environment variable "
                "or pass api_key parameter."
            )

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(self.model)
        prompt = self._build_prompt(query, metadata)

        response = model.generate_content(prompt)
        response_text = response.text

        return self._parse_response(response_text, "gemini", self.model)


def get_provider(provider: str | AIProvider, **kwargs) -> BaseAIProvider:
    """
    Factory function to get an AI provider instance.

    Args:
        provider: Provider name ('claude', 'gpt', 'gemini') or AIProvider enum
        **kwargs: Additional arguments passed to provider constructor
                  (api_key, model, etc.)

    Returns:
        Configured AI provider instance

    Example:
        >>> provider = get_provider("claude", api_key="sk-...")
        >>> response = provider.analyze_query(query, metadata)
    """
    if isinstance(provider, AIProvider):
        provider = provider.value

    providers = {
        "claude": ClaudeProvider,
        "gpt": GPTProvider,
        "openai": GPTProvider,  # Alias
        "gemini": GeminiProvider,
        "google": GeminiProvider,  # Alias
    }

    provider_class = providers.get(provider.lower())
    if not provider_class:
        raise ValueError(
            f"Unknown provider: {provider}. " f"Supported: {', '.join(providers.keys())}"
        )

    return provider_class(**kwargs)


def analyze_with_ai(query: str, metadata: dict, provider: str = "claude", **kwargs) -> AIResponse:
    """
    Convenience function to analyze a query with AI.

    Args:
        query: XQL query string
        metadata: Query metadata (title, severity, mitre_techniques, etc.)
        provider: AI provider to use ('claude', 'gpt', 'gemini')
        **kwargs: Additional provider arguments

    Returns:
        AIResponse with analysis results

    Example:
        >>> response = analyze_with_ai(
        ...     query="| dataset = xdr_data | filter ...",
        ...     metadata={"title": "LSASS Detection", "mitre_techniques": ["T1003.001"]},
        ...     provider="claude"
        ... )
        >>> print(response.query_explanation)
    """
    ai_provider = get_provider(provider, **kwargs)
    return ai_provider.analyze_query(query, metadata)


# =============================================================================
# Integration with HTML Report Generator
# =============================================================================


def enrich_report_with_ai(
    query: str, metadata: dict, provider: str = "claude", fallback_to_static: bool = True, **kwargs
) -> dict:
    """
    Enrich report data with AI-generated content.

    This function can be used to enhance the static MITRE_TECHNIQUES
    and analyze_query_purpose() output with dynamic AI-generated content.

    Args:
        query: XQL query string
        metadata: Query metadata
        provider: AI provider to use
        fallback_to_static: If True, return empty dict on failure (allows fallback)
        **kwargs: Additional provider arguments

    Returns:
        Dictionary with enriched content that can be merged with static analysis
    """
    try:
        response = analyze_with_ai(query, metadata, provider, **kwargs)

        return {
            "query_explanation": response.query_explanation,
            "threat_explanation": response.threat_explanation,
            "detection_tips": response.detection_tips,
            "fp_tuning": response.fp_tuning,
            "next_steps": response.next_steps,
            "related_queries": response.related_queries,
            "ai_provider": response.provider,
            "ai_model": response.model,
        }
    except Exception as e:
        if fallback_to_static:
            return {"ai_error": str(e)}
        raise


if __name__ == "__main__":
    # Example usage
    test_query = """
// Title: LSASS Memory Dump Detection
// MITRE ATT&CK: T1003.001
// Severity: Critical

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter (
    (actor_process_image_name in ("procdump.exe", "procdump64.exe")
     and actor_process_command_line contains "lsass")
    or
    (actor_process_image_name ~= "rundll32.exe"
     and actor_process_command_line contains "comsvcs"
     and actor_process_command_line contains "minidump")
)
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line
| sort desc _time
| limit 100
    """

    metadata = {
        "title": "LSASS Memory Dump Detection",
        "severity": "Critical",
        "mitre_techniques": ["T1003.001"],
    }

    # Check which provider is available
    providers_to_try = ["claude", "gpt", "gemini"]

    for provider_name in providers_to_try:
        try:
            print(f"\nTrying {provider_name}...")
            response = analyze_with_ai(test_query, metadata, provider=provider_name)
            print(f"Success with {provider_name}!")
            print(f"\nQuery Explanation:\n{response.query_explanation[:500]}...")
            break
        except (ImportError, ValueError) as e:
            print(f"  Skipped: {e}")
        except Exception as e:
            print(f"  Error: {e}")
    else:
        print("\nNo AI provider available. Set API keys or install required packages.")

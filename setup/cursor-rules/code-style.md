# Code Style Requirements

## Formatting (MUST FOLLOW)

- **Line length**: 100 characters (Black configured)
- **Formatter**: Black + isort (profile="black")
- **Type hints**: Required for all function parameters and returns
- **Docstrings**: Google style for public functions
- **Imports**: Sorted with isort, grouped by stdlib/third-party/local

## Example Function

```python
def analyze_threat(
    sample_data: dict[str, Any],
    threshold: float = 0.85,
    use_cache: bool = True,
) -> ThreatAnalysisResult:
    """Analyze a potential threat sample using ML classification.

    Args:
        sample_data: Dictionary containing sample features.
        threshold: Confidence threshold for positive classification.
        use_cache: Whether to use cached results if available.

    Returns:
        ThreatAnalysisResult with classification and confidence score.

    Raises:
        ValidationError: If sample_data is missing required fields.
    """
```

## Multi-Provider LLM Support

All LLM code must support multiple providers:

```python
from shared.llm_config import get_llm_client, get_chat_model

# Environment variables supported:
# ANTHROPIC_API_KEY - Claude (recommended)
# OPENAI_API_KEY - GPT-4
# GOOGLE_API_KEY - Gemini
# Ollama for local models (no key)
```

NEVER hardcode to a single LLM provider.

## Common Commands

```bash
# Format code
black . && isort .

# Lint
flake8 .

# Security scan
bandit -r labs/
```

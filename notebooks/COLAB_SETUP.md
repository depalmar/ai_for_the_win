# Colab Notebook Setup Guide

All notebooks in this repository are **provider-agnostic**. They work with:
- **Anthropic Claude** (first choice when key exists)
- **OpenAI GPT**
- **Google Gemini**
- **Ollama** (automatic fallback when the notebook can reach `http://localhost:11434`, typically local runtime)

## Quick Setup (Copy to First Cell)

```python
# === LLM Setup (Provider-Agnostic) ===
# Set ONE API key in Colab Secrets (🔑 icon in sidebar), or run Ollama locally:
#   - ANTHROPIC_API_KEY (Claude)
#   - OPENAI_API_KEY (GPT)
#   - GOOGLE_API_KEY (Gemini)
# Optional:
#   - OLLAMA_MODEL (default: llama3.2:3b)

# Install dependencies
!pip install anthropic openai google-generativeai ollama httpx python-dotenv -q

import os
from google.colab import userdata

# Load API settings from Colab Secrets
for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]:
    try:
        value = userdata.get(key)
        if value:
            os.environ[key] = value
    except Exception:
        pass

def _ollama_available() -> bool:
    """Check whether a local Ollama server is reachable."""
    try:
        import httpx
        response = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        return response.status_code == 200
    except Exception:
        return False

def setup_llm(default_ollama_model: str = "llama3.2:3b"):
    """Detect and configure LLM provider.

    Provider priority matches the notebooks:
    Anthropic -> OpenAI -> Google -> Ollama.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", "claude-sonnet-4-5"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai", "gpt-5"
    if os.environ.get("GOOGLE_API_KEY"):
        return "google", "gemini-3-flash"
    if _ollama_available():
        return "ollama", os.environ.get("OLLAMA_MODEL", default_ollama_model)
    raise ValueError(
        "❌ No LLM provider configured. Add ANTHROPIC_API_KEY, OPENAI_API_KEY, "
        "GOOGLE_API_KEY, or run Ollama locally on http://localhost:11434."
    )

def query_llm(prompt, system_prompt="You are a security analyst.", max_tokens=4096):
    """Query the configured LLM provider."""
    provider, model = setup_llm()
    
    if provider == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()
        response = client.messages.create(
            model=model, max_tokens=max_tokens, system=system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    
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
        response = model_instance.generate_content(f"{system_prompt}\n\n{prompt}")
        return response.text

    else:
        import ollama
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        )
        return response["message"]["content"]

# Test setup
provider, model = setup_llm()
print(f"✅ Using {provider} ({model})")
```

## Setting Up API Keys in Colab

1. Click the **🔑 Secrets** icon in the left sidebar
2. Click **+ Add new secret**
3. Add your preferred API key:
   - Name: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`
   - Value: Your API key
4. Toggle **Notebook access** ON

> If you want to use local models, set `OLLAMA_MODEL` (optional) and make sure an Ollama server is running at `http://localhost:11434`.
> In hosted Colab runtimes, this localhost endpoint is usually not available; Ollama fallback is mainly for local/Jupyter runtimes.

## Using the LLM in Notebooks

After running the setup cell, use `query_llm()` anywhere:

```python
# Simple query
response = query_llm("What are the indicators of a phishing email?")
print(response)

# With custom system prompt
response = query_llm(
    "Analyze this log: Failed login from 192.168.1.100",
    system_prompt="You are a SOC analyst. Be concise.",
    max_tokens=1024
)
```

## Local Development

When running locally (not in Colab), you can either:

1. **Use environment variables** - Set `ANTHROPIC_API_KEY` etc. in your shell
2. **Use .env file** - Create `.env` with your keys
3. **Use shared module** - `from shared.llm_config import query_llm`

## Changing Models

To use different defaults, edit `setup_llm()` directly:

```python
if os.environ.get("ANTHROPIC_API_KEY"):
    return "anthropic", "claude-sonnet-4-5"  # Change model here
if os.environ.get("OPENAI_API_KEY"):
    return "openai", "gpt-5-mini"
if os.environ.get("GOOGLE_API_KEY"):
    return "google", "gemini-3-flash"
if _ollama_available():
    return "ollama", os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
```

### Available Models (Jan 2026)

**Anthropic Claude:**
| Model | Best For | Cost |
|-------|----------|------|
| `claude-opus-4.5` | Most capable, complex analysis | $$$ |
| `claude-sonnet-4.5` | Balanced performance (default) | $$ |
| `claude-haiku-4.5` | Fast, simple tasks | $ |

**OpenAI:**
| Model | Best For | Cost |
|-------|----------|------|
| `gpt-5` | Most capable, 1M+ context (default) | $$ |
| `gpt-5-mini` | Fast, cost-effective | $ |
| `o3` | Advanced reasoning | $$$ |

**Google Gemini:**
| Model | Best For | Cost |
|-------|----------|------|
| `gemini-3-pro` | Most capable | $$ |
| `gemini-3-flash` | Fast, free tier (default) | $ |

## Provider Comparison

| Provider | Default Model | Speed | Cost | Best For |
|----------|---------------|-------|------|----------|
| Anthropic | claude-sonnet-4-5 | Fast | $$ | Complex reasoning, code |
| OpenAI | gpt-5 | Fast | $$ | General purpose, 1M+ context |
| Google | gemini-3-flash | Very Fast | $ | Long context, free tier |

## Troubleshooting

**"No LLM provider configured"**
- Check that your secret name matches exactly (case-sensitive)
- Ensure "Notebook access" is enabled for the secret
- Or start Ollama locally: `ollama serve`

**"Rate limit exceeded"**  
- Wait a few minutes and retry
- Consider using a different provider

**Import errors**
- Re-run the `!pip install` cell
- Restart runtime if needed

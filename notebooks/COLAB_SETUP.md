# Colab Notebook Setup Guide

All notebooks in this repository are **provider-agnostic**. They work with:
- **Anthropic Claude**
- **OpenAI GPT**
- **Google Gemini**
- **Local Ollama** (no API key)

Provider detection order in notebook setup cells:
1. `ANTHROPIC_API_KEY`
2. `OPENAI_API_KEY`
3. `GOOGLE_API_KEY`
4. Local Ollama at `http://localhost:11434`

## Quick Setup (Copy to First Cell)

```python
# === LLM Setup (Provider-Agnostic) ===
# Set ONE API key in Colab Secrets (🔑 icon in sidebar):
#   - ANTHROPIC_API_KEY (Claude)
#   - OPENAI_API_KEY (GPT)
#   - GOOGLE_API_KEY (Gemini)
# Optional for local Ollama:
#   - OLLAMA_MODEL (default: llama3.2:3b)

# Install dependencies
!pip install anthropic openai google-generativeai ollama httpx python-dotenv -q

import os

# Load secrets from Colab when available
try:
    from google.colab import userdata
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_MODEL"]:
        try:
            os.environ[key] = userdata.get(key)
        except Exception:
            pass
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
    """Detect and configure LLM provider."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", "claude-sonnet-4-5"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai", "gpt-5"
    if os.environ.get("GOOGLE_API_KEY"):
        return "google", "gemini-3-flash"
    if _ollama_available():
        return "ollama", os.environ.get("OLLAMA_MODEL", default_ollama_model)
    raise ValueError(
        "❌ No LLM provider configured. Add ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, "
        "or run Ollama locally on http://localhost:11434"
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
                {"role": "user", "content": prompt}
            ],
        )
        return response["message"]["content"]

# Test setup
provider, model = setup_llm()
```

## Setting Up API Keys in Colab

1. Click the **🔑 Secrets** icon in the left sidebar
2. Click **+ Add new secret**
3. Add your preferred API key:
   - Name: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`
   - Value: Your API key
4. Toggle **Notebook access** ON

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

1. **Use environment variables** - Set one API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`)
2. **Use .env file** - Create `.env` with your key(s)
3. **Use local Ollama** - Start Ollama and (optionally) set `OLLAMA_MODEL`
4. **Use shared module** - `from shared.llm_config import query_llm`

Check local Ollama quickly:

```bash
curl http://localhost:11434/api/tags
```

## Changing Models

To use different defaults, edit the model strings in `setup_llm()`:

```python
def setup_llm(default_ollama_model: str = "llama3.2:3b"):
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", "claude-sonnet-4-5"  # Change model here
    if os.environ.get("OPENAI_API_KEY"):
        return "openai", "gpt-5"  # Change model here
    if os.environ.get("GOOGLE_API_KEY"):
        return "google", "gemini-3-flash"  # Change model here
    if _ollama_available():
        # Or set export OLLAMA_MODEL="your-model"
        return "ollama", os.environ.get("OLLAMA_MODEL", default_ollama_model)
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
| Anthropic | claude-sonnet-4.5 | Fast | $$ | Complex reasoning, code |
| OpenAI | gpt-5 | Fast | $$ | General purpose, 1M+ context |
| Google | gemini-3-flash | Very Fast | $ | Long context, free tier |

## Troubleshooting

**"No LLM provider configured"**
- Check secret names exactly match (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`)
- Ensure "Notebook access" is enabled in Colab Secrets
- If running locally with Ollama, verify `http://localhost:11434/api/tags` returns `200`
- Optionally set `OLLAMA_MODEL` if your preferred model is not the default

**"Rate limit exceeded"**  
- Wait a few minutes and retry
- Consider using a different provider

**Import errors**
- Re-run the `!pip install` cell
- Restart runtime if needed

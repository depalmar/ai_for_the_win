# Colab Notebook Setup Guide

All notebooks in this repository are **provider-agnostic**. They work with:
- **Anthropic Claude** (recommended)
- **OpenAI GPT-4**
- **Google Gemini**

## Quick Setup (Copy to First Cell)

```python
# === LLM Setup (Provider-Agnostic) ===
# Set ONE API key in Colab Secrets (🔑 icon in sidebar):
#   - ANTHROPIC_API_KEY (Claude)
#   - OPENAI_API_KEY (GPT-4)  
#   - GOOGLE_API_KEY (Gemini)

# Install dependencies
!pip install anthropic openai google-generativeai python-dotenv -q

import os
from google.colab import userdata

# Load API key from Colab Secrets
for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"]:
    try:
        os.environ[key] = userdata.get(key)
    except:
        pass

def setup_llm():
    """Detect and configure LLM provider."""
    providers = {
        "anthropic": ("ANTHROPIC_API_KEY", "claude-sonnet-4.5"),
        "openai": ("OPENAI_API_KEY", "gpt-5"),
        "google": ("GOOGLE_API_KEY", "gemini-3-flash"),
    }
    
    for name, (key, model) in providers.items():
        if os.environ.get(key):
            print(f"✅ Using {name.title()} ({model})")
            return name, model
    
    raise ValueError("❌ No API key found. Add one to Colab Secrets (🔑 sidebar)")

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

1. **Use environment variables** - Set `ANTHROPIC_API_KEY` etc. in your shell
2. **Use .env file** - Create `.env` with your keys
3. **Use shared module** - `from shared.llm_config import query_llm`

## Provider Comparison

| Provider | Model | Speed | Cost | Best For |
|----------|-------|-------|------|----------|
| Anthropic | claude-sonnet-4.5 | Fast | $$ | Complex reasoning, code |
| OpenAI | gpt-5 | Fast | $$ | General purpose, 1M+ context |
| Google | gemini-3-flash | Very Fast | $ | Long context, free tier |

## Troubleshooting

**"No API key found"**
- Check that your secret name matches exactly (case-sensitive)
- Ensure "Notebook access" is enabled for the secret

**"Rate limit exceeded"**  
- Wait a few minutes and retry
- Consider using a different provider

**Import errors**
- Re-run the `!pip install` cell
- Restart runtime if needed

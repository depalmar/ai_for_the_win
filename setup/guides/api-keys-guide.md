# API Keys Guide: Getting Started with LLM Providers

**Cost**: Free to start (all providers have free tiers)

Labs 04-20 use Large Language Models (LLMs) like Claude, GPT-4, or Gemini. This guide shows you how to get API keys and manage costs.

---

## Quick Start: Which Provider Should I Choose?

| Provider | Free Credits | Best For | Recommended Model |
|----------|--------------|----------|-------------------|
| **Anthropic (Claude)** | $5 free | Best reasoning, coding | `claude-sonnet-4-20250514` |
| **OpenAI (GPT)** | $5 free (new accounts) | Widely supported | `gpt-4o` |
| **Google (Gemini)** | Free tier (generous) | Budget-friendly | `gemini-2.0-flash` |
| **Ollama** | Completely free | Privacy, offline use | `llama3.2`, `mistral` |

**Recommendation**: Start with **Anthropic Claude** - it has the best reasoning for security tasks and $5 free credits.

---

## Option 1: Anthropic (Claude) - Recommended

### Step 1: Create an Account
1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Sign up with email or Google
3. Verify your email

### Step 2: Get Your API Key
1. Click on **API Keys** in the left sidebar
2. Click **Create Key**
3. Give it a name like "ai-security-labs"
4. Copy the key - you won't see it again!

### Step 3: Add to Your Project
Create a `.env` file in the project root:
```bash
# In the ai_for_the_win folder
cp .env.example .env
```

Edit `.env` and add your key:
```
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxx
```

### Pricing (2025)
| Model | Input | Output | Cost per Lab |
|-------|-------|--------|--------------|
| Claude Sonnet 4 | $3/1M tokens | $15/1M tokens | ~$0.10-0.50 |
| Claude Haiku 3.5 | $0.25/1M | $1.25/1M | ~$0.01-0.05 |

**Tip**: Use Haiku for testing, Sonnet for final runs.

---

## Option 2: OpenAI (GPT-4)

### Step 1: Create an Account
1. Go to [platform.openai.com](https://platform.openai.com/)
2. Sign up and verify your phone number
3. Add a payment method (required, but free credits cover initial use)

### Step 2: Get Your API Key
1. Go to [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Click **Create new secret key**
3. Copy and save it immediately

### Step 3: Add to Your Project
```
OPENAI_API_KEY=sk-xxxxxxxxxxxxx
```

### Pricing (2025)
| Model | Input | Output | Cost per Lab |
|-------|-------|--------|--------------|
| GPT-4o | $2.50/1M | $10/1M | ~$0.10-0.40 |
| GPT-4o-mini | $0.15/1M | $0.60/1M | ~$0.01-0.05 |

---

## Option 3: Google (Gemini) - Most Budget-Friendly

### Step 1: Create an Account
1. Go to [aistudio.google.com](https://aistudio.google.com/)
2. Sign in with your Google account
3. Accept the terms

### Step 2: Get Your API Key
1. Click **Get API Key** in the top right
2. Click **Create API Key**
3. Copy the key

### Step 3: Add to Your Project
```
GOOGLE_API_KEY=AIzaxxxxxxxxxxxxx
```

### Pricing (2025)
| Model | Input | Output | Cost per Lab |
|-------|-------|--------|--------------|
| Gemini 2.0 Flash | Free tier / $0.10/1M | $0.40/1M | ~$0.01-0.10 |
| Gemini 2.0 Pro | $1.25/1M | $5/1M | ~$0.05-0.25 |

**Best for**: Beginners on a budget - generous free tier!

---

## Option 4: Ollama (Free, Local, Private)

Run models on your own machine - completely free and private.

### Step 1: Install Ollama
**Windows/macOS**: Download from [ollama.ai](https://ollama.ai/)

**Linux**:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### Step 2: Pull a Model
```bash
# Lightweight and fast
ollama pull llama3.2

# Better reasoning
ollama pull mistral

# Coding-focused
ollama pull codellama
```

### Step 3: Configure the Labs
No API key needed! Set in `.env`:
```
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2
```

### Requirements
- 8GB RAM minimum (16GB recommended)
- 10-20GB disk space per model
- GPU optional but speeds things up significantly

---

## Managing Costs

### Set Spending Limits

**Anthropic**:
- Go to [console.anthropic.com/settings/limits](https://console.anthropic.com/settings/limits)
- Set a monthly limit (e.g., $10)

**OpenAI**:
- Go to [platform.openai.com/settings/organization/limits](https://platform.openai.com/settings/organization/limits)
- Set a hard cap

**Google**:
- Free tier is generous - 1M tokens/month free

### Cost-Saving Tips

1. **Start with free Labs 01-03** - no API needed, learn ML foundations
2. **Use cheaper models for testing** - Haiku, GPT-4o-mini, Gemini Flash
3. **Switch to full models for final runs**
4. **Run Ollama locally** for unlimited experimentation
5. **Cache responses** - avoid re-running the same prompts

### Estimated Costs Per Lab

| Lab Range | Estimated Cost | Notes |
|-----------|---------------|-------|
| Labs 01-03 | $0 | ML only, no LLM |
| Labs 04-07 | $0.50-2 | Basic LLM use |
| Labs 08-10 | $1-4 | More LLM calls |
| Labs 11-15 | $2-5 | Complex analysis |
| Labs 16-20 | $3-8 | Advanced features |

**Total for all LLM labs**: ~$15-30 with paid APIs, or **$0 with Ollama**

---

## Security Best Practices

### Never Commit API Keys

The `.env` file is already in `.gitignore`, but double-check:
```bash
git status
# .env should NOT appear in the list
```

### Use Environment Variables

Don't hardcode keys in your code:
```python
# BAD - never do this
api_key = "sk-ant-api03-xxxxx"

# GOOD - use environment variables
import os
api_key = os.getenv("ANTHROPIC_API_KEY")
```

### Rotate Keys Periodically

If you suspect a key was exposed:
1. Generate a new key
2. Update your `.env` file
3. Delete the old key from the provider's dashboard

### Use Separate Keys for Testing vs Production

Create multiple API keys:
- `ai-security-labs-dev` - for experimentation
- `ai-security-labs-prod` - for final runs

---

## Verify Your Setup

Run the verification script:
```bash
python scripts/verify_setup.py
```

You should see:
```
[✓] ANTHROPIC_API_KEY found
[✓] API connection successful
[✓] Ready for Labs 04+
```

---

## Troubleshooting

### "API key not found"
- Make sure `.env` is in the project root (same folder as `requirements.txt`)
- Check for typos in the variable name
- Restart your terminal after creating `.env`

### "Insufficient credits"
- Check your balance on the provider's dashboard
- Add payment method or switch to free tier model

### "Rate limit exceeded"
- Wait a few minutes and try again
- Use a smaller model
- Add delays between API calls

### "Invalid API key"
- Regenerate the key and try again
- Make sure you copied the full key (no extra spaces)

---

## Quick Reference

```bash
# Check which keys are configured
python -c "import os; print('Anthropic:', 'Yes' if os.getenv('ANTHROPIC_API_KEY') else 'No'); print('OpenAI:', 'Yes' if os.getenv('OPENAI_API_KEY') else 'No'); print('Google:', 'Yes' if os.getenv('GOOGLE_API_KEY') else 'No')"
```

---

## Next Steps

With your API key configured:
- [Lab 04: LLM Log Analysis](../../labs/lab04-llm-log-analysis/) - Your first LLM lab
- [Lab 05: Threat Intel Agent](../../labs/lab05-threat-intel-agent/) - Build an AI agent
- [Lab 06: Security RAG](../../labs/lab06-security-rag/) - Query your own docs

**No API key yet?** Start with [Lab 01: Phishing Classifier](../../labs/lab01-phishing-classifier/) - it uses ML, not LLMs!

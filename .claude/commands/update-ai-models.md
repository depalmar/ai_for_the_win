# Update AI Model References

Update AI model references across the curriculum to current versions.

## Instructions

**IMPORTANT: Web search for latest model info before updating.**

1. Search for current model versions:
   - `"Claude API models 2026 latest sonnet opus"` - Anthropic
   - `"GPT-5 models 2026 OpenAI latest"` - OpenAI
   - `"Gemini 3 models 2026 Google latest"` - Google
   - `"Llama 3.3 models 2026 Meta"` - Meta

2. Update the reference file first:
   ```
   scripts/check_ai_model_freshness.py
   ```
   - Update CURRENT_MODELS dict with new versions
   - Move old versions to "outdated" list
   - Update notes with release dates

3. Run the checker to find outdated references:
   ```bash
   python scripts/check_ai_model_freshness.py
   ```

4. Update files with outdated references:
   - Focus on code examples and API calls
   - Keep historical mentions labeled as such
   - Update model capability descriptions

## Current Model Guide (January 2026)

**IMPORTANT**: Always web search before updating - models change rapidly!

### Anthropic Claude
| Model | Use Case |
|-------|----------|
| claude-sonnet-4-5 | Best for coding/agents (Sep 2025) |
| claude-opus-4-5 | Most intelligent, complex reasoning |
| claude-haiku-4-5 | Fast, affordable (Oct 2025) |
| claude-sonnet-4 | Previous gen, still excellent |

### OpenAI GPT
| Model | Use Case |
|-------|----------|
| gpt-5.2 | Latest, 90%+ ARC-AGI (Dec 2025) |
| gpt-5 | General purpose |
| gpt-5.2-codex | Agentic coding |
| o1-pro | Advanced reasoning |

### Google Gemini
| Model | Use Case |
|-------|----------|
| gemini-3-flash | Default, 78% SWE-bench |
| gemini-3-pro | Complex reasoning, 1M context |
| gemini-2.5-pro | Production stable |
| gemini-2.5-flash | Fast general purpose |

### Meta Llama (Open Source)
| Model | Use Case |
|-------|----------|
| llama-3.3-70b | Best open source |
| llama-3.2-vision | Multimodal |
| llama-3.1-405b | Largest open model |

## Validation

After updating, run:
```bash
python scripts/check_ai_model_freshness.py
```

Should show: "All AI model references appear current"

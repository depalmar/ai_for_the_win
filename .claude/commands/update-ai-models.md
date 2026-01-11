# Update AI Model References

Update AI model references across the curriculum to current versions.

## Instructions

**IMPORTANT: Web search for latest model info before updating.**

1. Search for current model versions:
   - `"Claude API models 2025 2026 latest"` - Anthropic
   - `"GPT-4o o1 models 2025 OpenAI"` - OpenAI
   - `"Gemini 2.0 models 2025 Google"` - Google
   - `"Llama 3.3 models 2025 Meta"` - Meta

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

### Anthropic Claude
| Model | Use Case |
|-------|----------|
| claude-opus-4 | Most capable, complex reasoning |
| claude-sonnet-4 | Balanced performance/cost |
| claude-3-5-sonnet | Previous gen, still good |
| claude-3-5-haiku | Fast, affordable |

### OpenAI GPT
| Model | Use Case |
|-------|----------|
| o1-pro | Advanced reasoning |
| o1 / o1-mini | Reasoning tasks |
| gpt-4o | General purpose |
| gpt-4o-mini | Fast, affordable |

### Google Gemini
| Model | Use Case |
|-------|----------|
| gemini-2.0-flash | Fast, multimodal |
| gemini-1.5-pro | Long context (1M tokens) |
| gemini-1.5-flash | Fast general purpose |

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

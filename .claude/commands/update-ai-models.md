# Update AI Model References

Update AI model references across the curriculum to current versions.

## Instructions

**IMPORTANT: Web search for latest model info before updating.**

1. Search for current model versions:
   - `"Claude API models 2026 latest sonnet opus"` - Anthropic
   - `"GPT-5 models 2026 OpenAI latest"` - OpenAI
   - `"Gemini 3 models 2026 Google latest"` - Google
   - `"Llama 3.3 models 2026 Meta"` - Meta

2. Read each provider's deprecation page directly (search summaries get IDs wrong):
   - https://platform.claude.com/docs/en/about-claude/model-deprecations
   - https://developers.openai.com/api/docs/deprecations
   - https://ai.google.dev/gemini-api/docs/deprecations

3. Update the reference file first:
   ```
   scripts/check_ai_model_freshness.py
   ```
   - Add newly deprecated IDs to DEPRECATED_MODELS with the retirement date and the
     provider's recommended replacement (this is what fails CI on stale code)
   - Update CURRENT_MODELS dict with new versions
   - Update notes with release dates

4. Run the checker to find retired, retiring, and outdated references:
   ```bash
   python scripts/check_ai_model_freshness.py
   ```

5. Update files with outdated references:
   - Focus on code examples and API calls (shared/llm_config.py holds the defaults)
   - Check each new model's API changes, not just the ID: e.g. Claude 4.7+ models reject
     a non-default `temperature`, and Sonnet 5.5 thinks by default (read content by type)
   - Keep historical mentions labeled as such
   - Update model capability descriptions

## Current Model Guide (verified 2026-11-20)

**IMPORTANT**: Always web search before updating - models change rapidly!

### Anthropic Claude
| Model | Use Case |
|-------|----------|
| claude-sonnet-5-5 | Repo default; everyday coding and agents (thinking off: `between_tools`) |
| claude-opus-5-5 | Most capable Opus; complex reasoning |
| claude-haiku-5-5 | Fast, low cost (`thinking: disabled` for text-only replies) |
| claude-fable-5-2 | Most capable widely released model |

Retired or retiring: claude-sonnet-4-5 (2026-11-30), claude-sonnet-4 and claude-opus-4
(2026-06-15), claude-opus-4-1 (2026-08-05), all Claude 3.x.

### OpenAI GPT
| Model | Use Case |
|-------|----------|
| gpt-6.2-sol | Repo default; OpenAI's go-to model for everyday work |
| gpt-6.2-astra | Most capable, hardest projects |
| gpt-6.1-terra | Fast, efficient (replaces gpt-5-mini) |
| gpt-6-luna | Most efficient, high-volume tasks |

Retiring: gpt-5, gpt-5-mini, gpt-5-nano, gpt-5-pro, o3 (2026-12-11). Retired: o1, o1-pro,
o3-mini (2026-10-23).

### Google Gemini
| Model | Use Case |
|-------|----------|
| gemini-3.8-flash | Repo default; stable, no shutdown announced |
| gemini-3.5-flash-lite | Lightweight (replaces gemini-2.5-flash) |

Retiring: gemini-2.5-pro and gemini-2.5-flash (2026-12-01). Retired: gemini-3-pro-preview.

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

It must exit 0, meaning no retired or retiring model IDs in code (CI runs it too).
Warnings about prose mentions are fine when they are historical; update copy-paste
code samples in docs. `tests/test_ai_model_freshness.py` covers the checker itself.

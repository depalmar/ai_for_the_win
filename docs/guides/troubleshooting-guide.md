# Troubleshooting Guide

Common issues and solutions for the AI for the Win security training labs.

## Table of Contents

1. [API Key Issues](#api-key-issues)
2. [Installation Problems](#installation-problems)
3. [Setup Verification](#setup-verification-scriptsverify_setuppy)
4. [Lab-Specific Issues](#lab-specific-issues)
5. [Performance Problems](#performance-problems)
6. [Docker Issues](#docker-issues)

---

## API Key Issues

### "Invalid API Key" Error

**Symptoms:**
```
anthropic.AuthenticationError: Invalid API key
```

**Solutions:**

1. **Verify your API key is set:**
   ```bash
   echo $ANTHROPIC_API_KEY
   ```

2. **Set the API key:**
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

3. **For persistent configuration, add to your shell profile:**
   ```bash
   # ~/.bashrc or ~/.zshrc
   export ANTHROPIC_API_KEY="your-key-here"
   ```

4. **Check for leading/trailing whitespace:**
   ```python
   import os
   key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
   ```

### API Rate Limits

**Symptoms:**
```
RateLimitError: Rate limit exceeded
```

**Solutions:**

1. **Add retry logic:**
   ```python
   import time
   from anthropic import RateLimitError

   for attempt in range(3):
       try:
           response = client.messages.create(...)
           break
       except RateLimitError:
           time.sleep(2 ** attempt)
   ```

2. **Reduce request frequency**
3. **Check your API tier limits at console.anthropic.com**

### API Key Not Found in Environment

**Symptoms:**
```
ValueError: ANTHROPIC_API_KEY not found
```

**Solutions:**

1. **Use a .env file:**
   ```bash
   cp .env.example .env
   # Edit .env and add your key
   ```

2. **Load with python-dotenv:**
   ```python
   from dotenv import load_dotenv
   load_dotenv()
   ```

---

## Installation Problems

### ModuleNotFoundError

**Symptoms:**
```
ModuleNotFoundError: No module named 'anthropic'
```

**Solutions:**

1. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify you're in the right virtual environment:**
   ```bash
   which python
   pip list | grep anthropic
   ```

3. **Create a fresh virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Dependency Resolution Too Deep (Python 3.14)

**Symptoms:**
```
× Dependency resolution exceeded maximum depth
╰─> Pip cannot resolve the current dependencies as the dependency graph
    is too complex for pip to solve efficiently.
```

Also look for `cp314` in the error output — this confirms you're on Python 3.14.

**Root cause:** Python 3.14 is too new. Many packages (PyTorch, LangChain, etc.) don't have pre-built 3.14 wheels yet, which forces pip to explore thousands of version combinations until it gives up.

**Solutions (in order of preference):**

1. **Use Python 3.10, 3.11, or 3.12 (recommended):**
   ```bash
   # macOS with pyenv
   pyenv install 3.12.8
   pyenv local 3.12.8
   python -m venv venv && source venv/bin/activate
   pip install -r requirements.txt

   # macOS with Homebrew
   brew install python@3.12
   python3.12 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Use `uv` instead of pip (much faster resolver):**
   ```bash
   pip install uv
   uv pip install -r requirements.txt
   ```

3. **Install only what you need (lighter dependency graph):**
   ```bash
   pip install -e "."                  # Core only (Labs 00-13, no LLM)
   pip install -e ".[anthropic]"       # Core + Claude (Labs 00-18)
   pip install -e ".[ollama]"          # Core + Ollama (free, local)
   ```

4. **Check your Python version:**
   ```bash
   python --version
   python scripts/verify_setup.py      # Will warn about unsupported versions
   ```

### Dependency Conflicts

**Symptoms:**
```
ERROR: pip's dependency resolver does not currently take into account...
```

**Solutions:**

1. **Use a fresh virtual environment:**
   ```bash
   rm -rf venv
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Use `uv` for more reliable resolution:**
   ```bash
   pip install uv
   uv pip install -r requirements.txt
   ```

### Python Version Issues

**Symptoms:**
```
SyntaxError: invalid syntax
# or
TypeError: 'type' object is not subscriptable
```

**Solutions:**

1. **Verify Python version (3.10+ required):**
   ```bash
   python --version
   ```

2. **Use pyenv to install correct version:**
   ```bash
   pyenv install 3.11.0
   pyenv local 3.11.0
   ```

---

## Setup Verification (`scripts/verify_setup.py`)

### "No usable LLM provider!"

**Symptoms:**
```text
[FAIL] No usable LLM provider!
You need BOTH a package AND its configuration
```

**What this means:** The verifier checks complete provider stacks, not just API keys:
- **Ollama** needs `langchain_ollama` installed **and** the Ollama runtime running
- **Anthropic/OpenAI/Google** need provider package installed **and** API key set

**Solutions:**

1. **Install at least one provider package:**
   ```bash
   pip install -e ".[ollama]"     # Local, no API key
   pip install -e ".[anthropic]"  # Claude
   pip install -e ".[openai]"     # GPT
   pip install -e ".[google]"     # Gemini
   ```

2. **Configure the provider you installed:**
   ```bash
   # Local provider
   ollama serve

   # Cloud providers (set one or more)
   export ANTHROPIC_API_KEY="..."
   export OPENAI_API_KEY="..."
   export GOOGLE_API_KEY="..."
   ```

3. **Re-run setup verification:**
   ```bash
   python scripts/verify_setup.py
   ```

> Optional keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`) do not block lab setup.

### Python 3.14 Fails Verification

**Symptoms:**
```text
[FAIL] Python 3.14.x — NOT SUPPORTED
```

**Root cause:** `pyproject.toml` requires `<3.14`, and many transitive dependencies still lack stable 3.14 wheels.

**Fix:** Use Python 3.10-3.12 (3.13 is experimental) and recreate your virtual environment.

---

## Lab-Specific Issues

### Lab 01: Phishing Classifier

**Issue:** "TfidfVectorizer not found"
```bash
pip install scikit-learn
```

**Issue:** Poor classification results
- Ensure you have enough training data
- Check class balance
- Try adjusting max_features parameter

### Lab 04: LLM Log Analysis

**Issue:** Logs not parsing correctly
- Check log format matches expected pattern
- Verify timestamp format
- Try different regex patterns

### Lab 05: Threat Intel Agent

**Status:** ✅ **RESOLVED** - All tests now passing (21/21)

**What was fixed:**
- Updated LangChain ChatAnthropic model name to current API identifier (`claude-sonnet-4-20250514`)
- Updated ChatOpenAI model to `gpt-5` (from deprecated `gpt-4o`)
- Updated ChatGoogleGenerativeAI model to `gemini-2.5-pro` (from deprecated `gemini-1.5-pro`)

All agent tests now pass successfully. If you still see failures, ensure you have:
1. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY` in your `.env` file
2. Installed latest dependencies: `pip install --upgrade -r requirements.txt`

### Lab 06: Security RAG

**Issue:** "ChromaDB connection failed"
```bash
pip install chromadb
# or use the simple in-memory store provided
```

### Lab 11: Ransomware Detection

**Issue:** File monitoring not working
- Ensure you have read permissions on target directory
- Check watchdog installation: `pip install watchdog`

### Lab 12: Purple Team Simulation

**Status:** ✅ **RESOLVED** - All tests now passing (11/11)

**What was fixed:**
- Updated Anthropic SDK model name to current API identifier (`claude-sonnet-4-20250514`)
- Updated OpenAI model to `gpt-5` (from deprecated `gpt-4o`)
- Updated Google Gemini model to `gemini-2.5-pro` (from deprecated `gemini-1.5-pro`)

All LLM provider detection now works correctly. If you still see "No LLM provider available":
1. Verify API key is set: `echo $ANTHROPIC_API_KEY` (Linux/Mac) or `echo %ANTHROPIC_API_KEY%` (Windows)
2. Check `.env` file exists with valid key
3. Restart your terminal/IDE to load new environment variables

**Safety feature:** "Target directory must be in temp"
- This is intentional - only temp directories allowed for safety
- Use `tempfile.mkdtemp()` for test directories

---

## Performance Problems

### Slow API Responses

**Solutions:**

1. **Use streaming for long responses:**
   ```python
   with client.messages.stream(...) as stream:
       for text in stream.text_stream:
           print(text, end="", flush=True)
   ```

2. **Reduce max_tokens for faster responses**

3. **Use haiku model for simple tasks:**
   ```python
   model="claude-haiku-4-5-20251001"
   ```

### Memory Issues

**Symptoms:**
```
MemoryError
# or
Killed (out of memory)
```

**Solutions:**

1. **Process data in batches:**
   ```python
   for batch in chunks(data, size=100):
       process(batch)
   ```

2. **Use generators instead of lists:**
   ```python
   def process_logs(filepath):
       with open(filepath) as f:
           for line in f:
               yield parse_log(line)
   ```

3. **Reduce embedding dimensions or use simpler models**

---

## Docker Issues

### Build Failures

**Issue:** "pip install failed"
```bash
# Clean Docker cache
docker builder prune
docker compose build --no-cache
```

### Container Can't Access API Key

**Issue:** API key not available in container

**Solution:** Pass via environment:
```bash
docker compose run --rm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e GOOGLE_API_KEY="$GOOGLE_API_KEY" \
  jupyter python scripts/verify_setup.py
```

Or add provider keys directly to the `jupyter` service in `docker/docker-compose.yml`:
```yaml
services:
  jupyter:
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - GOOGLE_API_KEY=${GOOGLE_API_KEY}
```

### Port Already in Use

**Issue:** "Port 8888 is already in use"

**Solution:**
```bash
# Find process using port
lsof -i :8888
# Kill it or use different port
# then update docker/docker-compose.yml:
# ports:
#   - "8889:8888"
# and restart:
docker compose down && docker compose up -d
```

---

## Getting Help

If these solutions don't resolve your issue:

1. **Check existing issues:** https://github.com/depalmar/ai_for_the_win/issues
2. **Open a new issue** with:
   - Operating system and version
   - Python version
   - Full error message and traceback
   - Steps to reproduce
3. **Community resources:**
   - Anthropic Discord
   - Stack Overflow (tag: anthropic-api)

---

## Quick Diagnostic Commands

Use the built-in verifier first:

```bash
python scripts/verify_setup.py
```

Then run targeted checks:

```bash
python --version
pip show langchain-anthropic langchain-openai langchain-google-genai langchain-ollama
docker compose ps
docker compose logs --tail=100 jupyter
```

---

## Still Stuck? Use AI for Help

If the solutions above don't work, AI assistants are excellent at debugging:

### Ask AI for Help

Copy this template into Claude.ai or ChatGPT:

```
I'm working on [Lab name] in the AI for the Win security training course.

Problem:
[Describe what's happening]

Error message:
[Paste the full error traceback]

My code:
[Paste relevant code]

What I've tried:
[List what you've attempted]

Environment:
- OS: [Windows/Mac/Linux]
- Python version: [run `python --version`]
- Error happens when: [running script/importing/etc.]

Can you help me debug this?
```

### Pro Tips for AI Debugging

1. **Include the FULL error message** - The whole traceback, not just the last line
2. **Paste your actual code** - Don't paraphrase; copy-paste exactly
3. **Describe what you expected** - "I expected X but got Y"
4. **Mention what you've tried** - Helps AI avoid suggesting things you've already done

### Recommended AI Tools

| Tool | Best For | Link |
|------|----------|------|
| **Claude.ai** | Complex debugging, explanations | [claude.ai](https://claude.ai) |
| **ChatGPT** | Quick questions | [chat.openai.com](https://chat.openai.com) |
| **Phind** | Developer-focused search | [phind.com](https://phind.com) |

> 📖 See [Using AI for Learning](./using-ai-for-learning.md) for comprehensive tips on leveraging AI throughout the course.

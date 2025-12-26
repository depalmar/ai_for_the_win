# Troubleshooting Guide

Common issues and solutions for the AI for the Win security training labs.

## Table of Contents

1. [API Key Issues](#api-key-issues)
2. [Installation Problems](#installation-problems)
3. [Lab-Specific Issues](#lab-specific-issues)
4. [Performance Problems](#performance-problems)
5. [Docker Issues](#docker-issues)

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

2. **Try pip with legacy resolver:**
   ```bash
   pip install --use-deprecated=legacy-resolver -r requirements.txt
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

**Issue:** Agent tests failing (4 agent-related tests)

**Status:** Known issue - non-agent functionality works correctly (13/17 tests pass)

**Affected tests:**
- `test_agent_initialization`
- `test_investigate_ioc`
- `test_investigate_returns_classification`
- `test_investigate_with_context`

**Workaround:** Use the non-agent threat intelligence functions directly:
```python
from labs.lab05_threat_intel_agent.solution.main import (
    enrich_ip_address,
    check_ip_reputation,
    map_technique_to_tactic
)
```

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

**Issue:** "No LLM provider available" despite API key being set

**Status:** Known issue - All 11 tests failing with API key detection error

**Error message:**
```
ValueError: No LLM provider available. Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY
```

**Current investigation:** API key is properly set in environment but Lab12 is not detecting it. This appears to be a code issue in the lab's initialization logic.

**Workaround:** None currently available. This lab is being fixed in a future update.

**Other issue:** "Target directory must be in temp"
- This is a safety feature - only temp directories allowed
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
   model="claude-3-haiku-20240307"
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
docker-compose build --no-cache
```

### Container Can't Access API Key

**Issue:** API key not available in container

**Solution:** Pass via environment:
```bash
docker-compose run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY dev
```

Or use .env file:
```yaml
# docker-compose.yml
env_file:
  - .env
```

### Port Already in Use

**Issue:** "Port 8888 is already in use"

**Solution:**
```bash
# Find process using port
lsof -i :8888
# Kill it or use different port
docker-compose run -p 8889:8888 notebook
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

## Quick Diagnostic Script

Run this to check your environment:

```python
#!/usr/bin/env python3
"""Diagnostic script for AI for the Win labs."""

import sys
import os

def check_python():
    version = sys.version_info
    ok = version >= (3, 10)
    print(f"[{'OK' if ok else 'FAIL'}] Python: {version.major}.{version.minor}.{version.micro}")
    return ok

def check_api_key():
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    ok = key.startswith("sk-ant-")
    print(f"[{'OK' if ok else 'FAIL'}] ANTHROPIC_API_KEY: {'Set' if ok else 'Not set or invalid'}")
    return ok

def check_packages():
    required = ["anthropic", "pandas", "sklearn", "numpy"]
    all_ok = True
    for pkg in required:
        try:
            __import__(pkg.replace("-", "_"))
            print(f"[OK] {pkg}")
        except ImportError:
            print(f"[FAIL] {pkg} not installed")
            all_ok = False
    return all_ok

if __name__ == "__main__":
    print("=== AI for the Win - Environment Check ===\n")

    results = [
        check_python(),
        check_api_key(),
        check_packages()
    ]

    print("\n" + "=" * 40)
    if all(results):
        print("All checks passed!")
    else:
        print("Some checks failed. See above for details.")
```

Save as `check_env.py` and run:
```bash
python check_env.py
```

# Environment Verification

Verify your AI for the Win environment is correctly configured.

## Usage

```
/verify-setup           # Run full environment check
/verify-setup quick     # Quick check (Python + core packages only)
/verify-setup api       # Check API keys configuration
/verify-setup docker    # Check Docker environment
```

## Instructions

When the user invokes this command:

### 1. Full Verification (no args)

Run the verification script and interpret results:

```bash
python3 scripts/verify_setup.py
```

Then summarize:
- Python version status
- Full-environment required packages (numpy, pandas, sklearn, langchain, chromadb, yara, gradio)
- Optional packages (torch, transformers, litellm, instructor)
- LLM provider readiness (provider package plus API key or local Ollama runtime)
- Sample data, Lab 01 structure, and CTF infrastructure status

### 2. Quick Check

Only verify essentials:
```python
import sys
print(f"Python: {sys.version}")

# Core imports
import numpy, pandas, sklearn
print("Core ML packages: OK")
```

### 3. API Key Check

Check for configured API keys:
```python
import os
keys = {
    "ANTHROPIC_API_KEY": "Claude",
    "OPENAI_API_KEY": "OpenAI",
    "GOOGLE_API_KEY": "Gemini",
    "VIRUSTOTAL_API_KEY": "VirusTotal",
    "SHODAN_API_KEY": "Shodan"
}
for key, name in keys.items():
    status = "configured" if os.getenv(key) else "not set"
    print(f"{name}: {status}")
```

### 4. Docker Check

Verify Docker environment:
```bash
docker --version
docker compose version
docker ps
```

Check if lab services are available:
- Jupyter notebook
- Ollama
- ChromaDB
- Optional Elasticsearch/Kibana services from `docker/docker-compose.yml`

## Expected Output

```
## Environment Verification

### Python
✓ Python 3.11.5 (3.10+ required)

### Core Packages
✓ numpy 1.26.0
✓ pandas 2.1.0
✓ scikit-learn 1.3.0

### LLM Packages
✓ LangChain (LLM orchestration)
✓ ChromaDB (vector database)
! LiteLLM (unified LLM API) - not installed (optional)

### Security Tools
✓ yara-python 4.3.0

### LLM Configuration
✓ Anthropic (Claude) - READY (package installed + API key set)
! Ollama - package installed but runtime not available

### Docker
✓ Docker 24.0.6
✓ Docker Compose 2.21.0

### Summary
Environment ready!
- Core and data checks passed
- Labs 00-13 ready without LLM API keys
- Labs 14+ ready with one complete LLM provider stack
```

## Troubleshooting

If issues found, suggest fixes:

| Issue | Fix |
|-------|-----|
| Python < 3.10 | Install Python 3.10+ from python.org |
| Missing package in full verification | `pip install -r requirements.txt` |
| Core/ML-only setup needed | `pip install -e .` (enough for many Labs 00-13, but not a full verifier pass) |
| Missing LLM package | `pip install -e ".[ollama]"`, `".[anthropic]"`, `".[openai]"`, or `".[google]"` |
| API key set but provider package missing | Install the matching `pyproject.toml` extra |
| Provider package installed but API key missing | Add the key to `.env` or the shell environment |
| Ollama package installed but runtime unavailable | Run `ollama serve` or start the Docker `ollama-cpu` service |
| Docker not running | Start Docker Desktop or the Docker daemon |

## Quick Fix Commands

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install selectively for lab-specific work
pip install -e .
pip install -e ".[ollama]"  # or .[anthropic], .[openai], .[google]

# Create .env from template
cp .env.example .env

# Start Docker services
cd docker && docker compose up -d jupyter ollama-cpu chromadb
```

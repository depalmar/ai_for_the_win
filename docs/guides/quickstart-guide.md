# Quick Start Guide

Get a working AI for the Win environment in 10-15 minutes.

This guide is aligned to the current codebase:
- `docker/docker-compose.yml` service names
- selective provider installs from `pyproject.toml` extras
- runtime validation from `scripts/verify_setup.py`
- provider-agnostic notebook setup cells in `notebooks/*.ipynb`

---

## TL;DR

Choose one setup path:

1. **Docker (recommended for fastest onboarding)**
2. **Local Python venv (recommended for development)**
3. **Google Colab (zero local setup)**

Run `python scripts/verify_setup.py` after setup to confirm your environment.

---

## Path A: Docker (fastest)

### 1) Start core services

```bash
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win/docker

# Jupyter + local LLM + vector DB (good default for many LLM labs)
docker compose up -d jupyter ollama-cpu chromadb
```

### 2) Open Jupyter

- URL: http://localhost:8888
- Token: `aiforthewin`

### 3) Pull an Ollama model (once)

```bash
docker exec lab-ollama ollama pull llama3.2:3b
```

> Notebook setup cells use `llama3.2:3b` by default when falling back to Ollama.

### 4) Optional service bundles

```bash
# Log analysis labs
docker compose up -d elasticsearch kibana

# Cloud/data labs
docker compose up -d postgres minio redis
```

For full service details, see `docker/README.md`.

---

## Path B: Local Python (best for contributors)

### 1) Create and activate a virtual environment

```bash
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 2) Install dependencies (selective provider install)

```bash
# Core only (Labs 00-13)
pip install -e .

# Add ONE provider for LLM labs (14+)
pip install -e ".[ollama]"      # local/free
# or: pip install -e ".[anthropic]"
# or: pip install -e ".[openai]"
# or: pip install -e ".[google]"
```

### 3) Configure environment variables

```bash
cp .env.example .env
```

Set at least one cloud key in `.env` for cloud providers:
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GOOGLE_API_KEY`

If you use Ollama locally, no API key is required (runtime must be reachable at
`http://localhost:11434`).

### 4) Verify setup

```bash
python scripts/verify_setup.py
```

`verify_setup.py` validates:
- Python version support (`>=3.10,<3.14`)
- required package imports
- installed provider packages
- usable provider configuration (package + API key or Ollama runtime)
- sample data, Lab 01 structure, and CTF directories

---

## How notebook provider detection works

Many LLM notebooks (for example, `notebooks/lab15_llm_log_analysis.ipynb`) now use
a provider-agnostic setup cell:

1. Check for `ANTHROPIC_API_KEY`
2. Else check for `OPENAI_API_KEY`
3. Else check for `GOOGLE_API_KEY`
4. Else fall back to Ollama if `http://localhost:11434/api/tags` responds
5. Else raise a clear configuration error

This means you can run the same notebook with cloud APIs or local Ollama without
rewriting notebook logic.

---

## Path C: Google Colab (zero setup)

Open notebooks directly in Colab from the repository links in `README.md`, then set
secrets (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`) in Colab.

For local Ollama fallback, use Docker or local runtime instead of Colab.

---

## Common pitfalls

### "No usable LLM provider"

You installed base packages but did not finish provider config.

Fix:
- install one provider extra (for example `pip install -e ".[anthropic]"`), and
- set its API key in `.env`, or run Ollama and install `.[ollama]`.

### "Python 3.14 causes resolution-too-deep errors"

Use Python 3.10, 3.11, or 3.12 (3.13 is experimental). Recreate your venv after
switching Python.

### "Ollama package installed but runtime not available"

Start the runtime:

```bash
ollama serve
```

Or in Docker:

```bash
cd docker
docker compose up -d ollama-cpu
```

---

## First run checklist

1. Run `python scripts/verify_setup.py`
2. Start your first free lab:
   - `python labs/lab10-phishing-classifier/solution/main.py`
3. Start your first LLM notebook:
   - `notebooks/lab15_llm_log_analysis.ipynb`

---

## Next docs to read

- `docs/GETTING_STARTED.md`
- `docs/guides/api-keys-guide.md`
- `docs/guides/troubleshooting-guide.md`
- `docker/README.md`

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI for the Win is a hands-on training program for security practitioners building AI-powered tools. It contains 24 labs (including 4 intro labs), 4 capstone projects, and 15 CTF challenges covering threat detection, incident response, and security automation.

## Common Commands

```bash
# Setup
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Verify setup
python scripts/verify_setup.py

# Run all tests
pytest tests/ -v

# Run specific lab tests
pytest tests/test_lab01_phishing_classifier.py -v

# Run tests with coverage
pytest tests/ --cov=labs --cov-report=html

# Code formatting
black .
isort .

# Linting
flake8 .

# Security scan
bandit -r labs/

# Run a lab solution
python labs/lab01-phishing-classifier/solution/main.py

# Launch demos
python scripts/launcher.py

# Docker
docker-compose up dev
docker-compose run test
docker-compose up notebook  # Jupyter at localhost:8888
```

## Architecture

### Lab Structure
Each lab follows this pattern:
```
labXX-topic-name/
├── README.md         # Objectives, instructions, hints
├── starter/          # Starter code with TODOs
│   └── main.py
├── solution/         # Reference implementation
│   └── main.py
├── data/             # Sample datasets
└── tests/
    └── test_*.py
```

### Lab Progression
- **Labs 00a-00c**: Intro (Python, ML concepts, prompting) - no API keys needed
- **Labs 01-03**: ML foundations (classification, clustering, anomaly detection) - no API keys needed
- **Labs 04-07**: LLM basics (prompts, RAG, code generation) - requires API key
- **Labs 08-10**: Advanced (agents, pipelines, copilots)
- **Labs 11-19**: Expert (DFIR, forensics, C2 detection, adversarial ML)

### Multi-Provider LLM Support
All LLM labs support multiple providers via environment variables:
- `ANTHROPIC_API_KEY` - Claude (recommended)
- `OPENAI_API_KEY` - GPT-4
- `GOOGLE_API_KEY` - Gemini
- Ollama for local models (no key needed)

### Key Technologies
- **ML**: scikit-learn, PyTorch, Hugging Face
- **LLM**: LangChain, LangGraph, LiteLLM, Instructor
- **Vector DB**: ChromaDB, sentence-transformers
- **Security**: YARA, pefile, MITRE ATT&CK mappings
- **UI**: Gradio, Streamlit, FastAPI

## Code Style

- Python 3.10+ required
- Line length: 100 characters (configured in pyproject.toml)
- Use Black for formatting, isort for imports
- Type hints for function parameters and returns
- PEP 8 style guidelines

## Test Markers

```bash
pytest -m "not slow"           # Skip slow tests
pytest -m "not integration"    # Skip integration tests
pytest -m "not requires_api"   # Skip tests requiring API keys
```

## Important Directories

- `labs/` - 24 hands-on labs with starter/solution code
- `capstone-projects/` - 4 comprehensive projects
- `templates/` - Reusable agent, prompt, and visualization templates
- `resources/` - Tools, datasets, cheatsheets
- `mcp-servers/` - MCP server implementations
- `docs/guides/` - Troubleshooting and configuration guides
- `notebooks/` - Jupyter notebooks (Colab-ready)

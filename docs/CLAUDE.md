# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI for the Win is a hands-on training program for security practitioners building AI-powered tools. It contains 50+ labs, 4 capstone projects, and 15 CTF challenges covering threat detection, incident response, and security automation.

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
pytest tests/test_lab10_phishing_classifier.py -v

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
python labs/lab10-phishing-classifier/solution/main.py

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
- **Labs 00-09**: Foundation (Python, ML concepts, prompting) - no API keys needed
- **Labs 10-13**: ML foundations (classification, clustering, anomaly detection) - no API keys needed
- **Labs 14-18**: LLM basics (prompts, RAG, agents) - requires API key
- **Labs 19-24**: Detection engineering (pipelines, monitoring)
- **Labs 25-35**: DFIR (forensics, ransomware, C2 detection)
- **Labs 36-50**: Advanced (adversarial ML, cloud security, red team)

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

- `labs/` - 50+ hands-on labs with starter/solution code
- `capstone-projects/` - 4 comprehensive projects
- `templates/` - Reusable agent, prompt, and visualization templates
- `resources/` - Tools, datasets, cheatsheets
- `mcp-servers/` - MCP server implementations
- `docs/guides/` - Troubleshooting and configuration guides
- `notebooks/` - Jupyter notebooks (Colab-ready)

## Documentation Maintenance

### Lab Navigator (README.md)
When adding or modifying labs:
- The Lab Navigator table in README.md must display labs in **sequential order** (00, 01, 02, 03...)
- Never scramble lab order (e.g., 00, 01, 04, 02 is wrong)
- Update the legend if category ranges change
- Legend format: `Grey Foundation (00-09, Free) | Green ML Foundations (10-13, Free) | Purple LLM Basics (14-18) | Orange Detection/DFIR (19-29) | Red Advanced/Cloud (30-50)`
- Run `pytest tests/test_lab_data_integrity.py::TestLabCategoryConsistency -v` to verify

### GitHub Pages Lab Navigator (docs/index.md)
The docs/index.md file powers the GitHub Pages site at https://depalmar.github.io/ai_for_the_win/#labs

**Critical: Lab card display numbers MUST match folder numbers**
- Each lab card has a display number (`<span class="lab-number ...">XX</span>`)
- This display number MUST match the lab folder number in the href
- Example: `labs/lab23-detection-pipeline` must show display number `23`, not `09`

When adding or modifying labs in docs/index.md:
1. **Display number must match folder number**: lab23-* shows "23", lab24-* shows "24"
2. **Order labs sequentially**: 00, 01, 02... through 50
3. **Update category colors**: intro (grey), ml (green), llm (purple), advanced (orange), dfir (red)
4. **Run tests**: `pytest tests/test_lab_data_integrity.py::TestLabCategoryConsistency::test_index_md_lab_card_display_numbers_match_folder -v`

Common mistakes to avoid:
- Using old numbering scheme (09, 09b, 10, 10a) instead of actual folder numbers (23, 24, 25, 26)
- Mixing lab folder numbers with display numbers
- Forgetting to update both the href path AND the display number when renumbering

### Lab Category Ranges (Canonical)
Keep these in sync across all documentation:
| Category | Range | API Required |
|----------|-------|--------------|
| Foundation | 00-09 | No |
| ML Foundations | 10-13 | No |
| LLM Basics | 14-18 | Yes |
| Detection Engineering | 19-24 | Yes |
| DFIR | 25-35 | Yes |
| Advanced Threats | 36-43 | Yes |
| Cloud & Red Team | 44-50 | Yes |

Files that reference lab ranges:
- README.md (Lab Navigator table and legend)
- labs/README.md
- .claude/commands/lab.md
- docs/index.md (GitHub Pages)
- docs/ARCHITECTURE.md
- ctf/README.md (prerequisites)

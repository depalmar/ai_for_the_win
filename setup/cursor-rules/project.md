# Project Context

## Overview

AI for the Win is a hands-on training program for security practitioners building AI-powered tools.

- 24 labs (including 4 intro labs)
- 4 capstone projects
- 15 CTF challenges

Topics covered:
- Threat detection & classification
- Incident response automation
- Malware analysis & YARA generation
- LLM-powered security tools

## Technology Stack

- **Python**: 3.10+ (required - use modern syntax)
- **ML/AI**: scikit-learn, PyTorch, Hugging Face transformers
- **LLM**: LangChain, LangGraph, LiteLLM, Instructor, Anthropic/OpenAI/Google SDKs
- **Vector DB**: ChromaDB with sentence-transformers
- **Security**: YARA, pefile, MITRE ATT&CK mappings
- **UI**: Gradio 6.x, Streamlit, FastAPI
- **Testing**: pytest with markers (slow, integration, requires_api)

## Key Directories

- `labs/` - Main lab content (24 labs)
- `notebooks/` - Jupyter notebooks (Colab-ready)
- `templates/` - Reusable code templates
- `shared/` - Shared utilities (llm_config.py, ioc_utils.py)
- `data/` - Sample datasets
- `tests/` - pytest test files
- `docs/guides/` - Troubleshooting docs

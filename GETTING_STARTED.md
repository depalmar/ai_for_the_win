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

---

## Quick Setup (5 minutes)

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

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure API Keys

```bash
# Copy example environment file
cp .env.example .env

# Edit with your keys (at least one LLM provider)
nano .env   # or use any editor
```

**🆓 Start without API keys!** Labs 00c (intro to prompting), 00d (AI in SOC - conceptual), 01, 02, and 03 work without any API keys. You can explore LLMs and complete the ML foundations before paying for LLM API access.

**For LLM-powered labs** (choose at least one):
- `ANTHROPIC_API_KEY` - Get from [Anthropic Console](https://console.anthropic.com/) - **Recommended** (Labs 04+ use Claude)
- `OPENAI_API_KEY` - Get from [OpenAI Platform](https://platform.openai.com/)
- `GOOGLE_API_KEY` - Get from [Google AI Studio](https://aistudio.google.com/)

> 📊 **Which provider should I choose?** See our [LLM Provider Comparison Guide](./setup/guides/llm-provider-comparison.md) for benchmarks and recommendations. For cost optimization strategies, see the [Cost Management Guide](./setup/guides/cost-management.md).

**Google AI Ecosystem** (free tools):

| Tool | Description | Best For |
|------|-------------|----------|
| [Google AI Studio](https://aistudio.google.com) | Web interface for Gemini, prompt testing | Quick experiments, getting API keys |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Terminal AI agent (1M context, 1000 req/day free) | Large file analysis, research |
| [Gemini Code Assist](https://cloud.google.com/gemini/docs/codeassist) | Free AI coding assistant for IDEs | VS Code, JetBrains integration |
| [Firebase Studio](https://firebase.studio) | Full-stack AI app builder | Building security dashboards |

> See our [Gemini CLI Guide](./setup/guides/gemini-cli-guide.md) and [Google ADK Guide](./setup/guides/google-adk-guide.md) for detailed setup.

**Optional** (for threat intel labs):
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

### Step 5: Verify Setup

```bash
python scripts/verify_setup.py
```

This will check:
- Python version (3.10+ required)
- Required packages installed
- API keys configured
- Sample data accessible

---

## Choose Your Path

### Path A: Complete Beginner (Start Here)

If you're new to ML/AI for security, follow this order:

```
Phase 1: Foundation Labs
┌──────────────────────────────────────────────────────────────────────────────┐
│  (Optional)      (Optional)      Lab 01          Lab 02          Lab 03     │
│  Lab 00c         Lab 00d         Phishing    ──► Malware     ──► Anomaly    │
│  Intro to        AI in SOC       Classifier      Clustering      Detection  │
│  Prompting       (conceptual)                                               │
│  💰 FREE         💰 FREE         Learn: Text     Learn: PE       Learn:     │
│  (no API keys)   (no coding)     classification  analysis        Network    │
└──────────────────────────────────────────────────────────────────────────────┘

Phase 2: LLM Introduction
┌─────────────────────────────────────────────────────────────┐
│  Lab 04          Lab 06                                     │
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
- **Lab 00c (optional)**: Get hands-on with LLMs using free playgrounds - no API keys needed! Learn prompting basics and hallucination detection.
- **Lab 00d (optional)**: Understand where AI fits in SOC workflows - conceptual, no coding. Covers human-in-the-loop, AI as attack surface, and compliance.
- **Lab 01**: Teaches text classification (emails → phishing/not) - your first ML model
- **Lab 02**: Builds on 01 with unsupervised learning (no labels needed)
- **Lab 03**: Applies anomaly detection to network data
- **Lab 04**: Introduces LLMs for log analysis with API integration
- **Lab 06**: Shows how to give LLMs context with RAG (retrieval-augmented generation)

### Path B: Know ML, New to LLMs

Skip the ML foundations and dive into LLM-powered security tools:

```
(Optional)   Lab 04 ──► Lab 06 ──► Lab 05 ──► Lab 07
Lab 00c        │          │          │          │
Intro LLMs     ▼          ▼          ▼          ▼
& Prompting  Prompts    RAG       Agents    Advanced
(FREE)                                       Prompting
```

Start with Lab 00c if you've never used LLMs before - it's optional but recommended for understanding prompt engineering basics.

### Path C: Know LLMs, Want Security Focus

Jump straight to advanced security applications:

```
Lab 05 ──► Lab 09 ──► Lab 10 ──► Lab 11
  │          │          │          │
  ▼          ▼          ▼          ▼
Threat    Detection    IR       Ransomware
Intel     Pipeline   Copilot   Response
```

### Path D: DFIR Specialist

Focus on incident response and forensics:

```
Lab 03 ──► Lab 04 ──► Lab 09 ──► Lab 11 ──► Lab 12
  │          │          │          │          │
  ▼          ▼          ▼          ▼          ▼
Anomaly   Log       Pipeline  Ransomware  Purple
Detect   Analysis            Detection    Team
```

---

## Your First Lab

### Option 1: Start with LLM Basics (Lab 00c) - FREE, No API Keys

Want to get hands-on with LLMs before diving into ML? Start here:

```bash
# Navigate to Lab 00c
cd labs/lab00c-intro-prompt-engineering

# Open README.md and follow along with free AI playgrounds
```

This lab uses free tools (Google AI Studio, Claude.ai, Poe) - no API keys or setup required!

### Option 2: Start with ML Foundations (Lab 01)

Ready to build your first ML model? Let's run Lab 01 to make sure everything works:

```bash
# Navigate to Lab 01
cd labs/lab01-phishing-classifier

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
3. **Try Interactive Demos**: Run `python demo/launcher.py`
4. **Plan Your Path**: See [LEARNING_GUIDE.md](./LEARNING_GUIDE.md) for detailed paths

---

## Vibe Coding: AI-Assisted Development

This course is designed for **vibe coding** - working alongside AI to write and understand code faster. Instead of typing everything manually, you'll describe what you want and let AI help implement it.

### Recommended AI Coding Tools

| Tool | Best For | Guide |
|------|----------|-------|
| [Cursor](https://cursor.sh/) | Full IDE with AI built-in, composer mode | [Cursor Guide](./setup/guides/cursor-ide-guide.md) |
| [Claude Code](https://claude.ai/code) | Terminal-based AI coding assistant | [Claude Code Guide](./setup/guides/claude-code-cli-guide.md) |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | 1M token context, Google Search grounding, free tier | [Gemini CLI Guide](./setup/guides/gemini-cli-guide.md) |
| [GitHub Copilot](https://github.com/features/copilot) | Inline completions in VS Code | Works with any editor |
| [Windsurf](https://codeium.com/windsurf) | Free AI-powered IDE | Alternative to Cursor |

### How to Vibe Code These Labs

**Example workflow with Cursor/Claude Code:**

```
You: "Read the starter code in lab01 and explain what each TODO needs"
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
- [Cursor Cheatsheet](./resources/cheatsheets/cursor-cheatsheet.md)
- [Claude Code Cheatsheet](./resources/cheatsheets/claude-code-cheatsheet.md)
- [LangChain Security Cheatsheet](./resources/cheatsheets/langchain-security-cheatsheet.md)

---

## Quick Reference

| Task | Command |
|------|---------|
| Activate environment | `source venv/bin/activate` |
| Run a lab solution | `python labs/labXX-name/solution/main.py` |
| Run tests | `pytest tests/ -v` |
| Check setup | `python scripts/verify_setup.py` |
| Launch demos | `python demo/launcher.py` |
| Update dependencies | `pip install -r requirements.txt --upgrade` |

---

## Getting Help

- **Setup Issues**: See [troubleshooting-guide.md](./setup/guides/troubleshooting-guide.md)
- **Stuck on a Lab**: Check the [walkthroughs](./docs/walkthroughs/) for step-by-step solutions
- **Lab Questions**: Check the lab's README hints section
- **Find Resources**: See [DOCUMENTATION_GUIDE.md](./DOCUMENTATION_GUIDE.md) for navigation
- **General Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue

---

**Ready to start?**
- **New to LLMs?** → `cd labs/lab00c-intro-prompt-engineering` (FREE, no API keys)
- **New to ML?** → `cd labs/lab01-phishing-classifier` (FREE, no API keys)
- **Know both?** → Jump to Lab 04 or see paths above

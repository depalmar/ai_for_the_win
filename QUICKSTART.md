# Quick Start

Get running in 5 minutes.

---

## Option 1: Local Setup

```bash
# Clone
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# Setup Python environment
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt

# Run your first lab (no API key needed!)
python labs/lab01-phishing-classifier/solution/main.py

# Or start with foundations (interactive exercises)
python labs/lab00b-ml-concepts-primer/starter/main.py
```

## Option 2: Docker

```bash
docker-compose up dev
```

## Option 3: Google Colab (Zero Setup)

[![Open Lab 01](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb)

---

## Configure API Keys (for Labs 04+)

```bash
cp .env.example .env
# Edit .env and add your API key:
# ANTHROPIC_API_KEY=sk-ant-...
```

Get keys from:
- [Anthropic Console](https://console.anthropic.com) (recommended)
- [OpenAI Platform](https://platform.openai.com)
- [Google AI Studio](https://aistudio.google.com) (free tier: 1000 req/day)

---

## AI Coding Assistants

| Tool | Best For | Free Tier |
|------|----------|-----------|
| [Claude Code](https://claude.ai/code) | Git workflows, coding | Limited |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Large files (1M context), research | 1000/day |
| [Cursor](https://cursor.sh/) | Full IDE experience | Trial |

---

## Verify Setup

```bash
python scripts/verify_setup.py
```

---

## Where to Start

| Your Background | Start Here | API Key? |
|-----------------|------------|----------|
| Brand new | [Lab 00](./labs/lab00-environment-setup/) - Setup | No |
| New to Python | [Lab 00a](./labs/lab00a-python-security-fundamentals/) - Python basics | No |
| New to ML concepts | [Lab 00b](./labs/lab00b-ml-concepts-primer/) - ML theory | No |
| New to prompting | [Lab 00c](./labs/lab00c-intro-prompt-engineering/) - Prompt basics | No |
| Ready for ML labs | [Lab 01](./labs/lab01-phishing-classifier/) - First ML model | No |
| Know ML, want LLMs | [Lab 04](./labs/lab04-llm-log-analysis/) - First LLM | Yes |
| Want AI agents | [Lab 05](./labs/lab05-threat-intel-agent/) - Agents | Yes |

**Recommended path for beginners:** 00 → 00a → 00b → 00c → 01 → 02 → 03 → 04+

---

## Next Steps

- **Detailed setup**: [GETTING_STARTED.md](./GETTING_STARTED.md)
- **Learning paths**: [LEARNING_GUIDE.md](./LEARNING_GUIDE.md)
- **Find resources**: [DOCUMENTATION_GUIDE.md](./DOCUMENTATION_GUIDE.md)
- **Troubleshooting**: [setup/guides/troubleshooting-guide.md](./setup/guides/troubleshooting-guide.md)

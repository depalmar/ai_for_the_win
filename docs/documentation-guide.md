# Documentation Guide

**Lost in the docs? Start here.** This guide points you to exactly what you need.

---

## I want to

### Get Started

| Goal | Go To |
|------|-------|
| **Quick setup (15 min)** | [Quick Start Guide](./guides/quickstart-guide.md) |
| **Detailed setup** | [GETTING_STARTED.md](./GETTING_STARTED.md) |
| **Choose my learning path** | [Learning Paths Guide](./learning-guide.md) |
| **Run in Docker/Colab** | [README.md - Docker/Colab](../README.md#docker-quick-start) |

### Learn

| Goal | Go To |
|------|-------|
| **ML vs LLM decision** | [Learning Guide - Choosing Tools](./learning-guide.md#choosing-the-right-tool-ml-vs-llm) |
| **Understanding each lab** | [Lab README files](../labs/) |
| **Get unstuck on a lab** | [Lab Walkthroughs](./walkthroughs/) |
| **Find workshop materials** | [Workshops Guide](./guides/workshops-guide.md) |

### Set Up My Tools

| Goal | Go To |
|------|-------|
| **Cursor IDE** | [Cursor IDE Guide](./guides/cursor-ide-guide.md) |
| **Claude Code CLI** | [Claude Code CLI Guide](./guides/claude-code-cli-guide.md) |
| **Claude API/SDK (Python)** | [Claude API Guide](./guides/claude-api-guide.md) |
| **Compare AI dev tools** | [AI Dev Tools Comparison](./guides/ai-dev-tools-comparison.md) |
| **Compare LLM providers** | [LLM Provider Comparison](./guides/llm-provider-comparison.md) |
| **Google ADK** | [Google ADK Guide](./guides/google-adk-guide.md) |

### Troubleshoot

| Goal | Go To |
|------|-------|
| **Fix common errors** | [Troubleshooting Guide](./guides/troubleshooting-guide.md) |
| **Error handling patterns** | [Error Handling Guide](./guides/error-handling-guide.md) |
| **Cost management** | [Cost Management Guide](./guides/cost-management.md) |
| **Using AI for help** | [Using AI for Learning](./guides/using-ai-for-learning.md) |

### Find Resources

| Goal | Go To |
|------|-------|
| **Ready-to-use security prompts** | [Security Prompt Library](../resources/prompt-library/security-prompts.md) |
| **Tools, APIs, datasets** | [Tools & Resources](../resources/tools-and-resources.md) |
| **MCP servers for security** | [MCP Servers Guide](../resources/mcp-servers-security-guide.md) |
| **Quick reference guides** | [Setup Guides](./guides/) |

### Build Integrations

| Goal | Go To |
|------|-------|
| **Splunk integration** | [Splunk Guide](../resources/integrations/splunk-integration.md) |
| **Elastic/ELK integration** | [Elastic Guide](../resources/integrations/elastic-integration.md) |
| **All integrations** | [Integrations Index](../resources/integrations/) |

### Go Deeper

| Goal | Go To |
|------|-------|
| **Advanced patterns** | [Advanced Topics Guide](./guides/advanced-topics-guide.md) |
| **Embeddings & vectors** | [Embeddings Guide](./guides/embeddings-and-vectors.md) |
| **LLM output parsing** | [Structured Output Guide](./guides/structured-output-parsing.md) |
| **LLM testing/evaluation** | [LLM Evaluation Guide](./guides/llm-evaluation-testing.md) |
| **Prompt injection defense** | [Security Best Practices](./guides/prompt-injection-defense.md) |
| **Windows internals** | [Windows Internals Quick Reference](./guides/windows-internals-quickref.md) |

### For Beginners

| Goal | Go To |
|------|-------|
| **Security basics** | [Security Fundamentals for Beginners](./guides/security-fundamentals-for-beginners.md) |
| **Using AI to learn** | [Using AI for Learning](./guides/using-ai-for-learning.md) |
| **Cloud security basics** | [Lab 19a: Cloud Security Fundamentals](../labs/lab19a-cloud-security-fundamentals/) |

---

## Quick Reference

### Cheatsheets

| Tool | Guide |
|------|-------|
| Claude Code CLI | [claude-code-cli-guide.md](./guides/claude-code-cli-guide.md) |
| Gemini CLI | [gemini-cli-guide.md](./guides/gemini-cli-guide.md) |
| Cursor IDE | [cursor-ide-guide.md](./guides/cursor-ide-guide.md) |
| Google ADK | [google-adk-guide.md](./guides/google-adk-guide.md) |
| LangChain Security | [langchain-guide.md](./guides/langchain-guide.md) |

### Lab Walkthroughs (Solutions)

If you're stuck on a lab, these walkthroughs provide step-by-step solutions:

| Labs | Walkthroughs |
|------|--------------|
| Labs 01-05 | [lab01](./walkthroughs/lab01-phishing-classifier-walkthrough.md), [lab02](./walkthroughs/lab02-malware-clustering-walkthrough.md), [lab03](./walkthroughs/lab03-anomaly-detection-walkthrough.md), [lab04](./walkthroughs/lab04-llm-log-analysis-walkthrough.md), [lab05](./walkthroughs/lab05-threat-intel-agent-walkthrough.md) |
| Labs 06-10 | [lab06](./walkthroughs/lab06-security-rag-walkthrough.md), [lab07](./walkthroughs/lab07-yara-generator-walkthrough.md), [lab08](./walkthroughs/lab08-vuln-scanner-ai-walkthrough.md), [lab09](./walkthroughs/lab09-detection-pipeline-walkthrough.md), [lab10](./walkthroughs/lab10-ir-copilot-walkthrough.md) |
| Labs 11-16 | [lab11](./walkthroughs/lab11-ransomware-detection-walkthrough.md), [lab12](./walkthroughs/lab12-ransomware-simulation-walkthrough.md), [lab13](./walkthroughs/lab13-memory-forensics-ai-walkthrough.md), [lab14](./walkthroughs/lab14-c2-traffic-analysis-walkthrough.md), [lab15](./walkthroughs/lab15-lateral-movement-walkthrough.md), [lab16](./walkthroughs/lab16-threat-actor-profiling-walkthrough.md) |
| All walkthroughs | [Browse all](./walkthroughs/) |

---

## Documentation Map

```
Root
├── README.md                    # Project overview, quick start
│
├── docs/                        # All documentation
│   ├── GETTING_STARTED.md       # Detailed setup guide
│   ├── CLAUDE.md                # AI assistant instructions
│   ├── guides/                  # Tool setup & how-to guides
│   │   ├── quickstart-guide.md
│   │   ├── troubleshooting-guide.md
│   │   ├── cursor-ide-guide.md
│   │   └── ... (20+ guides)
│   ├── walkthroughs/            # Lab solution walkthroughs
│   ├── learning-guide.md        # Learning paths, ML vs LLM
│   └── documentation-guide.md   # You are here
│
├── resources/                   # Reference materials
│   ├── tools-and-resources.md   # 80+ tools/APIs/datasets
│   ├── prompt-library/          # Ready-to-use prompts
│   └── integrations/            # SIEM/SOAR integrations (Splunk, Elastic, etc.)
│
├── labs/                        # 24 hands-on labs
│   └── labXX-name/README.md
│
├── templates/                   # Reusable code templates
├── scripts/                     # Utility & demo scripts
└── notebooks/                   # Jupyter notebooks
```

---

## Still Can't Find It?

1. **Search the repo**: Use `Ctrl+Shift+F` in VS Code/Cursor
2. **Check the main README**: [README.md](./README.md)
3. **Open an issue**: [GitHub Issues](https://github.com/depalmar/ai_for_the_win/issues)

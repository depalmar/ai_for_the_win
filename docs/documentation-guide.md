# Documentation Guide

**Lost in the docs? Start here.** This guide points you to exactly what you need.

---

## I want to...

### Get Started

| Goal | Go To |
|------|-------|
| **Quick setup (15 min)** | [Quick Start Guide](../setup/guides/quickstart-guide.md) |
| **Detailed setup** | [GETTING_STARTED.md](../GETTING_STARTED.md) |
| **Choose my learning path** | [Learning Paths Guide](./learning-guide.md) |
| **Run in Docker/Colab** | [README.md - Docker/Colab](../README.md#docker-quick-start) |

### Learn

| Goal | Go To |
|------|-------|
| **ML vs LLM decision** | [Learning Guide - Choosing Tools](./learning-guide.md#choosing-the-right-tool-ml-vs-llm) |
| **Understanding each lab** | [Lab README files](../labs/) |
| **Get unstuck on a lab** | [Lab Walkthroughs](./walkthroughs/) |
| **Find workshop materials** | [Workshops Guide](../setup/guides/workshops-guide.md) |

### Set Up My Tools

| Goal | Go To |
|------|-------|
| **Cursor IDE** | [Cursor IDE Guide](../setup/guides/cursor-ide-guide.md) |
| **Claude Code CLI** | [Claude Code CLI Guide](../setup/guides/claude-code-cli-guide.md) |
| **Claude API/SDK (Python)** | [Claude API Guide](../setup/guides/claude-api-guide.md) |
| **Compare AI dev tools** | [AI Dev Tools Comparison](../setup/guides/ai-dev-tools-comparison.md) |
| **Compare LLM providers** | [LLM Provider Comparison](../setup/guides/llm-provider-comparison.md) |
| **Google ADK** | [Google ADK Guide](../setup/guides/google-adk-guide.md) |

### Troubleshoot

| Goal | Go To |
|------|-------|
| **Fix common errors** | [Troubleshooting Guide](../setup/guides/troubleshooting-guide.md) |
| **Error handling patterns** | [Error Handling Guide](../setup/guides/error-handling-guide.md) |
| **Cost management** | [Cost Management Guide](../setup/guides/cost-management.md) |

### Find Resources

| Goal | Go To |
|------|-------|
| **Ready-to-use security prompts** | [Security Prompt Library](../resources/prompt-library/security-prompts.md) |
| **Tools, APIs, datasets** | [Tools & Resources](../resources/tools-and-resources.md) |
| **MCP servers for security** | [MCP Servers Guide](../resources/mcp-servers-security-guide.md) |
| **Quick reference guides** | [Setup Guides](../setup/guides/) |

### Build Integrations

| Goal | Go To |
|------|-------|
| **Splunk integration** | [Splunk Guide](../resources/integrations/splunk-integration.md) |
| **Elastic/ELK integration** | [Elastic Guide](../resources/integrations/elastic-integration.md) |
| **Palo Alto XSIAM/XDR** | [XSIAM/XDR Guide](../resources/integrations/xsiam-xdr-integration.md) |
| **All integrations** | [Integrations Index](../resources/integrations/) |

### Go Deeper

| Goal | Go To |
|------|-------|
| **Advanced patterns** | [Advanced Topics Guide](../setup/guides/advanced-topics-guide.md) |
| **Embeddings & vectors** | [Embeddings Guide](../setup/guides/embeddings-and-vectors.md) |
| **LLM output parsing** | [Structured Output Guide](../setup/guides/structured-output-parsing.md) |
| **LLM testing/evaluation** | [LLM Evaluation Guide](../setup/guides/llm-evaluation-testing.md) |
| **Prompt injection defense** | [Security Best Practices](../setup/guides/prompt-injection-defense.md) |

---

## Quick Reference

### Cheatsheets

| Tool | Guide |
|------|-------|
| Claude Code CLI | [claude-code-cli-guide.md](../setup/guides/claude-code-cli-guide.md) |
| Gemini CLI | [gemini-cli-guide.md](../setup/guides/gemini-cli-guide.md) |
| Cursor IDE | [cursor-ide-guide.md](../setup/guides/cursor-ide-guide.md) |
| Google ADK | [google-adk-guide.md](../setup/guides/google-adk-guide.md) |
| LangChain Security | [langchain-guide.md](../setup/guides/langchain-guide.md) |

### Lab Walkthroughs (Solutions)

If you're stuck on a lab, these walkthroughs provide step-by-step solutions:

| Labs | Walkthroughs |
|------|--------------|
| Labs 01-05 | [lab01](./walkthroughs/lab01-walkthrough.md), [lab02](./walkthroughs/lab02-walkthrough.md), [lab03](./walkthroughs/lab03-walkthrough.md), [lab04](./walkthroughs/lab04-walkthrough.md), [lab05](./walkthroughs/lab05-walkthrough.md) |
| Labs 06-10 | [lab06](./walkthroughs/lab06-walkthrough.md), [lab07](./walkthroughs/lab07-walkthrough.md), [lab08](./walkthroughs/lab08-walkthrough.md), [lab09](./walkthroughs/lab09-walkthrough.md), [lab10](./walkthroughs/lab10-walkthrough.md) |
| Labs 11-16 | [lab11](./walkthroughs/lab11-walkthrough.md), [lab12](./walkthroughs/lab12-walkthrough.md), [lab13](./walkthroughs/lab13-walkthrough.md), [lab14](./walkthroughs/lab14-walkthrough.md), [lab15](./walkthroughs/lab15-walkthrough.md), [lab16](./walkthroughs/lab16-walkthrough.md) |
| All walkthroughs | [Browse all](./walkthroughs/) |

---

## Documentation Map

```
Root
├── README.md                    # Project overview, quick start
├── GETTING_STARTED.md           # Detailed setup guide
├── docs/learning-guide.md       # Learning paths, ML vs LLM
├── docs/documentation-guide.md  # You are here
│
├── setup/guides/                # Tool setup & troubleshooting
│   ├── quickstart-guide.md      # 15-minute fast path
│   ├── troubleshooting-guide.md # Fix common issues
│   ├── cursor-ide-guide.md      # Cursor setup
│   ├── claude-code-cli-guide.md # Claude Code CLI
│   ├── claude-api-guide.md      # Claude Python SDK
│   └── ...                      # More guides
│
├── resources/                   # Tools, prompts, integrations
│   ├── tools-and-resources.md   # 80+ tools/APIs/datasets
│   ├── prompt-library/          # Ready-to-use prompts
│   # Guides at setup/guides/
│   ├── integrations/            # SIEM integrations
│   └── mcp-servers-security-guide.md
│
├── labs/                        # 24 hands-on labs
│   └── labXX-name/README.md     # Each lab has instructions
│
└── docs/walkthroughs/           # Lab solution walkthroughs
    └── labXX-walkthrough.md     # Step-by-step solutions
```

---

## Still Can't Find It?

1. **Search the repo**: Use `Ctrl+Shift+F` in VS Code/Cursor
2. **Check the main README**: [README.md](./README.md)
3. **Open an issue**: [GitHub Issues](https://github.com/depalmar/ai_for_the_win/issues)

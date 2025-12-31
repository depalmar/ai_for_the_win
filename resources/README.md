# Resources

Curated resources for the AI Security Training Program.

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           RESOURCES OVERVIEW                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐               ║
║  │ 📚 Tools &      │  │ 💬 Prompt       │  │ 📋 Cheatsheets  │               ║
║  │    Resources    │  │    Library      │  │                 │               ║
║  │  70+ tools      │  │  15+ prompts    │  │  4 guides       │               ║
║  │  APIs, datasets │  │  Security AI    │  │  Quick ref      │               ║
║  └─────────────────┘  └─────────────────┘  └─────────────────┘               ║
║                                                                               ║
║  ┌─────────────────┐  ┌─────────────────────────────────────────┐            ║
║  │ 🔌 MCP Servers  │  │ 🔗 Platform Integrations                │            ║
║  │  DFIR, TI, Red  │  │  XSIAM, XDR, Splunk, Elastic            │            ║
║  │  Report Gen     │  │  SOAR, Threat Intel                     │            ║
║  └─────────────────┘  └─────────────────────────────────────────┘            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Directory Structure

```
resources/
├── README.md                    # This file
├── tools-and-resources.md       # Comprehensive tools and APIs guide
├── mcp-servers-security-guide.md # MCP servers for security operations
├── integrations/                # Enterprise platform integrations
│   ├── README.md               # Integration overview
│   ├── xsiam-xdr-integration.md # Palo Alto Cortex XSIAM/XDR
│   └── splunk-integration.md   # Splunk Enterprise/Cloud
├── prompt-library/              # Security analysis prompts
│   └── security-prompts.md      # Curated prompt templates
# Note: All comprehensive guides are at setup/guides/
# - LangChain Guide: setup/guides/langchain-guide.md
# - Cursor IDE Guide: setup/guides/cursor-ide-guide.md
# - Claude Code CLI: setup/guides/claude-code-cli-guide.md
```

## Quick Links

| Resource | Description |
|----------|-------------|
| [Tools & Resources](./tools-and-resources.md) | 70+ tools, APIs, datasets |
| [MCP Servers Guide](./mcp-servers-security-guide.md) | DFIR, threat intel, offensive security MCP servers |
| [Platform Integrations](./integrations/) | XSIAM, XDR, Splunk, Elastic guides |
| [Prompt Library](./prompt-library/) | Ready-to-use security prompts |
| [LangChain Guide](../setup/guides/langchain-guide.md) | Comprehensive LangChain security guide |

## Tools & Resources Overview

The main resources file includes:

- **AI Development Tools**: Cursor, Claude Code, GitHub Copilot
- **LLM APIs**: Anthropic, OpenAI, local models via Ollama
- **ML Libraries**: scikit-learn, PyTorch, XGBoost
- **Security Tools**: YARA, Sigma, Volatility, MISP
- **Datasets**: Malware samples, network traffic, threat intel
- **Pre-trained Models**: Security-specific embeddings and classifiers

## Prompt Library

The prompt library contains tested prompts for:

- Log analysis and parsing
- Threat detection and classification
- IOC extraction
- Incident summarization
- MITRE ATT&CK mapping
- Malware behavior analysis
- Vulnerability assessment

### Using Prompts

```python
from pathlib import Path

# Load a prompt template
prompt_path = Path("resources/prompt-library/log-analysis.md")
template = prompt_path.read_text()

# Customize with your data
prompt = template.format(logs=your_log_data)
```

## Cheatsheets

Quick reference guides for common tools:

### Cursor IDE
- Keyboard shortcuts
- AI features (Cmd+K, Cmd+L)
- Configuration tips

### Claude Code
- CLI commands
- Session management
- Best practices

### LangChain ([Full Guide](../setup/guides/langchain-guide.md))
- Multi-provider setup
- Chains, agents, RAG
- LangGraph workflows
- Security best practices

## MCP Servers for Security

The [MCP Servers Guide](./mcp-servers-security-guide.md) covers Model Context Protocol servers for:

### DFIR Operations
- Filesystem analysis and evidence collection
- SQLite database forensics
- Memory forensics with Volatility3 integration
- Timeline generation

### Threat Intelligence
- VirusTotal API integration
- MISP threat sharing platform
- Shodan/Censys asset discovery
- GreyNoise/AbuseIPDB reputation

### Offensive Security
- Nuclei vulnerability scanning
- Nmap network reconnaissance
- Custom security tool integration

### Report Generation
- Automated incident reports (Markdown, PDF, HTML)
- MITRE ATT&CK mapping templates
- Vulnerability assessment reports
- Threat intelligence briefings
- Plotly chart integration for visualizations

## Contributing Resources

To add new resources:

1. Add entries to `tools-and-resources.md` for tools/APIs
2. Create new files in `prompt-library/` for prompts
3. Add comprehensive guides to `setup/guides/`
4. Update this README with new additions

### Resource Format

For tools and resources entries:

```markdown
### Tool Name

**URL**: https://example.com
**Type**: Commercial / Open Source / API
**Use Case**: Brief description of security application

**Example**:
```python
# Code example
```
```

## External Resources

Beyond this repository:

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques
- [VirusTotal](https://www.virustotal.com/) - File/URL analysis
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Detection rules
- [YARA Rules](https://github.com/Yara-Rules/rules) - Malware detection

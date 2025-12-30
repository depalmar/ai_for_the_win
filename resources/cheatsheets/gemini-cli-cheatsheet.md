# Gemini CLI Cheat Sheet

Quick reference for Google's open-source AI agent in the terminal.

---

## Installation

```bash
npm install -g @google/gemini-cli
# or
npx @google/gemini-cli
```

---

## Authentication

```bash
# Login with Google account (free tier)
gemini auth login

# Or use API key
export GOOGLE_API_KEY="your-key"
```

---

## Basic Commands

```bash
# Interactive mode
gemini

# One-shot query
gemini "Your question here"

# With file input
gemini --file log.txt "Analyze this"

# Pipe input
cat data.json | gemini "Parse and summarize"

# Directory context
gemini --context ./project/ "Explain this codebase"
```

---

## Model Selection

```bash
# Gemini 3 Pro (most capable)
gemini --model gemini-3-pro "Complex analysis"

# Gemini 3 Flash (faster)
gemini --model gemini-3-flash "Quick task"

# Gemini 2.5 Pro (1M context, free default)
gemini --model gemini-2.5-pro "Large file analysis"
```

---

## Security Workflows

### Log Analysis
```bash
gemini "Find brute force attacks" < /var/log/auth.log
gemini --file security.evtx "Extract failed logins"
```

### Malware Analysis
```bash
gemini --file suspicious.ps1 "Analyze for malicious behavior"
cat sample.exe | gemini "Identify suspicious PE characteristics"
```

### Threat Intel
```bash
gemini "Extract IOCs from this report" < threat_report.pdf
gemini --search "Latest IOCs for LockBit ransomware"
```

### YARA/Sigma Generation
```bash
gemini "Generate YARA rule for this behavior" --context ./samples/
gemini "Create Sigma rule for detecting T1059.001"
```

---

## Advanced Features

```bash
# Enable shell execution
gemini --allow-shell "Run nmap and summarize"

# Google Search grounding
gemini --search "Current CVEs for Apache"

# Code execution
gemini --code-exec "Calculate file entropy"

# JSON output
gemini --output json "Extract IOCs" < report.txt

# Session management
gemini --session incident-001 "Start investigation"
gemini --resume incident-001 "Continue analysis"
```

---

## MCP Integration

```json
// ~/.gemini/mcp.json
{
  "servers": {
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-virustotal"]
    }
  }
}
```

---

## Free Tier Limits

| Resource | Limit |
|----------|-------|
| Requests/minute | 60 |
| Requests/day | 1,000 |
| Context window | 1M tokens |
| Model | Gemini 2.5 Pro |

---

## Comparison

| Feature | Gemini CLI | Claude Code |
|---------|------------|-------------|
| Context | 1M tokens | 200K tokens |
| Free tier | 1000/day | Limited |
| Google Search | Native | Via MCP |
| Best for | Large files, research | Coding, git |

---

**Full Guide**: [gemini-cli-guide.md](../../setup/guides/gemini-cli-guide.md)

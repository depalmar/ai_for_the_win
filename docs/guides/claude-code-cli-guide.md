# Claude Code CLI Complete Guide

Anthropic's official agentic coding assistant for terminal-based development.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Core Features](#core-features)
5. [Security-Focused Workflows](#security-focused-workflows)
6. [MCP Servers Integration](#mcp-servers-integration)
7. [Custom Slash Commands](#custom-slash-commands)
8. [Hooks and Automation](#hooks-and-automation)
9. [IDE Integration](#ide-integration)
10. [Best Practices for Security Development](#best-practices-for-security-development)

---

## Overview

**Claude Code** is Anthropic's official command-line interface for Claude that enables agentic, autonomous coding directly in your terminal. Unlike simple API wrappers, Claude Code can:

| Capability | Description |
|------------|-------------|
| **Agentic Execution** | Autonomously reads, writes, and edits files across your codebase |
| **Tool Use** | Executes shell commands, searches files, navigates codebases |
| **Multi-Step Tasks** | Plans and executes complex multi-file changes |
| **Context Awareness** | Understands your entire project structure |
| **MCP Integration** | Connects to Model Context Protocol servers for extended capabilities |
| **IDE Support** | Works standalone or integrated into VS Code/Cursor |

### Why Claude Code for Security Development?

1. **Rapid Prototyping**: Build security tools, detection rules, and analysis scripts quickly
2. **Code Review**: Analyze codebases for vulnerabilities with full context
3. **Automation**: Create custom workflows for DFIR and threat hunting tasks
4. **Documentation**: Generate comprehensive docs for security tooling
5. **Refactoring**: Modernize legacy security scripts with AI assistance

---

## Installation

### Prerequisites

- Node.js 18+ (LTS recommended)
- npm or yarn
- Anthropic API key

### Install Claude Code

```bash
# Install globally via npm
npm install -g @anthropic-ai/claude-code

# Or using yarn
yarn global add @anthropic-ai/claude-code

# Verify installation
claude --version
```

### Configure API Key

```bash
# Option 1: Environment variable (recommended)
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Add to shell profile for persistence
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.bashrc
source ~/.bashrc

# Option 2: Configure via CLI
claude config set api_key sk-ant-api03-...
```

### Initial Setup

```bash
# Navigate to your project
cd /path/to/security-project

# Start Claude Code
claude

# Claude will analyze your project and provide guidance
```

---

## Getting Started

### Basic Usage

```bash
# Start interactive mode in current directory
claude

# Start with a specific task
claude "Analyze this repository for security vulnerabilities"

# Continue previous conversation
claude --continue

# Start fresh conversation
claude --new
```

### Interactive Commands

Once in Claude Code, use these commands:

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/clear` | Clear conversation history |
| `/compact` | Summarize conversation to save context |
| `/cost` | Show token usage and costs |
| `/config` | View/modify configuration |
| `/doctor` | Diagnose installation issues |
| `/init` | Initialize Claude Code in project |
| `/memory` | View project memory/context |

### First Security Analysis

```bash
# Start Claude Code
claude

# In the interactive prompt:
> Analyze the codebase for:
> 1. Hardcoded credentials or API keys
> 2. SQL injection vulnerabilities
> 3. Command injection risks
> 4. Insecure file operations
> Provide a security report with severity ratings
```

---

## Core Features

### 1. File Operations

Claude Code can autonomously read, create, and edit files:

```bash
# Read and analyze files
> Read the main.py file and explain its security implications

# Create new files
> Create a YARA rule to detect the malware patterns we discussed

# Edit existing files
> Fix the SQL injection vulnerability in database.py line 45

# Multi-file operations
> Refactor the authentication module to use bcrypt instead of MD5
```

### 2. Shell Command Execution

Claude Code can execute shell commands with your approval:

```bash
# Run security scans
> Run bandit to check for Python security issues

# Execute tests
> Run the security test suite and fix any failures

# Build operations
> Build the Docker container and verify it runs correctly
```

### 3. Codebase Search

Powerful search capabilities across your project:

```bash
# Search for patterns
> Find all places where we handle user input without validation

# Grep-style searches
> Search for uses of subprocess.call with shell=True

# Semantic search
> Find code related to authentication and session management
```

### 4. Git Integration

Built-in git workflow support:

```bash
# Review changes
> Show me what changed in the last commit

# Create commits
> Commit the security fixes with an appropriate message

# Branch management
> Create a branch for the XSS vulnerability fix
```

### 5. Extended Thinking

For complex security analysis, enable extended thinking:

```bash
# In settings or via command
/config set extended_thinking true

# Or per-request
> [thinking] Analyze this malware sample and provide a detailed breakdown
> of its capabilities, persistence mechanisms, and C2 communication
```

---

## Security-Focused Workflows

### Workflow 1: Malware Analysis Assistant

```bash
claude

> I have a suspicious Python script at samples/suspicious.py
> Analyze it for:
> - Malicious capabilities (data exfiltration, persistence, etc.)
> - Obfuscation techniques used
> - Network indicators (domains, IPs, URLs)
> - File system artifacts it creates
> - MITRE ATT&CK technique mappings
> Generate a markdown threat report
```

### Workflow 2: Detection Rule Development

```bash
claude

> Based on the malware analysis, create:
> 1. A YARA rule to detect this malware family
> 2. A Sigma rule for the Windows event patterns
> 3. Snort/Suricata rules for network detection
> Save each to the appropriate directory in detection_rules/
```

### Workflow 3: Vulnerability Assessment

```bash
claude

> Perform a security audit of the src/ directory:
> 1. Identify OWASP Top 10 vulnerabilities
> 2. Check for insecure dependencies
> 3. Review authentication/authorization logic
> 4. Find data validation issues
> Create a findings report with severity and remediation steps
```

### Workflow 4: Incident Response Automation

```bash
claude

> Create a Python script that:
> 1. Parses Windows Security Event Log XML exports
> 2. Identifies failed login attempts (Event ID 4625)
> 3. Correlates source IPs with threat intelligence
> 4. Generates a timeline of suspicious activity
> 5. Outputs results in STIX 2.1 format
```

### Workflow 5: DFIR Tooling

```bash
claude

> Build a memory forensics helper that:
> 1. Uses Volatility3 to analyze memory dumps
> 2. Automatically runs common plugins (pslist, netscan, malfind)
> 3. Parses output into structured JSON
> 4. Identifies known-bad patterns
> 5. Generates an investigation report
```

---

## MCP Servers Integration

Model Context Protocol (MCP) extends Claude Code's capabilities with external tools and data sources.

### What is MCP?

MCP servers provide Claude Code with additional tools:
- Database access
- External APIs (VirusTotal, MISP, etc.)
- Custom security tools
- File system extensions

### Configuring MCP Servers

Create `.claude/mcp_servers.json` in your project:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-virustotal"],
      "env": {
        "VT_API_KEY": "${VIRUSTOTAL_API_KEY}"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/samples"]
    },
    "sqlite": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite", "--db", "threat_intel.db"]
    }
  }
}
```

### Available MCP Servers for Security

| Server | Purpose | Installation |
|--------|---------|--------------|
| **filesystem** | Secure file access | `@modelcontextprotocol/server-filesystem` |
| **sqlite** | Database queries | `@modelcontextprotocol/server-sqlite` |
| **postgres** | PostgreSQL access | `@modelcontextprotocol/server-postgres` |
| **brave-search** | Web search | `@anthropic-ai/mcp-server-brave-search` |
| **fetch** | HTTP requests | `@anthropic-ai/mcp-server-fetch` |
| **github** | GitHub integration | `@modelcontextprotocol/server-github` |

### Building Custom MCP Server for Security

```typescript
// mcp-server-threatintel/index.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "threat-intel-server",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// Define tools
server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "lookup_hash",
      description: "Look up file hash in threat intelligence databases",
      inputSchema: {
        type: "object",
        properties: {
          hash: { type: "string", description: "MD5, SHA1, or SHA256 hash" },
          sources: {
            type: "array",
            items: { type: "string" },
            description: "Intel sources: virustotal, malwarebazaar, otx"
          }
        },
        required: ["hash"]
      }
    },
    {
      name: "lookup_ip",
      description: "Check IP reputation across threat feeds",
      inputSchema: {
        type: "object",
        properties: {
          ip: { type: "string", description: "IP address to lookup" }
        },
        required: ["ip"]
      }
    },
    {
      name: "search_mitre",
      description: "Search MITRE ATT&CK for techniques",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          matrix: { type: "string", enum: ["enterprise", "mobile", "ics"] }
        },
        required: ["query"]
      }
    }
  ]
}));

// Implement tool handlers
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "lookup_hash":
      return await lookupHash(args.hash, args.sources);
    case "lookup_ip":
      return await lookupIP(args.ip);
    case "search_mitre":
      return await searchMitre(args.query, args.matrix);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
```

---

## Custom Slash Commands

Claude Code supports reusable slash commands backed by markdown files. This repo ships
course-specific commands for security analysis, lab navigation, and curriculum maintenance.

### Repo-Shipped Commands

The commands live in `.claude/commands/<name>.md` and are auto-discovered when you start
Claude Code from the repository root:

```bash
cd /path/to/ai_for_the_win
ls .claude/commands/  # Should list 15 .md files
claude

# In the Claude Code prompt, type "/" to see project commands autocomplete.
```

No extra install step is required beyond running Claude Code inside this repository. These
commands are Claude Code prompt templates, not shell executables; the markdown file tells
Claude what workflow to follow when you invoke the command.

### Security Analysis Commands

| Command | Purpose | Backing file |
|---------|---------|--------------|
| `/ioc-extractor` | Extract IOCs from text, logs, or files | `.claude/commands/ioc-extractor.md` |
| `/threat-intel` | Enrich IOCs via VirusTotal, AbuseIPDB, OTX, or Shodan | `.claude/commands/threat-intel.md` |
| `/sigma-create` | Generate Sigma rules from descriptions, logs, or MITRE IDs | `.claude/commands/sigma-create.md` |
| `/sigma-convert` | Convert Sigma rules to EQL, ES\|QL, KQL, or OpenSearch | `.claude/commands/sigma-convert.md` |
| `/log-parser` | Parse and normalize common log formats to ECS-style fields | `.claude/commands/log-parser.md` |
| `/threat-hunt` | Build hypothesis-driven threat hunting queries | `.claude/commands/threat-hunt.md` |
| `/dfir-analyze` | Scaffold DFIR case triage and analysis artifacts | `.claude/commands/dfir-analyze.md` |
| `/timeline-viz` | Generate incident timelines and Plotly visualizations | `.claude/commands/timeline-viz.md` |
| `/security-check` | Review code for vulnerabilities, secrets, and unsafe patterns | `.claude/commands/security-check.md` |

### Course and Maintenance Commands

| Command | Purpose | Backing file |
|---------|---------|--------------|
| `/lab` | List, view, start, or test labs | `.claude/commands/lab.md` |
| `/ctf` | Browse CTF challenges, hints, and solving workflow | `.claude/commands/ctf.md` |
| `/verify-setup` | Check Python, packages, and API key readiness | `.claude/commands/verify-setup.md` |
| `/curriculum-check` | Validate links, models, packages, and curriculum health | `.claude/commands/curriculum-check.md` |
| `/update-ai-models` | Refresh AI model references with web research | `.claude/commands/update-ai-models.md` |
| `/update-threat-intel` | Refresh threat intelligence content with web research | `.claude/commands/update-threat-intel.md` |

### Example Workflow

```bash
claude

# In the Claude Code prompt:
> /ioc-extractor sample-incident.log
> /log-parser sample-incident.log
> /threat-intel --file iocs.json
> /threat-hunt --mitre T1059.001
> /sigma-create --from-log sample-incident.log
> /sigma-convert rule.yml --target eql
```

Flags such as `--file`, `--mitre`, and `--target` are interpreted by Claude from each
command's instructions. They are convenient workflow hints, not a strict shell-style
argument parser.

### Inspecting or Customizing Commands

Open a command file to see the exact instructions Claude will follow:

```bash
sed -n '1,160p' .claude/commands/ioc-extractor.md
sed -n '1,160p' .claude/commands/threat-intel.md
```

Each command can reference shared knowledge in `.claude/knowledge/`, such as IOC regex
patterns, Sigma syntax, MITRE ATT&CK mappings, and log-format notes. To customize a
workflow, copy an existing file, edit the instructions, and restart Claude Code from the
repo root if autocomplete does not refresh.

### Creating Your Own Commands

Create a new markdown file under `.claude/commands/`:

```bash
mkdir -p .claude/commands
$EDITOR .claude/commands/my-workflow.md
```

Use this minimal structure:

```markdown
# My Workflow

Short description of what this command does.

## Usage

`/my-workflow <input>`

## Instructions

When invoked:
1. Read the input or ask for it if missing.
2. Follow the specific analysis steps.
3. Return the expected output format and any caveats.
```

### Common Pitfalls

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Project commands do not autocomplete | Claude Code was launched outside the repo root | `cd` to the repo root and restart `claude` |
| `/lab` works in Claude Code but not Cursor chat | These are Claude Code commands, not Cursor IDE slash commands | Run `claude` in a terminal, including Cursor's integrated terminal |
| API-backed enrichment skips a source | Required API key is missing | Export keys such as `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, or `SHODAN_API_KEY` |
| A command flag behaves differently than a CLI flag | Commands are markdown instructions interpreted by Claude | Open the backing file and adjust the instructions or usage examples |
| Autocomplete still shows an old command | Claude Code cached the command list for the session | Restart Claude Code from the repo root |

For learner-facing examples, see [Lab 03: Vibe Coding with AI Assistants](../../labs/lab03-vibe-coding-with-ai/).

---

## Hooks and Automation

Hooks let you automate actions before or after Claude Code operations.

### Hook Configuration

Create `.claude/hooks.json`:

```json
{
  "hooks": {
    "pre_file_write": [
      {
        "command": "python scripts/validate_security.py",
        "args": ["$FILE_PATH"],
        "description": "Validate security requirements before writing"
      }
    ],
    "post_file_write": [
      {
        "command": "bandit",
        "args": ["-r", "$FILE_PATH", "-f", "json"],
        "description": "Run security linter on new code"
      }
    ],
    "pre_command": [
      {
        "pattern": "rm -rf *",
        "action": "block",
        "message": "Dangerous command blocked"
      }
    ],
    "post_task": [
      {
        "command": "git diff --stat",
        "description": "Show changes after task completion"
      }
    ]
  }
}
```

### Security-Focused Hooks

**Pre-commit Security Check** (`.claude/hooks/pre-commit.sh`):

```bash
#!/bin/bash
# Security checks before any commit

echo "Running security checks..."

# Check for secrets
if command -v gitleaks &> /dev/null; then
    gitleaks detect --source . --verbose
    if [ $? -ne 0 ]; then
        echo "ERROR: Secrets detected! Remove before committing."
        exit 1
    fi
fi

# Check for vulnerable dependencies
if [ -f "requirements.txt" ]; then
    pip-audit -r requirements.txt --strict 2>/dev/null
fi

# Run bandit for Python
if ls *.py 1> /dev/null 2>&1; then
    bandit -r . -ll 2>/dev/null
fi

echo "Security checks passed!"
exit 0
```

---

## IDE Integration

### VS Code Integration

Install the Claude Code extension:

1. Open VS Code Extensions (Ctrl+Shift+X)
2. Search for "Claude Code"
3. Install the official Anthropic extension

Configure in `settings.json`:

```json
{
  "claude-code.apiKey": "${env:ANTHROPIC_API_KEY}",
  "claude-code.model": "claude-sonnet-4-20250514",
  "claude-code.enableExtendedThinking": true,
  "claude-code.autoApprove": ["read", "search"],
  "claude-code.requireApproval": ["write", "execute"],
  "claude-code.excludePaths": [
    "**/node_modules/**",
    "**/.git/**",
    "**/samples/malware/**"
  ]
}
```

### Cursor Integration

Cursor has native Claude support. For Claude Code CLI features:

1. Open integrated terminal in Cursor
2. Run `claude` to start Claude Code
3. Use alongside Cursor's built-in AI features

### Keybindings

Add to VS Code `keybindings.json`:

```json
[
  {
    "key": "ctrl+shift+c",
    "command": "claude-code.openPanel",
    "when": "editorFocus"
  },
  {
    "key": "ctrl+shift+a",
    "command": "claude-code.analyzeSelection",
    "when": "editorHasSelection"
  }
]
```

---

## Best Practices for Security Development

### 1. Project Configuration

Create `.claude/settings.json` for security projects:

```json
{
  "project_type": "security_tool",
  "allowed_operations": {
    "file_read": true,
    "file_write": true,
    "shell_execute": "ask",
    "network_access": false
  },
  "sensitive_paths": [
    "credentials/",
    "secrets/",
    ".env*",
    "*.pem",
    "*.key"
  ],
  "security_rules": {
    "no_secrets_in_code": true,
    "require_input_validation": true,
    "enforce_parameterized_queries": true
  },
  "custom_instructions": "This is a security analysis toolkit. Always consider defense-in-depth, validate all inputs, and follow secure coding practices. When analyzing potentially malicious code, provide detailed explanations but never enhance malicious capabilities."
}
```

### 2. Safe Malware Analysis

```bash
# Create isolated analysis environment
mkdir -p isolated_analysis
cd isolated_analysis

# Start Claude Code with restrictions
claude --no-execute "Analyze the malware sample at ../samples/suspect.exe"
```

### 3. Code Review Checklist

```bash
claude

> Review the pull request changes for:
>
> Security Checklist:
> [ ] No hardcoded secrets or credentials
> [ ] All user inputs validated and sanitized
> [ ] Parameterized queries for database operations
> [ ] Proper error handling without info disclosure
> [ ] Authentication checks on sensitive endpoints
> [ ] Authorization verified for resource access
> [ ] Cryptographic operations use secure algorithms
> [ ] Dependencies are up to date and not vulnerable
> [ ] Logging doesn't capture sensitive data
> [ ] Rate limiting on authentication endpoints
```

### 4. Documentation Generation

```bash
claude

> Generate security documentation for this project:
> 1. Architecture security overview
> 2. Threat model (using STRIDE)
> 3. Data flow diagrams with trust boundaries
> 4. Security controls matrix
> 5. Incident response procedures
```

### 5. Cost Management

Monitor API usage:

```bash
# Check current session cost
/cost

# Enable cost warnings
/config set cost_warning_threshold 5.00

# Use efficient models for simple tasks
/config set model claude-haiku-4  # For quick tasks
/config set model claude-sonnet-4-20250514  # For complex analysis
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| API key not found | Verify `ANTHROPIC_API_KEY` is set: `echo $ANTHROPIC_API_KEY` |
| Rate limited | Wait and retry, or upgrade API tier |
| Context too long | Use `/compact` to summarize conversation |
| Tool execution blocked | Check hook configurations and permissions |
| MCP server not loading | Verify server path and dependencies |

### Debug Mode

```bash
# Enable verbose logging
claude --debug

# Check configuration
claude config list

# Diagnose issues
claude doctor
```

### Getting Help

```bash
# Built-in help
claude --help

# Interactive help
> /help

# Documentation
# https://docs.anthropic.com/claude-code
```

---

## Quick Reference

### Essential Commands

| Command | Description |
|---------|-------------|
| `claude` | Start interactive chat |
| `claude "prompt"` | Run single prompt |
| `claude -c` | Continue last conversation |
| `claude -r "instructions"` | Resume with new instructions |
| `claude --print` | Print response only (no interactive) |

### Context Commands

```bash
/add src/auth.py      # Add file to context
/clear                # Clear context
/context              # Show current context
/cost                 # Check session cost
/help                 # Interactive help
```

### Security Workflows

```bash
# IOC extraction
claude "Extract all IOCs from this threat report: $(cat report.txt)"

# Malware analysis
claude "Analyze this suspicious script" < script.ps1

# Log analysis
claude "Find authentication failures in these logs" < auth.log
```

---

## Resources

- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Anthropic API Reference](https://docs.anthropic.com/api)
- [Claude Code GitHub](https://github.com/anthropics/claude-code)
- [MCP Server Registry](https://github.com/modelcontextprotocol/servers)

---

**Next**: [Google ADK Guide](./google-adk-guide.md) | [Cursor IDE Guide](./cursor-ide-guide.md)

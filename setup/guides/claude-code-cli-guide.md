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

Create reusable commands for common security tasks.

### Setup

Create `.claude/commands/` directory in your project:

```bash
mkdir -p .claude/commands
```

### Example Commands

**Vulnerability Scan** (`.claude/commands/vuln-scan.md`):

```markdown
# Vulnerability Scan Command

Perform a comprehensive vulnerability scan of the specified path.

## Parameters
- `$ARGUMENTS` - Path to scan (default: current directory)

## Task

Analyze the code at `$ARGUMENTS` for security vulnerabilities:

1. **Input Validation**
   - SQL injection
   - Command injection
   - Path traversal
   - XSS vulnerabilities

2. **Authentication/Authorization**
   - Hardcoded credentials
   - Weak password handling
   - Missing auth checks
   - Session management issues

3. **Cryptography**
   - Weak algorithms (MD5, SHA1 for passwords)
   - Hardcoded keys/IVs
   - Insecure random number generation

4. **Dependencies**
   - Check for known vulnerable packages
   - Review import statements for risky modules

5. **Output**
   - Create a markdown report with:
     - Severity ratings (Critical/High/Medium/Low)
     - Affected files and line numbers
     - Remediation recommendations
     - OWASP/CWE references
```

**IOC Extractor** (`.claude/commands/extract-iocs.md`):

```markdown
# IOC Extractor Command

Extract Indicators of Compromise from the specified file or text.

## Parameters
- `$ARGUMENTS` - File path or "clipboard" for pasted content

## Task

Extract all IOCs and format as structured output:

1. **Network Indicators**
   - IPv4/IPv6 addresses
   - Domain names
   - URLs (defanged output)
   - Email addresses

2. **File Indicators**
   - MD5, SHA1, SHA256 hashes
   - File names and paths
   - Registry keys (Windows)

3. **Behavioral Indicators**
   - Mutex names
   - Service names
   - Process names

Output JSON format:
```json
{
  "extraction_date": "ISO timestamp",
  "source": "filename or clipboard",
  "iocs": {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": {"md5": [], "sha1": [], "sha256": []},
    "emails": [],
    "files": [],
    "registry": [],
    "other": []
  },
  "mitre_mappings": []
}
```

**YARA Generator** (`.claude/commands/gen-yara.md`):

```markdown
# YARA Rule Generator

Generate a YARA rule based on provided indicators or malware description.

## Parameters
- `$ARGUMENTS` - Description or path to sample analysis

## Task

Create a production-quality YARA rule:

1. **Rule Structure**
   - Unique rule name (CamelCase with malware family)
   - Comprehensive metadata
   - Multiple detection strings

2. **String Patterns**
   - ASCII and wide string variants
   - Hex patterns for unique byte sequences
   - Regex for variable patterns

3. **Conditions**
   - File type checks (MZ header, etc.)
   - Size limits
   - String combination logic
   - Entry point checks if applicable

4. **Quality Checks**
   - Avoid false positives on legitimate software
   - Test against clean file samples mentally
   - Consider performance impact

Output the rule with comments explaining detection logic.
```

### Using Slash Commands

```bash
claude

# Use vulnerability scan command
> /vuln-scan src/webapp/

# Extract IOCs from a file
> /extract-iocs logs/suspicious_traffic.pcap

# Generate YARA rule
> /gen-yara "Emotet banking trojan with process injection capabilities"
```

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

## Resources

- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Anthropic API Reference](https://docs.anthropic.com/api)
- [Claude Code GitHub](https://github.com/anthropics/claude-code)
- [MCP Server Registry](https://github.com/modelcontextprotocol/servers)

---

**Next**: [Google ADK Guide](./google-adk-guide.md) | [Cursor IDE Guide](./cursor-ide-guide.md)

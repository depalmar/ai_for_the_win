# Cursor IDE Complete Guide

The AI-native IDE that supercharges your security tool development.

---

## Table of Contents

1. [Why Cursor for Security AI Development](#why-cursor-for-security-ai-development)
2. [Installation](#installation)
3. [Initial Setup](#initial-setup)
4. [Key Features](#key-features)
5. [Agent Mode](#agent-mode)
6. [Background Agents](#background-agents)
7. [MCP Integration](#mcp-integration)
8. [AI Models Configuration](#ai-models-configuration)
9. [Cursor Rules](#cursor-rules)
10. [Keyboard Shortcuts](#keyboard-shortcuts)
11. [Security-Focused Workflows](#security-focused-workflows)
12. [Best Practices](#best-practices)
13. [Advanced Configuration](#advanced-configuration)

---

## 🎯 Why Cursor for Security AI Development

Cursor is built on VS Code but adds native AI capabilities that are essential for building AI-powered security tools:

| Feature                        | Benefit for Security Development                                            |
| ------------------------------ | --------------------------------------------------------------------------- |
| **Inline AI Chat**             | Get instant explanations of malware code, log formats, or attack techniques |
| **Codebase-Aware Completions** | AI understands your entire security tool codebase                           |
| **Multi-File Editing**         | Refactor detection rules across multiple files simultaneously               |
| **Composer Mode**              | Build entire security agents from natural language descriptions             |
| **Terminal Integration**       | Run security tools with AI-assisted command building                        |

---

## 💾 Installation

### Download

```bash
# Visit
https://cursor.sh/

# Or direct download links:
# Windows: https://download.cursor.sh/windows/installer
# macOS: https://download.cursor.sh/mac/installer
# Linux: https://download.cursor.sh/linux/appImage
```

### Windows Installation

1. Download the installer from cursor.sh
2. Run `CursorSetup.exe`
3. Follow installation wizard
4. Launch Cursor from Start Menu

### macOS Installation

```bash
# Using Homebrew
brew install --cask cursor

# Or download .dmg and drag to Applications
```

### Linux Installation

```bash
# AppImage
chmod +x cursor-*.AppImage
./cursor-*.AppImage

# Or extract and run
./cursor
```

---

## ⚙️ Initial Setup

### 1. Sign In / Create Account

When you first launch Cursor:

1. Click "Sign In" or "Create Account"
2. You can use GitHub, Google, or email
3. Free tier includes limited AI requests
4. Pro ($20/month) unlocks unlimited requests

### 2. Import VS Code Settings

If you have VS Code installed:

1. Cursor will prompt to import settings
2. Select "Import from VS Code"
3. This brings over extensions, themes, and keybindings

### 3. Configure AI Provider

Go to **Settings** > **Cursor** > **Models**:

```json
{
  "cursor.aiProvider": "anthropic",
  "cursor.defaultModel": "claude-sonnet-4-20250514",
  "cursor.enableLongContext": true
}
```

### 4. Install Essential Extensions

Press `Ctrl+Shift+X` (Cmd+Shift+X on Mac) and install:

```
# Core Development
ms-python.python
ms-python.vscode-pylance
ms-toolsai.jupyter

# Git Integration
eamodio.gitlens
mhutchie.git-graph

# Security & Analysis
redhat.vscode-yaml
ms-vscode.hexeditor
timonwong.shellcheck

# Docker & Remote
ms-vscode-remote.remote-ssh
ms-azuretools.vscode-docker

# Formatting
esbenp.prettier-vscode
ms-python.black-formatter
```

---

## 🚀 Key Features

### Feature 1: Inline Chat (`Ctrl+L` / `Cmd+L`)

Select code and press `Ctrl+L` to ask questions:

```python
# Select this malware analysis function
def analyze_pe_file(filepath):
    pe = pefile.PE(filepath)
    # ... complex analysis code
    return results

# Press Ctrl+L and ask:
# "Explain what this function does step by step"
# "How can I add entropy calculation to this?"
# "What YARA signatures could detect this behavior?"
```

### Feature 2: Composer (`Ctrl+I` / `Cmd+I`)

Press `Ctrl+I` for multi-file AI editing:

```
Prompt: "Create a LangChain agent that:
1. Takes a suspicious URL as input
2. Checks it against VirusTotal API
3. Downloads and analyzes the content if safe
4. Generates a threat report"

Cursor will:
- Create new files as needed
- Import required libraries
- Implement the full agent
- Add error handling
```

### Feature 3: Codebase Chat (`Ctrl+Shift+L` / `Cmd+Shift+L`)

Ask questions about your entire codebase:

```
"Where do we handle MITRE ATT&CK mappings?"
"Show me all places where we parse Windows event logs"
"How does the threat scoring work?"
```

### Feature 4: Terminal AI (`Ctrl+K` in Terminal)

Get AI help with terminal commands:

```bash
# Press Ctrl+K in terminal and type:
"Run volatility3 to list processes from memory.dmp"

# Cursor suggests:
vol -f memory.dmp windows.pslist.PsList
```

### Feature 5: @ Mentions

Reference specific context in prompts:

```
@file:detection_rules.py - Reference a specific file
@folder:agents/ - Reference an entire folder
@codebase - Search entire codebase
@docs - Reference documentation
@web - Search the web
```

---

## Agent Mode

Agent Mode transforms Cursor from an AI assistant into an autonomous coding agent that can plan and execute complex multi-step tasks.

### Enabling Agent Mode

In Composer (`Ctrl+I`), enable Agent Mode:

```
1. Open Composer (Ctrl+I / Cmd+I)
2. Click the "Agent" toggle or use Ctrl+Shift+A
3. Agent Mode is now active
```

### Agent Capabilities

| Capability | Description |
|------------|-------------|
| **Multi-step Planning** | Breaks complex tasks into executable steps |
| **Autonomous Execution** | Runs through steps without constant approval |
| **File Operations** | Creates, reads, edits, and deletes files |
| **Terminal Commands** | Executes shell commands for builds, tests, etc. |
| **Error Recovery** | Detects and fixes errors automatically |
| **Context Gathering** | Searches codebase for relevant context |

### Security Development with Agent Mode

```
# Example: Build a complete detection system
Prompt in Agent Mode:

"Create a malware detection pipeline that:
1. Monitors a folder for new files
2. Calculates file hashes (MD5, SHA256)
3. Checks hashes against VirusTotal API
4. Scans files with YARA rules in rules/
5. Logs results to SQLite database
6. Sends alerts via Slack webhook for detections

Use Python asyncio for efficiency. Include proper error
handling and rate limiting for API calls."
```

The agent will:
1. Analyze your codebase structure
2. Create necessary Python files
3. Implement each component
4. Add error handling
5. Create configuration files
6. Write tests
7. Run and debug the implementation

### Agent Mode Best Practices

1. **Be Specific**: Detailed prompts get better results
2. **Provide Context**: Reference existing files with @mentions
3. **Review Changes**: Check each step before moving forward
4. **Set Boundaries**: Specify what NOT to modify
5. **Iterate**: Refine with follow-up instructions

---

## Background Agents

Background Agents allow you to run long-running AI tasks while continuing to work.

### Starting Background Agents

```bash
# From Cursor, press Ctrl+Shift+P
> "Start Background Agent"

# Or in Composer
> Toggle "Run in Background"
```

### Use Cases for Security Development

**1. Continuous Code Review:**
```
"Run in background: Monitor src/ for changes and perform
security review on modified files. Flag any:
- SQL injection risks
- Command injection
- Hardcoded secrets
- Authentication bypasses

Write findings to SECURITY_REVIEW.md"
```

**2. Automated Test Generation:**
```
"Background: Generate security-focused unit tests for all
functions in src/auth/. Include tests for:
- SQL injection attempts
- Buffer overflow inputs
- Path traversal attacks
- Invalid authentication tokens"
```

**3. Documentation Generation:**
```
"Background: Create comprehensive security documentation for
the entire codebase. Include:
- Architecture overview
- Security controls
- Data flow diagrams
- Threat model (STRIDE)
- API security specifications"
```

### Managing Background Agents

```bash
# View running agents
Ctrl+Shift+P > "View Background Agents"

# Stop an agent
Click "Stop" on the agent panel

# Review agent output
Agents write to designated output files or the agent panel
```

---

## MCP Integration

Model Context Protocol (MCP) extends Cursor's capabilities with external tools and services.

### What is MCP?

MCP allows Cursor to connect to external services:
- Security APIs (VirusTotal, Shodan, MISP)
- Databases and data sources
- Custom tooling and scripts
- File system extensions

### Configuring MCP Servers

Create `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "security-tools": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-fetch"],
      "env": {}
    },
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/directory"
      ]
    },
    "sqlite-threatdb": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-sqlite",
        "--db",
        "./data/threat_intel.db"
      ]
    }
  }
}
```

### Security-Focused MCP Servers

**VirusTotal Integration:**
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python",
      "args": ["./mcp/virustotal_server.py"],
      "env": {
        "VT_API_KEY": "${env:VIRUSTOTAL_API_KEY}"
      }
    }
  }
}
```

**MISP Integration:**
```json
{
  "mcpServers": {
    "misp": {
      "command": "python",
      "args": ["./mcp/misp_server.py"],
      "env": {
        "MISP_URL": "${env:MISP_URL}",
        "MISP_KEY": "${env:MISP_API_KEY}"
      }
    }
  }
}
```

### Using MCP Tools in Cursor

Once configured, MCP tools are available in chat:

```
@mcp:virustotal "Look up hash abc123def456..."

@mcp:misp "Search for IOCs related to APT29"

@mcp:sqlite-threatdb "Query recent malware samples"
```

---

## AI Models Configuration

### Available Models

| Model                        | Best For                                | Speed     | Cost |
| ---------------------------- | --------------------------------------- | --------- | ---- |
| **claude-sonnet-4-20250514** | Complex security analysis, long context | Medium    | $$   |
| **claude-opus-4-5**          | Deepest reasoning, architecture design  | Slow      | $$$  |
| **gpt-4o**                   | General coding, function calling        | Medium    | $$   |
| **gpt-4o**                   | Fast responses, balanced quality        | Fast      | $    |
| **cursor-small**             | Quick completions, simple tasks         | Very Fast | $    |

### Model-Specific Settings

```json
// settings.json
{
  // Default model for most tasks
  "cursor.defaultModel": "claude-sonnet-4-20250514",

  // Use faster model for autocomplete
  "cursor.autocomplete.model": "cursor-small",

  // Use strongest model for Composer
  "cursor.composer.model": "claude-opus-4-5",

  // Context settings
  "cursor.enableLongContext": true,
  "cursor.maxContextLines": 10000,

  // Privacy
  "cursor.enableTelemetry": false,
  "cursor.privacyMode": false
}
```

### Custom API Keys (Optional)

If you prefer using your own API keys:

```json
{
  "cursor.anthropicApiKey": "sk-ant-...",
  "cursor.openaiApiKey": "sk-...",
  "cursor.useOwnApiKeys": true
}
```

---

## Cursor Rules

Cursor Rules customize AI behavior for your project. Create rules at multiple levels.

### Rule File Locations

| File | Scope | Purpose |
|------|-------|---------|
| `.cursorrules` | Project root | Project-wide AI behavior |
| `.cursor/rules/*.mdc` | Subdirectory rules | Path-specific rules |
| `~/.cursor/rules/` | Global rules | User preferences across projects |

### Security Project Rules (.cursorrules)

Create `.cursorrules` in your project root:

```markdown
# Security Tool Development Rules

## Project Context
This is a security analysis toolkit for threat detection and incident response.
The codebase includes malware analysis tools, detection rules, and forensic utilities.

## Code Style Requirements
- Use Python 3.10+ with full type hints
- Follow PEP 8 and PEP 257 (docstrings)
- Use async/await for I/O operations
- Implement comprehensive error handling

## Security Requirements (CRITICAL)
- NEVER log sensitive data (passwords, API keys, PII, credentials)
- NEVER store secrets in code - use environment variables
- ALWAYS validate and sanitize external inputs
- ALWAYS use parameterized queries for databases
- ALWAYS escape output in web contexts
- NEVER use shell=True with user input
- NEVER disable SSL certificate verification in production
- ALWAYS implement rate limiting on API endpoints
- ALWAYS check authentication before authorization

## Analysis Guidelines
When analyzing potentially malicious code:
- Explain what the code does in detail
- Identify malicious capabilities
- Map to MITRE ATT&CK techniques
- Extract IOCs (indicators of compromise)
- NEVER enhance or weaponize malicious functionality

## Preferred Libraries
- langchain / langchain-anthropic: LLM operations
- pydantic: Data validation and settings
- httpx: Async HTTP client
- loguru: Logging (with PII filtering)
- yara-python: Pattern matching
- pefile: PE analysis
- volatility3: Memory forensics

## Output Formatting
- Include MITRE ATT&CK IDs when relevant (e.g., T1059.001)
- Reference CVE IDs for vulnerabilities
- Use CWE classifications for code weaknesses
- Format IOCs in defanged notation (hxxp://, [.])

## File Organization
```
src/
├── agents/         # LLM-powered agents
├── analyzers/      # Analysis modules
├── detectors/      # Detection logic
├── integrations/   # External API clients
├── models/         # Pydantic models
└── utils/          # Shared utilities
```

## Testing Requirements
- Unit tests for all public functions
- Integration tests for external APIs (mocked)
- Security-focused test cases (injection, overflow, etc.)
- Minimum 80% code coverage
```

### Path-Specific Rules (.cursor/rules/)

Create rules for specific directories:

**.cursor/rules/malware-analysis.mdc:**
```markdown
---
path: samples/**
---

# Malware Analysis Directory Rules

## Context
Files in this directory may contain malicious code samples or analysis artifacts.

## Handling Guidelines
- Treat all files as potentially dangerous
- Analyze but NEVER execute or enhance malicious code
- Extract IOCs without exposing working exploits
- Document capabilities for defensive purposes only

## Output Format
When analyzing samples, always provide:
1. File metadata (type, size, hashes)
2. Static analysis findings
3. Behavioral indicators (if available)
4. Network IOCs (defanged)
5. MITRE ATT&CK mapping
6. YARA rule for detection
```

**.cursor/rules/detection-rules.mdc:**
```markdown
---
path: rules/**
---

# Detection Rules Directory

## Context
This directory contains YARA, Sigma, and Snort/Suricata rules.

## Rule Quality Standards
- Include comprehensive metadata (author, date, description)
- Add MITRE ATT&CK tags
- Minimize false positives with specific conditions
- Test against known samples before committing
- Document expected log sources for Sigma rules

## Sigma Rule Format
Always use this structure:
```yaml
title: Descriptive Title
id: <unique-uuid>
status: experimental|test|stable
description: What this detects and why
author: Author Name
date: YYYY/MM/DD
references:
    - https://relevant-link
tags:
    - attack.tactic
    - attack.t1234
logsource:
    category: process_creation|network|etc
    product: windows|linux|etc
detection:
    selection:
        # Detection logic
    condition: selection
falsepositives:
    - Known false positive scenarios
level: critical|high|medium|low|informational
```
```

### Global User Rules

Create `~/.cursor/rules/security-defaults.mdc`:

```markdown
---
global: true
---

# Global Security Development Preferences

## Always Apply
- Security-first mindset
- Defense in depth approach
- Least privilege principle

## My Preferences
- Prefer Claude claude-sonnet-4-20250514 for security analysis
- Include detailed comments for complex security logic
- Generate security test cases automatically
- Flag potential security issues proactively
```

---

## Keyboard Shortcuts

### Essential Shortcuts

| Action                  | Windows/Linux          | macOS         |
| ----------------------- | ---------------------- | ------------- |
| **Inline Chat**         | `Ctrl+L`               | `Cmd+L`       |
| **Composer**            | `Ctrl+I`               | `Cmd+I`       |
| **Codebase Chat**       | `Ctrl+Shift+L`         | `Cmd+Shift+L` |
| **Terminal AI**         | `Ctrl+K` (in terminal) | `Cmd+K`       |
| **Accept Suggestion**   | `Tab`                  | `Tab`         |
| **Reject Suggestion**   | `Escape`               | `Escape`      |
| **Next Suggestion**     | `Alt+]`                | `Option+]`    |
| **Previous Suggestion** | `Alt+[`                | `Option+[`    |
| **Trigger Suggestion**  | `Ctrl+Space`           | `Cmd+Space`   |

### Custom Keybindings for Security Work

Add to `keybindings.json`:

```json
[
  // Quick analyze selected code
  {
    "key": "ctrl+shift+a",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Analyze this code for security vulnerabilities" }
  },

  // Generate YARA rule from selection
  {
    "key": "ctrl+shift+y",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Generate a YARA rule to detect this pattern" }
  },

  // Explain malware behavior
  {
    "key": "ctrl+shift+m",
    "command": "cursor.chat.sendSelection",
    "args": { "prompt": "Explain what this malware code does" }
  }
]
```

---

## 🔐 Security-Focused Workflows

### Workflow 1: Analyzing Malware Samples

```python
# 1. Open a malware analysis file
# 2. Select suspicious code
# 3. Press Ctrl+L and ask:

"""
Prompts to use:
- "What Windows API calls indicate malicious behavior?"
- "Identify any obfuscation techniques used"
- "What persistence mechanisms does this implement?"
- "Map this code to MITRE ATT&CK techniques"
- "Generate IOCs from this sample"
"""
```

### Workflow 2: Building Detection Rules

```
# Use Composer (Ctrl+I) with prompts like:

"Create a Sigma rule that detects:
- PowerShell downloading files from the internet
- Base64 encoded commands
- Execution from temp directories
Include references to MITRE ATT&CK T1059.001"

"Convert this Sigma rule to a Splunk query"

"Generate a YARA rule from these strings: [paste strings]"
```

### Workflow 3: Developing AI Agents

```
# In Composer mode:

"Build a LangChain agent for incident response that can:
1. Parse Windows Security event logs
2. Identify failed login attempts
3. Correlate with known bad IPs from threat intel
4. Generate a timeline of suspicious activity
5. Recommend containment actions

Use these files as reference:
@file:agents/base_agent.py
@folder:config/"
```

### Workflow 4: Code Review for Vulnerabilities

```python
# Select your code and ask:

"Review this code for:
1. SQL injection vulnerabilities
2. Command injection risks
3. Hardcoded credentials
4. Insecure deserialization
5. Path traversal issues

Provide specific line numbers and remediation steps."
```

---

## 💡 Best Practices

### 1. Use .cursorrules File

Create `.cursorrules` in your project root to customize AI behavior:

```markdown
# .cursorrules

## Project Context

This is an AI-powered security tool for threat detection and incident response.

## Code Style

- Use type hints for all Python functions
- Follow PEP 8 style guidelines
- Include docstrings with security considerations
- Log all security-relevant actions

## Security Requirements

- Never log sensitive data (passwords, API keys, PII)
- Validate all external inputs
- Use parameterized queries for databases
- Implement proper error handling without exposing internals

## Preferred Libraries

- Use `langchain` for LLM operations
- Use `pydantic` for data validation
- Use `loguru` for logging
- Use `httpx` for async HTTP requests

## Response Format

- Include MITRE ATT&CK references where applicable
- Add IOC extraction for malware analysis
- Reference relevant CVEs when discussing vulnerabilities
```

### 2. Provide Context in Prompts

❌ Bad prompt:

```
"Fix this code"
```

✅ Good prompt:

```
"This function parses Windows Event Log 4688 (Process Creation).
It's currently missing extraction of:
- Parent process information
- Command line arguments
- Token elevation type

Add these fields and include proper error handling for malformed logs."
```

### 3. Use Incremental Development

Instead of asking for complete implementations:

```
Step 1: "Create the class structure for a VirusTotal scanner agent"
Step 2: "Add the file hash lookup method"
Step 3: "Add rate limiting and retry logic"
Step 4: "Add result caching"
Step 5: "Add async batch scanning support"
```

### 4. Review AI Suggestions Carefully

Always verify AI-generated security code:

```python
# AI might suggest:
def check_password(user_input, stored_hash):
    return user_input == stored_hash  # ❌ WRONG - comparing plaintext to hash!

# You need to catch this and fix:
def check_password(user_input, stored_hash):
    return bcrypt.checkpw(user_input.encode(), stored_hash)  # ✅ Correct
```

### 5. Leverage Multi-File Context

When working on complex features:

```
@file:models/threat.py
@file:agents/detection_agent.py
@file:config/rules.yaml

"Add a new threat type 'cryptominer' with:
- Detection rules based on CPU usage patterns
- Network IOCs for mining pools
- Process name patterns
Update all relevant files to support this new threat type."
```

---

## 🔧 Troubleshooting

### AI Not Responding

1. Check internet connection
2. Verify you haven't exceeded rate limits
3. Try switching models
4. Restart Cursor

### Slow Completions

```json
// Reduce context size
{
  "cursor.maxContextLines": 5000,
  "cursor.autocomplete.debounceMs": 200
}
```

### Wrong Language Completions

```json
// Force Python for security tools
{
  "cursor.language.preferredLanguage": "python"
}
```

### Privacy Concerns

```json
// Enable privacy mode
{
  "cursor.privacyMode": true,
  "cursor.enableTelemetry": false,
  "cursor.excludeFromIndexing": ["**/secrets/**", "**/.env", "**/credentials/**", "**/samples/**"]
}
```

---

## Additional Resources

- [Cursor Documentation](https://docs.cursor.sh)
- [Cursor Discord Community](https://discord.gg/cursor)
- [VS Code Keybindings Reference](https://code.visualstudio.com/docs/getstarted/keybindings)
- [Python Extension Documentation](https://code.visualstudio.com/docs/python/python-tutorial)

---

## Advanced Configuration

### Performance Optimization

```json
// settings.json - Performance tuning
{
  // Reduce memory usage
  "cursor.maxContextLines": 5000,
  "cursor.autocomplete.debounceMs": 150,

  // Exclude large/binary directories from indexing
  "cursor.excludeFromIndexing": [
    "**/node_modules/**",
    "**/.git/**",
    "**/venv/**",
    "**/samples/malware/**",
    "**/*.exe",
    "**/*.dll",
    "**/*.bin",
    "**/memory_dumps/**"
  ],

  // Optimize for large codebases
  "cursor.codebaseIndex.maxFileSize": 1000000,
  "cursor.codebaseIndex.maxFiles": 10000
}
```

### Security-Hardened Configuration

```json
{
  // Privacy settings
  "cursor.privacyMode": true,
  "cursor.enableTelemetry": false,

  // Exclude sensitive paths from AI context
  "cursor.excludeFromContext": [
    "**/.env*",
    "**/secrets/**",
    "**/credentials/**",
    "**/*.pem",
    "**/*.key",
    "**/config/production.*"
  ],

  // Require confirmation for certain operations
  "cursor.requireConfirmation": {
    "fileDelete": true,
    "terminalCommand": true,
    "externalApi": true
  }
}
```

### Workspace-Specific Settings

Create `.vscode/settings.json` for project-specific configuration:

```json
{
  // Project-specific model selection
  "cursor.defaultModel": "claude-sonnet-4-20250514",
  "cursor.composer.model": "claude-sonnet-4-20250514",

  // Custom instructions for this project
  "cursor.customInstructions": "This is a security analysis toolkit. Always consider OWASP Top 10 and map findings to MITRE ATT&CK.",

  // Project-specific exclusions
  "cursor.excludeFromIndexing": [
    "**/test_samples/**",
    "**/malware_zoo/**"
  ]
}
```

### Remote Development Setup

For analyzing malware in isolated environments:

```json
{
  // Remote SSH configuration
  "remote.SSH.defaultExtensions": [
    "ms-python.python",
    "ms-python.vscode-pylance"
  ],

  // Container development
  "dev.containers.defaultExtensions": [
    "ms-python.python"
  ],

  // WSL settings (Windows)
  "remote.WSL.fileWatcher.polling": true
}
```

### Integration with Security Tools

```json
{
  // Linting with security focus
  "python.linting.banditEnabled": true,
  "python.linting.banditArgs": ["-ll", "-r"],

  // Pre-commit hooks
  "git.enableCommitSigning": true,

  // Terminal integration
  "terminal.integrated.env.linux": {
    "PYTHONPATH": "${workspaceFolder}/src"
  }
}
```

---

## Quick Reference

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + K` | Inline edit (edit selected code) |
| `Cmd/Ctrl + L` | Open Chat panel |
| `Cmd/Ctrl + I` | Composer (multi-file edits) |
| `Cmd/Ctrl + Shift + K` | Terminal command generation |
| `Tab` | Accept autocomplete suggestion |
| `Esc` | Reject suggestion |

### Context References

| Shortcut | Action |
|----------|--------|
| `@file` | Reference specific file |
| `@folder` | Reference folder |
| `@codebase` | Search entire codebase |
| `@docs` | Reference documentation |
| `@web` | Search the web |
| `@git` | Reference git history |

### Tips

1. **Be specific** - Detailed prompts get better results
2. **Use @mentions** - Reference files and docs explicitly
3. **Review diffs** - Always review before accepting changes
4. **Iterate** - Ask follow-up questions to refine
5. **Use .cursorrules** - Set project-specific guidelines

---

**Next**: [Claude Code CLI Guide](./claude-code-cli-guide.md) | [Google ADK Guide](./google-adk-guide.md)

# Claude Code CLI Cheat Sheet

Quick reference for Claude Code commands and workflows.

---

## Installation & Setup

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# Authenticate
claude login

# Check version
claude --version

# Initialize in project
cd your-project && claude init
```

---

## Essential Commands

| Command | Description |
|---------|-------------|
| `claude` | Start interactive chat |
| `claude "prompt"` | Run single prompt |
| `claude -c` | Continue last conversation |
| `claude -r "instructions"` | Resume with new instructions |
| `claude --print` | Print response only (no interactive) |

---

## Common Workflows

### Code Analysis
```bash
# Analyze a file
claude "Review this code for security issues" < vulnerable.py

# Analyze directory
claude "Find all SQL injection vulnerabilities in this codebase"
```

### Code Generation
```bash
# Generate with context
claude "Write unit tests for the UserAuth class"

# Pipe output to file
claude "Generate a Python YARA rule parser" --print > parser.py
```

### Git Integration
```bash
# Commit assistance
claude "Write a commit message for staged changes"

# PR review
claude "Review the changes in this PR and identify security concerns"
```

---

## Context Management

```bash
# Add files to context
/add src/auth.py src/database.py

# Clear context
/clear

# Show current context
/context
```

---

## Configuration

### Project Settings (.claude/settings.json)
```json
{
  "model": "claude-sonnet-4-20250514",
  "allowedTools": ["Read", "Write", "Bash"],
  "maxTokens": 8192
}
```

### MCP Server Setup (.claude/mcp.json)
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python",
      "args": ["./mcp-servers/virustotal.py"],
      "env": {"VT_API_KEY": "${VT_API_KEY}"}
    }
  }
}
```

---

## Security Analysis Prompts

```bash
# IOC extraction
claude "Extract all IOCs from this threat report: $(cat report.txt)"

# Malware analysis
claude "Analyze this suspicious script and identify malicious behaviors" < script.ps1

# Log analysis
claude "Find authentication failures in these logs" < auth.log
```

---

## Tips

1. **Use specific prompts** - Be explicit about what you want
2. **Provide context** - Add relevant files to context
3. **Iterate** - Use `-c` to continue conversations
4. **Automate** - Combine with shell scripts for workflows

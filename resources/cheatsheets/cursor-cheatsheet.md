# Cursor IDE Cheat Sheet

Quick reference for Cursor shortcuts and features.

---

## Keyboard Shortcuts

### AI Features
| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + K` | Inline edit (edit selected code) |
| `Cmd/Ctrl + L` | Open Chat panel |
| `Cmd/Ctrl + I` | Composer (multi-file edits) |
| `Cmd/Ctrl + Shift + K` | Terminal command generation |
| `Tab` | Accept autocomplete suggestion |
| `Esc` | Reject suggestion |

### Context
| Shortcut | Action |
|----------|--------|
| `@file` | Reference specific file |
| `@folder` | Reference folder |
| `@codebase` | Search entire codebase |
| `@docs` | Reference documentation |
| `@web` | Search the web |
| `@git` | Reference git history |

---

## Chat Commands

```
# Reference files
@src/auth.py what does this do?

# Codebase search
@codebase where is authentication handled?

# Web search
@web latest CVE for Log4j

# Documentation
@docs how do I use pytest fixtures?
```

---

## Agent Mode

Enable in Settings > Features > Agent Mode

### Capabilities
- Multi-file editing
- Terminal command execution
- Automatic context gathering
- Iterative problem solving

### Best Practices
```
# Good prompt for Agent Mode
"Implement rate limiting for the /api/analyze endpoint.
Add tests and update the documentation."

# Let agent work autonomously
# Review changes before accepting
```

---

## .cursorrules Template

Create `.cursorrules` in project root:

```markdown
# Project: Security Analysis Tool

## Context
- Python 3.11+ security toolkit
- Uses LangChain for LLM operations
- Focus: Threat detection and analysis

## Code Style
- Type hints required
- Async for I/O operations
- Pydantic for validation

## Security Rules
- NEVER log sensitive data
- Always validate inputs
- Defang IOCs in output
```

---

## MCP Integration

### Setup (.cursor/mcp.json)
```json
{
  "mcpServers": {
    "security-tools": {
      "command": "python",
      "args": ["-m", "security_mcp_server"],
      "env": {
        "API_KEY": "${SECURITY_API_KEY}"
      }
    }
  }
}
```

### Usage in Chat
```
Use the security-tools MCP to look up this hash:
a1b2c3d4e5f6...
```

---

## Composer Workflows

### Multi-File Refactoring
```
Cmd/Ctrl + I to open Composer

"Refactor the authentication system:
1. Extract token validation to separate module
2. Add refresh token support
3. Update all endpoints using auth
4. Add unit tests"
```

### Feature Implementation
```
"Add malware scanning feature:
- New endpoint POST /api/scan
- Integration with VirusTotal API
- Result caching in Redis
- Rate limiting per user"
```

---

## Tips

1. **Be specific** - Detailed prompts get better results
2. **Use @mentions** - Reference files and docs explicitly
3. **Review diffs** - Always review before accepting changes
4. **Iterate** - Ask follow-up questions to refine
5. **Use .cursorrules** - Set project-specific guidelines

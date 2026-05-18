# Cursor AI Rules for AI for the Win

These rules help Cursor's AI assistant understand the project context and provide better guidance.

## Quick Setup

Copy all rule files to your local `.cursor/rules/` directory:

```bash
# From project root
mkdir -p .cursor/rules
cp setup/cursor-rules/{project,labs,code-style,security,testing,patterns}.md .cursor/rules/
```

Or on Windows (PowerShell):
```powershell
New-Item -ItemType Directory -Force -Path .cursor\rules
Copy-Item setup\cursor-rules\project.md .cursor\rules\
Copy-Item setup\cursor-rules\labs.md .cursor\rules\
Copy-Item setup\cursor-rules\code-style.md .cursor\rules\
Copy-Item setup\cursor-rules\security.md .cursor\rules\
Copy-Item setup\cursor-rules\testing.md .cursor\rules\
Copy-Item setup\cursor-rules\patterns.md .cursor\rules\
```

## What's Included

| File | Purpose |
|------|---------|
| `project.md` | Project overview, tech stack, directory structure |
| `labs.md` | Lab structure, teaching guidelines (hints vs solutions) |
| `code-style.md` | Formatting rules, multi-provider LLM support |
| `security.md` | IOC defanging, MITRE ATT&CK references, data handling |
| `testing.md` | pytest conventions, markers, test structure |
| `patterns.md` | Pydantic, LangChain, async, RAG patterns |

## How It Works

When you use Cursor's AI features (Cmd+K, Cmd+L, or agent mode), it reads these rules to:

- Understand the project structure
- Follow code style conventions
- Give hints instead of full solutions (for learning)
- Include security references (MITRE ATT&CK, CVE)
- Defang IOCs in output

## Customization

Feel free to modify the rules for your needs. The `.cursor/` directory is gitignored, so your local changes stay private.

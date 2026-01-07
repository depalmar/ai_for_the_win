# Lab 00h: Vibe Coding with AI Assistants

## Overview

Welcome to the world of **vibe coding** - a modern approach to software development where you collaborate with AI assistants to write, debug, and understand code faster than ever before. This lab will equip you with the skills to leverage AI coding tools throughout your security training journey.

> **What is Vibe Coding?** It's a development style where you work alongside AI assistants, describing what you want to build in natural language and iteratively refining the output. Think of it as pair programming with an infinitely patient, knowledgeable partner.

## Learning Objectives

By the end of this lab, you will be able to:

1. **Set up and configure** at least one AI coding assistant for your development environment
2. **Write effective prompts** to generate security-focused Python code
3. **Iterate and refine** AI-generated code through conversation
4. **Understand the code** AI generates (not just copy-paste blindly)
5. **Apply vibe coding** techniques to accelerate your learning in subsequent labs
6. **Use Claude Code's advanced features** including slash commands, custom skills, and MCP servers

## Time Estimate

**45 minutes**

## Prerequisites

- Computer with internet access
- Python 3.10+ installed (from Lab 00)
- A code editor (VS Code recommended)
- At least one API key OR local tool:
  - Anthropic API key (Claude)
  - OpenAI API key (GPT-4)
  - GitHub Copilot subscription
  - Local: Ollama, LM Studio, or similar

## Why Vibe Coding Matters for Security Professionals

As a security practitioner, you'll write tools for:
- Log analysis and parsing
- Threat detection rules
- Incident response automation
- Malware analysis scripts
- Vulnerability scanning

AI assistants can help you build these tools **10x faster** while teaching you best practices along the way. But there's a critical rule:

> **The Golden Rule**: Always understand what the AI generates. In security, blindly running code you don't understand is a vulnerability in itself.

---

## Part 1: Choose Your AI Coding Assistant

### Option A: Claude Code (CLI) - Recommended

Claude Code is Anthropic's official CLI tool that brings Claude directly into your terminal.

**Installation:**
```bash
# Install via npm
npm install -g @anthropic-ai/claude-code

# Or use directly with npx
npx @anthropic-ai/claude-code
```

**Setup:**
```bash
# Set your API key
export ANTHROPIC_API_KEY="your-key-here"

# Start Claude Code
claude
```

**Why Claude Code for this course:**
- Works directly in your terminal alongside your code
- Can read, write, and edit files
- Understands project context
- Great for security-focused development

**Claude Code Power Features:**

Claude Code has advanced features that make it especially powerful for security work:

**Slash Commands** - Quick actions you can invoke:
```bash
/help          # Get help with Claude Code
/clear         # Clear conversation history
/compact       # Summarize conversation to save context
/init          # Initialize CLAUDE.md project instructions
/memory        # Edit persistent memory across sessions
/mcp           # Configure Model Context Protocol servers
```

**Custom Skills** - This course includes pre-built skills for security tasks:
```bash
/ioc-extractor      # Extract IOCs from text or logs
/sigma-create       # Create Sigma detection rules
/sigma-convert      # Convert Sigma rules to various formats
/threat-hunt        # Build threat hunting queries
/log-parser         # Parse common log formats
/dfir-analyze       # Analyze DFIR datasets
```

**MCP (Model Context Protocol)** - Connect Claude to external tools:
```bash
# Example: Enable Brave Search for threat intel research
/mcp

# MCP servers can provide:
# - Web search for threat intelligence
# - Database queries for log analysis
# - API integrations for enrichment
```

**Memory & Context** - Claude remembers across sessions:
```bash
# Store investigation context
/memory add "Current incident: Ransomware on WORKSTATION01"

# View stored memories
/memory
```

> **Pro Tip**: Run `/help` in Claude Code to see all available commands and features!

### Option B: Cursor IDE

Cursor is a VS Code fork with AI deeply integrated.

**Installation:**
1. Download from [cursor.sh](https://cursor.sh)
2. Import your VS Code settings (optional)
3. Sign in with your API key or use Cursor's built-in models

**Key Features:**
- Cmd/Ctrl+K: Generate code
- Cmd/Ctrl+L: Chat about code
- Tab: Accept AI suggestions
- Select code + Cmd/Ctrl+K: Edit selection with AI

### Option C: GitHub Copilot

GitHub's AI pair programmer integrated into VS Code.

**Installation:**
1. Install "GitHub Copilot" extension in VS Code
2. Sign in with GitHub account (requires subscription)

**Key Features:**
- Inline suggestions as you type
- Copilot Chat panel for conversations
- Ghost text completions

### Option D: Continue.dev (Open Source)

Open-source AI assistant that works with any model.

**Installation:**
1. Install "Continue" extension in VS Code
2. Configure with your preferred model (local or API)

### Option E: Local Models (Ollama + Codeium)

For offline/privacy-focused development:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a coding model
ollama pull codellama:13b
ollama pull deepseek-coder:6.7b

# Start the server
ollama serve
```

Then use with Continue.dev or other compatible extensions.

---

## Part 2: Your First Vibe Coding Session

### Exercise 1: Generate a Security Tool

Let's build a simple log analyzer using vibe coding. Open your AI assistant and try this prompt:

```
Create a Python script that:
1. Reads a log file containing authentication attempts
2. Identifies failed login attempts (look for "failed" or "invalid")
3. Groups failures by IP address
4. Flags IPs with more than 5 failures as potential brute force attacks
5. Outputs a summary report

Use argparse for CLI arguments and include proper error handling.
```

**What to observe:**
- How does the AI structure the code?
- What libraries does it choose?
- Does it follow security best practices?

### Exercise 2: Iterate and Improve

Now refine the generated code. Try follow-up prompts:

```
Good start! Now please:
1. Add timestamps to the output showing when each IP's attacks occurred
2. Export the results to both JSON and CSV formats
3. Add a --threshold flag to customize the brute force detection limit
```

**Key Insight:** Vibe coding is conversational. You don't need to get everything right in the first prompt.

### Exercise 3: Understand Before You Run

Before running any AI-generated code:

1. **Read through it line by line**
2. **Identify each function's purpose**
3. **Check for potential issues:**
   - Does it validate input?
   - Does it handle file paths safely?
   - Are there any hardcoded credentials?
   - Does it use `eval()` or `exec()` unsafely?

Ask your AI assistant:
```
Explain this code line by line. Are there any security concerns I should be aware of?
```

### Exercise 4: Using Claude Code Skills (Optional)

If you're using Claude Code with this course's custom skills, try these:

```bash
# Extract IOCs from sample log data
/ioc-extractor

# Generate a threat hunting query
/threat-hunt

# Parse a log file
/log-parser
```

**Try this workflow:**
1. Paste some sample log data or describe a threat scenario
2. Use `/ioc-extractor` to pull out indicators
3. Use `/threat-hunt` to build a detection query
4. Use `/sigma-create` to generate a Sigma detection rule

> **Note**: Custom skills are defined in your Claude Code configuration. Run `/README` to see all available skills for this course.

---

## Part 3: Effective Prompting for Security Code

### The SPARK Framework for Security Prompts

| Letter | Meaning | Example |
|--------|---------|---------|
| **S** | Specific | "Parse Windows Event Log format" not "parse logs" |
| **P** | Purpose | "for detecting lateral movement" |
| **A** | Approach | "using regex patterns and pandas" |
| **R** | Requirements | "handle files up to 1GB, output JSON" |
| **K** | Knowledge | "following MITRE ATT&CK T1021" |

### Example SPARK Prompt

```
Create a Python script to detect potential credential dumping attacks.

SPECIFIC: Parse Windows Security Event Logs (Event IDs 4624, 4625, 4648)
PURPOSE: Identify suspicious authentication patterns indicating credential theft
APPROACH: Use python-evtx library, output to pandas DataFrame
REQUIREMENTS:
- Handle large log files (>100MB) efficiently
- Group by source IP and target user
- Flag unusual login times (outside 6am-8pm)
- Output findings as JSON report
KNOWLEDGE: Reference MITRE ATT&CK techniques T1003 and T1078
```

### Prompts That Work Well

| Goal | Prompt Pattern |
|------|---------------|
| **Parsing** | "Parse [format] logs and extract [fields], handling [edge cases]" |
| **Detection** | "Detect [threat] by looking for [indicators] in [data source]" |
| **Automation** | "Automate [task] with error handling and logging" |
| **Analysis** | "Analyze [data] to identify [patterns], output [format]" |

### Prompts to Avoid

| Bad Prompt | Why It Fails | Better Version |
|------------|--------------|----------------|
| "Write malware" | Unethical, won't help | "Explain how [technique] works for defense" |
| "Hack this" | Too vague | "Identify vulnerabilities in this code" |
| "Make it work" | No context | "Debug this error: [error message]" |

---

## Part 4: Vibe Coding Workflow for Labs

Here's how to use vibe coding effectively throughout this course:

### Step 1: Understand the Lab Goal
Read the lab README completely before touching AI. Know what you're building.

### Step 2: Start with Structure
Ask AI to scaffold the solution:
```
I need to build [lab goal]. Create a skeleton Python script with:
- Main function structure
- Required imports
- Placeholder functions for each major component
- Docstrings explaining what each function should do
```

### Step 3: Implement Incrementally
Fill in one function at a time:
```
Implement the [function_name] function that [description].
Here's the current code context: [paste relevant code]
```

### Step 4: Debug with AI
When errors occur:
```
I'm getting this error: [paste error]
Here's my code: [paste code]
What's wrong and how do I fix it?
```

### Step 5: Learn from the Code
After getting something working:
```
Explain how this [specific part] works.
Why did you choose [approach] over [alternative]?
What are the security implications?
```

---

## Part 5: Hands-On Challenge

### Challenge: Build a Password Strength Analyzer

Using vibe coding, create a tool that:

1. **Accepts a password** via CLI argument or stdin
2. **Analyzes strength** based on:
   - Length (minimum 12 characters for "strong")
   - Character variety (uppercase, lowercase, numbers, symbols)
   - Common password check (against a list)
   - Pattern detection (keyboard walks like "qwerty", repeated chars)
3. **Provides feedback** with specific improvement suggestions
4. **Scores the password** from 0-100

**Starter Prompt:**
```
Create a password strength analyzer in Python that scores passwords
from 0-100 based on length, character variety, common password matching,
and pattern detection. Include helpful feedback for users.
Use argparse, no external API calls, include a small built-in list of
common passwords for testing.
```

**Your Task:**
1. Generate the initial code with your AI assistant
2. Test it with these passwords:
   - `password123`
   - `Tr0ub4dor&3`
   - `correct-horse-battery-staple`
   - `qwertyuiop`
3. Iterate to improve detection accuracy
4. Add at least one feature the AI didn't include initially

---

## Part 6: Best Practices for Learning with AI

### Do's

- **Read every line** before running
- **Ask "why"** to understand design decisions
- **Experiment** by modifying the generated code
- **Verify** security-sensitive code manually
- **Use AI to explain** concepts you don't understand
- **Build incrementally** rather than asking for complete solutions

### Don'ts

- **Don't copy-paste blindly** - you won't learn
- **Don't skip the lab READMEs** - context matters
- **Don't trust AI for crypto** - always use established libraries
- **Don't share secrets** - never paste API keys or passwords into prompts
- **Don't give up on errors** - use AI to debug and learn

### The Learning Mindset

```
Traditional: Read → Write code → Debug → Learn
Vibe Coding: Read → Describe intent → Review AI code → Understand → Modify → Learn faster
```

AI doesn't replace learning - it accelerates it. You still need to understand what you're building.

---

## Tools Quick Reference

| Tool | Best For | Cost |
|------|----------|------|
| **Claude Code** | Terminal-based development, file operations | API usage |
| **Cursor** | Full IDE experience, large projects | Free tier + paid |
| **GitHub Copilot** | Inline suggestions, existing VS Code users | $10-19/month |
| **Continue.dev** | Open source, local models | Free |
| **Ollama** | Offline, privacy-focused | Free |
| **Codeium** | Free alternative to Copilot | Free |

---

## Completion Checklist

Before moving on, ensure you can:

- [ ] Set up at least one AI coding assistant
- [ ] Generate a simple Python security tool using natural language
- [ ] Iterate on AI-generated code through conversation
- [ ] Explain what generated code does before running it
- [ ] Use the SPARK framework for effective prompts
- [ ] Complete the password analyzer challenge

---

## Resources

### Official Documentation
- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [Cursor Documentation](https://docs.cursor.com)
- [GitHub Copilot Docs](https://docs.github.com/en/copilot)

### Learning More
- [Prompt Engineering Guide](https://www.promptingguide.ai/)
- [AI-Assisted Development Best Practices](https://github.blog/2024-01-17-a-beginners-guide-to-ai-assisted-development/)

### Community
- Join discussions in course Discord/Slack
- Share your vibe coding tips with classmates
- Post interesting AI-generated solutions (with explanations!)

---

## What's Next?

Now that you're equipped with vibe coding skills, you'll use them throughout the remaining labs. In **Lab 01: Phishing Email Classifier**, you'll combine prompt engineering with your new AI-assisted workflow to build your first real security ML tool.

**Pro Tip:** Keep a "prompt journal" - save effective prompts that worked well for security tasks. You'll build a personal library of patterns.

---

*Remember: AI is your copilot, not your autopilot. Stay in control, understand your code, and enjoy the accelerated learning journey!*

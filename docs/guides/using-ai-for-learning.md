# Using AI to Accelerate Your Learning

A practical guide to leveraging AI assistants for learning security and AI development.

---

## Why Use AI for Learning?

AI assistants are like having a patient tutor available 24/7. They can:
- Explain concepts at your level
- Debug your code and explain why it failed
- Suggest improvements and best practices
- Give you practice problems
- Answer "why?" questions that documentation doesn't cover

**But remember**: AI is a learning accelerator, not a replacement for thinking. The goal is to understand, not just get answers.

---

## Recommended AI Tools

### For Learning & Explanations

| Tool | Best For | Cost | Link |
|------|----------|------|------|
| **Claude.ai** | Deep explanations, code review, reasoning | Free tier / Pro $20/mo | [claude.ai](https://claude.ai) |
| **ChatGPT** | General help, quick answers, browsing | Free tier / Plus $20/mo | [chatgpt.com](https://chatgpt.com) |
| **Perplexity** | Research with citations, tech evaluation | Free / Pro $20/mo | [perplexity.ai](https://perplexity.ai) |
| **Phind** | Developer-focused search, docs lookup | Free / Pro $15/mo | [phind.com](https://phind.com) |

### For Coding

| Tool | Best For | Cost | Link |
|------|----------|------|------|
| **Claude Code** | Agentic coding — terminal, IDE, web, desktop | Pro $20/mo / Max $100-200/mo / API pay-per-token | [claude.ai/code](https://claude.ai/code) |
| **Cursor** | Full IDE with multi-model AI | Free (limited) / Pro $20/mo | [cursor.com](https://cursor.com) |
| **GitHub Copilot** | Code completion across IDEs | Free (2k completions) / Pro $10/mo / Pro+ $39/mo | [github.com/copilot](https://github.com/features/copilot) |
| **Windsurf** | Agentic IDE (formerly Codeium) | Free / Pro $15/mo | [windsurf.com](https://windsurf.com) |

### For Agentic Workflows

| Tool | Best For | Link |
|------|----------|------|
| **MCP (Model Context Protocol)** | Connect AI agents to external tools (databases, APIs, dev tools) | [modelcontextprotocol.io](https://modelcontextprotocol.io) |
| **Claude Agent SDK** | Build custom AI agents with tool use | [docs.anthropic.com](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/claude-code-sdk-overview) |

> **Our Recommendation**: Use **Claude Code** for coding (terminal, IDE, or web — it's what we built this course with) and **Claude.ai** for explanations and learning. Add **Perplexity** for research with citations and **Phind** for documentation lookups.

---

## Effective Prompting for Learning

### The CLEAR Framework (For Learning)

When asking AI for help understanding something, include:

- **C**ontext: What are you working on?
- **L**earning goal: What are you trying to understand?
- **E**rror/Issue: What's not working?
- **A**ttempt: What have you tried?
- **R**equest: What specific help do you need?

### The CRTSE Framework (For Building)

When asking AI to write or fix code, include:

- **C**ontext: Project background, tech stack, constraints
- **R**ole: What expertise should the AI apply? (e.g., "Act as a security engineer")
- **T**ask: What specifically needs to be done?
- **S**tandards: Code style, security requirements, testing expectations
- **E**xamples: Sample inputs/outputs, similar code in the project

### Example Prompts by Situation

#### When You Get an Error

```
Context: I'm working on Lab 01 (Phishing Classifier) and trying to train a model.

Error:
Traceback (most recent call last):
  File "main.py", line 45, in <module>
    model.fit(X_train, y_train)
ValueError: could not convert string to float: 'phishing'

My code:
[paste relevant code]

What I tried: I thought y_train should have the label strings.

Help me understand why this error happens and how to fix it.
```

#### When You Don't Understand a Concept

```
I'm learning about TF-IDF in Lab 01 for phishing detection.

Please explain:
1. What TF-IDF does in simple terms
2. Why it's useful for text classification
3. A simple example with email words
4. How it helps detect phishing specifically

I'm a beginner, so please avoid jargon or explain it when you use it.
```

#### When You're Stuck on Implementation

```
I'm trying to extract IP addresses from log files in Lab 01.

Goal: Find all IPv4 addresses in a string of text.

I know I need to use regex, but I don't understand the pattern.

Can you:
1. Explain the regex pattern for IPv4 addresses piece by piece
2. Show me how to use re.findall() for this
3. Give me a test case to verify it works
```

#### When You Want Code Review

```
Here's my solution for the IOC extractor in Lab 01.

[paste your code]

Please review for:
1. Bugs or edge cases I'm missing
2. Security issues
3. Pythonic improvements
4. Better error handling

Explain why each suggestion is an improvement.
```

#### When You Want to Go Deeper

```
I completed Lab 03 (Anomaly Detection) using Isolation Forest.

I understand the basic usage but want to understand:
1. How does Isolation Forest actually work internally?
2. Why is it good for security anomalies specifically?
3. What are its limitations?
4. When would I use something else?

I learn best with analogies and examples.
```

---

## Learning Strategies with AI

### 1. The "Explain Then Do" Method

Before coding:
```
Explain the concept of [X] and the general approach to solve [problem].
Don't give me code yet - I want to understand the logic first.
```

After understanding, implement it yourself. Then compare with AI's solution.

### 2. The "Rubber Duck" Method

Explain your problem to AI like it's a rubber duck:
```
I'm trying to [goal].
I've done [steps so far].
I expected [X] but got [Y].
I think the problem might be [your hypothesis].

Am I on the right track? What am I missing?
```

### 3. The "Teach Me by Fixing" Method

When AI fixes your code:
```
Thanks for the fix! Now explain:
1. What was wrong with my original approach?
2. Why does your solution work?
3. What's the underlying concept I was missing?
```

### 4. The "Practice Problem" Method

After completing a lab:
```
I just learned about [concept] in Lab [X].
Give me 3 practice problems to reinforce this:
1. An easy one similar to the lab
2. A medium one with a twist
3. A harder one that extends the concept

Include test cases so I can verify my solutions.
```

### 5. The "Connect the Dots" Method

When learning new concepts:
```
How does [new concept] relate to [previous concept]?
For example, how does RAG (Lab 06) build on embeddings (Lab 06a)?
Help me see the bigger picture.
```

### 6. The "Agentic Pair Programming" Method

Use AI as a collaborator, not just a Q&A bot:
```
I'm working on Lab 23 (Detection Pipeline). Let's work through this together:
1. First, review my starter code and tell me what the overall approach should be
2. I'll implement each function — check my work as I go
3. When I'm done, run the tests and help me fix any failures

Don't write the solution for me. Guide me step by step.
```

This mirrors the most effective AI-assisted learning pattern from 2026 research: **humans define goals, AI executes guidance, humans review at checkpoints**.

---

## Using AI in Your Code Editor

### Claude Code (Recommended)

Claude Code is an agentic coding tool that reads your entire codebase, edits files, runs commands, and integrates with your dev tools. It runs in the **terminal**, **VS Code/JetBrains**, **desktop app**, and **browser** ([claude.ai/code](https://claude.ai/code)).

| Interface | How to Launch | Best For |
|-----------|---------------|----------|
| Terminal CLI | `claude` in any project directory | Full control, scripting, CI/CD |
| VS Code / JetBrains | Install Claude Code extension | Inline diffs, IDE integration |
| Web App | [claude.ai/code](https://claude.ai/code) | Browser-based, no install needed |
| Desktop App | [Download](https://claude.com/download) | Standalone, persistent sessions |

**Key capabilities:**
- Browses your entire codebase and understands project structure
- Makes multi-file edits with visual diffs
- Runs tests, linters, and build commands directly
- Connects to external tools via MCP (Model Context Protocol)
- Supports custom slash commands and hooks for your workflow

**Effective Claude Code prompts:**
- "Explain how the auth middleware works in this project"
- "Find and fix the bug causing test_phishing_classifier to fail"
- "Add input validation to the IOC extractor and write tests for it"
- "Refactor the detection pipeline to use async processing"
- "Review my changes for security issues before I commit"

**Power user tips:**
```bash
# Start Claude Code in your lab directory
cd labs/lab10-phishing-classifier && claude

# Use slash commands
/help                  # See all available commands
/clear                 # Clear conversation context

# Reference specific files in your prompts
"Look at starter/main.py and explain the TODO on line 42"
```

### Cursor

| Shortcut | Action | Use Case |
|----------|--------|----------|
| `Ctrl+L` | Open chat | Ask questions about your code |
| `Ctrl+K` | Inline edit | "Fix this", "Improve this" |
| `Tab` | Accept suggestion | Code completion |
| `@file` / `@folder` | Add context | Reference files and folders |

**Cursor now uses a credit-based system** — your monthly credits deplete based on which AI model you use. All paid plans include unlimited Tab completions and auto-mode.

**Effective Cursor prompts:**
- "Explain what this function does"
- "Why is this code throwing [error]?"
- "Refactor this to be more readable"
- "Add error handling to this function"
- "Write tests for this function"

### VS Code with GitHub Copilot

| Feature | How to Use | Best For |
|---------|------------|----------|
| Ghost text | Just type, suggestions appear | Writing boilerplate |
| `Ctrl+Enter` | See multiple suggestions | Choosing best option |
| Comments | Write a comment, get code | Generating functions |
| Copilot Chat | `Ctrl+Shift+I` or sidebar | Asking questions, agent mode |

The **free tier** (2,000 completions + 50 chat requests/month) covers light usage. Includes access to Claude Sonnet and GPT-4.1 models.

**Effective comment-driven generation:**
```python
# Extract all email addresses from the text using regex
# Validate each email format
# Return a list of unique, valid emails sorted alphabetically

# Copilot will generate the function below this comment
```

---

## Best Practices

### ✅ Do's

1. **Try first, then ask** - Struggle a bit before asking AI. You learn more this way.

2. **Ask "why?"** - Don't just accept solutions. Understand them.
   ```
   That works, but why? What was wrong with my approach?
   ```

3. **Verify AI answers** - AI makes mistakes. Test the code it gives you.

4. **Be specific** - Vague questions get vague answers.
   - Bad: "Help me with Lab 01"
   - Good: "In Lab 01, my TF-IDF vectorizer returns all zeros. Here's my code..."

5. **Iterate** - If the answer doesn't help, rephrase and ask again.
   ```
   That's still not clear. Can you explain [specific part] differently?
   ```

6. **Build understanding** - Use AI to learn concepts, not just get code.
   ```
   Before showing code, explain the approach conceptually.
   ```

### ❌ Don'ts

1. **Don't copy-paste blindly** - Understand every line before using it.

2. **Don't skip the learning** - If AI solves it instantly, still study the solution.

3. **Don't assume AI is always right** - Especially for:
   - Newer libraries/APIs (AI's knowledge may be outdated)
   - Security best practices (verify with official docs)
   - Specific version syntax

4. **Don't ask AI to complete entire labs** - You're here to learn!

5. **Don't forget to experiment** - After AI helps, modify the code, break it, understand it.

6. **Don't paste secrets into AI chat** - Never share API keys, tokens, or credentials. Use environment variables and `.env` files (see Lab 14+ setup). AI tools with codebase access (Claude Code, Cursor, Copilot) can see your files — keep secrets out of your repo.

---

## Common Mistakes to Avoid

### Mistake 1: Over-Relying on AI

**Problem**: Using AI for every small question without trying yourself.

**Fix**: Set a "struggle timer" - try for 10-15 minutes before asking AI.

### Mistake 2: Not Providing Context

**Problem**: "My code doesn't work" with no code or error.

**Fix**: Always include:
- The error message (full traceback)
- Your code
- What you expected vs. what happened
- What you've tried

### Mistake 3: Accepting Without Understanding

**Problem**: Code works but you don't know why.

**Fix**: Always follow up with "explain why this works" or "what was wrong with my approach?"

### Mistake 4: Asking Multiple Questions at Once

**Problem**: "Explain X, Y, and Z and also help me fix this error and review my code."

**Fix**: One question at a time. You'll get better answers.

### Mistake 5: Not Iterating

**Problem**: Giving up if the first answer doesn't help.

**Fix**: Rephrase, provide more context, or ask for a different approach.

---

## Quick Reference: Prompt Templates

### Error Debugging
```
Error: [paste full traceback]
Code: [paste relevant code]
Goal: [what you're trying to do]
Tried: [what you've attempted]
Help me understand and fix this.
```

### Concept Explanation
```
Explain [concept] for someone learning [field].
Include:
- Simple definition
- Why it matters
- A practical example
- Common misconceptions
```

### Code Review
```
Review this code for:
- Bugs
- Security issues
- Improvements
- Best practices

[paste code]

Explain why each suggestion matters.
```

### Learning Reinforcement
```
I just learned [concept] in [Lab].
Give me:
1. A summary of key points
2. 2-3 practice problems (easy to hard)
3. Common mistakes to avoid
4. When I would use this in real security work
```

### Going Deeper
```
I understand the basics of [concept].
Now explain:
- How it works under the hood
- Advanced use cases
- Limitations and alternatives
- Real-world security applications
```

---

## Resources

### Prompt Engineering Guides
- [Anthropic — Prompt Engineering Overview](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview)
- [Anthropic — Claude 4 Best Practices](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/claude-4-best-practices)
- [Anthropic — Interactive Prompt Engineering Tutorial](https://github.com/anthropics/prompt-eng-interactive-tutorial)
- [OpenAI — Prompt Engineering Guide](https://platform.openai.com/docs/guides/prompt-engineering)
- [OpenAI — GPT-5 Prompting Guide](https://cookbook.openai.com/examples/gpt-5/gpt-5_prompting_guide)

### Tool Documentation
- [Claude Code Documentation](https://code.claude.com/docs/en/overview)
- [Cursor Documentation](https://cursor.com/docs)
- [GitHub Copilot Documentation](https://docs.github.com/en/copilot)
- [Windsurf Documentation](https://windsurf.com/docs)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)

### AI-Assisted Learning Research
- [Addy Osmani — My LLM Coding Workflow (2026)](https://addyosmani.com/blog/ai-coding-workflow/)
- [IBM — The 2026 Guide to Prompt Engineering](https://www.ibm.com/think/prompt-engineering)

---

*Remember: The goal is to become a better security professional, not to get AI to do your work. Use AI as a learning accelerator, and you'll grow much faster than going it alone!*

# Lab 00c: Introduction to Prompt Engineering

Learn the fundamentals of prompting Large Language Models (LLMs) for security tasks. This hands-on introduction uses **free playground tools** - no API keys or coding required!

## Learning Objectives

By the end of this lab, you will:
1. Understand what LLMs are and how they work
2. Write clear, effective prompts for security analysis
3. Structure prompts for consistent, reliable outputs
4. Recognize common prompting pitfalls and how to avoid them
5. Use free AI playgrounds for testing and experimentation

## Estimated Time

1-2 hours

## Prerequisites

- Curiosity about AI and LLMs
- No programming required!
- No API keys needed!

---

## Part 1: What are LLMs?

### Understanding Large Language Models

**LLMs (Large Language Models)** are AI systems trained on massive amounts of text to understand and generate human-like responses.

```
┌──────────────────────────────────────────────────────────────┐
│             HOW LLMs WORK (Simplified)                        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. TRAINING                                                  │
│  ┌─────────────────┐                                         │
│  │ Trained on      │                                         │
│  │ billions of     │──► Learns patterns, concepts,           │
│  │ words from      │    relationships                         │
│  │ books, web,     │                                         │
│  │ etc.            │                                         │
│  └─────────────────┘                                         │
│                                                               │
│  2. YOUR PROMPT                                               │
│  ┌─────────────────┐                                         │
│  │ "Analyze this   │──► LLM processes your input              │
│  │  security log"  │                                         │
│  └─────────────────┘                                         │
│                                                               │
│  3. GENERATION                                                │
│  ┌─────────────────┐                                         │
│  │ LLM predicts    │──► Produces a response                   │
│  │ most likely     │    based on learned patterns             │
│  │ next words      │                                         │
│  └─────────────────┘                                         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Popular LLMs for Security

| Model | Provider | Best For |
|-------|----------|----------|
| **Claude** (Anthropic) | Anthropic | Long documents, complex analysis |
| **GPT-4** (OpenAI) | OpenAI | General purpose, well-documented |
| **Gemini** (Google) | Google | Free tier, fast responses |

### Why Use LLMs for Security?

**LLMs can help with:**
- Analyzing logs and alerts
- Extracting IOCs from threat reports
- Writing detection rules
- Explaining complex malware behavior
- Drafting incident reports
- Security research and learning

**But LLMs are NOT:**
- Perfect or always accurate (they can hallucinate)
- A replacement for security tools
- Trained on your specific environment
- Always up-to-date (training data has a cutoff)

---

## Part 2: Hands-On with Free Playgrounds

### Setting Up (No API Keys Required!)

We'll use **Google AI Studio** - it's free, requires no credit card, and perfect for learning.

**Step 1: Access Google AI Studio**
1. Go to [aistudio.google.com](https://aistudio.google.com/)
2. Sign in with a Google account
3. Click "Create new prompt"
4. Choose "Freeform prompt"

**Alternative Free Options:**
- [Claude.ai](https://claude.ai/) - Free tier available
- [Poe.com](https://poe.com/) - Access multiple models
- [Perplexity.ai](https://perplexity.ai/) - Good for research

---

## Part 3: Writing Your First Prompts

### Exercise 1: Basic Security Analysis

**Weak Prompt:**
```
analyze this log
```

**Why it's weak:**
- No context
- No specific task
- No output format

**Better Prompt:**
```
I have a failed login attempt in my server logs.
Can you tell me if this looks suspicious?

Log entry: "Failed password for admin from 185.220.101.5 port 22"
```

**Why it's better:**
- Provides context (failed login)
- Asks a specific question (is it suspicious?)
- Includes the data to analyze

**Try it yourself in AI Studio:**
1. Copy the "Better Prompt" above
2. Paste into Google AI Studio
3. Click "Run"
4. See what the LLM says!

### Exercise 2: Adding Structure

**Even Better Prompt:**
```
Analyze this authentication log entry for security concerns.

LOG ENTRY:
Failed password for admin from 185.220.101.5 port 22 ssh2

Please provide:
1. Is this suspicious? (Yes/No/Maybe)
2. Why or why not?
3. What additional information would help determine if this is malicious?
4. What should a security analyst do next?
```

**What makes this excellent:**
- Clear task ("Analyze for security concerns")
- Numbered questions for structured output
- Specific about what you want to know

**Try it yourself:**
- Run this in AI Studio
- Compare the output to Exercise 1
- Notice how the structured questions produce organized answers

### Exercise 3: Providing Context

Giving the LLM context about your environment improves accuracy.

**Prompt with Context:**
```
I'm a security analyst at a small company. We're analyzing our SSH logs.

CONTEXT:
- Our admin account should only login from 10.0.0.0/8 (internal network)
- Normal login times are 9 AM - 5 PM EST Monday-Friday
- We've seen brute force attacks from IPs in 185.220.0.0/16 before

LOG ENTRY:
2024-01-15 03:00:00 Failed password for admin from 185.220.101.5 port 22

QUESTION:
Based on the context above, assess the threat level of this login attempt.
Rate it: Low / Medium / High / Critical
Explain your reasoning.
```

**Try it yourself:**
- Run this prompt
- Notice how context improves the analysis
- The LLM can now consider your specific environment

---

## Part 4: Common Prompting Mistakes

### Mistake #1: Being Too Vague

❌ **Bad:**
```
Is this bad?
```

✅ **Good:**
```
Is this network traffic pattern indicative of a security threat?
[paste traffic data here]
```

### Mistake #2: Asking Multiple Unrelated Questions

❌ **Bad:**
```
Analyze this log and also explain what a SQL injection is
and write me a Python script to parse logs.
```

✅ **Good:**
```
Focus on ONE task per prompt. Break complex requests into steps.
```

### Mistake #3: No Examples or Format

❌ **Bad:**
```
Extract the IOCs from this report.
```

✅ **Good:**
```
Extract all Indicators of Compromise from this threat report.

REPORT:
[paste report]

Please list them in this format:
- IP Addresses: [list]
- Domains: [list]
- File Hashes: [list]
```

### Mistake #4: Assuming Too Much Knowledge

❌ **Bad:**
```
Analyze for T1078.003
```
*(LLM may not know this MITRE ATT&CK technique)*

✅ **Good:**
```
Analyze this event for signs of "Valid Accounts: Local Accounts"
(MITRE ATT&CK technique T1078.003), which involves adversaries
obtaining and abusing credentials of local accounts.
```

---

## Part 5: Prompt Templates for Security

### Template 1: Log Analysis

```
You are a security analyst reviewing [LOG_TYPE] logs.

LOG ENTRIES:
[paste logs here]

Please analyze for:
- Suspicious patterns
- Potential security incidents
- Anomalies

Provide findings in this format:
1. FINDING: [description]
   SEVERITY: [Low/Medium/High/Critical]
   EVIDENCE: [specific log lines]

2. FINDING: [description]
   ...
```

### Template 2: IOC Extraction

```
Extract all Indicators of Compromise from the following text.

TEXT:
[paste threat intel or report]

Return results as:
IP ADDRESSES:
- [list]

DOMAINS:
- [list]

FILE HASHES:
- [list]

Only include items explicitly mentioned. Do not infer or guess.
```

### Template 3: Threat Assessment

```
Assess the security threat in this scenario:

SCENARIO:
[describe the situation]

Please provide:
1. Threat Level (Low/Medium/High/Critical)
2. Primary Concerns
3. Immediate Actions Recommended
4. Questions I should investigate
```

---

## Part 6: Practice Exercises

### Exercise 4: Analyze a Suspicious Email

**Your Task:** Use Google AI Studio to analyze this phishing email.

**Prompt Template:**
```
Analyze this email for phishing indicators.

FROM: security@paypa1-verify.com
TO: victim@company.com
SUBJECT: Urgent: Verify your account

Dear valued customer,

Your PayPal account has been limited. Click here to verify your
identity within 24 hours or your account will be permanently suspended.

http://paypa1-verify.com/login.php

Thank you,
PayPal Security Team

Please provide:
1. Is this likely phishing? (Yes/No)
2. What are the red flags?
3. What makes this convincing?
4. How would you explain this to a non-technical user?
```

**Try different versions:**
- What happens if you remove context?
- What if you ask it to explain in one sentence vs detailed analysis?
- What if you specify an output format like a table?

### Exercise 5: IOC Extraction

**Your Task:** Extract IOCs from this threat report.

```
Extract all Indicators of Compromise from this report.

REPORT:
The ransomware sample (SHA256: 5d41402abc4b2a76b9719d911017c592)
connects to command-and-control server at evil-domain.xyz (IP: 45.33.32.156)
over port 8443. It drops a file at C:\Windows\Temp\malware.exe.

Format as:
- HASHES: [list]
- DOMAINS: [list]
- IPS: [list]
- FILE PATHS: [list]
- PORTS: [list]
```

### Exercise 6: Incident Response Advice

**Your Task:** Get next-step recommendations.

```
I'm responding to a potential security incident. What should I do?

SITUATION:
- User clicked on suspicious email link 2 hours ago
- User's computer is a Windows 10 laptop
- User is still logged in and working
- No obvious signs of compromise yet
- We have endpoint detection (EDR) installed

What immediate steps should I take to:
1. Contain potential damage?
2. Investigate what happened?
3. Determine if there's real compromise?

Please prioritize your recommendations.
```

---

## Part 7: Tips for Effective Security Prompts

### The 4 C's of Good Prompts

**1. CLEAR**
- Be specific about what you want
- Avoid ambiguous language
- Define any acronyms or jargon

**2. CONTEXTUAL**
- Provide relevant background
- Explain your environment/constraints
- Share what you already know

**3. CONCISE**
- Don't overwhelm with unnecessary details
- Focus on relevant information
- Break complex asks into steps

**4. CONSTRAINED**
- Specify output format
- Set boundaries ("only analyze X, not Y")
- Request confidence levels when uncertain

### Iterative Prompting

If you don't get what you need, refine and try again:

```
1st Try: "Analyze this log"
   ↓
Response is too generic
   ↓
2nd Try: "Analyze this authentication log for brute force attempts"
   ↓
Better, but no specifics
   ↓
3rd Try: "Analyze this auth log. List any IPs with >5 failed attempts.
          Format as a table with columns: IP, Failed Attempts, Time Range"
   ↓
Perfect!
```

### When to Use AI vs Traditional Tools

**Use LLMs for:**
- ✅ Understanding and explaining concepts
- ✅ Drafting reports or documentation
- ✅ Brainstorming detection ideas
- ✅ Quick analysis of small data sets
- ✅ Learning and education

**Use traditional tools for:**
- ❌ Large-scale log analysis (use SIEM)
- ❌ Real-time detection (use IDS/IPS)
- ❌ Precise pattern matching (use regex/rules)
- ❌ Production security controls
- ❌ Anything requiring 100% accuracy

---

## Part 8: Common Pitfalls and How to Avoid Them

### Pitfall #1: Hallucinations

**Problem:** LLMs sometimes make up facts confidently.

**Example:**
```
Prompt: "What CVE is associated with the Log4j vulnerability?"
Bad Response: "CVE-2021-44228, CVE-2021-45046, and CVE-2024-99999"
                                                          ↑ FAKE!
```

**How to avoid:**
- Ask for sources/references
- Verify critical information independently
- Use phrases like "based on the text I provided" to ground responses

**Verification Technique: The Double-Check Prompt**

After getting a response, ask the LLM to verify itself:

```
Original prompt: "Extract IOCs from this threat report:
[paste report]"

LLM Response: Lists IP: 192.168.1.1, Domain: evil.com, Hash: abc123...

Your verification prompt:
"Review your previous response. For each IOC you listed, quote
the exact sentence from the original text where it appears.
If you cannot find an exact quote, mark it as [NOT FOUND]."
```

This forces the LLM to cite evidence and catches fabricated details!

**Verification Technique: Ask for Confidence**

```
"On a scale of 1-10, how confident are you in each finding?
For any rating below 8, explain what information would increase your confidence."
```

**Verification Technique: Request Alternatives**

```
"What alternative explanations could fit this evidence?
What would disprove your current assessment?"
```

**Practice Exercise:**

1. Go to AI Studio and ask: "What malware family is associated with the Petya ransomware?"
2. Get the response
3. Then ask: "How confident are you in that answer? What if I told you Petya and NotPetya are different?"
4. See how the LLM adjusts - this demonstrates it can hallucinate initially!

### Pitfall #2: Overconfidence

**Problem:** LLMs sound certain even when guessing.

**How to avoid:**
- Ask "How confident are you in this assessment?"
- Request "possible alternative explanations"
- Add "If you're unsure, please say so"

### Pitfall #3: Outdated Knowledge

**Problem:** LLMs have a training cutoff date.

**How to avoid:**
- Provide current threat intelligence in your prompt
- Don't rely on LLMs for very recent events
- Cross-reference with up-to-date sources

---

## Part 9: Next Steps

### Progression Path

```
┌────────────────────────────────────────────────────────────┐
│  YOU ARE HERE: Lab 00c                                     │
│  Basic prompting with free playgrounds ✓                   │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  NEXT: Labs 01-03                                          │
│  Build ML skills (NO LLMs, NO API keys needed)             │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  THEN: Lab 04                                               │
│  LLM Log Analysis (first API key needed, build on Lab 00c) │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│  LATER: Lab 07                                              │
│  Advanced prompt engineering (hallucination detection,      │
│  self-improving prompts, production workflows)              │
└────────────────────────────────────────────────────────────┘
```

### Continue Learning

**Free Resources:**
- [Anthropic's Prompt Engineering Guide](https://docs.anthropic.com/claude/docs/intro-to-prompting)
- [OpenAI Prompt Engineering Best Practices](https://platform.openai.com/docs/guides/prompt-engineering)
- [Learn Prompting](https://learnprompting.org/) - Comprehensive free course

**Practice Playgrounds:**
- [Google AI Studio](https://aistudio.google.com/) - Free Gemini access
- [Claude.ai](https://claude.ai/) - Generous free tier
- [Poe](https://poe.com/) - Try multiple models

---

## Glossary

| Term | Definition |
|------|------------|
| **LLM** | Large Language Model - AI trained on text to understand and generate language |
| **Prompt** | The input/question you give to an LLM |
| **Hallucination** | When an LLM confidently states incorrect information |
| **Context** | Background information provided to help the LLM understand your request |
| **Temperature** | Setting that controls randomness (0 = focused, 1 = creative) |
| **Token** | Unit of text (roughly 3/4 of a word) used to measure LLM input/output |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│              PROMPT STRUCTURE TEMPLATE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [ROLE] You are a [security role].                          │
│                                                              │
│  [CONTEXT] Background information about your environment.   │
│                                                              │
│  [DATA] The specific data to analyze.                       │
│                                                              │
│  [TASK] What you want the LLM to do.                        │
│                                                              │
│  [FORMAT] How to structure the response.                    │
│                                                              │
│  [CONSTRAINTS] What to avoid or focus on.                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘

EXAMPLE:
┌─────────────────────────────────────────────────────────────┐
│ [ROLE] You are a SOC analyst.                               │
│                                                              │
│ [CONTEXT] I'm investigating unusual network activity.       │
│                                                              │
│ [DATA] 50 connections to 185.220.101.5:443 in 5 minutes    │
│                                                              │
│ [TASK] Assess if this is suspicious.                        │
│                                                              │
│ [FORMAT] Provide: Risk Level, Reasoning, Next Steps         │
│                                                              │
│ [CONSTRAINTS] Focus only on the connection pattern.         │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

**You've learned:**
- ✅ What LLMs are and how they work
- ✅ How to write clear, effective prompts
- ✅ Common mistakes and how to avoid them
- ✅ Practical templates for security tasks
- ✅ How to use free AI playgrounds

**Key Takeaways:**
1. **Be specific**: Clear prompts get better answers
2. **Provide context**: Help the LLM understand your situation
3. **Structure output**: Tell the LLM how to format responses
4. **Verify everything**: LLMs can hallucinate - always double-check
5. **Practice iteratively**: Refine prompts based on results

**Ready for more?**
- **Labs 01-03**: Build ML foundations (no API keys)
- **Lab 04**: Apply prompting to real log analysis (API key needed)
- **Lab 07**: Master advanced prompting techniques

---

Happy prompting! 🔐🤖

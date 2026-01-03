# Lab 00c Walkthrough: Prompt Engineering for Security

## Overview

This walkthrough teaches you to write effective prompts for security analysis tasks. Optional API key for live testing.

**Time to complete:** 45-60 minutes

---

## Why Prompt Engineering Matters

The same data with different prompts produces very different results:

```
WEAK PROMPT:
"What's wrong with this log?"
→ Vague, unhelpful response

STRUCTURED PROMPT:
"As a security analyst, analyze these SSH logs for:
 1. Brute force indicators
 2. Successful unauthorized access
 3. Recommended actions"
→ Actionable security assessment
```

---

## Exercise 1: Basic vs Structured Prompts

### The Problem with Weak Prompts

```python
# WEAK - No context, no structure
weak_prompt = f"Analyze these logs: {logs}"

# ISSUES:
# - No role defined
# - No specific questions
# - No output format
# - LLM doesn't know what you're looking for
```

### Building a Strong Prompt

**The CRISP Framework:**

| Element | Purpose | Example |
|---------|---------|---------|
| **C**ontext | Set the scene | "You are a senior security analyst" |
| **R**ole | Define expertise | "reviewing authentication logs" |
| **I**nstructions | Clear tasks | "Identify brute force attempts" |
| **S**tructure | Output format | "Return as markdown table" |
| **P**recision | Specific details | "Include source IPs and timestamps" |

### Solution Structure

```python
prompt = f"""You are a senior security analyst reviewing authentication logs.

## Task
Analyze these SSH log entries for security concerns.

## Log Entries
{formatted_logs}

## Analysis Required
For each entry, determine:
1. Status: Normal / Suspicious / Malicious
2. Reason: Why you classified it this way
3. Source Analysis: Internal or external IP?

## Output Format
Provide as a markdown table with columns:
| Entry | Status | Source IP | Reason |
"""
```

---

## Exercise 2: IOC Extraction

### What Makes a Good Extraction Prompt

IOC extraction needs:
1. **Clear definitions** - What counts as an IOC?
2. **Categorization** - Group by type
3. **Defanging awareness** - Handle `[.]` notation
4. **Validation hints** - Help LLM avoid false positives

### Prompt Template

```python
prompt = f"""Extract all Indicators of Compromise (IOCs) from this threat report.

## IOC Types to Extract
- IP addresses (IPv4 and IPv6)
- Domain names (including subdomains)
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- URLs
- File paths

## Report
{threat_report}

## Output Format
Return as JSON:
{{
  "ips": ["x.x.x.x"],
  "domains": ["example.com"],
  "hashes": {{"md5": [], "sha1": [], "sha256": []}},
  "urls": ["https://..."],
  "emails": []
}}

## Notes
- Defang IOCs in output: evil.com → evil[.]com
- Include confidence level if uncertain
- Note any IOCs that appear to be benign
"""
```

### Common Pitfalls

| Issue | Solution |
|-------|----------|
| Extracts legitimate IPs (8.8.8.8) | Add "Focus on suspicious indicators" |
| Misses defanged IOCs | Add "Handle [.] notation" |
| Wrong hash types | Specify exact lengths (MD5=32, SHA256=64) |

---

## Exercise 3: Phishing Analysis

### Multi-Factor Analysis Prompt

```python
prompt = f"""Analyze this email for phishing indicators.

## Email Details
From: {email['from']}
To: {email['to']}
Subject: {email['subject']}

## Body
{email['body']}

## Analysis Required

### 1. Sender Analysis
- Is the domain legitimate or lookalike?
- Does the display name match the email domain?

### 2. Content Analysis
- Urgency language?
- Grammar/spelling issues?
- Generic greeting?
- Threatening language?

### 3. Link Analysis
- Do visible URLs match actual URLs?
- Are domains suspicious?

### 4. Request Analysis
- What action is requested?
- Is it reasonable for the claimed sender?

## Verdict
Provide:
- Classification: Phishing / Suspicious / Legitimate
- Confidence: High / Medium / Low
- Key indicators (bullet list)
- Recommended action
"""
```

---

## Exercise 4: PowerShell Analysis

### Encoded Command Analysis

PowerShell encoded commands hide malicious intent:

```powershell
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
```

### Analysis Prompt

```python
prompt = f"""Analyze this PowerShell command for malicious behavior.

## Command
{encoded_command}

## Analysis Steps
1. Decode any Base64 encoding
2. Identify the actual operations
3. Check for:
   - Download operations (IEX, Invoke-WebRequest)
   - Execution policy bypass (-ep bypass)
   - Hidden windows (-w hidden)
   - Remote connections
   - Registry modifications
   - Persistence mechanisms

## Output Format
### Decoded Command
[Show the decoded command]

### Behavior Analysis
| Technique | Present | Details |
|-----------|---------|---------|

### MITRE ATT&CK Mapping
- Technique ID: Description

### Risk Assessment
- Severity: Critical/High/Medium/Low
- Recommended action
"""
```

---

## Prompt Engineering Best Practices

### 1. Be Specific

```python
# BAD
"Is this malicious?"

# GOOD
"Analyze this network connection for C2 indicators including:
 beaconing patterns, known bad IPs, suspicious ports"
```

### 2. Provide Examples

```python
prompt = """Classify these alerts.

Examples:
- "Failed login from internal IP" → Low priority
- "Failed login from Tor exit node" → High priority

Now classify:
{alert}
"""
```

### 3. Request Structured Output

```python
# BAD
"Tell me about this malware"

# GOOD
"Analyze this malware sample. Return JSON with:
 - family: string
 - capabilities: string[]
 - iocs: {ips: [], domains: [], hashes: []}
 - mitre_techniques: string[]"
```

### 4. Chain of Thought

```python
prompt = """Analyze this security alert step by step:

1. First, identify what triggered the alert
2. Then, assess the source (internal/external, known/unknown)
3. Next, evaluate the target (critical asset?)
4. Finally, determine severity and recommended action

Alert: {alert}
"""
```

---

## Testing Your Prompts

### Without API Key

The lab shows you the prompt structure. Evaluate mentally:
- Is the task clear?
- Is the output format defined?
- Would you know what to do with this prompt?

### With API Key

```bash
# Set your key
export ANTHROPIC_API_KEY="sk-..."
# or
export OPENAI_API_KEY="sk-..."

# Run with live API
python solution/main.py
```

---

## Key Takeaways

1. **Structure beats cleverness** - Clear sections > creative wording
2. **Define the role** - "You are a security analyst" sets expectations
3. **Specify output format** - JSON, markdown, tables are parseable
4. **Include examples** - Show the LLM what you want
5. **Iterate and test** - Prompts need refinement

---

## Next Steps

Continue to:
- [Lab 00d: AI in Security Ops](./lab00d-walkthrough.md) - When to use AI
- [Lab 04: LLM Log Analysis](./lab04-walkthrough.md) - Apply prompts to real logs

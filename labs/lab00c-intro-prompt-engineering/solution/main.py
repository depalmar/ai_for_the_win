#!/usr/bin/env python3
"""
Lab 00c: Introduction to Prompt Engineering - SOLUTIONS

This file contains well-crafted prompts for security analysis tasks.
Compare with your starter/main.py implementations.
"""

import json
import os
from pathlib import Path

HAS_ANTHROPIC = bool(os.environ.get("ANTHROPIC_API_KEY"))
HAS_OPENAI = bool(os.environ.get("OPENAI_API_KEY"))
HAS_API = HAS_ANTHROPIC or HAS_OPENAI


def load_samples() -> dict:
    """Load security samples for exercises."""
    data_path = Path(__file__).parent.parent / "data" / "security_samples.json"
    with open(data_path) as f:
        return json.load(f)


def print_prompt(prompt: str, title: str = "PROMPT"):
    """Display a prompt in a formatted box."""
    print(f"\n{'='*60}")
    print(f"📝 {title}")
    print("="*60)
    print(prompt)
    print("="*60)


def call_llm(prompt: str) -> str | None:
    """Call LLM API if available."""
    if not HAS_API:
        return None
    try:
        if HAS_ANTHROPIC:
            from anthropic import Anthropic
            client = Anthropic()
            response = client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        elif HAS_OPENAI:
            from openai import OpenAI
            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
    except Exception as e:
        print(f"API Error: {e}")
        return None


# =============================================================================
# EXERCISE 1: Structured Log Analysis Prompt - SOLUTION
# =============================================================================

def exercise_1_solution(log_entries: list[str]) -> str:
    """
    Well-structured prompt for log analysis.
    
    Key elements:
    1. Role/persona for the LLM
    2. Clear task description
    3. Structured output format
    4. Data clearly separated
    """
    logs_formatted = "\n".join(f"  {i+1}. {log}" for i, log in enumerate(log_entries))
    
    prompt = f"""You are a senior security analyst reviewing authentication logs for suspicious activity.

## Task
Analyze the following SSH authentication log entries and identify any security concerns.

## Log Entries
{logs_formatted}

## Analysis Required
For each log entry, determine:
1. **Status**: Normal / Suspicious / Malicious
2. **Reason**: Why you classified it this way
3. **Source Analysis**: Is the source IP internal or external? Is it known malicious?

## Output Format
Provide your analysis as a structured report:

### Summary
[One sentence overall assessment]

### Detailed Analysis
| # | Status | Source IP | Reason |
|---|--------|-----------|--------|
| 1 | ... | ... | ... |

### Recommendations
[Bullet points of recommended actions]

### IOCs Identified
[List any IPs, usernames, or patterns to investigate]
"""
    return prompt


def run_exercise_1():
    """Demonstrate structured log analysis prompt."""
    print("\n" + "="*60)
    print("EXERCISE 1: Structured Log Analysis - SOLUTION")
    print("="*60)
    
    samples = load_samples()
    logs = samples["log_entries"]
    
    prompt = exercise_1_solution(logs)
    print_prompt(prompt, "WELL-STRUCTURED PROMPT")
    
    print("\n✅ Key improvements over weak prompt:")
    print("   - Role: 'senior security analyst'")
    print("   - Clear task: 'identify security concerns'")
    print("   - Structured output: table format")
    print("   - Specific asks: Status, Reason, IOCs")
    
    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# EXERCISE 2: IOC Extraction Prompt - SOLUTION
# =============================================================================

def exercise_2_solution(threat_report: str) -> str:
    """
    Comprehensive IOC extraction prompt.
    
    Key elements:
    - Specific IOC types to look for
    - Defanging instructions
    - Confidence levels
    - JSON output for automation
    """
    prompt = f"""You are a threat intelligence analyst extracting Indicators of Compromise (IOCs) from a threat report.

## Task
Extract ALL indicators of compromise from the following threat report. Be thorough - security teams will use these IOCs for detection.

## Threat Report
---
{threat_report}
---

## IOC Types to Extract
Look for and extract:
- **IP Addresses**: IPv4 and IPv6
- **Domains**: Including subdomains
- **URLs**: Full URLs with paths
- **File Hashes**: MD5, SHA1, SHA256
- **File Names**: Malicious files mentioned
- **File Paths**: Windows/Linux paths
- **Registry Keys**: Windows registry paths
- **Email Addresses**: Attacker emails
- **Mutexes**: Named mutexes
- **User Agents**: HTTP user agents
- **Scheduled Tasks**: Task names

## Output Format
Provide IOCs as JSON for easy ingestion into security tools:

```json
{{
  "ip_addresses": [
    {{"value": "x.x.x.x", "context": "C2 server", "confidence": "high"}}
  ],
  "domains": [
    {{"value": "example.com", "context": "payload host", "confidence": "medium"}}
  ],
  "urls": [],
  "file_hashes": [],
  "file_names": [],
  "file_paths": [],
  "registry_keys": [],
  "scheduled_tasks": [],
  "other": []
}}
```

## Notes
- Defang IOCs in the JSON (use [.] for dots, [://] for protocols)
- Include context about where/how each IOC is used
- Rate confidence: high/medium/low based on specificity in the report
- If no IOCs of a type exist, use empty array []
"""
    return prompt


def run_exercise_2():
    """Demonstrate IOC extraction prompt."""
    print("\n" + "="*60)
    print("EXERCISE 2: IOC Extraction - SOLUTION")
    print("="*60)
    
    samples = load_samples()
    report = samples["threat_report_excerpt"]
    
    prompt = exercise_2_solution(report)
    print_prompt(prompt, "IOC EXTRACTION PROMPT")
    
    print("\n✅ Key elements:")
    print("   - Comprehensive IOC type list")
    print("   - JSON output for automation")
    print("   - Defanging instructions")
    print("   - Confidence levels")
    
    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# EXERCISE 3: Phishing Analysis Prompt - SOLUTION
# =============================================================================

def exercise_3_solution(email: dict) -> str:
    """
    Comprehensive phishing analysis prompt.
    
    Key elements:
    - Structured email display
    - Specific indicators to check
    - Risk scoring
    - Actionable recommendations
    """
    prompt = f"""You are an email security analyst investigating a potentially malicious email.

## Task
Analyze this email for phishing indicators and provide a risk assessment.

## Email Details
**From:** {email['from']}
**To:** {email['to']}
**Subject:** {email['subject']}

**Body:**
---
{email['body']}
---

## Analysis Checklist
Evaluate each category:

### 1. Sender Analysis
- Is the sender domain legitimate or spoofed?
- Does the domain look like a legitimate company's domain?
- Are there typos or lookalike characters?

### 2. Content Analysis  
- Urgency tactics (time pressure, threats)?
- Grammar/spelling issues?
- Generic vs personalized greeting?
- Suspicious requests (credentials, money, actions)?

### 3. Link Analysis
- Do URLs match the claimed sender?
- Are there URL shorteners or redirects?
- Does the domain look suspicious?

### 4. Technical Indicators
- Would headers show SPF/DKIM failures? (if visible)
- Are there encoding tricks or hidden text?

## Output Format

### Verdict
**Classification:** [PHISHING / SUSPICIOUS / LIKELY LEGITIMATE]
**Confidence:** [HIGH / MEDIUM / LOW]

### Red Flags Identified
1. [Flag 1]
2. [Flag 2]
...

### Risk Score: [1-10]

### Recommended Actions
- [ ] Action 1
- [ ] Action 2

### IOCs to Block
- Domains:
- URLs:
- Sender addresses:
"""
    return prompt


def run_exercise_3():
    """Demonstrate phishing analysis prompt."""
    print("\n" + "="*60)
    print("EXERCISE 3: Phishing Analysis - SOLUTION")
    print("="*60)
    
    samples = load_samples()
    email = samples["suspicious_email"]
    
    prompt = exercise_3_solution(email)
    print_prompt(prompt, "PHISHING ANALYSIS PROMPT")
    
    print("\n✅ Key elements:")
    print("   - Structured analysis checklist")
    print("   - Clear verdict format")
    print("   - Risk scoring")
    print("   - Actionable recommendations")
    
    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# EXERCISE 4: PowerShell Analysis Prompt - SOLUTION
# =============================================================================

def exercise_4_solution(encoded_command: str) -> str:
    """
    PowerShell deobfuscation and analysis prompt.
    
    Key elements:
    - Step-by-step decoding
    - Behavior analysis
    - MITRE ATT&CK mapping
    - Detection opportunities
    """
    prompt = f"""You are a malware analyst investigating suspicious PowerShell activity.

## Task
Analyze this PowerShell command, decode any obfuscation, and explain its behavior.

## Suspicious Command
```powershell
{encoded_command}
```

## Analysis Steps

### 1. Deobfuscation
- If base64 encoded (-enc/-encodedcommand), decode it
- If there are escape sequences, resolve them
- Show the final readable command

### 2. Behavior Analysis
Explain what the command does:
- What actions does it perform?
- What resources does it access?
- What data does it send/receive?

### 3. Malicious Indicators
- Why is this suspicious?
- What techniques is it using?

### 4. MITRE ATT&CK Mapping
Map to relevant techniques:
| Tactic | Technique | ID |
|--------|-----------|-----|
| ... | ... | T#### |

### 5. IOCs Extracted
- URLs/IPs contacted:
- Files created/modified:
- Processes spawned:

### 6. Detection Opportunities
How could defenders detect this?
- Process command line patterns
- Network indicators
- File system artifacts

## Output Format
Provide clear sections for each analysis step above.
"""
    return prompt


def run_exercise_4():
    """Demonstrate PowerShell analysis prompt."""
    print("\n" + "="*60)
    print("EXERCISE 4: PowerShell Analysis - SOLUTION")
    print("="*60)
    
    samples = load_samples()
    ps_command = samples["powershell_command"]
    
    prompt = exercise_4_solution(ps_command)
    print_prompt(prompt, "POWERSHELL ANALYSIS PROMPT")
    
    print("\n✅ Key elements:")
    print("   - Step-by-step deobfuscation")
    print("   - MITRE ATT&CK mapping")
    print("   - Detection recommendations")
    print("   - IOC extraction")
    
    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# BONUS: Reusable Security Prompt Template
# =============================================================================

def security_analysis_template(
    task_type: str,
    data: str,
    output_format: str = "structured",
    extract_iocs: bool = True
) -> str:
    """
    Reusable template for security analysis prompts.
    
    This demonstrates how to create a flexible template
    that can be adapted for different security tasks.
    """
    ioc_section = """
## IOCs to Extract
If present, extract:
- IP addresses (defanged)
- Domains (defanged)
- File hashes
- File paths
- Any other indicators
""" if extract_iocs else ""

    prompt = f"""You are an experienced security analyst performing {task_type}.

## Task
{task_type}

## Data to Analyze
---
{data}
---

## Required Analysis
1. Identify any malicious or suspicious elements
2. Explain the significance of findings
3. Provide confidence levels for conclusions
4. Recommend defensive actions
{ioc_section}
## Output Format
Provide a {output_format} report with clear sections:
- Executive Summary (1-2 sentences)
- Detailed Findings
- Risk Assessment (Low/Medium/High/Critical)
- Recommendations
{"- Extracted IOCs" if extract_iocs else ""}
"""
    return prompt


def run_bonus():
    """Demonstrate reusable template."""
    print("\n" + "="*60)
    print("BONUS: Reusable Security Analysis Template")
    print("="*60)
    
    # Example usage
    sample_data = "User 'admin' logged in from IP 185.220.101.5 at 3:00 AM"
    
    prompt = security_analysis_template(
        task_type="authentication log analysis",
        data=sample_data,
        output_format="structured markdown",
        extract_iocs=True
    )
    
    print_prompt(prompt, "TEMPLATE-GENERATED PROMPT")
    print("\n✅ This template can be reused for:")
    print("   - Log analysis")
    print("   - Malware analysis")
    print("   - Phishing analysis")
    print("   - Threat report analysis")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run all solution demonstrations."""
    print("\n" + "="*60)
    print("Lab 00c: Prompt Engineering - SOLUTIONS")
    print("="*60)
    
    if HAS_API:
        print("✅ API key detected - will show LLM responses")
    else:
        print("ℹ️  No API key - prompts displayed for copy/paste")
    
    exercises = [
        ("1", "Structured Log Analysis", run_exercise_1),
        ("2", "IOC Extraction", run_exercise_2),
        ("3", "Phishing Analysis", run_exercise_3),
        ("4", "PowerShell Analysis", run_exercise_4),
        ("B", "Bonus Template", run_bonus),
    ]
    
    print("\nExercises:")
    for num, name, _ in exercises:
        print(f"  {num}. {name}")
    print("  A. Run all")
    
    choice = input("\nWhich exercise? (1-4, B, or A): ").strip().upper()
    
    if choice == "A":
        for _, _, func in exercises:
            func()
            input("\nPress Enter to continue...")
    elif choice in ["1", "2", "3", "4"]:
        idx = int(choice) - 1
        exercises[idx][2]()
    elif choice == "B":
        run_bonus()
    else:
        for _, _, func in exercises:
            func()


if __name__ == "__main__":
    main()

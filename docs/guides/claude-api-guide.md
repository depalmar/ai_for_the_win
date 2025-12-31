# Claude API & SDK Guide

Master the Claude API and Python SDK for AI-powered security development.

> **Looking for Claude Code CLI?** See [Claude Code CLI Guide](./claude-code-cli-guide.md) for the `claude` command, MCP servers, and hooks.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Claude API Setup](#claude-api-setup)
3. [Claude in Cursor](#claude-in-cursor)
4. [Claude CLI Tools](#claude-cli-tools)
5. [Python SDK Usage](#python-sdk-usage)
6. [Security-Specific Prompting](#security-specific-prompting)
7. [Building Security Agents](#building-security-agents)
8. [Best Practices](#best-practices)

---

## 🎯 Overview

Claude (by Anthropic) excels at security-related tasks due to:

| Capability                     | Security Application                              |
| ------------------------------ | ------------------------------------------------- |
| **Long Context (200K tokens)** | Analyze entire malware codebases, large log files |
| **Code Understanding**         | Reverse engineering, vulnerability analysis       |
| **Structured Output**          | Generate STIX/TAXII, JSON IOCs, YARA rules        |
| **Reasoning**                  | Threat attribution, attack chain analysis         |
| **Safety Training**            | Appropriate handling of sensitive security topics |

### Model Comparison

| Model                 | Best For                         | Context | Cost                          |
| --------------------- | -------------------------------- | ------- | ----------------------------- |
| **Claude 3.5 Sonnet** | Daily development, code analysis | 200K    | $3/M input, $15/M output      |
| **Claude 3 Opus**     | Complex reasoning, architecture  | 200K    | $15/M input, $75/M output     |
| **Claude 3 Haiku**    | Quick tasks, high volume         | 200K    | $0.25/M input, $1.25/M output |

---

## 🔑 Claude API Setup

### 1. Create Anthropic Account

1. Visit [console.anthropic.com](https://console.anthropic.com)
2. Sign up with email or Google
3. Verify your email
4. Add payment method (required for API access)

### 2. Generate API Key

1. Go to **API Keys** section
2. Click **Create Key**
3. Name it (e.g., "security-training")
4. Copy the key immediately (shown only once)

### 3. Secure Your Key

```bash
# Create .env file (never commit this!)
echo "ANTHROPIC_API_KEY=sk-ant-api03-..." >> .env

# Add to .gitignore
echo ".env" >> .gitignore
```

### 4. Verify Setup

```python
import anthropic
import os
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

# Test the connection
message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=100,
    messages=[{"role": "user", "content": "Say 'API working!' if you can read this."}]
)
print(message.content[0].text)
```

---

## 💻 Claude in Cursor

### Configuration

Cursor has native Claude integration. Configure in settings:

```json
// settings.json
{
  "cursor.aiProvider": "anthropic",
  "cursor.defaultModel": "claude-sonnet-4-20250514",
  "cursor.enableLongContext": true,

  // Optional: Use your own API key
  "cursor.anthropicApiKey": "${env:ANTHROPIC_API_KEY}",
  "cursor.useOwnApiKeys": true
}
```

### Using Claude in Cursor

```
# Inline Chat (Ctrl+L)
Select code → Ctrl+L → Ask Claude

# Composer (Ctrl+I)
Ctrl+I → Describe what you want to build

# Codebase Chat (Ctrl+Shift+L)
Ctrl+Shift+L → Ask about your codebase
```

### Model Selection Per Task

```
# In Cursor chat, prefix with model:
@claude-opus-4-5 "Design the architecture for a SIEM integration"
@claude-sonnet-4 "Write a function to parse these logs"
@claude-haiku-4 "Add comments to this code"
```

---

## 🖥️ Claude CLI Tools

### Anthropic CLI

```bash
# Install
pip install anthropic

# Set API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Use CLI (if available)
anthropic messages create \
  --model claude-sonnet-4-20250514 \
  --max-tokens 1024 \
  --messages '[{"role":"user","content":"Analyze this hash: abc123..."}]'
```

### Custom CLI Wrapper

Create a `claude-cli.py` for security tasks:

````python
#!/usr/bin/env python3
"""
Claude CLI for Security Analysis
Usage: python claude-cli.py analyze <file>
       python claude-cli.py ioc <text>
       python claude-cli.py yara <description>
"""

import anthropic
import sys
import argparse
from pathlib import Path

client = anthropic.Anthropic()

SECURITY_SYSTEM_PROMPT = """You are an expert security analyst assistant.
When analyzing code or data:
1. Identify potential threats and vulnerabilities
2. Extract IOCs (IPs, domains, hashes, file paths)
3. Map findings to MITRE ATT&CK where applicable
4. Provide actionable recommendations
Format output in structured markdown."""

def analyze_file(filepath: str) -> str:
    """Analyze a file for security issues."""
    content = Path(filepath).read_text()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=SECURITY_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Analyze this file for security issues:\n\n```\n{content}\n```"
        }]
    )
    return response.content[0].text

def extract_iocs(text: str) -> str:
    """Extract IOCs from text."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": f"""Extract all IOCs from this text and format as JSON:

{text}

Output format:
{{
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": {{"md5": [], "sha1": [], "sha256": []}},
    "emails": [],
    "file_paths": []
}}"""
        }]
    )
    return response.content[0].text

def generate_yara(description: str) -> str:
    """Generate YARA rule from description."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": f"""Generate a YARA rule for the following:

{description}

Include:
- Proper metadata (author, date, description, reference)
- Multiple string patterns (hex, ascii, regex where appropriate)
- Reasonable condition logic
- Comments explaining the rule"""
        }]
    )
    return response.content[0].text

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Claude Security CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a file")
    analyze_parser.add_argument("file", help="File to analyze")

    # IOC command
    ioc_parser = subparsers.add_parser("ioc", help="Extract IOCs from text")
    ioc_parser.add_argument("text", help="Text to extract IOCs from")

    # YARA command
    yara_parser = subparsers.add_parser("yara", help="Generate YARA rule")
    yara_parser.add_argument("description", help="Description of what to detect")

    args = parser.parse_args()

    if args.command == "analyze":
        print(analyze_file(args.file))
    elif args.command == "ioc":
        print(extract_iocs(args.text))
    elif args.command == "yara":
        print(generate_yara(args.description))
    else:
        parser.print_help()
````

---

## 🐍 Python SDK Usage

### Installation

```bash
pip install anthropic
```

### Basic Usage

```python
import anthropic

client = anthropic.Anthropic()  # Uses ANTHROPIC_API_KEY env var

# Simple message
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "What is a SQL injection attack?"}
    ]
)
print(response.content[0].text)
```

### With System Prompt

```python
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    system="""You are a senior security analyst at a SOC.
    Always provide:
    1. Technical explanation
    2. Detection methods
    3. MITRE ATT&CK mapping
    4. Remediation steps""",
    messages=[
        {"role": "user", "content": "Explain process injection techniques"}
    ]
)
```

### Streaming Responses

```python
with client.messages.stream(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    messages=[{"role": "user", "content": "Write a detailed malware analysis report..."}]
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
```

### Multi-Turn Conversation

```python
conversation = []

def chat(user_message: str) -> str:
    conversation.append({"role": "user", "content": user_message})

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system="You are a malware analyst assistant.",
        messages=conversation
    )

    assistant_message = response.content[0].text
    conversation.append({"role": "assistant", "content": assistant_message})

    return assistant_message

# Usage
print(chat("I found a suspicious DLL in System32"))
print(chat("The hash is abc123..."))
print(chat("What persistence mechanisms should I check?"))
```

### Async Usage

```python
import asyncio
import anthropic

async def analyze_multiple_samples(samples: list[str]) -> list[str]:
    client = anthropic.AsyncAnthropic()

    async def analyze_one(sample: str) -> str:
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": f"Analyze this malware sample: {sample}"
            }]
        )
        return response.content[0].text

    tasks = [analyze_one(s) for s in samples]
    return await asyncio.gather(*tasks)

# Usage
samples = ["hash1...", "hash2...", "hash3..."]
results = asyncio.run(analyze_multiple_samples(samples))
```

---

## 🔐 Security-Specific Prompting

### Prompt Templates

#### Malware Analysis

```python
MALWARE_ANALYSIS_PROMPT = """Analyze this malware sample:

Code/Data:
```

{sample_data}

```

Provide:
1. **Malware Type**: Classification (trojan, ransomware, etc.)
2. **Capabilities**: What does it do?
3. **Persistence**: How does it survive reboots?
4. **C2 Communication**: Network indicators
5. **Evasion Techniques**: Anti-analysis methods
6. **IOCs**: Extractable indicators
7. **MITRE ATT&CK**: Relevant techniques
8. **Detection**: YARA rule or Sigma rule"""
```

#### Vulnerability Assessment

````python
VULN_ASSESSMENT_PROMPT = """Review this code for security vulnerabilities:

```{language}
{code}
````

For each vulnerability found, provide:

1. **Severity**: Critical/High/Medium/Low
2. **Type**: CWE classification
3. **Location**: Line number(s)
4. **Description**: What's the issue
5. **Exploitation**: How could it be exploited
6. **Remediation**: Code fix with example
7. **References**: CVE if applicable"""

````

#### Log Analysis

```python
LOG_ANALYSIS_PROMPT = """Analyze these security logs for suspicious activity:

````

{logs}

```

Identify:
1. **Anomalies**: Unusual patterns
2. **Threats**: Potential attacks in progress
3. **Timeline**: Sequence of events
4. **Affected Systems**: IPs, hostnames, users
5. **IOCs**: Indicators to block/monitor
6. **Recommendations**: Immediate actions needed"""
```

#### Threat Intelligence

```python
THREAT_INTEL_PROMPT = """Process this threat intelligence report:

{report_text}

Extract and structure:
1. **Threat Actor**: Name, aliases, attribution
2. **TTPs**: Tactics, techniques, procedures
3. **IOCs**: All indicators (IPs, domains, hashes, etc.)
4. **Targets**: Industries, geographies
5. **Timeline**: Campaign dates
6. **Recommendations**: Defensive actions

Output as structured JSON."""
```

### Few-Shot Prompting

````python
def generate_sigma_rule(log_description: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": """Generate Sigma rules. Here are examples:

Example 1:
Input: "Detect PowerShell downloading files"
Output:
```yaml
title: PowerShell Download Activity
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects PowerShell downloading files from the internet
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
            - 'DownloadFile'
            - 'DownloadString'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059.001
````

Example 2:
Input: "Detect scheduled task creation"
Output:

```yaml
title: Scheduled Task Created
id: 8ec1bd25-9b7c-45a1-9c42-c9e1b0a5d8e6
status: experimental
description: Detects creation of scheduled tasks
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1053.005
```

Now generate a Sigma rule for:
Input: "{log_description}"
Output:"""
}]
)
return response.content[0].text

````

---

## 🤖 Building Security Agents

### Basic Agent Structure

```python
from anthropic import Anthropic
import json
from typing import Callable

class SecurityAgent:
    def __init__(self, name: str, system_prompt: str):
        self.name = name
        self.client = Anthropic()
        self.system_prompt = system_prompt
        self.tools: dict[str, Callable] = {}
        self.conversation = []

    def add_tool(self, name: str, func: Callable, description: str):
        """Register a tool the agent can use."""
        self.tools[name] = {
            "function": func,
            "description": description
        }

    def _get_tools_description(self) -> str:
        """Format tools for the prompt."""
        tools_text = "Available tools:\n"
        for name, tool in self.tools.items():
            tools_text += f"- {name}: {tool['description']}\n"
        return tools_text

    def run(self, task: str) -> str:
        """Execute a task with the agent."""
        full_system = f"""{self.system_prompt}

{self._get_tools_description()}

To use a tool, respond with:
TOOL: tool_name
INPUT: tool input

After receiving tool output, continue your analysis."""

        self.conversation.append({"role": "user", "content": task})

        while True:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=full_system,
                messages=self.conversation
            )

            assistant_message = response.content[0].text
            self.conversation.append({"role": "assistant", "content": assistant_message})

            # Check if agent wants to use a tool
            if "TOOL:" in assistant_message:
                # Parse tool call
                lines = assistant_message.split("\n")
                tool_name = None
                tool_input = None

                for i, line in enumerate(lines):
                    if line.startswith("TOOL:"):
                        tool_name = line.replace("TOOL:", "").strip()
                    if line.startswith("INPUT:"):
                        tool_input = line.replace("INPUT:", "").strip()

                if tool_name and tool_name in self.tools:
                    # Execute tool
                    result = self.tools[tool_name]["function"](tool_input)

                    # Add result to conversation
                    self.conversation.append({
                        "role": "user",
                        "content": f"Tool result:\n{result}"
                    })
                else:
                    break
            else:
                break

        return assistant_message


# Example: Threat Intel Agent
def lookup_virustotal(hash_value: str) -> str:
    """Simulate VirusTotal lookup."""
    # In real implementation, call VT API
    return json.dumps({
        "hash": hash_value,
        "detections": 45,
        "total": 70,
        "malware_family": "Emotet"
    })

def lookup_mitre(technique_id: str) -> str:
    """Simulate MITRE ATT&CK lookup."""
    return json.dumps({
        "technique_id": technique_id,
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes..."
    })

# Create agent
agent = SecurityAgent(
    name="ThreatIntelAgent",
    system_prompt="""You are a threat intelligence analyst.
    Analyze provided indicators and enrich them with context.
    Use available tools to gather additional information.
    Provide actionable intelligence reports."""
)

agent.add_tool("virustotal", lookup_virustotal, "Look up file hash in VirusTotal")
agent.add_tool("mitre", lookup_mitre, "Look up MITRE ATT&CK technique")

# Run agent
result = agent.run("""
Analyze these IOCs from a recent incident:
- Hash: d41d8cd98f00b204e9800998ecf8427e
- Technique observed: T1055
Provide a threat assessment.
""")
print(result)
````

---

## 💡 Best Practices

### 1. Rate Limiting

```python
import time
from functools import wraps

def rate_limit(calls_per_minute: int):
    """Decorator to rate limit API calls."""
    min_interval = 60.0 / calls_per_minute
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            wait_time = min_interval - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        return wrapper
    return decorator

@rate_limit(calls_per_minute=50)
def call_claude(prompt: str) -> str:
    # API call here
    pass
```

### 2. Error Handling

```python
import anthropic
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def safe_claude_call(messages: list) -> str:
    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=messages
        )
        return response.content[0].text
    except anthropic.RateLimitError:
        print("Rate limited, retrying...")
        raise
    except anthropic.APIError as e:
        print(f"API error: {e}")
        raise
```

### 3. Cost Management

```python
def estimate_cost(input_tokens: int, output_tokens: int, model: str = "claude-sonnet-4-20250514") -> float:
    """Estimate API call cost."""
    pricing = {
        "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
        "claude-opus-4-5": {"input": 15.0, "output": 75.0},
        "claude-haiku-4": {"input": 0.25, "output": 1.25}
    }

    rates = pricing.get(model, pricing["claude-sonnet-4-20250514"])
    input_cost = (input_tokens / 1_000_000) * rates["input"]
    output_cost = (output_tokens / 1_000_000) * rates["output"]

    return input_cost + output_cost

# Track usage
response = client.messages.create(...)
cost = estimate_cost(
    response.usage.input_tokens,
    response.usage.output_tokens
)
print(f"Call cost: ${cost:.4f}")
```

### 4. Caching Responses

```python
import hashlib
import json
from pathlib import Path

CACHE_DIR = Path(".claude_cache")
CACHE_DIR.mkdir(exist_ok=True)

def cached_claude_call(prompt: str, **kwargs) -> str:
    """Cache Claude responses to avoid redundant API calls."""
    cache_key = hashlib.md5(
        json.dumps({"prompt": prompt, **kwargs}).encode()
    ).hexdigest()

    cache_file = CACHE_DIR / f"{cache_key}.json"

    if cache_file.exists():
        return json.loads(cache_file.read_text())["response"]

    response = client.messages.create(
        model=kwargs.get("model", "claude-sonnet-4-20250514"),
        max_tokens=kwargs.get("max_tokens", 4096),
        messages=[{"role": "user", "content": prompt}]
    )

    result = response.content[0].text
    cache_file.write_text(json.dumps({"response": result}))

    return result
```

---

**Next**: [GitHub Workflow Guide](./github-workflow-guide.md)

# AI Security Development Workshops

Hands-on exercises for building AI-powered security tools using modern development tools.

---

## Table of Contents

1. [Workshop Overview](#workshop-overview)
2. [Prerequisites](#prerequisites)
3. [Workshop 1: Getting Started with AI IDEs](#workshop-1-getting-started-with-ai-ides)
4. [Workshop 2: Building Your First Security Agent](#workshop-2-building-your-first-security-agent)
5. [Workshop 3: Detection Rule Generation](#workshop-3-detection-rule-generation)
6. [Workshop 4: Threat Intelligence Automation](#workshop-4-threat-intelligence-automation)
7. [Workshop 5: Log Analysis with LLMs](#workshop-5-log-analysis-with-llms)
8. [Workshop 6: Building MCP Servers](#workshop-6-building-mcp-servers)
9. [Workshop 7: Multi-Agent Security Systems](#workshop-7-multi-agent-security-systems)
10. [Self-Assessment](#self-assessment)

---

## Workshop Overview

These workshops provide hands-on experience with AI-assisted security development. Each workshop builds on previous concepts and can be completed independently.

### Time Estimates

| Workshop | Duration | Difficulty |
|----------|----------|------------|
| Workshop 1: AI IDEs | 30-45 min | Beginner |
| Workshop 2: Security Agent | 60-90 min | Beginner |
| Workshop 3: Detection Rules | 45-60 min | Intermediate |
| Workshop 4: Threat Intel | 60-90 min | Intermediate |
| Workshop 5: Log Analysis | 60-90 min | Intermediate |
| Workshop 6: MCP Servers | 90-120 min | Advanced |
| Workshop 7: Multi-Agent | 120-180 min | Advanced |

### Tools Used

- **Cursor** or **VS Code with Continue.dev**
- **Claude Code CLI** (optional but recommended)
- **Python 3.10+**
- **Anthropic API key** (or OpenAI/Ollama alternative)

---

## Prerequisites

### Environment Setup

```bash
# Create workshop directory
mkdir -p ~/ai-security-workshops
cd ~/ai-security-workshops

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install base dependencies
pip install anthropic langchain langchain-anthropic chromadb \
    yara-python requests pydantic python-dotenv

# Set API key
export ANTHROPIC_API_KEY="your-key-here"
```

### Verify Setup

```python
# test_setup.py
import anthropic

client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=100,
    messages=[{"role": "user", "content": "Say 'Setup complete!' if you can read this."}]
)
print(response.content[0].text)
```

---

## Workshop 1: Getting Started with AI IDEs

**Duration**: 30-45 minutes
**Difficulty**: Beginner
**Goal**: Learn to effectively use AI coding assistants for security development

### Exercise 1.1: Basic Prompting (10 min)

Open your AI IDE (Cursor or VS Code with Continue.dev) and practice these prompts:

**Task**: Create a file `hash_calculator.py`

```
Prompt in Composer/Chat:

"Create a Python script that:
1. Takes a file path as command line argument
2. Calculates MD5, SHA1, and SHA256 hashes
3. Outputs results in JSON format
4. Handles file not found errors gracefully

Include type hints and docstrings."
```

**Expected Output**: A working Python script with proper error handling.

### Exercise 1.2: Code Explanation (10 min)

Open any Python file from the training labs and practice understanding code:

```
Prompt (select code first):

"Explain what this code does step by step.
Identify any security considerations or potential vulnerabilities."
```

### Exercise 1.3: Incremental Development (15 min)

Practice building a tool incrementally:

```
Step 1: "Create a class structure for a VirusTotal scanner with methods for:
         - hash lookup
         - URL scan
         - file upload"

Step 2: "Add the hash lookup method using the VT API v3"

Step 3: "Add rate limiting (4 requests per minute for free tier)"

Step 4: "Add result caching to SQLite"
```

### Exercise 1.4: Security Code Review (10 min)

Create a file with intentional vulnerabilities and ask the AI to find them:

```python
# vulnerable_example.py
import subprocess
import sqlite3

def search_logs(user_query):
    # Find in logs
    cmd = f"grep {user_query} /var/log/app.log"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def read_config(config_name):
    with open(f"/etc/app/{config_name}") as f:
        return f.read()
```

```
Prompt:

"Review this code for security vulnerabilities.
For each issue found:
1. Identify the vulnerability type (CWE)
2. Explain the risk
3. Provide a secure fix"
```

### Checkpoint

By now you should be able to:
- Write effective prompts for code generation
- Use AI to explain and review code
- Build tools incrementally with AI assistance

---

## Workshop 2: Building Your First Security Agent

**Duration**: 60-90 minutes
**Difficulty**: Beginner
**Goal**: Create a functional security analysis agent using LangChain

### Exercise 2.1: Simple Agent Setup (20 min)

```python
# workshop2/simple_agent.py
"""
Workshop 2.1: Build a simple security analyst agent
"""

from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain import hub

# TODO 1: Initialize the Claude model
# Hint: Use ChatAnthropic with model="claude-sonnet-4-20250514"

# TODO 2: Define a simple tool
def analyze_hash(hash_value: str) -> str:
    """Analyze a hash value and determine its type."""
    hash_len = len(hash_value)
    if hash_len == 32:
        return f"MD5 hash detected: {hash_value}"
    elif hash_len == 40:
        return f"SHA1 hash detected: {hash_value}"
    elif hash_len == 64:
        return f"SHA256 hash detected: {hash_value}"
    else:
        return f"Unknown hash type (length: {hash_len})"

# TODO 3: Create the tool list
# Hint: Use Tool(name="...", func=..., description="...")

# TODO 4: Get a prompt template
# Hint: Use hub.pull("hwchase17/react")

# TODO 5: Create the agent and executor
# Hint: create_react_agent(llm, tools, prompt)
# Hint: AgentExecutor(agent=agent, tools=tools, verbose=True)

# TODO 6: Run the agent
# agent_executor.invoke({"input": "Analyze this hash: d41d8cd98f00b204e9800998ecf8427e"})
```

Use your AI IDE to help complete the TODOs:

```
Prompt:

"Help me complete this LangChain agent. Fill in the TODO sections
to create a working ReAct agent that can analyze file hashes."
```

### Exercise 2.2: Adding More Tools (25 min)

Extend the agent with additional security tools:

```python
# workshop2/extended_agent.py
"""
Workshop 2.2: Extend the agent with more security tools
"""

import re
from datetime import datetime

# TODO: Add these tool functions

def extract_iocs(text: str) -> str:
    """Extract indicators of compromise from text."""
    iocs = {
        "ips": re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
        "domains": re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', text),
        "urls": re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text),
        "md5": re.findall(r'\b[a-fA-F0-9]{32}\b', text),
        "sha256": re.findall(r'\b[a-fA-F0-9]{64}\b', text)
    }
    return str(iocs)

def defang_ioc(ioc: str) -> str:
    """Defang an IOC for safe sharing."""
    result = ioc.replace("http://", "hxxp://")
    result = result.replace("https://", "hxxps://")
    result = result.replace(".", "[.]")
    return result

def check_ip_type(ip: str) -> str:
    """Check if an IP is public, private, or reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return "Invalid IP format"

    first = int(parts[0])
    second = int(parts[1])

    if first == 10:
        return f"{ip} is a Private IP (10.0.0.0/8)"
    elif first == 172 and 16 <= second <= 31:
        return f"{ip} is a Private IP (172.16.0.0/12)"
    elif first == 192 and second == 168:
        return f"{ip} is a Private IP (192.168.0.0/16)"
    elif first == 127:
        return f"{ip} is a Loopback address"
    else:
        return f"{ip} appears to be a Public IP"

# TODO: Create an agent with all three tools
# and test with: "Analyze this report: Found connection to 192.168.1.100 and malware.evil.com"
```

### Exercise 2.3: Adding Memory (20 min)

Add conversation memory to the agent:

```python
# workshop2/agent_with_memory.py
"""
Workshop 2.3: Add conversation memory to the agent
"""

from langchain.memory import ConversationBufferMemory
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub

# TODO: Create agent with memory
# 1. Initialize ConversationBufferMemory
# 2. Create agent with memory in AgentExecutor
# 3. Test multi-turn conversation:
#    - "I found a suspicious file with hash abc123..."
#    - "What type of hash is that?"
#    - "What should I do next?"
```

### Exercise 2.4: Integration Challenge (25 min)

Combine everything into a functional IOC analyzer:

```
Use your AI IDE with this prompt:

"Create a complete IOC analyzer agent that:
1. Extracts IOCs from user-provided text
2. Identifies hash types
3. Classifies IP addresses (public/private)
4. Defangs IOCs for safe sharing
5. Maintains conversation history
6. Provides recommendations based on findings

Include proper error handling and a simple CLI interface."
```

### Checkpoint

By now you should be able to:
- Create LangChain agents with custom tools
- Implement multi-tool agents
- Add conversation memory
- Build useful security analysis tools

---

## Workshop 3: Detection Rule Generation

**Duration**: 45-60 minutes
**Difficulty**: Intermediate
**Goal**: Use AI to generate YARA and Sigma detection rules

### Exercise 3.1: YARA Rule Generation (20 min)

```python
# workshop3/yara_generator.py
"""
Workshop 3.1: Generate YARA rules from malware descriptions
"""

from anthropic import Anthropic

client = Anthropic()

YARA_PROMPT = """You are an expert malware analyst and YARA rule developer.

Given the following malware description, create a production-quality YARA rule.

Requirements:
1. Include comprehensive metadata (author, date, description, reference)
2. Use multiple string patterns (ascii, wide, hex where appropriate)
3. Include reasonable conditions to minimize false positives
4. Add comments explaining the detection logic
5. Follow YARA best practices

Malware Description:
{description}

Generate the YARA rule:"""

def generate_yara_rule(description: str) -> str:
    """Generate a YARA rule from a malware description."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": YARA_PROMPT.format(description=description)
        }]
    )
    return response.content[0].text

# Test with different malware descriptions
descriptions = [
    """
    Emotet banking trojan that:
    - Uses PowerShell for initial execution
    - Creates persistence via scheduled tasks
    - Communicates with C2 servers over HTTPS
    - Drops payload in %TEMP% directory
    - Contains strings "emotet" and "epoch"
    """,

    """
    Ransomware variant that:
    - Encrypts files with .locked extension
    - Drops ransom note README_DECRYPT.txt
    - Uses AES-256 encryption
    - Deletes shadow copies via vssadmin
    - Contains Bitcoin wallet address
    """
]

# TODO: Generate rules for each description and save to files
```

### Exercise 3.2: Sigma Rule Generation (20 min)

```python
# workshop3/sigma_generator.py
"""
Workshop 3.2: Generate Sigma rules for detection
"""

from anthropic import Anthropic

client = Anthropic()

SIGMA_PROMPT = """You are a detection engineer expert in Sigma rules.

Create a Sigma rule for the following detection scenario.

Requirements:
1. Follow the official Sigma specification
2. Include proper metadata (title, id, status, description, author, date)
3. Add MITRE ATT&CK tags
4. Specify the correct logsource
5. Create precise detection logic
6. Document false positives
7. Set appropriate severity level

Detection Scenario:
{scenario}

Generate the Sigma rule in YAML format:"""

def generate_sigma_rule(scenario: str) -> str:
    """Generate a Sigma rule from a detection scenario."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": SIGMA_PROMPT.format(scenario=scenario)
        }]
    )
    return response.content[0].text

# Test scenarios
scenarios = [
    "Detect PowerShell execution with encoded commands commonly used by attackers",
    "Detect creation of scheduled tasks for persistence",
    "Detect potential credential dumping via LSASS memory access",
    "Detect lateral movement using PsExec or similar tools"
]

# TODO: Generate Sigma rules and convert to Splunk queries
```

### Exercise 3.3: Rule Validation (15 min)

```python
# workshop3/rule_validator.py
"""
Workshop 3.3: Validate generated detection rules
"""

import yara
import yaml

def validate_yara_rule(rule_text: str) -> dict:
    """Validate a YARA rule for syntax errors."""
    try:
        yara.compile(source=rule_text)
        return {"valid": True, "errors": []}
    except yara.SyntaxError as e:
        return {"valid": False, "errors": [str(e)]}

def validate_sigma_rule(rule_text: str) -> dict:
    """Validate a Sigma rule structure."""
    errors = []
    try:
        rule = yaml.safe_load(rule_text)

        # Check required fields
        required = ["title", "status", "logsource", "detection"]
        for field in required:
            if field not in rule:
                errors.append(f"Missing required field: {field}")

        # Check detection has condition
        if "detection" in rule and "condition" not in rule["detection"]:
            errors.append("Detection missing 'condition' field")

        return {"valid": len(errors) == 0, "errors": errors}
    except yaml.YAMLError as e:
        return {"valid": False, "errors": [f"YAML parse error: {e}"]}

# TODO: Create a pipeline that generates, validates, and fixes rules
```

### Checkpoint

By now you should be able to:
- Generate YARA rules from malware descriptions
- Create Sigma rules for detection scenarios
- Validate generated rules
- Iterate on rule quality

---

## Workshop 4: Threat Intelligence Automation

**Duration**: 60-90 minutes
**Difficulty**: Intermediate
**Goal**: Build automated threat intelligence processing tools

### Exercise 4.1: IOC Enrichment (25 min)

```python
# workshop4/ioc_enricher.py
"""
Workshop 4.1: Build an IOC enrichment pipeline
"""

import re
import json
from dataclasses import dataclass
from anthropic import Anthropic

@dataclass
class IOC:
    value: str
    ioc_type: str
    context: str = ""

@dataclass
class EnrichedIOC:
    ioc: IOC
    threat_score: int
    classification: str
    mitre_techniques: list
    recommendations: list

def extract_iocs(text: str) -> list[IOC]:
    """Extract IOCs from text."""
    iocs = []

    # IPs
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        iocs.append(IOC(value=ip, ioc_type="ip"))

    # Domains
    for domain in re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', text):
        if domain not in ["example.com", "test.com"]:
            iocs.append(IOC(value=domain, ioc_type="domain"))

    # Hashes
    for hash_val in re.findall(r'\b[a-fA-F0-9]{32}\b', text):
        iocs.append(IOC(value=hash_val, ioc_type="md5"))

    for hash_val in re.findall(r'\b[a-fA-F0-9]{64}\b', text):
        iocs.append(IOC(value=hash_val, ioc_type="sha256"))

    return iocs

def enrich_ioc(ioc: IOC, client: Anthropic) -> EnrichedIOC:
    """Use LLM to enrich an IOC with context."""
    prompt = f"""Analyze this indicator of compromise and provide threat intelligence:

IOC Type: {ioc.ioc_type}
IOC Value: {ioc.value}

Provide analysis in JSON format:
{{
    "threat_score": <0-100>,
    "classification": "<benign|suspicious|malicious|unknown>",
    "mitre_techniques": ["T1XXX", ...],
    "recommendations": ["action1", "action2", ...]
}}

Consider:
- Is this IOC format valid?
- What threat actor TTPs commonly use this type?
- What defensive actions are appropriate?"""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse response
    # TODO: Extract JSON from response and create EnrichedIOC
    pass

# TODO: Build complete enrichment pipeline
```

### Exercise 4.2: Threat Report Parsing (25 min)

```python
# workshop4/report_parser.py
"""
Workshop 4.2: Parse threat intelligence reports
"""

from anthropic import Anthropic
import json

REPORT_PARSER_PROMPT = """You are a threat intelligence analyst.

Parse the following threat report and extract structured intelligence:

{report}

Extract the following in JSON format:
{{
    "threat_actor": {{
        "name": "",
        "aliases": [],
        "motivation": "",
        "sophistication": ""
    }},
    "campaign": {{
        "name": "",
        "first_seen": "",
        "last_seen": "",
        "target_sectors": [],
        "target_regions": []
    }},
    "ttps": [
        {{
            "tactic": "",
            "technique_id": "",
            "technique_name": "",
            "description": ""
        }}
    ],
    "iocs": {{
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "file_names": [],
        "registry_keys": [],
        "mutexes": []
    }},
    "recommendations": []
}}"""

def parse_threat_report(report_text: str) -> dict:
    """Parse a threat report into structured intelligence."""
    client = Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4000,
        messages=[{
            "role": "user",
            "content": REPORT_PARSER_PROMPT.format(report=report_text)
        }]
    )

    # TODO: Parse JSON from response
    # TODO: Validate structure
    # TODO: Return structured intel
    pass

# Sample report for testing
SAMPLE_REPORT = """
APT29, also known as Cozy Bear, has been observed conducting a new campaign
targeting government organizations in Europe. The campaign, active since
March 2024, uses spear-phishing emails with malicious PDF attachments.

The attack chain involves:
1. Initial access via phishing (T1566.001)
2. Execution of PowerShell downloaders (T1059.001)
3. Persistence through scheduled tasks (T1053.005)
4. Credential dumping using Mimikatz (T1003.001)
5. Lateral movement via WMI (T1047)

IOCs observed:
- C2 Server: 185.220.101.55
- C2 Domain: update-service[.]net
- Malware hash: a1b2c3d4e5f6...
- Dropped file: svchost_update.exe
- Mutex: Global\\UpdateServiceMutex
"""

# TODO: Parse the sample report
```

### Exercise 4.3: STIX/TAXII Output (20 min)

```python
# workshop4/stix_generator.py
"""
Workshop 4.3: Generate STIX 2.1 objects from parsed intelligence
"""

from datetime import datetime
import uuid
import json

def generate_stix_indicator(ioc_type: str, ioc_value: str, description: str) -> dict:
    """Generate a STIX 2.1 Indicator object."""
    patterns = {
        "ip": f"[ipv4-addr:value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
        "md5": f"[file:hashes.'MD5' = '{ioc_value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']"
    }

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"Malicious {ioc_type}: {ioc_value}",
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern": patterns.get(ioc_type, f"[artifact:payload_bin = '{ioc_value}']"),
        "pattern_type": "stix",
        "valid_from": datetime.utcnow().isoformat() + "Z"
    }

# TODO: Create functions for other STIX objects:
# - generate_stix_malware()
# - generate_stix_threat_actor()
# - generate_stix_attack_pattern()
# - generate_stix_bundle()
```

### Checkpoint

By now you should be able to:
- Extract and enrich IOCs from text
- Parse threat intelligence reports
- Generate STIX 2.1 objects
- Build automated intel processing pipelines

---

## Workshop 5: Log Analysis with LLMs

**Duration**: 60-90 minutes
**Difficulty**: Intermediate
**Goal**: Use LLMs for intelligent log analysis and anomaly detection

### Exercise 5.1: Windows Event Log Analysis (25 min)

```python
# workshop5/windows_log_analyzer.py
"""
Workshop 5.1: Analyze Windows Security Event Logs
"""

from anthropic import Anthropic
import json

# Sample Windows Security Events
SAMPLE_EVENTS = """
Event ID: 4625 | Failure Reason: Unknown user name or bad password
Account Name: admin | Source IP: 10.1.1.100 | Time: 2024-01-15 03:15:22

Event ID: 4625 | Failure Reason: Unknown user name or bad password
Account Name: administrator | Source IP: 10.1.1.100 | Time: 2024-01-15 03:15:23

Event ID: 4625 | Failure Reason: Unknown user name or bad password
Account Name: root | Source IP: 10.1.1.100 | Time: 2024-01-15 03:15:24

Event ID: 4624 | Logon Type: 10 (RemoteInteractive)
Account Name: svc_backup | Source IP: 192.168.1.50 | Time: 2024-01-15 03:16:00

Event ID: 4688 | New Process: C:\\Windows\\System32\\cmd.exe
Parent Process: C:\\Windows\\System32\\services.exe | Time: 2024-01-15 03:16:05

Event ID: 4688 | New Process: C:\\Windows\\Temp\\svchost.exe
Parent Process: cmd.exe | Time: 2024-01-15 03:16:10
"""

LOG_ANALYSIS_PROMPT = """You are a SOC analyst reviewing Windows Security Event Logs.

Analyze these events and identify:
1. Any suspicious patterns or anomalies
2. Potential attack indicators
3. MITRE ATT&CK technique mappings
4. Recommended response actions

Events:
{events}

Provide your analysis in this format:
- Summary of findings
- Timeline of suspicious activity
- Attack techniques identified
- Recommended actions
- Severity assessment (Critical/High/Medium/Low)"""

def analyze_windows_logs(events: str) -> str:
    """Analyze Windows Security Event Logs."""
    client = Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": LOG_ANALYSIS_PROMPT.format(events=events)
        }]
    )

    return response.content[0].text

# TODO: Analyze the sample events
# TODO: Create a function to detect brute force patterns
# TODO: Create a function to detect suspicious process chains
```

### Exercise 5.2: Network Log Analysis (25 min)

```python
# workshop5/network_analyzer.py
"""
Workshop 5.2: Analyze network connection logs for threats
"""

NETWORK_LOGS = """
timestamp,src_ip,dst_ip,dst_port,protocol,bytes_sent,bytes_recv,duration
2024-01-15 02:00:00,10.1.1.50,8.8.8.8,53,UDP,64,128,0.1
2024-01-15 02:00:01,10.1.1.50,185.220.101.1,443,TCP,1024,2048,5.2
2024-01-15 02:00:02,10.1.1.50,185.220.101.1,443,TCP,5120,10240,10.5
2024-01-15 02:00:15,10.1.1.50,185.220.101.1,443,TCP,1048576,512,30.0
2024-01-15 02:01:00,10.1.1.50,10.1.1.100,445,TCP,2048,4096,2.1
2024-01-15 02:01:30,10.1.1.50,10.1.1.101,445,TCP,2048,4096,2.0
2024-01-15 02:02:00,10.1.1.50,10.1.1.102,445,TCP,2048,4096,2.1
2024-01-15 03:00:00,10.1.1.50,suspicious.evil.com,443,TCP,512,1024,1.0
"""

NETWORK_ANALYSIS_PROMPT = """You are a network security analyst.

Analyze these network connection logs and identify:
1. Potential C2 (command and control) communication
2. Data exfiltration indicators
3. Lateral movement patterns
4. Suspicious connection patterns
5. Beaconing behavior

Network Logs (CSV format):
{logs}

Provide analysis including:
- Suspicious connections with reasoning
- Timeline of potential attack activity
- MITRE ATT&CK mappings
- Network-based IOCs to block
- Recommended containment actions"""

# TODO: Implement network log analysis
# TODO: Add beaconing detection (regular interval connections)
# TODO: Add data exfiltration detection (large outbound transfers)
```

### Exercise 5.3: Multi-Source Correlation (20 min)

```python
# workshop5/log_correlator.py
"""
Workshop 5.3: Correlate logs from multiple sources
"""

from anthropic import Anthropic

CORRELATION_PROMPT = """You are an incident responder correlating security events.

Given logs from multiple sources, build a timeline of the attack and identify:
1. Initial compromise vector
2. Attacker movement through the network
3. Persistence mechanisms
4. Data access or exfiltration

Windows Events:
{windows_logs}

Network Logs:
{network_logs}

Firewall Logs:
{firewall_logs}

Provide:
1. Unified attack timeline
2. Affected systems
3. Attacker TTPs
4. Scope assessment
5. Containment priorities"""

def correlate_logs(windows: str, network: str, firewall: str) -> str:
    """Correlate logs from multiple sources."""
    client = Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=3000,
        messages=[{
            "role": "user",
            "content": CORRELATION_PROMPT.format(
                windows_logs=windows,
                network_logs=network,
                firewall_logs=firewall
            )
        }]
    )

    return response.content[0].text

# TODO: Create sample logs and test correlation
# TODO: Generate incident report from correlated data
```

### Checkpoint

By now you should be able to:
- Analyze Windows Security Event Logs
- Detect network-based threats
- Correlate logs from multiple sources
- Generate incident timelines

---

## Workshop 6: Building MCP Servers

**Duration**: 90-120 minutes
**Difficulty**: Advanced
**Goal**: Create custom MCP servers for security tool integration

### Exercise 6.1: Basic MCP Server (30 min)

```typescript
// workshop6/basic-mcp-server/src/index.ts
/**
 * Workshop 6.1: Build a basic MCP server
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "security-tools",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// TODO 1: Implement tools/list handler
// Return a list of available tools with their schemas

// TODO 2: Implement hash_type tool
// Identify hash type (MD5, SHA1, SHA256) from input

// TODO 3: Implement defang_ioc tool
// Defang URLs, IPs, and domains for safe sharing

// TODO 4: Implement extract_iocs tool
// Extract IOCs from text input

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
```

### Exercise 6.2: VirusTotal MCP Server (40 min)

```python
# workshop6/virustotal-mcp/server.py
"""
Workshop 6.2: Build a VirusTotal MCP server
"""

import os
import json
import asyncio
from mcp import Server, Tool
from mcp.server.stdio import stdio_server
import httpx

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

server = Server("virustotal-mcp")

@server.tool()
async def lookup_hash(hash_value: str) -> str:
    """Look up a file hash in VirusTotal."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{VT_BASE_URL}/files/{hash_value}",
            headers={"x-apikey": VT_API_KEY}
        )

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return json.dumps({
                "hash": hash_value,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            })
        elif response.status_code == 404:
            return json.dumps({"error": "Hash not found in VirusTotal"})
        else:
            return json.dumps({"error": f"API error: {response.status_code}"})

# TODO: Add lookup_ip tool
# TODO: Add lookup_domain tool
# TODO: Add scan_url tool

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    asyncio.run(main())
```

### Exercise 6.3: MISP MCP Server (30 min)

```python
# workshop6/misp-mcp/server.py
"""
Workshop 6.3: Build a MISP MCP server for threat intelligence
"""

import os
import json
import asyncio
from mcp import Server, Tool
from mcp.server.stdio import stdio_server
from pymisp import PyMISP

MISP_URL = os.environ.get("MISP_URL")
MISP_KEY = os.environ.get("MISP_KEY")

server = Server("misp-mcp")

def get_misp_client():
    return PyMISP(MISP_URL, MISP_KEY, ssl=False)

@server.tool()
async def search_ioc(ioc_value: str, ioc_type: str = "ip-dst") -> str:
    """Search MISP for an indicator of compromise."""
    misp = get_misp_client()

    results = misp.search(
        controller="attributes",
        value=ioc_value,
        type_attribute=ioc_type
    )

    # Format results
    formatted = []
    for attr in results.get("Attribute", []):
        formatted.append({
            "value": attr.get("value"),
            "type": attr.get("type"),
            "event_id": attr.get("event_id"),
            "timestamp": attr.get("timestamp")
        })

    return json.dumps({"results": formatted, "count": len(formatted)})

# TODO: Add search_event tool
# TODO: Add add_attribute tool
# TODO: Add get_threat_level tool

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    asyncio.run(main())
```

### Checkpoint

By now you should be able to:
- Create basic MCP servers
- Integrate security APIs via MCP
- Connect MCP servers to Claude Code

---

## Workshop 7: Multi-Agent Security Systems

**Duration**: 120-180 minutes
**Difficulty**: Advanced
**Goal**: Build coordinated multi-agent systems for security operations

### Exercise 7.1: Agent Team Design (30 min)

Design a security operations team with specialized agents:

```python
# workshop7/agent_team.py
"""
Workshop 7.1: Design a multi-agent security team
"""

from dataclasses import dataclass
from enum import Enum

class AgentRole(Enum):
    TRIAGE = "triage"
    ANALYST = "analyst"
    THREAT_INTEL = "threat_intel"
    RESPONDER = "responder"
    REPORTER = "reporter"

@dataclass
class AgentSpec:
    role: AgentRole
    name: str
    system_prompt: str
    tools: list[str]
    input_from: list[AgentRole]
    output_to: list[AgentRole]

# Define the agent team
SECURITY_TEAM = [
    AgentSpec(
        role=AgentRole.TRIAGE,
        name="TriageAgent",
        system_prompt="""You are a Tier 1 SOC analyst responsible for initial alert triage.
        Your job is to:
        1. Quickly assess incoming alerts
        2. Categorize by type (malware, phishing, intrusion, etc.)
        3. Assign initial priority (Critical/High/Medium/Low)
        4. Extract key indicators for further analysis
        5. Route to appropriate specialist""",
        tools=["extract_iocs", "categorize_alert"],
        input_from=[],
        output_to=[AgentRole.ANALYST, AgentRole.THREAT_INTEL]
    ),
    # TODO: Define ANALYST agent
    # TODO: Define THREAT_INTEL agent
    # TODO: Define RESPONDER agent
    # TODO: Define REPORTER agent
]
```

### Exercise 7.2: Agent Communication (45 min)

```python
# workshop7/agent_orchestrator.py
"""
Workshop 7.2: Build agent communication and orchestration
"""

from anthropic import Anthropic
from dataclasses import dataclass
from typing import Optional
import json

@dataclass
class AgentMessage:
    from_agent: str
    to_agent: str
    message_type: str  # "handoff", "query", "response", "report"
    content: dict
    priority: int = 0

class AgentOrchestrator:
    def __init__(self):
        self.client = Anthropic()
        self.agents = {}
        self.message_queue = []
        self.conversation_history = []

    def register_agent(self, name: str, system_prompt: str, tools: list):
        """Register an agent with the orchestrator."""
        self.agents[name] = {
            "system_prompt": system_prompt,
            "tools": tools,
            "state": {}
        }

    def send_message(self, message: AgentMessage):
        """Queue a message between agents."""
        self.message_queue.append(message)
        self.message_queue.sort(key=lambda m: -m.priority)

    def run_agent(self, agent_name: str, input_data: dict) -> dict:
        """Run a single agent with input data."""
        agent = self.agents[agent_name]

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=agent["system_prompt"],
            messages=[{
                "role": "user",
                "content": json.dumps(input_data)
            }]
        )

        return json.loads(response.content[0].text)

    async def process_incident(self, alert_data: dict) -> dict:
        """Process an incident through the agent pipeline."""
        # TODO: Implement pipeline processing
        # 1. Send to triage agent
        # 2. Route based on triage results
        # 3. Gather intel in parallel
        # 4. Coordinate response
        # 5. Generate report
        pass

# TODO: Implement the full orchestration
```

### Exercise 7.3: Complete SOC Automation (60 min)

```python
# workshop7/soc_automation.py
"""
Workshop 7.3: Build a complete SOC automation system
"""

import asyncio
from typing import Optional
from anthropic import Anthropic
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub

class SOCAutomation:
    """Automated Security Operations Center system."""

    def __init__(self):
        self.llm = ChatAnthropic(model="claude-sonnet-4-20250514")
        self.agents = {}
        self.setup_agents()

    def setup_agents(self):
        """Initialize all SOC agents."""
        # Triage Agent
        self.agents["triage"] = self._create_agent(
            system_prompt="""You are an alert triage specialist.
            Analyze incoming alerts and provide:
            1. Alert category
            2. Priority level
            3. Key IOCs
            4. Initial assessment
            Output as JSON.""",
            tools=self._get_triage_tools()
        )

        # TODO: Set up analysis agent
        # TODO: Set up threat intel agent
        # TODO: Set up response agent
        # TODO: Set up reporting agent

    def _create_agent(self, system_prompt: str, tools: list) -> AgentExecutor:
        """Create an agent with specified configuration."""
        prompt = hub.pull("hwchase17/react")
        agent = create_react_agent(self.llm, tools, prompt)
        return AgentExecutor(agent=agent, tools=tools, verbose=True)

    def _get_triage_tools(self) -> list:
        """Get tools for triage agent."""
        # TODO: Implement triage tools
        return []

    async def handle_alert(self, alert: dict) -> dict:
        """Handle an incoming security alert."""
        # Step 1: Triage
        triage_result = await self._run_triage(alert)

        # Step 2: Analysis (if needed)
        if triage_result["priority"] in ["Critical", "High"]:
            analysis_result = await self._run_analysis(alert, triage_result)
        else:
            analysis_result = None

        # Step 3: Threat Intel Enrichment
        intel_result = await self._run_intel_enrichment(
            triage_result.get("iocs", [])
        )

        # Step 4: Response Recommendation
        response_result = await self._run_response(
            alert, triage_result, analysis_result, intel_result
        )

        # Step 5: Generate Report
        report = await self._generate_report(
            alert, triage_result, analysis_result, intel_result, response_result
        )

        return report

    async def _run_triage(self, alert: dict) -> dict:
        """Run triage agent on alert."""
        # TODO: Implement
        pass

    async def _run_analysis(self, alert: dict, triage: dict) -> dict:
        """Run deep analysis on alert."""
        # TODO: Implement
        pass

    async def _run_intel_enrichment(self, iocs: list) -> dict:
        """Enrich IOCs with threat intelligence."""
        # TODO: Implement
        pass

    async def _run_response(self, alert, triage, analysis, intel) -> dict:
        """Generate response recommendations."""
        # TODO: Implement
        pass

    async def _generate_report(self, *args) -> dict:
        """Generate incident report."""
        # TODO: Implement
        pass

# Main execution
async def main():
    soc = SOCAutomation()

    sample_alert = {
        "id": "ALT-2024-001",
        "source": "EDR",
        "timestamp": "2024-01-15T03:15:00Z",
        "title": "Suspicious PowerShell Execution",
        "description": "PowerShell executed encoded command on WORKSTATION-15",
        "severity": "High",
        "host": "WORKSTATION-15",
        "user": "jsmith",
        "process": "powershell.exe",
        "command_line": "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS..."
    }

    result = await soc.handle_alert(sample_alert)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
```

### Checkpoint

By now you should be able to:
- Design multi-agent security systems
- Implement agent communication
- Build automated SOC workflows
- Orchestrate complex security operations

---

## Self-Assessment

### Knowledge Check

After completing these workshops, you should be able to answer:

1. **AI IDE Usage**
   - How do you effectively prompt AI for security code generation?
   - What are the best practices for incremental development with AI?

2. **Agent Development**
   - How do you create a LangChain agent with custom tools?
   - What is the ReAct pattern and how is it used?

3. **Detection Engineering**
   - How do you generate quality YARA rules with AI?
   - What makes a good Sigma rule?

4. **Threat Intelligence**
   - How do you automate IOC enrichment?
   - What is STIX 2.1 and how do you generate it?

5. **Log Analysis**
   - How do you use LLMs for log analysis?
   - What patterns indicate potential attacks?

6. **MCP Development**
   - How do you create an MCP server?
   - How do you integrate security APIs via MCP?

7. **Multi-Agent Systems**
   - How do you design agent teams?
   - How do you orchestrate multiple agents?

### Practical Challenge

Build a complete "Security Analyst Copilot" that:
1. Accepts security alerts via CLI or API
2. Triages and prioritizes automatically
3. Enriches with threat intelligence
4. Generates detection rules for similar threats
5. Produces incident reports

This combines all workshop concepts into a real-world tool.

---

## Next Steps

1. Complete the [Labs](../../labs/README.md) for more hands-on practice
2. Work on a [Capstone Project](../../capstone-projects/README.md)
3. Explore the [Training Curriculum](../../docs/ai-security-training-program.md)
4. Review [Tools and Resources](../../resources/tools-and-resources.md)

---

**Related Guides**: [Claude Code CLI](./claude-code-cli-guide.md) | [Google ADK](./google-adk-guide.md) | [Cursor IDE](./cursor-ide-guide.md)

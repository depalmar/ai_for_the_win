# Lab 05 Walkthrough: Threat Intelligence Agent

## Overview

This walkthrough guides you through building an autonomous threat intelligence agent using the ReAct pattern and tool use.

**Time to complete walkthrough:** 35 minutes

---

## Step 1: Understanding the Architecture

### What We're Building

```
              USER QUERY
                  |
                  v
        +-------------------+
        |    ReAct Agent    |
        |  (Reason + Act)   |
        +-------------------+
                  |
    +-------------+-------------+
    |             |             |
    v             v             v
+-------+    +--------+    +--------+
| Search|    | Lookup |    | Enrich |
| IOCs  |    | CVEs   |    | Context|
+-------+    +--------+    +--------+
    |             |             |
    +-------------+-------------+
                  |
                  v
        +-------------------+
        |  Final Analysis   |
        +-------------------+
```

### Why ReAct Pattern?
- **Reasoning**: Agent explains its thinking
- **Acting**: Agent uses tools to gather information
- **Iterative**: Multiple rounds of thought → action → observation
- **Transparent**: See the agent's decision process

---

## Step 2: Setting Up the Agent Framework

### Using LangChain

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain_anthropic import ChatAnthropic
from langchain.tools import Tool
import os

# Initialize LLM
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
)
```

### Alternative: Build from Scratch

```python
from anthropic import Anthropic

class SimpleReActAgent:
    """Simple ReAct agent without LangChain"""

    def __init__(self, tools: dict):
        self.client = Anthropic()
        self.tools = tools
        self.max_iterations = 10

    def run(self, query: str) -> str:
        """Execute ReAct loop"""
        messages = []
        system_prompt = self._build_system_prompt()

        for i in range(self.max_iterations):
            # Get agent response
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=system_prompt,
                messages=messages + [{"role": "user", "content": query if i == 0 else "Continue."}]
            )

            response_text = response.content[0].text
            messages.append({"role": "assistant", "content": response_text})

            # Check for final answer
            if "FINAL ANSWER:" in response_text:
                return response_text.split("FINAL ANSWER:")[-1].strip()

            # Extract and execute action
            action = self._extract_action(response_text)
            if action:
                observation = self._execute_action(action)
                messages.append({"role": "user", "content": f"Observation: {observation}"})

        return "Max iterations reached without final answer"

    def _build_system_prompt(self) -> str:
        tool_descriptions = "\n".join([
            f"- {name}: {func.__doc__}"
            for name, func in self.tools.items()
        ])

        return f"""You are a threat intelligence analyst agent. Use the available tools to investigate threats.

Available Tools:
{tool_descriptions}

Format your responses as:
THOUGHT: [your reasoning]
ACTION: [tool_name]
ACTION INPUT: [input for the tool]

When you have enough information, respond with:
FINAL ANSWER: [your complete analysis]
"""

    def _extract_action(self, text: str) -> dict:
        """Extract action from agent response"""
        if "ACTION:" not in text:
            return None

        lines = text.split("\n")
        action = None
        action_input = None

        for line in lines:
            if line.startswith("ACTION:"):
                action = line.replace("ACTION:", "").strip()
            elif line.startswith("ACTION INPUT:"):
                action_input = line.replace("ACTION INPUT:", "").strip()

        if action and action_input:
            return {"tool": action, "input": action_input}
        return None

    def _execute_action(self, action: dict) -> str:
        """Execute tool and return observation"""
        tool_name = action["tool"]
        tool_input = action["input"]

        if tool_name in self.tools:
            try:
                result = self.tools[tool_name](tool_input)
                return str(result)
            except Exception as e:
                return f"Error: {str(e)}"

        return f"Unknown tool: {tool_name}"
```

---

## Step 3: Defining Tools

### Tool 1: IOC Lookup

```python
import json

def lookup_ioc(ioc: str) -> dict:
    """
    Look up an Indicator of Compromise (IP, domain, or hash).
    Returns threat intelligence data about the IOC.
    """
    # Load sample IOC database
    with open('data/threat-intel/iocs.json') as f:
        ioc_db = json.load(f)

    # Search for IOC
    for entry in ioc_db:
        if entry['value'] == ioc:
            return {
                "found": True,
                "type": entry['type'],
                "malicious": entry['malicious'],
                "confidence": entry['confidence'],
                "threat_type": entry.get('threat_type'),
                "tags": entry.get('tags', []),
                "description": entry.get('description', '')
            }

    return {
        "found": False,
        "message": f"IOC {ioc} not found in database"
    }


# Example tool for external API (VirusTotal)
def lookup_virustotal(ioc: str) -> dict:
    """
    Query VirusTotal for IOC reputation.
    Supports IPs, domains, and file hashes.
    """
    import requests

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    # Determine IOC type
    if len(ioc) in [32, 40, 64]:  # MD5, SHA1, SHA256
        endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc.replace('.', '').isdigit():  # IP address
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:  # Domain
        endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    headers = {"x-apikey": api_key}
    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "undetected": stats.get('undetected', 0)
        }

    return {"error": f"API request failed: {response.status_code}"}
```

### Tool 2: CVE Lookup

```python
def lookup_cve(cve_id: str) -> dict:
    """
    Look up CVE details from NIST NVD.
    Returns vulnerability information including CVSS score.
    """
    import requests

    # Clean CVE ID
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get('totalResults', 0) == 0:
            return {"error": f"CVE {cve_id} not found"}

        cve = data['vulnerabilities'][0]['cve']

        # Extract CVSS score
        cvss = None
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            cvss = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']

        return {
            "cve_id": cve_id,
            "description": cve['descriptions'][0]['value'],
            "cvss_score": cvss,
            "published": cve.get('published'),
            "references": [ref['url'] for ref in cve.get('references', [])[:3]]
        }

    except requests.RequestException as e:
        return {"error": f"Failed to fetch CVE: {str(e)}"}
```

### Tool 3: MITRE ATT&CK Lookup

```python
def lookup_mitre_technique(technique_id: str) -> dict:
    """
    Look up MITRE ATT&CK technique details.
    Returns technique name, description, and mitigations.
    """
    # Simplified lookup - in production, use MITRE STIX data
    techniques = {
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "platforms": ["Windows", "macOS", "Linux"],
            "mitigations": ["Execution Prevention", "Antivirus/Antimalware"]
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Adversaries may communicate using application layer protocols.",
            "platforms": ["Windows", "macOS", "Linux"],
            "mitigations": ["Network Intrusion Prevention"]
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversaries may encrypt data on target systems to interrupt availability.",
            "platforms": ["Windows", "macOS", "Linux"],
            "mitigations": ["Data Backup"]
        }
    }

    technique_id = technique_id.upper().strip()

    if technique_id in techniques:
        return techniques[technique_id]

    return {"error": f"Technique {technique_id} not found"}
```

### Tool 4: Network Enrichment

```python
def enrich_ip(ip: str) -> dict:
    """
    Enrich IP address with geolocation and ASN information.
    """
    import requests

    try:
        # Using ip-api.com (free, no key required)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data.get('status') == 'success':
            return {
                "ip": ip,
                "country": data.get('country'),
                "city": data.get('city'),
                "isp": data.get('isp'),
                "org": data.get('org'),
                "asn": data.get('as'),
                "is_proxy": data.get('proxy', False)
            }

        return {"error": "IP lookup failed"}

    except requests.RequestException as e:
        return {"error": f"Network error: {str(e)}"}
```

---

## Step 4: Building the Agent

### With LangChain

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain.tools import Tool

# Define tools
tools = [
    Tool(
        name="IOC_Lookup",
        func=lookup_ioc,
        description="Look up an IOC (IP, domain, or hash) in the threat intelligence database"
    ),
    Tool(
        name="CVE_Lookup",
        func=lookup_cve,
        description="Look up CVE vulnerability details including CVSS score"
    ),
    Tool(
        name="MITRE_Lookup",
        func=lookup_mitre_technique,
        description="Look up MITRE ATT&CK technique by ID (e.g., T1059)"
    ),
    Tool(
        name="IP_Enrichment",
        func=enrich_ip,
        description="Get geolocation and ASN info for an IP address"
    )
]

# ReAct prompt template
template = """You are a threat intelligence analyst investigating security threats.

Available tools:
{tools}

Tool names: {tool_names}

Use this format:

Question: the input question you must answer
Thought: think about what to do
Action: the tool to use (one of [{tool_names}])
Action Input: the input to the tool
Observation: the result of the action
... (repeat Thought/Action/Observation as needed)
Thought: I now have enough information
Final Answer: your complete analysis

Question: {input}
{agent_scratchpad}"""

prompt = PromptTemplate(
    template=template,
    input_variables=["input", "agent_scratchpad", "tools", "tool_names"]
)

# Create agent
agent = create_react_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,  # Shows reasoning
    max_iterations=10,
    handle_parsing_errors=True
)
```

### Without LangChain

```python
# Using the SimpleReActAgent from Step 2
agent = SimpleReActAgent(tools={
    "IOC_Lookup": lookup_ioc,
    "CVE_Lookup": lookup_cve,
    "MITRE_Lookup": lookup_mitre_technique,
    "IP_Enrichment": enrich_ip
})
```

---

## Step 5: Running Investigations

### Example 1: IOC Investigation

```python
# Investigate a suspicious IP
result = agent_executor.invoke({
    "input": """Investigate the IP address 185.234.72.19.
    I need to know:
    1. Is it malicious?
    2. What threat type is it associated with?
    3. What's its geographic location?
    4. What MITRE techniques might be relevant?
    """
})

print(result["output"])
```

### Expected Agent Reasoning
```
Thought: I need to investigate this IP address. Let me start by looking it up in our IOC database.

Action: IOC_Lookup
Action Input: 185.234.72.19

Observation: {"found": true, "malicious": true, "threat_type": "c2_server", "tags": ["cobalt-strike", "apt29"]}

Thought: The IP is a known C2 server associated with Cobalt Strike. Let me get more context about its location.

Action: IP_Enrichment
Action Input: 185.234.72.19

Observation: {"country": "Russia", "isp": "Hosting Provider", "asn": "AS12345"}

Thought: This is a Russian hosting IP. The tags mention APT29. Let me look up relevant MITRE techniques for C2.

Action: MITRE_Lookup
Action Input: T1071

Observation: {"name": "Application Layer Protocol", "tactic": "Command and Control", ...}

Thought: I now have enough information to provide a complete analysis.

Final Answer: The IP 185.234.72.19 is a confirmed malicious C2 server...
```

### Example 2: Vulnerability Assessment

```python
result = agent_executor.invoke({
    "input": """We detected exploitation attempts for CVE-2024-1234.
    What is this vulnerability and how severe is it?
    What MITRE techniques are associated with its exploitation?
    """
})
```

---

## Step 6: Advanced Agent Patterns

### Adding Memory

```python
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True
)

agent_executor_with_memory = AgentExecutor(
    agent=agent,
    tools=tools,
    memory=memory,
    verbose=True
)

# First query
result1 = agent_executor_with_memory.invoke({
    "input": "Look up the IP 185.234.72.19"
})

# Follow-up (agent remembers context)
result2 = agent_executor_with_memory.invoke({
    "input": "What MITRE techniques are associated with that threat?"
})
```

### Parallel Tool Execution

```python
from concurrent.futures import ThreadPoolExecutor

def investigate_multiple_iocs(iocs: list) -> list:
    """Investigate multiple IOCs in parallel"""

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lookup_ioc, iocs))

    return results

# Use in agent tool
def batch_ioc_lookup(iocs_str: str) -> dict:
    """Look up multiple IOCs (comma-separated)"""
    iocs = [ioc.strip() for ioc in iocs_str.split(",")]
    results = investigate_multiple_iocs(iocs)
    return dict(zip(iocs, results))
```

---

## Common Mistakes & Solutions

### Mistake 1: Agent Loops Forever

```python
# WRONG: No iteration limit
agent_executor = AgentExecutor(agent=agent, tools=tools)

# RIGHT: Set max iterations
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=10,
    max_execution_time=60  # seconds
)
```

### Mistake 2: Poor Tool Descriptions

```python
# WRONG: Vague description
Tool(name="lookup", func=lookup_ioc, description="Looks things up")

# RIGHT: Clear, specific description
Tool(
    name="IOC_Lookup",
    func=lookup_ioc,
    description="Look up an IOC (IP address, domain name, or file hash) in the threat intelligence database. Returns malicious status, threat type, and associated tags."
)
```

### Mistake 3: Not Handling Errors

```python
def safe_tool_wrapper(func):
    """Wrap tool to handle errors gracefully"""
    def wrapper(input_str):
        try:
            return func(input_str)
        except Exception as e:
            return f"Error: {str(e)}. Please try a different approach."
    return wrapper

# Apply wrapper
tools = [
    Tool(name="IOC_Lookup", func=safe_tool_wrapper(lookup_ioc), ...)
]
```

---

## Extension Exercises

### Exercise A: Add VirusTotal Integration

```python
def create_virustotal_tool():
    """Create a VirusTotal lookup tool with rate limiting"""
    import time
    last_call = [0]

    def lookup_with_rate_limit(ioc: str) -> dict:
        # Rate limit: 4 requests/minute for free API
        elapsed = time.time() - last_call[0]
        if elapsed < 15:
            time.sleep(15 - elapsed)

        result = lookup_virustotal(ioc)
        last_call[0] = time.time()
        return result

    return Tool(
        name="VirusTotal_Lookup",
        func=lookup_with_rate_limit,
        description="Query VirusTotal for file hash, IP, or domain reputation"
    )
```

### Exercise B: Build Investigation Report

```python
def generate_investigation_report(investigation_results: list) -> str:
    """Generate markdown report from agent investigation"""

    report = """# Threat Investigation Report

## Executive Summary
{summary}

## IOCs Investigated
{iocs}

## Findings
{findings}

## Recommendations
{recommendations}

## MITRE ATT&CK Mapping
{mitre}
"""

    # Use LLM to generate report sections
    # ...

    return report
```

### Exercise C: Custom Tool Creation

```python
def create_custom_tool(name: str, api_endpoint: str, api_key_env: str):
    """Factory function to create custom API tools"""

    def tool_func(query: str) -> dict:
        import requests
        api_key = os.getenv(api_key_env)
        response = requests.get(
            api_endpoint,
            params={"q": query},
            headers={"Authorization": f"Bearer {api_key}"}
        )
        return response.json()

    return Tool(
        name=name,
        func=tool_func,
        description=f"Query {name} API"
    )
```

---

## Key Takeaways

1. **ReAct pattern** - Combines reasoning and actions transparently
2. **Tool design** - Clear descriptions help the agent choose correctly
3. **Error handling** - Gracefully handle tool failures
4. **Rate limiting** - Respect API limits in production
5. **Memory** - Enable follow-up queries with conversation history

---

## Next Lab

Continue to [Lab 06: Security RAG](./lab06-walkthrough.md) to build a retrieval-augmented generation system for security documentation.

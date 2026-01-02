# Google Agent Development Kit (ADK) Guide

Build production-ready AI agents for security operations using Google's Agent Development Kit.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Core Concepts](#core-concepts)
4. [Building Your First Agent](#building-your-first-agent)
5. [Tool Development](#tool-development)
6. [Multi-Agent Systems](#multi-agent-systems)
7. [Security-Focused Agents](#security-focused-agents)
8. [Memory and State Management](#memory-and-state-management)
9. [Deployment Options](#deployment-options)
10. [Best Practices](#best-practices)

---

## Overview

**Google Agent Development Kit (ADK)** is a Python framework for building sophisticated AI agents powered by Gemini and other LLMs. It provides:

| Feature                       | Description                                               |
| ----------------------------- | --------------------------------------------------------- |
| **Agent Framework**           | Structured approach to building LLM-powered agents        |
| **Tool System**               | Define and compose custom tools for agent capabilities    |
| **Multi-Agent Orchestration** | Build systems with specialized, collaborating agents      |
| **Memory Management**         | Persistent and session-based memory systems               |
| **Streaming Support**         | Real-time response streaming for interactive applications |
| **Model Flexibility**         | Support for Gemini, OpenAI, and other LLM providers       |
| **Built-in Safety**           | Content filtering and safety guardrails                   |

### Why ADK for Security Development?

1. **Structured Agent Design**: Build complex security workflows with composable agents
2. **Tool Integration**: Easily integrate with security APIs (VirusTotal, MISP, etc.)
3. **Multi-Agent Coordination**: Coordinate specialized agents for comprehensive analysis
4. **Enterprise Ready**: Production deployment patterns with monitoring
5. **Google Cloud Integration**: Native support for Vertex AI and Google services

### Comparison with Other Frameworks

| Framework      | Strengths                              | Best For                             |
| -------------- | -------------------------------------- | ------------------------------------ |
| **Google ADK** | Multi-agent, Gemini native, enterprise | Production systems, Google ecosystem |
| **LangChain**  | Extensive integrations, flexibility    | Prototyping, diverse LLM support     |
| **CrewAI**     | Role-based agents, simple API          | Team simulations, workflows          |
| **AutoGen**    | Microsoft ecosystem, async             | Research, complex conversations      |

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- Google Cloud account (for Vertex AI)
- API key or service account

### Installation

```bash
# Create virtual environment
python -m venv adk-env
source adk-env/bin/activate  # Linux/macOS
# or: adk-env\Scripts\activate  # Windows

# Install Google ADK
pip install google-adk

# Install with all optional dependencies
pip install google-adk[all]

# For security tooling
pip install google-adk yara-python virustotal3 pymisp
```

### Configuration

**Option 1: API Key (Development)**

```bash
# Set environment variable
export GOOGLE_API_KEY="your-api-key"

# Or in .env file
echo "GOOGLE_API_KEY=your-api-key" >> .env
```

**Option 2: Vertex AI (Production)**

```bash
# Install Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth application-default login

# Set project
gcloud config set project your-project-id

# Set environment variables
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="us-central1"
```

### Verify Installation

```python
from google.adk import Agent
from google.adk.models import Gemini

# Create simple agent
agent = Agent(
    name="test-agent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="You are a helpful security assistant."
)

# Test
response = agent.run("What is a SQL injection attack?")
print(response.text)
```

---

## Core Concepts

### Agents

Agents are the primary building blocks:

```python
from google.adk import Agent
from google.adk.models import Gemini

# Basic agent definition
security_analyst = Agent(
    name="security_analyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="""You are a senior security analyst.
    Analyze threats, identify indicators of compromise, and
    provide actionable recommendations. Always reference
    MITRE ATT&CK when relevant.""",
    tools=[],  # Add tools here
)
```

### Tools

Tools extend agent capabilities:

```python
from google.adk import Tool
from google.adk.tools import FunctionTool

# Define a tool function
def lookup_ip_reputation(ip_address: str) -> dict:
    """Look up IP address reputation in threat intelligence."""
    # Implementation here
    return {"ip": ip_address, "reputation": "malicious", "score": 85}

# Create tool
ip_lookup_tool = FunctionTool(
    function=lookup_ip_reputation,
    description="Check IP address reputation against threat feeds"
)
```

### Sessions

Manage conversation state:

```python
from google.adk import Session

# Create session
session = Session()

# Run agent with session
response = agent.run(
    "Analyze this suspicious IP: 192.168.1.100",
    session=session
)

# Continue conversation
response = agent.run(
    "What other indicators should I look for?",
    session=session
)
```

### Events

Handle real-time streaming:

```python
# Stream responses
for event in agent.run_stream("Analyze this malware sample"):
    if event.is_text:
        print(event.text, end="", flush=True)
    elif event.is_tool_call:
        print(f"\n[Calling tool: {event.tool_name}]")
    elif event.is_done:
        print("\n[Analysis complete]")
```

---

## Building Your First Agent

### Simple Threat Intel Agent

```python
# threat_intel_agent.py
from google.adk import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
import requests
import os

# Define tools
def query_virustotal(hash_value: str) -> dict:
    """Query VirusTotal for file hash analysis."""
    api_key = os.environ.get("VT_API_KEY")
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "hash": hash_value,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0)
            }
        else:
            return {"error": f"API returned {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_abuseipdb(ip_address: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    url = "https://api.abuseipdb.com/api/v2/check"

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip_address,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "total_reports": data.get("totalReports", 0)
            }
        else:
            return {"error": f"API returned {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def search_mitre_attack(technique_or_keyword: str) -> dict:
    """Search MITRE ATT&CK for techniques."""
    # Simplified - in production, use MITRE STIX data
    common_techniques = {
        "t1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "t1055": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        "t1003": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
        "t1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        "phishing": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        "persistence": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    }

    keyword = technique_or_keyword.lower().replace("-", "")
    if keyword in common_techniques:
        return common_techniques[keyword]
    return {"message": f"Technique '{technique_or_keyword}' not found in cache. Query MITRE API for full search."}


# Create tools
vt_tool = FunctionTool(
    function=query_virustotal,
    description="Query VirusTotal for file hash (MD5, SHA1, SHA256) analysis results"
)

abuseipdb_tool = FunctionTool(
    function=query_abuseipdb,
    description="Check IP address reputation using AbuseIPDB"
)

mitre_tool = FunctionTool(
    function=search_mitre_attack,
    description="Search MITRE ATT&CK framework for techniques and tactics"
)

# Create agent
threat_intel_agent = Agent(
    name="ThreatIntelAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="""You are an expert threat intelligence analyst.

    Your responsibilities:
    1. Analyze indicators of compromise (IOCs) using available tools
    2. Correlate findings across multiple intelligence sources
    3. Map malicious activity to MITRE ATT&CK framework
    4. Provide actionable recommendations for defenders

    Always structure your analysis with:
    - Executive Summary
    - IOC Analysis
    - MITRE ATT&CK Mapping
    - Recommendations

    When you don't have enough information, clearly state what
    additional data would help your analysis.""",
    tools=[vt_tool, abuseipdb_tool, mitre_tool]
)


# Main execution
if __name__ == "__main__":
    from google.adk import Session

    session = Session()

    # Example analysis request
    query = """
    Analyze these indicators from a recent incident:
    - File hash: d41d8cd98f00b204e9800998ecf8427e
    - Suspicious IP: 185.220.101.1
    - Observed technique: Process injection

    Provide a threat assessment.
    """

    print("Threat Intelligence Analysis")
    print("=" * 50)

    for event in threat_intel_agent.run_stream(query, session=session):
        if event.is_text:
            print(event.text, end="", flush=True)
        elif event.is_tool_call:
            print(f"\n[Using tool: {event.tool_name}]")

    print("\n" + "=" * 50)
```

### Running the Agent

```bash
# Set API keys
export GOOGLE_API_KEY="your-key"
export VT_API_KEY="your-virustotal-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"

# Run agent
python threat_intel_agent.py
```

---

## Tool Development

### Tool Types

**1. Function Tools** - Wrap Python functions:

```python
from google.adk.tools import FunctionTool

def parse_windows_event(event_xml: str) -> dict:
    """Parse Windows Security Event XML."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(event_xml)

    # Extract key fields
    event_id = root.find(".//EventID").text
    time_created = root.find(".//TimeCreated").get("SystemTime")

    return {
        "event_id": event_id,
        "timestamp": time_created,
        "parsed": True
    }

event_parser = FunctionTool(
    function=parse_windows_event,
    description="Parse Windows Security Event XML and extract key fields"
)
```

**2. Retrieval Tools** - For RAG applications:

```python
from google.adk.tools import RetrievalTool
from google.adk.retrievers import ChromaRetriever

# Create retriever with threat intel documents
retriever = ChromaRetriever(
    collection_name="threat_reports",
    embedding_model="text-embedding-004"
)

threat_search = RetrievalTool(
    retriever=retriever,
    description="Search threat intelligence reports and documentation"
)
```

**3. Code Execution Tools** - Run code safely:

```python
from google.adk.tools import CodeExecutionTool

code_tool = CodeExecutionTool(
    allowed_imports=["pandas", "json", "re", "hashlib"],
    timeout_seconds=30,
    description="Execute Python code for data analysis"
)
```

### Security Tool Examples

**YARA Scanner Tool:**

```python
import yara
from google.adk.tools import FunctionTool

def scan_with_yara(file_path: str, rules_path: str = "rules/") -> dict:
    """Scan a file with YARA rules."""
    try:
        # Compile rules
        rules = yara.compile(filepath=f"{rules_path}/index.yar")

        # Scan file
        matches = rules.match(file_path)

        results = []
        for match in matches:
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "strings": [str(s) for s in match.strings[:5]]  # Limit strings
            })

        return {
            "file": file_path,
            "matches": len(results),
            "rules_matched": results
        }
    except Exception as e:
        return {"error": str(e)}

yara_tool = FunctionTool(
    function=scan_with_yara,
    description="Scan files with YARA rules for malware detection"
)
```

**Sigma Rule Converter:**

```python
from google.adk.tools import FunctionTool

def convert_sigma_rule(sigma_yaml: str, target: str = "splunk") -> dict:
    """Convert Sigma rule to target SIEM format."""
    try:
        from sigma.rule import SigmaRule
        from sigma.backends.splunk import SplunkBackend
        from sigma.backends.elasticsearch import ElasticsearchBackend
        from sigma.pipelines.sysmon import sysmon_pipeline

        rule = SigmaRule.from_yaml(sigma_yaml)

        if target == "splunk":
            backend = SplunkBackend(pipeline=sysmon_pipeline())
        elif target == "elasticsearch":
            backend = ElasticsearchBackend(pipeline=sysmon_pipeline())
        else:
            return {"error": f"Unsupported target: {target}"}

        query = backend.convert_rule(rule)[0]

        return {
            "rule_title": rule.title,
            "target": target,
            "query": query
        }
    except Exception as e:
        return {"error": str(e)}

sigma_tool = FunctionTool(
    function=convert_sigma_rule,
    description="Convert Sigma detection rules to SIEM query formats (Splunk, Elasticsearch)"
)
```

---

## Multi-Agent Systems

### Agent Orchestration Patterns

**1. Sequential Pipeline:**

```python
from google.adk import Agent, Pipeline
from google.adk.models import Gemini

# Specialized agents
triage_agent = Agent(
    name="TriageAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Quickly categorize and prioritize security alerts. Output: priority (critical/high/medium/low), category, initial assessment."
)

analysis_agent = Agent(
    name="AnalysisAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Perform deep analysis on security incidents. Correlate IOCs, identify attack patterns, map to MITRE ATT&CK.",
    tools=[vt_tool, mitre_tool]
)

response_agent = Agent(
    name="ResponseAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Generate incident response recommendations. Include containment, eradication, and recovery steps."
)

# Create pipeline
incident_pipeline = Pipeline(
    agents=[triage_agent, analysis_agent, response_agent],
    name="IncidentResponsePipeline"
)

# Run pipeline
result = incident_pipeline.run("Alert: Multiple failed SSH logins from IP 192.168.1.100")
```

**2. Parallel Analysis:**

```python
from google.adk import Agent, ParallelRunner
from google.adk.models import Gemini
import asyncio

# Specialized analyzers
malware_analyst = Agent(
    name="MalwareAnalyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Analyze potential malware samples. Focus on capabilities, persistence, and C2.",
    tools=[yara_tool, vt_tool]
)

network_analyst = Agent(
    name="NetworkAnalyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Analyze network traffic and connections. Identify C2, data exfiltration, lateral movement.",
    tools=[abuseipdb_tool]
)

forensic_analyst = Agent(
    name="ForensicAnalyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Analyze system artifacts. Focus on timeline, persistence mechanisms, user activity."
)

async def parallel_analysis(incident_data: str):
    """Run multiple analysts in parallel."""
    runner = ParallelRunner()

    tasks = [
        runner.run_async(malware_analyst, incident_data),
        runner.run_async(network_analyst, incident_data),
        runner.run_async(forensic_analyst, incident_data)
    ]

    results = await asyncio.gather(*tasks)

    return {
        "malware_analysis": results[0].text,
        "network_analysis": results[1].text,
        "forensic_analysis": results[2].text
    }

# Execute
results = asyncio.run(parallel_analysis("Incident data here..."))
```

**3. Supervisor Pattern:**

```python
from google.adk import Agent, Supervisor
from google.adk.models import Gemini

# Worker agents
workers = {
    "malware": malware_analyst,
    "network": network_analyst,
    "forensics": forensic_analyst
}

# Supervisor agent that coordinates workers
supervisor = Supervisor(
    name="IncidentCommander",
    model=Gemini(model="gemini-2.0-flash-exp"),
    workers=workers,
    system_instruction="""You are an incident commander coordinating a security response.

    Available specialists:
    - malware: Analyzes malware samples and suspicious files
    - network: Analyzes network traffic and connections
    - forensics: Analyzes system artifacts and timelines

    Delegate tasks to appropriate specialists and synthesize their findings
    into a comprehensive incident report."""
)

# The supervisor automatically routes to appropriate workers
response = supervisor.run("""
    Incident Alert:
    - Suspicious PowerShell execution detected
    - Outbound connection to known C2 IP
    - New scheduled task created
    - Investigate and provide incident report
""")
```

---

## Security-Focused Agents

### SOC Analyst Agent

```python
from google.adk import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
from google.adk.memory import ConversationMemory

# SOC tools
def query_siem(query: str, time_range: str = "24h") -> dict:
    """Query SIEM for security events."""
    # Implementation - connect to Splunk/Elastic/etc.
    return {"results": [], "count": 0}

def create_ticket(title: str, severity: str, description: str) -> dict:
    """Create incident ticket in ticketing system."""
    # Implementation - connect to ServiceNow/Jira/etc.
    return {"ticket_id": "INC0012345", "status": "created"}

def enrich_alert(alert_id: str) -> dict:
    """Enrich alert with threat intelligence."""
    # Implementation
    return {"enriched": True, "threat_score": 75}

soc_agent = Agent(
    name="SOCAnalyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="""You are a Tier 2 SOC Analyst responsible for:

    1. Alert Triage: Analyze incoming alerts, determine true/false positives
    2. Investigation: Gather context from SIEM, threat intel, and asset inventory
    3. Response: Recommend or execute containment actions
    4. Documentation: Create detailed incident tickets

    Investigation Framework:
    - What happened? (timeline, events)
    - Who/what is affected? (assets, users, data)
    - How did it happen? (attack vector, techniques)
    - What's the impact? (business, security)
    - What actions are needed? (contain, remediate)

    Always reference:
    - MITRE ATT&CK for technique mapping
    - Kill chain stage identification
    - Severity scoring (Critical/High/Medium/Low)""",
    tools=[
        FunctionTool(function=query_siem, description="Query SIEM for events"),
        FunctionTool(function=create_ticket, description="Create incident ticket"),
        FunctionTool(function=enrich_alert, description="Enrich alert with threat intel"),
        vt_tool,
        abuseipdb_tool,
        mitre_tool
    ],
    memory=ConversationMemory(max_messages=50)
)
```

### Threat Hunter Agent

```python
threat_hunter = Agent(
    name="ThreatHunter",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="""You are an advanced threat hunter specializing in:

    1. Hypothesis-Driven Hunting
       - Develop hunting hypotheses based on TTPs
       - Create detection queries to test hypotheses
       - Document findings and refine detections

    2. Anomaly Detection
       - Identify statistical anomalies in logs
       - Baseline normal behavior patterns
       - Flag deviations for investigation

    3. Threat Intelligence Integration
       - Apply IOCs to historical data
       - Hunt for emerging threat actor TTPs
       - Correlate internal data with external intel

    Output Format:
    - Hypothesis: What are you hunting for?
    - Data Sources: What logs/telemetry needed?
    - Detection Logic: Queries, rules, patterns
    - Findings: What was discovered?
    - Recommendations: New detections, mitigations""",
    tools=[
        FunctionTool(function=query_siem, description="Query SIEM for threat hunting"),
        sigma_tool,
        mitre_tool
    ]
)
```

### Malware Reverse Engineer Agent

```python
malware_re_agent = Agent(
    name="MalwareReverseEngineer",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="""You are a malware reverse engineer providing:

    1. Static Analysis
       - File type, headers, sections
       - Strings analysis
       - Import/export analysis
       - Packer/crypter detection

    2. Behavioral Analysis
       - File system operations
       - Registry modifications
       - Network communications
       - Process injection/hollowing

    3. Code Analysis
       - Key function identification
       - Algorithm recognition
       - C2 protocol analysis
       - Encryption/encoding schemes

    4. Intelligence Extraction
       - IOCs (hashes, IPs, domains, URLs)
       - YARA rule generation
       - MITRE ATT&CK mapping
       - Family/variant classification

    Safety: Analyze and explain code behavior but never enhance
    or weaponize malicious functionality.""",
    tools=[
        yara_tool,
        vt_tool,
        mitre_tool,
        FunctionTool(function=parse_pe_headers, description="Parse PE file headers"),
        FunctionTool(function=extract_strings, description="Extract strings from binary"),
    ]
)
```

---

## Memory and State Management

### Conversation Memory

```python
from google.adk.memory import ConversationMemory

memory = ConversationMemory(
    max_messages=100,
    summarize_after=50,  # Auto-summarize older messages
    persist_path="./memory/conversations/"  # Optional persistence
)

agent = Agent(
    name="AnalystWithMemory",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="You are a security analyst...",
    memory=memory
)
```

### Knowledge Base Memory

```python
from google.adk.memory import KnowledgeMemory
from google.adk.retrievers import ChromaRetriever

# Create knowledge base from security docs
knowledge = KnowledgeMemory(
    retriever=ChromaRetriever(
        collection_name="security_knowledge",
        embedding_model="text-embedding-004"
    ),
    sources=[
        "./docs/playbooks/",
        "./docs/procedures/",
        "./docs/threat_intel/"
    ]
)

agent = Agent(
    name="KnowledgeableAnalyst",
    model=Gemini(model="gemini-2.0-flash-exp"),
    system_instruction="Use your knowledge base to answer security questions...",
    memory=knowledge
)
```

### Persistent State

```python
from google.adk.state import StateManager

state = StateManager(
    backend="redis",  # or "sqlite", "firestore"
    connection_string="redis://localhost:6379"
)

# Store investigation state
state.set("investigation_123", {
    "status": "in_progress",
    "assigned_to": "analyst@company.com",
    "findings": [],
    "timeline": []
})

# Retrieve state
inv_state = state.get("investigation_123")
```

---

## Deployment Options

### Local Development

```python
# Simple local execution
if __name__ == "__main__":
    response = agent.run("Your query here")
    print(response.text)
```

### FastAPI Server

```python
# agent_server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google.adk import Agent, Session
from google.adk.models import Gemini

app = FastAPI(title="Security Agent API")

# Initialize agents
agents = {
    "threat_intel": threat_intel_agent,
    "soc_analyst": soc_agent,
}

sessions = {}

class QueryRequest(BaseModel):
    agent_name: str
    query: str
    session_id: str | None = None

class QueryResponse(BaseModel):
    response: str
    session_id: str

@app.post("/query", response_model=QueryResponse)
async def query_agent(request: QueryRequest):
    if request.agent_name not in agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = agents[request.agent_name]

    # Get or create session
    if request.session_id and request.session_id in sessions:
        session = sessions[request.session_id]
    else:
        session = Session()
        session_id = str(uuid.uuid4())
        sessions[session_id] = session

    response = agent.run(request.query, session=session)

    return QueryResponse(
        response=response.text,
        session_id=session_id
    )

@app.get("/agents")
async def list_agents():
    return {"agents": list(agents.keys())}

# Run: uvicorn agent_server:app --reload
```

### Cloud Run Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "agent_server:app", "--host", "0.0.0.0", "--port", "8080"]
```

```bash
# Deploy to Cloud Run
gcloud run deploy security-agents \
    --source . \
    --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars "GOOGLE_API_KEY=$GOOGLE_API_KEY"
```

### Vertex AI Agent Builder

For enterprise deployments, Vertex AI Agent Builder provides a managed platform for deploying and scaling agents.

#### When to Use Agent Builder

| Use Case                  | Agent Builder          | ADK + Cloud Run      |
| ------------------------- | ---------------------- | -------------------- |
| **Rapid prototyping**     | ✅ Visual builder      | Code-first           |
| **Enterprise compliance** | ✅ Built-in governance | Manual setup         |
| **Scaling**               | ✅ Auto-managed        | Configure yourself   |
| **Custom tools**          | Limited                | ✅ Full flexibility  |
| **Cost**                  | Higher (managed)       | Lower (self-managed) |

#### Setting Up Agent Builder

**Step 1: Enable APIs**

```bash
gcloud services enable \
    aiplatform.googleapis.com \
    dialogflow.googleapis.com \
    discoveryengine.googleapis.com
```

**Step 2: Create Agent in Console**

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to **Vertex AI → Agent Builder**
3. Click **Create Agent**
4. Configure:
   - **Name**: `security-analyst-agent`
   - **Region**: Choose your region
   - **Model**: Gemini 2.0 Flash or Pro

**Step 3: Define Tools**

In the Agent Builder UI:

1. Click **Tools** → **Create Tool**
2. Choose tool type:
   - **OpenAPI**: Connect to REST APIs (VirusTotal, AbuseIPDB)
   - **Data Store**: Query your threat intel documents
   - **Code Interpreter**: Run Python analysis

**Step 4: Configure Data Stores (RAG)**

For security knowledge bases:

```bash
# Create data store for threat intel
gcloud alpha discovery-engine data-stores create threat-intel-store \
    --location=global \
    --project=$PROJECT_ID \
    --industry-vertical=generic

# Import documents
gcloud alpha discovery-engine documents import \
    --data-store=threat-intel-store \
    --location=global \
    --source=gs://your-bucket/threat-reports/
```

**Step 5: Connect to ADK Code**

Export your Agent Builder agent for use with ADK:

```python
from google.adk import Agent
from google.adk.integrations import VertexAgentBuilder

# Connect to deployed Agent Builder agent
agent = VertexAgentBuilder.from_agent_id(
    agent_id="projects/your-project/locations/us-central1/agents/security-analyst",
    tools=additional_local_tools  # Combine with local tools
)

# Use like any ADK agent
response = agent.run("Analyze this suspicious IP: 185.220.101.5")
```

#### Monitoring and Observability

Agent Builder integrates with Google Cloud monitoring:

```python
# View agent metrics in Cloud Monitoring
# Metrics available:
# - agent/request_count
# - agent/latency
# - agent/error_count
# - tool/invocation_count

# Set up alerting
gcloud alpha monitoring policies create \
    --display-name="Agent Error Rate" \
    --condition-display-name="High error rate" \
    --condition-filter='metric.type="aiplatform.googleapis.com/agent/error_count"' \
    --condition-threshold-value=10 \
    --condition-threshold-duration=300s
```

#### Hybrid Architecture Pattern

Best practice: Use Agent Builder for orchestration, ADK for custom tools:

```
┌─────────────────────────────────────────────────────────────┐
│                  Vertex AI Agent Builder                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Orchestrator│──│ RAG Store   │──│ Cloud Tools │          │
│  │   Agent     │  │ (Threat     │  │ (BigQuery,  │          │
│  │             │  │  Intel)     │  │  Logging)   │          │
│  └──────┬──────┘  └─────────────┘  └─────────────┘          │
└─────────┼───────────────────────────────────────────────────┘
          │
          │ gRPC/REST
          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ADK Custom Tools                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ YARA        │  │ PE Analysis │  │ Memory      │          │
│  │ Scanner     │  │ Tool        │  │ Forensics   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

---

## Best Practices

### 1. Security Considerations

```python
# Sanitize inputs
def sanitize_query(query: str) -> str:
    """Remove potentially dangerous content."""
    # Remove shell metacharacters
    dangerous_chars = [";", "|", "&", "`", "$", "(", ")"]
    for char in dangerous_chars:
        query = query.replace(char, "")
    return query

# Limit tool capabilities
file_tool = FunctionTool(
    function=safe_file_read,
    description="Read file contents",
    allowed_paths=["/data/", "/logs/"],  # Restrict paths
    max_file_size=10_000_000  # 10MB limit
)

# Rate limiting
from google.adk.middleware import RateLimiter

agent = Agent(
    name="RateLimitedAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    middleware=[
        RateLimiter(requests_per_minute=60)
    ]
)
```

### 2. Error Handling

```python
from google.adk.exceptions import AgentError, ToolError

try:
    response = agent.run(query)
except ToolError as e:
    logger.error(f"Tool execution failed: {e}")
    # Graceful degradation
except AgentError as e:
    logger.error(f"Agent error: {e}")
    # Return error to user
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    # Alert on-call
```

### 3. Logging and Monitoring

```python
import logging
from google.adk.observability import Tracer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Enable tracing
tracer = Tracer(
    service_name="security-agents",
    export_to="cloud_trace"  # or "jaeger", "zipkin"
)

agent = Agent(
    name="TracedAgent",
    model=Gemini(model="gemini-2.0-flash-exp"),
    tracer=tracer
)
```

### 4. Testing

```python
# test_agents.py
import pytest
from unittest.mock import Mock, patch

def test_threat_intel_agent_hash_lookup():
    """Test hash lookup functionality."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 45}}}
        }

        result = query_virustotal("abc123")
        assert result["malicious"] == 45

def test_agent_response_format():
    """Test agent response structure."""
    response = threat_intel_agent.run("Analyze hash: abc123")
    assert response.text is not None
    assert len(response.text) > 0

@pytest.mark.integration
def test_full_analysis_pipeline():
    """Integration test for full analysis."""
    result = incident_pipeline.run("Test incident")
    assert "recommendations" in result.text.lower()
```

---

## Quick Reference

### Basic Agent

```python
from google.adk import Agent, Tool
from google.adk.llms import Gemini

agent = Agent(
    name="security_analyst",
    model=Gemini("gemini-2.0-flash"),
    system_instruction="You are a security analyst."
)
response = agent.run("Analyze this IP: 192.168.1.100")
```

### Define Tools

```python
from pydantic import BaseModel, Field

class IOCInput(BaseModel):
    text: str = Field(description="Text containing IOCs")

@Tool(schema=IOCInput)
def extract_iocs(text: str) -> dict:
    return {"ips": [], "domains": [], "hashes": []}
```

### Multi-Agent Team

```python
from google.adk import Team

team = Team(
    name="security_ops",
    agents=[analyst, responder, reporter],
    workflow="sequential"  # or "parallel", "coordinator"
)
result = team.run("Analyze alert and recommend actions")
```

### Tips

1. Use `gemini-2.0-flash` for speed, `gemini-pro` for complex tasks
2. Define clear Pydantic schemas for tools and outputs
3. Add callbacks for logging and auditing
4. Wrap in try/except for production
5. Use teams for complex multi-step workflows

---

## Resources

- [Google ADK Documentation](https://ai.google.dev/adk)
- [Gemini API Reference](https://ai.google.dev/gemini-api)
- [Vertex AI Agent Builder](https://cloud.google.com/vertex-ai/docs/agents)
- [Google Cloud Security](https://cloud.google.com/security)
- [ADK GitHub Repository](https://github.com/google/adk)

---

**Next**: [Claude Code CLI Guide](./claude-code-cli-guide.md) | [LangChain Integration](../curriculum/ai-security-training-program.md)

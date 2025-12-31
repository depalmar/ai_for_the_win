# LangChain Security Guide

Build production-ready security tools with LangChain — from simple chains to complex multi-agent systems.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Multi-Provider Configuration](#multi-provider-configuration)
4. [Core Concepts](#core-concepts)
5. [Building Security Tools](#building-security-tools)
6. [RAG for Threat Intelligence](#rag-for-threat-intelligence)
7. [Agents and Tools](#agents-and-tools)
8. [LangGraph for Complex Workflows](#langgraph-for-complex-workflows)
9. [Structured Output Parsing](#structured-output-parsing)
10. [Security Best Practices](#security-best-practices)
11. [Testing and Evaluation](#testing-and-evaluation)
12. [Production Deployment](#production-deployment)
13. [When to Use What](#when-to-use-what)

---

## Overview

**LangChain** is a framework for building LLM-powered applications. For security practitioners, it provides:

| Feature | Security Use Case |
|---------|-------------------|
| **Chains** | Multi-step log analysis, IOC extraction pipelines |
| **Agents** | Autonomous threat investigation, IR assistants |
| **RAG** | Query threat intel, runbooks, MITRE ATT&CK |
| **Tools** | Integrate VirusTotal, MISP, Shodan, custom APIs |
| **Memory** | Conversational IR copilots, investigation context |
| **Structured Output** | Reliable JSON for SIEM integration |

### LangChain Ecosystem

```
┌─────────────────────────────────────────────────────────────┐
│                    LangChain Ecosystem                       │
├─────────────────────────────────────────────────────────────┤
│  langchain-core     Core abstractions (messages, prompts)   │
│  langchain          Chains, agents, retrieval               │
│  langchain-community Third-party integrations               │
│  langchain-anthropic Claude integration                     │
│  langchain-openai   OpenAI/GPT integration                  │
│  langchain-google   Gemini integration                      │
│  langgraph          Stateful multi-agent workflows          │
│  langserve          Deploy chains as REST APIs              │
│  langsmith          Tracing, evaluation, monitoring         │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation & Setup

### Basic Installation

```bash
# Core packages
pip install langchain langchain-core

# Provider-specific (install one or more)
pip install langchain-anthropic   # Claude
pip install langchain-openai      # GPT-4
pip install langchain-google-genai # Gemini
pip install langchain-ollama      # Local models

# For RAG
pip install chromadb sentence-transformers

# For agents
pip install langgraph

# For production
pip install langserve langsmith
```

### Environment Setup

```bash
# .env file
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# Optional: LangSmith for tracing
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls__...
LANGCHAIN_PROJECT=security-tools
```

```python
# Load environment variables
from dotenv import load_dotenv
load_dotenv()
```

---

## Multi-Provider Configuration

### Provider-Agnostic Setup

Support multiple LLM providers with a single interface:

```python
import os
from typing import Optional

def get_llm(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.0,
    max_tokens: int = 4096
):
    """
    Get LLM instance for any provider.
    Auto-detects provider from environment if not specified.
    """
    # Auto-detect provider
    if provider is None:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        elif os.environ.get("GOOGLE_API_KEY"):
            provider = "google"
        else:
            provider = "ollama"  # Fallback to local
    
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model or "claude-sonnet-4-20250514",
            temperature=temperature,
            max_tokens=max_tokens
        )
    
    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model or "gpt-4o",
            temperature=temperature,
            max_tokens=max_tokens
        )
    
    elif provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model or "gemini-2.0-flash",
            temperature=temperature,
            max_output_tokens=max_tokens
        )
    
    elif provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model or "llama3.1:8b",
            temperature=temperature,
            num_predict=max_tokens
        )
    
    raise ValueError(f"Unknown provider: {provider}")
```

### Usage

```python
# Auto-detect (uses whichever API key you have)
llm = get_llm()

# Or specify explicitly
llm = get_llm(provider="anthropic", model="claude-sonnet-4-20250514")
llm = get_llm(provider="openai", model="gpt-4o")
llm = get_llm(provider="google", model="gemini-2.0-flash")
llm = get_llm(provider="ollama", model="llama3.1:8b")
```

### Provider Comparison for Security Tasks

| Task | Best Provider | Why |
|------|---------------|-----|
| Long document analysis | Claude | 200K context window |
| Code analysis | Claude or GPT-4o | Strong reasoning |
| Quick triage | Gemini Flash | Fast, cost-effective |
| Sensitive data | Ollama (local) | Data stays on-premise |
| Tool use/agents | Claude or GPT-4o | Better function calling |

---

## Core Concepts

### Messages

LangChain uses a message-based API:

```python
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

messages = [
    SystemMessage(content="You are a security analyst specializing in malware analysis."),
    HumanMessage(content="What are the indicators of a Cobalt Strike beacon?"),
]

response = llm.invoke(messages)
print(response.content)
```

### Prompt Templates

Reusable prompts with variables:

```python
from langchain_core.prompts import ChatPromptTemplate

# Simple template
template = ChatPromptTemplate.from_messages([
    ("system", "You are a security analyst. Analyze threats concisely."),
    ("human", "Analyze this IOC: {ioc}")
])

# Use the template
prompt = template.invoke({"ioc": "185.220.101.5"})
response = llm.invoke(prompt)
```

### Chains (LCEL)

LangChain Expression Language (LCEL) for composable pipelines:

```python
from langchain_core.output_parsers import StrOutputParser

# Simple chain: prompt → LLM → parse
chain = template | llm | StrOutputParser()

# Run it
result = chain.invoke({"ioc": "185.220.101.5"})
print(result)
```

### Batch Processing

Process multiple items efficiently:

```python
# Analyze multiple IOCs in parallel
iocs = [
    {"ioc": "185.220.101.5"},
    {"ioc": "malware.evil.com"},
    {"ioc": "a1b2c3d4e5f6..."},  # hash
]

results = chain.batch(iocs, config={"max_concurrency": 5})
```

### Streaming

For real-time output:

```python
for chunk in chain.stream({"ioc": "185.220.101.5"}):
    print(chunk, end="", flush=True)
```

---

## Building Security Tools

### IOC Extraction Chain

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import List

class IOCExtraction(BaseModel):
    """Extracted indicators of compromise."""
    ips: List[str] = Field(default_factory=list, description="IPv4/IPv6 addresses")
    domains: List[str] = Field(default_factory=list, description="Domain names")
    urls: List[str] = Field(default_factory=list, description="Full URLs")
    hashes: List[str] = Field(default_factory=list, description="MD5/SHA1/SHA256 hashes")
    emails: List[str] = Field(default_factory=list, description="Email addresses")

parser = JsonOutputParser(pydantic_object=IOCExtraction)

ioc_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are an IOC extraction specialist.
Extract all indicators of compromise from the provided text.
Return ONLY indicators actually present in the text - do not invent any.

{format_instructions}"""),
    ("human", "{text}")
])

ioc_chain = (
    ioc_prompt.partial(format_instructions=parser.get_format_instructions())
    | llm
    | parser
)

# Usage
threat_report = """
The attacker used IP 192.168.1.100 to connect to evil.malware.com.
They downloaded payload from http://bad.actor.net/stage2.exe
File hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
Contact: attacker@phishing.org
"""

iocs = ioc_chain.invoke({"text": threat_report})
print(iocs)
# {'ips': ['192.168.1.100'], 'domains': ['evil.malware.com', 'bad.actor.net'], ...}
```

### Log Analysis Chain

```python
from langchain_core.prompts import ChatPromptTemplate

log_analysis_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a security analyst reviewing system logs.
    
For each log entry, determine:
1. Event type (authentication, network, file, process, etc.)
2. Severity (info, low, medium, high, critical)
3. Whether it's suspicious and why
4. Recommended action

Be conservative - only flag truly suspicious activity.
If uncertain, say so rather than guessing."""),
    ("human", """Analyze these log entries:

{logs}

Provide analysis for each entry.""")
])

log_chain = log_analysis_prompt | llm | StrOutputParser()

# Usage
logs = """
[2024-01-15 10:30:00] Failed password for admin from 185.220.101.5 port 22
[2024-01-15 10:30:01] Failed password for admin from 185.220.101.5 port 22
[2024-01-15 10:30:02] Failed password for admin from 185.220.101.5 port 22
[2024-01-15 10:35:00] Accepted publickey for deploy from 10.0.0.50 port 22
"""

analysis = log_chain.invoke({"logs": logs})
print(analysis)
```

### Threat Assessment Chain

```python
from pydantic import BaseModel, Field
from typing import List, Literal

class ThreatAssessment(BaseModel):
    """Structured threat assessment."""
    threat_level: Literal["low", "medium", "high", "critical"] = Field(
        description="Overall threat severity"
    )
    confidence: float = Field(
        ge=0, le=1, description="Confidence in assessment (0-1)"
    )
    threat_type: str = Field(description="Type of threat (malware, phishing, etc.)")
    mitre_tactics: List[str] = Field(
        default_factory=list, description="Relevant MITRE ATT&CK tactics"
    )
    iocs: List[str] = Field(
        default_factory=list, description="Indicators of compromise found"
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Recommended response actions"
    )
    summary: str = Field(description="Brief summary of the threat")

assessment_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a senior threat analyst.
Assess the provided security data and produce a structured threat assessment.

Be precise:
- Only include IOCs actually present in the data
- Map to MITRE ATT&CK tactics when clearly applicable
- Be conservative with threat_level - require strong evidence for "critical"
- Confidence should reflect certainty (0.5 = uncertain, 0.9+ = very confident)

{format_instructions}"""),
    ("human", "{data}")
])

parser = JsonOutputParser(pydantic_object=ThreatAssessment)

assessment_chain = (
    assessment_prompt.partial(format_instructions=parser.get_format_instructions())
    | llm
    | parser
)
```

---

## RAG for Threat Intelligence

### Setting Up a Threat Intel Knowledge Base

```python
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import DirectoryLoader, TextLoader

# 1. Load threat intel documents
loader = DirectoryLoader(
    "./threat_intel/",
    glob="**/*.md",
    loader_cls=TextLoader
)
documents = loader.load()

# 2. Split into chunks
splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200,
    separators=["\n## ", "\n### ", "\n\n", "\n", " "]
)
chunks = splitter.split_documents(documents)

# 3. Create embeddings (local, no API needed)
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2"
)

# 4. Store in vector database
vectorstore = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings,
    persist_directory="./threat_intel_db"
)

print(f"Indexed {len(chunks)} chunks from {len(documents)} documents")
```

### RAG Chain for Threat Intel Queries

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough

# Create retriever
retriever = vectorstore.as_retriever(
    search_type="similarity",
    search_kwargs={"k": 5}
)

# RAG prompt
rag_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a threat intelligence analyst.
Answer questions using ONLY the provided context.
If the context doesn't contain the answer, say "I don't have information about that in my knowledge base."

Do not make up information. Cite which document the information came from when possible.

Context:
{context}"""),
    ("human", "{question}")
])

def format_docs(docs):
    return "\n\n---\n\n".join(
        f"Source: {doc.metadata.get('source', 'Unknown')}\n{doc.page_content}"
        for doc in docs
    )

# RAG chain
rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | rag_prompt
    | llm
    | StrOutputParser()
)

# Usage
response = rag_chain.invoke("What TTPs are associated with APT29?")
print(response)
```

### Hybrid Search (Semantic + Keyword)

```python
from langchain.retrievers import EnsembleRetriever
from langchain_community.retrievers import BM25Retriever

# BM25 for keyword search
bm25_retriever = BM25Retriever.from_documents(chunks)
bm25_retriever.k = 5

# Combine semantic + keyword
ensemble_retriever = EnsembleRetriever(
    retrievers=[retriever, bm25_retriever],
    weights=[0.6, 0.4]  # 60% semantic, 40% keyword
)
```

---

## Agents and Tools

### Defining Custom Tools

```python
from langchain.tools import tool
from langchain_core.tools import ToolException
import requests

@tool
def lookup_ip(ip_address: str) -> str:
    """
    Look up threat intelligence for an IP address.
    Returns reputation data and geolocation.
    
    Args:
        ip_address: IPv4 or IPv6 address to look up
    """
    try:
        # Example: AbuseIPDB lookup (replace with your API)
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": os.environ.get("ABUSEIPDB_API_KEY")},
            params={"ipAddress": ip_address, "maxAgeInDays": 90}
        )
        data = response.json()["data"]
        return f"""
IP: {ip_address}
Abuse Confidence: {data['abuseConfidenceScore']}%
Country: {data['countryCode']}
ISP: {data['isp']}
Reports: {data['totalReports']} in last 90 days
"""
    except Exception as e:
        raise ToolException(f"IP lookup failed: {e}")

@tool
def lookup_hash(file_hash: str) -> str:
    """
    Look up a file hash in VirusTotal.
    
    Args:
        file_hash: MD5, SHA1, or SHA256 hash
    """
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY")}
        )
        if response.status_code == 404:
            return f"Hash {file_hash} not found in VirusTotal"
        
        data = response.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        return f"""
Hash: {file_hash}
Detections: {stats['malicious']}/{sum(stats.values())}
Type: {data.get('type_description', 'Unknown')}
Names: {', '.join(data.get('names', [])[:3])}
"""
    except Exception as e:
        raise ToolException(f"Hash lookup failed: {e}")

@tool
def search_mitre_attack(technique_id: str) -> str:
    """
    Search MITRE ATT&CK for a technique.
    
    Args:
        technique_id: MITRE technique ID (e.g., T1566, T1059.001)
    """
    # Simplified - in production, use MITRE STIX data
    techniques = {
        "T1566": "Phishing - Initial Access via phishing emails",
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell - Execution via PowerShell",
        "T1003": "OS Credential Dumping",
        "T1071": "Application Layer Protocol - C2 communication",
    }
    return techniques.get(
        technique_id.upper(),
        f"Technique {technique_id} not found. Check https://attack.mitre.org"
    )
```

### Creating a ReAct Agent

```python
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate

# Define tools
tools = [lookup_ip, lookup_hash, search_mitre_attack]

# ReAct prompt
react_prompt = PromptTemplate.from_template("""You are a security analyst investigating potential threats.

You have access to these tools:
{tools}

Tool names: {tool_names}

Use this format:

Question: the input question you must answer
Thought: think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (repeat Thought/Action/Action Input/Observation as needed)
Thought: I now know the final answer
Final Answer: the final answer to the original question

Important:
- Verify findings using multiple sources when possible
- Be explicit about confidence levels
- If a tool fails, note it and continue with available information

Question: {input}
{agent_scratchpad}""")

# Create agent
agent = create_react_agent(llm, tools, react_prompt)

# Create executor
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=10,
    handle_parsing_errors=True
)

# Run investigation
result = agent_executor.invoke({
    "input": "Investigate IP 185.220.101.5 - is it malicious?"
})
print(result["output"])
```

### Tool Agent with Memory

```python
from langchain.memory import ConversationBufferWindowMemory

# Memory for conversation context
memory = ConversationBufferWindowMemory(
    memory_key="chat_history",
    return_messages=True,
    k=10  # Keep last 10 exchanges
)

# Update prompt for memory
memory_prompt = PromptTemplate.from_template("""You are a security analyst assistant.

Previous conversation:
{chat_history}

Tools available:
{tools}

Tool names: {tool_names}

Use this format:
Question: the input question
Thought: think about what to do
Action: tool name
Action Input: tool input
Observation: tool result
... (repeat as needed)
Thought: I now know the final answer
Final Answer: your answer

Question: {input}
{agent_scratchpad}""")

# Agent with memory
memory_agent = create_react_agent(llm, tools, memory_prompt)

memory_executor = AgentExecutor(
    agent=memory_agent,
    tools=tools,
    memory=memory,
    verbose=True,
    handle_parsing_errors=True
)
```

---

## LangGraph for Complex Workflows

LangGraph enables stateful, multi-step workflows with conditional logic.

### Installation

```bash
pip install langgraph
```

### Security Triage Workflow

```python
from typing import TypedDict, Literal, Annotated
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# Define state
class TriageState(TypedDict):
    messages: Annotated[list, add_messages]
    alert: dict
    severity: str
    iocs: list
    enrichment: dict
    recommendation: str

# Define nodes
def classify_alert(state: TriageState) -> TriageState:
    """Classify alert severity using LLM."""
    alert = state["alert"]
    
    prompt = f"""Classify this security alert:
    
{alert}

Severity options: low, medium, high, critical

Respond with just the severity level."""
    
    response = llm.invoke(prompt)
    severity = response.content.strip().lower()
    
    return {"severity": severity}

def extract_iocs(state: TriageState) -> TriageState:
    """Extract IOCs from alert."""
    alert = state["alert"]
    
    # Use the IOC extraction chain from earlier
    iocs = ioc_chain.invoke({"text": str(alert)})
    
    return {"iocs": iocs}

def enrich_iocs(state: TriageState) -> TriageState:
    """Enrich IOCs with threat intelligence."""
    iocs = state["iocs"]
    enrichment = {}
    
    for ip in iocs.get("ips", []):
        try:
            enrichment[ip] = lookup_ip.invoke(ip)
        except:
            enrichment[ip] = "Lookup failed"
    
    for hash_val in iocs.get("hashes", []):
        try:
            enrichment[hash_val] = lookup_hash.invoke(hash_val)
        except:
            enrichment[hash_val] = "Lookup failed"
    
    return {"enrichment": enrichment}

def generate_recommendation(state: TriageState) -> TriageState:
    """Generate response recommendation."""
    prompt = f"""Based on this security alert analysis:

Severity: {state['severity']}
IOCs Found: {state['iocs']}
Enrichment Data: {state['enrichment']}

Provide a recommended response action. Be specific and actionable."""
    
    response = llm.invoke(prompt)
    
    return {"recommendation": response.content}

def should_enrich(state: TriageState) -> Literal["enrich", "recommend"]:
    """Decide whether to enrich IOCs based on severity."""
    if state["severity"] in ["high", "critical"]:
        return "enrich"
    return "recommend"

# Build graph
workflow = StateGraph(TriageState)

# Add nodes
workflow.add_node("classify", classify_alert)
workflow.add_node("extract", extract_iocs)
workflow.add_node("enrich", enrich_iocs)
workflow.add_node("recommend", generate_recommendation)

# Add edges
workflow.set_entry_point("classify")
workflow.add_edge("classify", "extract")
workflow.add_conditional_edges(
    "extract",
    should_enrich,
    {
        "enrich": "enrich",
        "recommend": "recommend"
    }
)
workflow.add_edge("enrich", "recommend")
workflow.add_edge("recommend", END)

# Compile
triage_graph = workflow.compile()

# Run
result = triage_graph.invoke({
    "messages": [],
    "alert": {
        "type": "suspicious_login",
        "source_ip": "185.220.101.5",
        "user": "admin",
        "attempts": 50,
        "timestamp": "2024-01-15T10:30:00Z"
    }
})

print(f"Severity: {result['severity']}")
print(f"Recommendation: {result['recommendation']}")
```

### Multi-Agent Investigation

```python
from langgraph.graph import StateGraph, END

class InvestigationState(TypedDict):
    messages: Annotated[list, add_messages]
    incident: dict
    network_findings: str
    endpoint_findings: str
    threat_intel: str
    final_report: str

def network_analyst(state: InvestigationState) -> InvestigationState:
    """Network analysis specialist."""
    prompt = f"""You are a network security analyst.
    
Analyze the network aspects of this incident:
{state['incident']}

Focus on: traffic patterns, C2 indicators, lateral movement, data exfiltration."""
    
    response = llm.invoke(prompt)
    return {"network_findings": response.content}

def endpoint_analyst(state: InvestigationState) -> InvestigationState:
    """Endpoint analysis specialist."""
    prompt = f"""You are an endpoint security analyst.
    
Analyze the endpoint aspects of this incident:
{state['incident']}

Focus on: process execution, file modifications, persistence mechanisms, credential access."""
    
    response = llm.invoke(prompt)
    return {"endpoint_findings": response.content}

def threat_intel_analyst(state: InvestigationState) -> InvestigationState:
    """Threat intelligence specialist."""
    # Use RAG to query threat intel
    query = f"What threat actors or campaigns match: {state['incident']}"
    
    try:
        intel = rag_chain.invoke(query)
    except:
        intel = "No matching threat intelligence found."
    
    return {"threat_intel": intel}

def lead_analyst(state: InvestigationState) -> InvestigationState:
    """Synthesize findings into final report."""
    prompt = f"""You are the lead security analyst.
    
Synthesize these specialist findings into a cohesive incident report:

NETWORK ANALYSIS:
{state['network_findings']}

ENDPOINT ANALYSIS:
{state['endpoint_findings']}

THREAT INTELLIGENCE:
{state['threat_intel']}

Provide:
1. Executive Summary
2. Timeline of Events
3. Impact Assessment
4. Attribution (if possible)
5. Recommended Actions"""
    
    response = llm.invoke(prompt)
    return {"final_report": response.content}

# Build multi-agent graph
investigation = StateGraph(InvestigationState)

# Add specialist nodes
investigation.add_node("network", network_analyst)
investigation.add_node("endpoint", endpoint_analyst)
investigation.add_node("threat_intel", threat_intel_analyst)
investigation.add_node("lead", lead_analyst)

# Parallel analysis then synthesis
investigation.set_entry_point("network")
investigation.add_edge("network", "endpoint")
investigation.add_edge("endpoint", "threat_intel")
investigation.add_edge("threat_intel", "lead")
investigation.add_edge("lead", END)

investigation_graph = investigation.compile()
```

---

## Structured Output Parsing

### Using Pydantic Models

```python
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import re

class SecurityAlert(BaseModel):
    """Structured security alert."""
    alert_id: str = Field(description="Unique alert identifier")
    severity: Literal["low", "medium", "high", "critical"]
    category: str = Field(description="Alert category (malware, phishing, etc.)")
    source_ip: Optional[str] = Field(default=None, description="Source IP if applicable")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP")
    description: str = Field(description="Brief description of the alert")
    recommended_action: str = Field(description="Recommended response action")
    
    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ip(cls, v):
        if v is None:
            return None
        # Basic IP validation
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, v):
            raise ValueError(f"Invalid IP address: {v}")
        return v

parser = PydanticOutputParser(pydantic_object=SecurityAlert)

structured_prompt = ChatPromptTemplate.from_messages([
    ("system", """Parse the security event into structured format.
{format_instructions}

Important: Only include information explicitly present. Use null for missing fields."""),
    ("human", "{event}")
])

structured_chain = (
    structured_prompt.partial(format_instructions=parser.get_format_instructions())
    | llm
    | parser
)
```

### With Instructor (Alternative)

For more reliable structured output:

```bash
pip install instructor
```

```python
import instructor
from anthropic import Anthropic

# Patch the client
client = instructor.from_anthropic(Anthropic())

# Use Pydantic models directly
alert = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": f"Parse this event: {event_data}"}],
    response_model=SecurityAlert
)
```

---

## Security Best Practices

### Input Sanitization

```python
import re

def sanitize_input(text: str) -> str:
    """Remove potential prompt injection attempts."""
    # Remove common injection patterns
    patterns = [
        r"ignore previous instructions",
        r"disregard.*above",
        r"you are now",
        r"new instructions:",
        r"system:",
        r"<\|.*\|>",  # Special tokens
    ]
    
    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE)
    
    return sanitized

# Use in chains
def safe_chain(chain, inputs: dict) -> str:
    sanitized_inputs = {k: sanitize_input(str(v)) for k, v in inputs.items()}
    return chain.invoke(sanitized_inputs)
```

### Output Validation

```python
def validate_iocs(iocs: dict) -> dict:
    """Validate extracted IOCs are real, not hallucinated."""
    import ipaddress
    
    validated = {"ips": [], "domains": [], "hashes": [], "urls": []}
    
    for ip in iocs.get("ips", []):
        try:
            ipaddress.ip_address(ip)
            validated["ips"].append(ip)
        except ValueError:
            pass  # Invalid IP, skip
    
    for domain in iocs.get("domains", []):
        # Basic domain validation
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$', domain):
            validated["domains"].append(domain)
    
    for hash_val in iocs.get("hashes", []):
        # Validate hash format
        if re.match(r'^[a-fA-F0-9]{32}$', hash_val):  # MD5
            validated["hashes"].append(hash_val)
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_val):  # SHA1
            validated["hashes"].append(hash_val)
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_val):  # SHA256
            validated["hashes"].append(hash_val)
    
    return validated
```

### Rate Limiting

```python
from tenacity import retry, stop_after_attempt, wait_exponential
import time

class RateLimitedLLM:
    def __init__(self, llm, requests_per_minute: int = 60):
        self.llm = llm
        self.min_interval = 60 / requests_per_minute
        self.last_call = 0
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=60)
    )
    def invoke(self, *args, **kwargs):
        # Enforce rate limit
        elapsed = time.time() - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_call = time.time()
        return self.llm.invoke(*args, **kwargs)

# Usage
rate_limited_llm = RateLimitedLLM(llm, requests_per_minute=30)
```

### Logging and Audit Trail

```python
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='security_llm_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def audit_llm_call(func):
    """Decorator to log all LLM interactions."""
    def wrapper(*args, **kwargs):
        start_time = datetime.now()
        
        # Log input
        logging.info(json.dumps({
            "event": "llm_call_start",
            "function": func.__name__,
            "timestamp": start_time.isoformat(),
            "input_preview": str(args)[:500]  # Truncate for privacy
        }))
        
        try:
            result = func(*args, **kwargs)
            
            # Log success
            logging.info(json.dumps({
                "event": "llm_call_success",
                "function": func.__name__,
                "duration_ms": (datetime.now() - start_time).total_seconds() * 1000,
                "output_preview": str(result)[:500]
            }))
            
            return result
        except Exception as e:
            # Log failure
            logging.error(json.dumps({
                "event": "llm_call_error",
                "function": func.__name__,
                "error": str(e)
            }))
            raise
    
    return wrapper
```

---

## Testing and Evaluation

### Unit Testing Chains

```python
import pytest
from unittest.mock import Mock, patch

def test_ioc_extraction_chain():
    """Test IOC extraction with known input."""
    test_input = "Malicious IP: 192.168.1.100 contacted evil.com"
    
    result = ioc_chain.invoke({"text": test_input})
    
    assert "192.168.1.100" in result.get("ips", [])
    assert "evil.com" in result.get("domains", [])

def test_ioc_extraction_no_hallucination():
    """Ensure chain doesn't invent IOCs."""
    test_input = "This is a normal log with no indicators."
    
    result = ioc_chain.invoke({"text": test_input})
    
    assert result.get("ips", []) == []
    assert result.get("hashes", []) == []

@patch('langchain_anthropic.ChatAnthropic')
def test_chain_with_mock(mock_llm):
    """Test chain with mocked LLM."""
    mock_llm.return_value.invoke.return_value.content = '{"ips": ["10.0.0.1"]}'
    
    # Test your chain logic without actual API calls
    pass
```

### Evaluation with LangSmith

```python
from langsmith import Client
from langsmith.evaluation import evaluate

# Create evaluation dataset
client = Client()

# Define evaluators
def ioc_accuracy(run, example):
    """Check if extracted IOCs match expected."""
    predicted = run.outputs.get("iocs", {})
    expected = example.outputs.get("iocs", {})
    
    # Calculate precision/recall
    predicted_ips = set(predicted.get("ips", []))
    expected_ips = set(expected.get("ips", []))
    
    if not expected_ips:
        return {"score": 1.0 if not predicted_ips else 0.0}
    
    recall = len(predicted_ips & expected_ips) / len(expected_ips)
    precision = len(predicted_ips & expected_ips) / len(predicted_ips) if predicted_ips else 0
    
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {"score": f1}

# Run evaluation
results = evaluate(
    ioc_chain.invoke,
    data="ioc-extraction-dataset",
    evaluators=[ioc_accuracy]
)
```

---

## Production Deployment

### LangServe API

```python
# server.py
from fastapi import FastAPI
from langserve import add_routes

app = FastAPI(
    title="Security Analysis API",
    description="LLM-powered security analysis tools"
)

# Add chain endpoints
add_routes(app, ioc_chain, path="/ioc-extraction")
add_routes(app, log_chain, path="/log-analysis")
add_routes(app, assessment_chain, path="/threat-assessment")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

```bash
# Run server
python server.py

# Test endpoints
curl -X POST http://localhost:8000/ioc-extraction/invoke \
    -H "Content-Type: application/json" \
    -d '{"input": {"text": "Malicious IP: 192.168.1.100"}}'
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Monitoring with LangSmith

```python
import os

# Enable tracing
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "your-langsmith-key"
os.environ["LANGCHAIN_PROJECT"] = "security-production"

# All chain invocations are now traced
# View at https://smith.langchain.com
```

---

## When to Use What

### Decision Framework

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHEN TO USE LANGCHAIN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  USE LANGCHAIN WHEN:                                            │
│  ✓ Building multi-step pipelines                                │
│  ✓ Need RAG (retrieval + generation)                            │
│  ✓ Building agents with tools                                   │
│  ✓ Want provider flexibility                                    │
│  ✓ Need conversation memory                                     │
│  ✓ Deploying as API (LangServe)                                 │
│                                                                 │
│  USE DIRECT API WHEN:                                           │
│  ✓ Simple single prompts                                        │
│  ✓ Maximum control needed                                       │
│  ✓ Minimal dependencies required                                │
│  ✓ Provider-specific features                                   │
│                                                                 │
│  USE INSTRUCTOR WHEN:                                           │
│  ✓ Structured output is critical                                │
│  ✓ Need validation + retries                                    │
│  ✓ Pydantic integration                                         │
│                                                                 │
│  USE LANGGRAPH WHEN:                                            │
│  ✓ Complex stateful workflows                                   │
│  ✓ Conditional branching                                        │
│  ✓ Multi-agent coordination                                     │
│  ✓ Human-in-the-loop patterns                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Comparison Table

| Feature | LangChain | Direct API | Instructor | LangGraph |
|---------|-----------|------------|------------|-----------|
| Learning curve | Medium | Low | Low | High |
| Flexibility | High | Highest | Medium | Very High |
| Provider switching | Easy | Manual | Easy | Easy |
| RAG support | Built-in | Manual | N/A | Via LangChain |
| Agents/Tools | Built-in | Manual | N/A | Built-in |
| Structured output | Good | Manual | Best | Via LangChain |
| Stateful workflows | Basic | Manual | N/A | Best |
| Production deploy | LangServe | FastAPI | FastAPI | LangServe |

---

## Resources

### Official Documentation
- [LangChain Docs](https://python.langchain.com/docs/)
- [LangGraph Docs](https://langchain-ai.github.io/langgraph/)
- [LangSmith](https://docs.smith.langchain.com/)
- [LangServe](https://python.langchain.com/docs/langserve)

### Course Labs Using LangChain
- [Lab 04: LLM Log Analysis](../../labs/lab04-llm-log-analysis/) - Chains, prompts
- [Lab 05: Threat Intel Agent](../../labs/lab05-threat-intel-agent/) - Agents, tools
- [Lab 06: Security RAG](../../labs/lab06-security-rag/) - RAG, embeddings
- [Lab 10: IR Copilot](../../labs/lab10-ir-copilot/) - Memory, conversation

### Related Guides
- [Structured Output Parsing](./structured-output-parsing.md)
- [Prompt Injection Defense](./prompt-injection-defense.md)
- [LLM Evaluation & Testing](./llm-evaluation-testing.md)
- [Embeddings and Vectors](./embeddings-and-vectors.md)

---

**Next**: [Google ADK Guide](./google-adk-guide.md) | [LLM Provider Comparison](./llm-provider-comparison.md)

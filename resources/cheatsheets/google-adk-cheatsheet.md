# Google ADK (Agent Development Kit) Cheat Sheet

Quick reference for building agents with Google ADK.

---

## Installation

```bash
pip install google-adk
```

---

## Basic Agent

```python
from google.adk import Agent, Tool
from google.adk.llms import Gemini

# Create agent
agent = Agent(
    name="security_analyst",
    model=Gemini("gemini-2.0-flash"),
    system_instruction="You are a security analyst assistant."
)

# Run
response = agent.run("Analyze this IP: 192.168.1.100")
print(response.content)
```

---

## Define Tools

```python
from google.adk import Tool
from pydantic import BaseModel, Field

class IOCInput(BaseModel):
    text: str = Field(description="Text containing IOCs")

@Tool(schema=IOCInput)
def extract_iocs(text: str) -> dict:
    """Extract indicators of compromise from text."""
    # Implementation
    return {"ips": [], "domains": [], "hashes": []}

# Add to agent
agent = Agent(
    name="ioc_extractor",
    model=Gemini("gemini-2.0-flash"),
    tools=[extract_iocs]
)
```

---

## Multi-Agent System

```python
from google.adk import Agent, Team

# Specialist agents
analyst = Agent(
    name="analyst",
    model=Gemini("gemini-2.0-flash"),
    system_instruction="Analyze security data and identify threats."
)

responder = Agent(
    name="responder",
    model=Gemini("gemini-2.0-flash"),
    system_instruction="Recommend incident response actions."
)

reporter = Agent(
    name="reporter",
    model=Gemini("gemini-2.0-flash"),
    system_instruction="Generate security reports."
)

# Create team
security_team = Team(
    name="security_operations",
    agents=[analyst, responder, reporter],
    coordinator_instructions="""
    Route tasks appropriately:
    - Analysis tasks → analyst
    - Response planning → responder
    - Report generation → reporter
    """
)

# Run team
result = security_team.run("Analyze this alert and recommend actions")
```

---

## Memory & Context

```python
from google.adk.memory import ConversationMemory

# With memory
agent = Agent(
    name="analyst",
    model=Gemini("gemini-2.0-flash"),
    memory=ConversationMemory(max_turns=20)
)

# Conversation
agent.run("What is APT29?")
agent.run("What TTPs do they use?")  # Remembers context
```

---

## Structured Output

```python
from pydantic import BaseModel

class ThreatAssessment(BaseModel):
    threat_level: str
    confidence: float
    recommendations: list[str]

agent = Agent(
    name="assessor",
    model=Gemini("gemini-2.0-flash"),
    output_schema=ThreatAssessment
)

result = agent.run("Assess this threat: ...")
# result.content is ThreatAssessment object
```

---

## Async Operations

```python
import asyncio

async def analyze_multiple(items: list[str]):
    agent = Agent(
        name="analyzer",
        model=Gemini("gemini-2.0-flash")
    )

    tasks = [agent.arun(f"Analyze: {item}") for item in items]
    results = await asyncio.gather(*tasks)
    return results

# Run
results = asyncio.run(analyze_multiple(["item1", "item2", "item3"]))
```

---

## Callbacks & Hooks

```python
from google.adk import Agent, Callback

class AuditCallback(Callback):
    def on_tool_start(self, tool_name: str, inputs: dict):
        print(f"[AUDIT] Tool: {tool_name}, Inputs: {inputs}")

    def on_tool_end(self, tool_name: str, output: str):
        print(f"[AUDIT] Tool: {tool_name} completed")

agent = Agent(
    name="audited_agent",
    model=Gemini("gemini-2.0-flash"),
    callbacks=[AuditCallback()]
)
```

---

## Error Handling

```python
from google.adk.exceptions import AgentError, ToolError

try:
    result = agent.run(query)
except ToolError as e:
    print(f"Tool failed: {e.tool_name} - {e.message}")
except AgentError as e:
    print(f"Agent error: {e}")
```

---

## Common Patterns

### Security Analyst Agent
```python
tools = [
    extract_iocs,
    lookup_hash,
    check_ip_reputation,
    search_mitre_attack
]

analyst = Agent(
    name="security_analyst",
    model=Gemini("gemini-2.0-flash"),
    tools=tools,
    system_instruction="""
    You are a security analyst. When analyzing threats:
    1. Extract all IOCs
    2. Look up reputation data
    3. Map to MITRE ATT&CK
    4. Provide recommendations
    """
)
```

### Incident Response Team
```python
team = Team(
    name="ir_team",
    agents=[triage_agent, analysis_agent, containment_agent],
    workflow="sequential"  # or "parallel", "coordinator"
)
```

---

## Tips

1. **Use specific models** - gemini-2.0-flash for speed, pro for complex tasks
2. **Define clear schemas** - Pydantic models for tools and outputs
3. **Add callbacks** - For logging, monitoring, and auditing
4. **Handle errors** - Wrap in try/except for production
5. **Use teams** - For complex multi-step workflows

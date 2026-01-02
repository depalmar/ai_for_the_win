# AI Agent Architectures for Security

A comprehensive guide to AI agent patterns and when to use them for security operations.

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        AI AGENT ARCHITECTURE GUIDE                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   🔄 ReAct          │  📋 Plan-Execute   │  🔀 LangGraph     │  👥 Multi-Agent ║
║   Think→Act→Obs    │  Plan→Execute      │  State Machine   │  Team Roles    ║
║   Simple tasks     │  Complex tasks     │  Workflows       │  SOC automation║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## Quick Reference: Which Agent Pattern?

| Use Case | Recommended Pattern | Why |
|----------|---------------------|-----|
| IOC enrichment | **ReAct** | Simple tool calls, quick iteration |
| Alert triage | **ReAct** or **Tool-calling** | Straightforward classification |
| Incident investigation | **Plan-and-Execute** | Complex, multi-step reasoning |
| IR playbook automation | **LangGraph** | Conditional workflows, human checkpoints |
| SOC automation | **Multi-Agent** | Specialized roles (triage, hunting, response) |
| Threat hunting | **Plan-and-Execute** | Requires upfront hypothesis planning |
| Report generation | **ReAct** | Gather data, then synthesize |
| Continuous monitoring | **LangGraph** | Long-running, stateful workflows |

---

## 1. ReAct Agents (Reason + Act)

The most common pattern. Agent thinks, acts, observes, repeats.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    ReAct Loop                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │  THINK   │───▶│   ACT    │───▶│ OBSERVE  │──┐       │
│  │          │    │          │    │          │  │       │
│  │ "I need  │    │ Call     │    │ "Tool    │  │       │
│  │  to look │    │ tool     │    │  returned│  │       │
│  │  up IP"  │    │          │    │  data"   │  │       │
│  └──────────┘    └──────────┘    └──────────┘  │       │
│       ▲                                        │       │
│       └────────────────────────────────────────┘       │
│                    (repeat until done)                  │
│                                                         │
│  ┌──────────────────────────────────────────────┐      │
│  │                  ANSWER                       │      │
│  │  "Based on my investigation, this IP is..."  │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Security Use Cases

- **IOC Enrichment**: Look up IPs, domains, hashes across multiple sources
- **Alert Triage**: Analyze alert, check context, classify severity
- **Log Analysis**: Query logs, identify patterns, summarize findings

### Code Example

```python
from langchain.agents import create_react_agent, AgentExecutor
from langchain_anthropic import ChatAnthropic
from langchain.tools import Tool
from langchain import hub

# Define security tools
tools = [
    Tool(
        name="lookup_ip",
        func=lambda ip: virustotal_lookup(ip),
        description="Look up IP reputation in VirusTotal"
    ),
    Tool(
        name="query_logs",
        func=lambda query: siem_query(query),
        description="Query SIEM logs"
    ),
    Tool(
        name="check_asset",
        func=lambda host: asset_inventory(host),
        description="Get asset information"
    ),
]

# Create ReAct agent
llm = ChatAnthropic(model="claude-sonnet-4-20250514")
prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm, tools, prompt)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=10,
    handle_parsing_errors=True
)

# Run investigation
result = executor.invoke({
    "input": "Investigate IP 192.168.1.100 for potential C2 activity"
})
```

### Pros & Cons

| Pros | Cons |
|------|------|
| ✅ Simple to implement | ❌ Can get stuck in loops |
| ✅ Good for straightforward tasks | ❌ No upfront planning |
| ✅ Well-documented pattern | ❌ May use tools inefficiently |
| ✅ Works with any LLM | ❌ Hard to debug complex reasoning |

---

## 2. Plan-and-Execute Agents

Agent creates a plan first, then executes step-by-step.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│                Plan-and-Execute                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────────────────────────────┐      │
│  │              PLANNING PHASE                   │      │
│  │                                               │      │
│  │  Task: "Investigate potential data breach"   │      │
│  │                                               │      │
│  │  Plan:                                        │      │
│  │  1. Identify affected systems                 │      │
│  │  2. Query logs for suspicious activity        │      │
│  │  3. Check for data exfiltration indicators    │      │
│  │  4. Identify compromised accounts             │      │
│  │  5. Generate timeline                         │      │
│  │  6. Create incident report                    │      │
│  └──────────────────────────────────────────────┘      │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────┐      │
│  │            EXECUTION PHASE                    │      │
│  │                                               │      │
│  │  Step 1: ████████████ Complete               │      │
│  │  Step 2: ████████░░░░ In Progress            │      │
│  │  Step 3: ░░░░░░░░░░░░ Pending                │      │
│  │  ...                                          │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Security Use Cases

- **Incident Investigation**: Complex investigations requiring structured approach
- **Threat Hunting**: Hypothesis-driven hunting with planned queries
- **Compliance Audits**: Systematic checks across systems
- **Forensic Analysis**: Structured evidence collection

### Code Example

```python
from langchain.agents import AgentExecutor
from langchain_experimental.plan_and_execute import (
    PlanAndExecute, 
    load_agent_executor, 
    load_chat_planner
)
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

# Create planner and executor
planner = load_chat_planner(llm)
executor = load_agent_executor(llm, tools, verbose=True)

# Create Plan-and-Execute agent
agent = PlanAndExecute(
    planner=planner,
    executor=executor,
    verbose=True
)

# Run complex investigation
result = agent.run("""
Investigate potential data breach:
- User 'jsmith' account may be compromised
- Suspicious after-hours activity detected
- Possible data exfiltration to external IP
""")
```

### Pros & Cons

| Pros | Cons |
|------|------|
| ✅ Better for complex tasks | ❌ Planning overhead |
| ✅ More predictable execution | ❌ Plan may become stale |
| ✅ Easier to audit/explain | ❌ Less adaptive to surprises |
| ✅ Can parallelize steps | ❌ More complex implementation |

---

## 3. LangGraph State Machines

Stateful workflows with conditional branching and human-in-the-loop.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│              LangGraph Workflow                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │  START  │────▶│   TRIAGE    │────▶│  SEVERITY?  │   │
│  └─────────┘     └─────────────┘     └─────────────┘   │
│                                             │           │
│                    ┌────────────────────────┼───────┐   │
│                    │                        │       │   │
│                    ▼                        ▼       ▼   │
│            ┌──────────────┐    ┌───────┐  ┌───────┐    │
│            │ AUTO-CONTAIN │    │ ALERT │  │  LOG  │    │
│            │  (Critical)  │    │(High) │  │ (Low) │    │
│            └──────────────┘    └───────┘  └───────┘    │
│                    │                │                   │
│                    ▼                ▼                   │
│            ┌──────────────────────────┐                │
│            │    HUMAN APPROVAL?       │◀───────────┐   │
│            └──────────────────────────┘            │   │
│                    │                               │   │
│          ┌────────┴────────┐                      │   │
│          ▼                 ▼                      │   │
│    ┌──────────┐     ┌──────────┐                 │   │
│    │ APPROVED │     │ REJECTED │─────────────────┘   │
│    └──────────┘     └──────────┘                     │
│          │                                           │
│          ▼                                           │
│    ┌──────────┐     ┌──────────┐                    │
│    │ EXECUTE  │────▶│   END    │                    │
│    └──────────┘     └──────────┘                    │
│                                                      │
└─────────────────────────────────────────────────────────┘
```

### Security Use Cases

- **IR Playbooks**: Automated response with approval gates
- **Alert Workflows**: Escalation paths based on severity
- **Continuous Monitoring**: Long-running detection pipelines
- **Approval Workflows**: Human-in-the-loop for critical actions

### Code Example

```python
from typing import Annotated, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_anthropic import ChatAnthropic

# Define state
class IRState(TypedDict):
    messages: Annotated[list, add_messages]
    alert: dict
    severity: str
    containment_approved: bool
    actions_taken: list

# Define nodes
def triage_alert(state: IRState) -> IRState:
    """Analyze alert and determine severity."""
    llm = ChatAnthropic(model="claude-sonnet-4-20250514")
    
    response = llm.invoke(f"""
    Analyze this security alert and classify severity as 
    CRITICAL, HIGH, MEDIUM, or LOW:
    
    {state['alert']}
    """)
    
    # Parse severity from response
    severity = parse_severity(response.content)
    return {"severity": severity}

def auto_contain(state: IRState) -> IRState:
    """Automatic containment for critical threats."""
    actions = []
    if state["severity"] == "CRITICAL":
        actions.append("Isolated affected host")
        actions.append("Blocked malicious IP at firewall")
        actions.append("Disabled compromised account")
    return {"actions_taken": actions}

def request_approval(state: IRState) -> IRState:
    """Request human approval for containment."""
    # In production, this would integrate with Slack/Teams/PagerDuty
    print(f"🚨 Approval required for: {state['actions_taken']}")
    return state

def execute_response(state: IRState) -> IRState:
    """Execute approved response actions."""
    for action in state["actions_taken"]:
        print(f"✅ Executing: {action}")
    return state

# Define routing logic
def route_by_severity(state: IRState) -> str:
    if state["severity"] == "CRITICAL":
        return "auto_contain"
    elif state["severity"] == "HIGH":
        return "alert_analyst"
    else:
        return "log_only"

def check_approval(state: IRState) -> str:
    if state.get("containment_approved", False):
        return "execute"
    return "wait_approval"

# Build graph
workflow = StateGraph(IRState)

# Add nodes
workflow.add_node("triage", triage_alert)
workflow.add_node("auto_contain", auto_contain)
workflow.add_node("request_approval", request_approval)
workflow.add_node("execute", execute_response)

# Add edges
workflow.set_entry_point("triage")
workflow.add_conditional_edges(
    "triage",
    route_by_severity,
    {
        "auto_contain": "auto_contain",
        "alert_analyst": END,
        "log_only": END
    }
)
workflow.add_edge("auto_contain", "request_approval")
workflow.add_conditional_edges(
    "request_approval",
    check_approval,
    {
        "execute": "execute",
        "wait_approval": "request_approval"
    }
)
workflow.add_edge("execute", END)

# Compile
app = workflow.compile()

# Run workflow
result = app.invoke({
    "messages": [],
    "alert": {"type": "ransomware", "host": "workstation-01"},
    "severity": "",
    "containment_approved": False,
    "actions_taken": []
})
```

### Pros & Cons

| Pros | Cons |
|------|------|
| ✅ Explicit control flow | ❌ More complex to design |
| ✅ Human-in-the-loop built-in | ❌ Requires upfront workflow design |
| ✅ Stateful (survives restarts) | ❌ Steeper learning curve |
| ✅ Great for compliance/audit | ❌ Less flexible than ReAct |

---

## 4. Multi-Agent Systems

Multiple specialized agents working together.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│                 Multi-Agent SOC Team                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │                  ORCHESTRATOR                      │ │
│  │           (Coordinates all agents)                 │ │
│  └───────────────────────────────────────────────────┘ │
│           │              │              │               │
│           ▼              ▼              ▼               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │
│  │   TRIAGE    │ │   HUNTER    │ │  RESPONDER  │      │
│  │    AGENT    │ │    AGENT    │ │    AGENT    │      │
│  ├─────────────┤ ├─────────────┤ ├─────────────┤      │
│  │ • Classify  │ │ • Hunt for  │ │ • Execute   │      │
│  │   alerts    │ │   threats   │ │   playbooks │      │
│  │ • Prioritize│ │ • Correlate │ │ • Contain   │      │
│  │ • Escalate  │ │   events    │ │ • Remediate │      │
│  └─────────────┘ └─────────────┘ └─────────────┘      │
│           │              │              │               │
│           ▼              ▼              ▼               │
│  ┌───────────────────────────────────────────────────┐ │
│  │              SHARED MEMORY / STATE                 │ │
│  │    (Findings, IOCs, Timeline, Actions Taken)      │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Security Use Cases

- **SOC Automation**: Triage, hunting, response agents
- **Red vs Blue**: Attacker simulation vs defender agents
- **Compliance**: Auditor, remediator, reporter agents
- **Threat Intel**: Collector, analyzer, disseminator agents

### Code Example (CrewAI)

```python
from crewai import Agent, Task, Crew, Process
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

# Define specialized agents
triage_agent = Agent(
    role="Security Triage Analyst",
    goal="Quickly classify and prioritize security alerts",
    backstory="""You are a Tier 1 SOC analyst with expertise in 
    alert triage. You efficiently classify alerts by severity and 
    determine which require immediate attention.""",
    llm=llm,
    tools=[alert_lookup_tool, asset_lookup_tool]
)

hunter_agent = Agent(
    role="Threat Hunter",
    goal="Proactively search for indicators of compromise",
    backstory="""You are an experienced threat hunter who 
    specializes in finding hidden threats that evade automated 
    detection. You use hypothesis-driven hunting techniques.""",
    llm=llm,
    tools=[siem_query_tool, ti_lookup_tool, endpoint_query_tool]
)

responder_agent = Agent(
    role="Incident Responder",
    goal="Contain and remediate security incidents",
    backstory="""You are a senior incident responder who 
    executes containment and remediation actions. You follow 
    established playbooks while adapting to unique situations.""",
    llm=llm,
    tools=[containment_tool, remediation_tool, ticket_tool]
)

# Define tasks
triage_task = Task(
    description="Analyze alert {alert_id} and classify severity",
    expected_output="Severity classification with justification",
    agent=triage_agent
)

hunt_task = Task(
    description="Hunt for related IOCs based on triage findings",
    expected_output="List of related IOCs and affected systems",
    agent=hunter_agent,
    context=[triage_task]  # Uses output from triage
)

respond_task = Task(
    description="Execute appropriate response actions",
    expected_output="List of containment/remediation actions taken",
    agent=responder_agent,
    context=[triage_task, hunt_task]  # Uses both outputs
)

# Create crew
soc_crew = Crew(
    agents=[triage_agent, hunter_agent, responder_agent],
    tasks=[triage_task, hunt_task, respond_task],
    process=Process.sequential,  # or Process.hierarchical
    verbose=True
)

# Execute
result = soc_crew.kickoff(inputs={"alert_id": "ALERT-2024-001"})
```

### Pros & Cons

| Pros | Cons |
|------|------|
| ✅ Specialized expertise | ❌ Coordination overhead |
| ✅ Parallel processing | ❌ More API calls (cost) |
| ✅ Mirrors real teams | ❌ Complex to debug |
| ✅ Scalable | ❌ Potential for conflicts |

---

## 5. Tool-Calling Agents

Simple function-calling without complex reasoning loops.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│              Tool-Calling Agent                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  User: "Check if 192.168.1.100 is malicious"           │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────┐      │
│  │              LLM DECIDES                      │      │
│  │    "I should call the lookup_ip tool"        │      │
│  └──────────────────────────────────────────────┘      │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────┐      │
│  │           TOOL EXECUTION                      │      │
│  │    lookup_ip("192.168.1.100")                │      │
│  │    → {"malicious": true, "score": 85}        │      │
│  └──────────────────────────────────────────────┘      │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────┐      │
│  │              LLM RESPONDS                     │      │
│  │    "This IP is malicious with score 85..."   │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Code Example

```python
from anthropic import Anthropic

client = Anthropic()

# Define tools
tools = [
    {
        "name": "lookup_ip",
        "description": "Look up threat intelligence for an IP address",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "query_logs",
        "description": "Query SIEM logs with a search query",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "hours": {"type": "integer", "description": "Hours to search back"}
            },
            "required": ["query"]
        }
    }
]

# Tool execution functions
def execute_tool(name: str, inputs: dict) -> str:
    if name == "lookup_ip":
        return virustotal_lookup(inputs["ip"])
    elif name == "query_logs":
        return siem_query(inputs["query"], inputs.get("hours", 24))
    return "Unknown tool"

# Agent loop
def run_agent(user_message: str) -> str:
    messages = [{"role": "user", "content": user_message}]
    
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            tools=tools,
            messages=messages
        )
        
        # Check if model wants to use a tool
        if response.stop_reason == "tool_use":
            # Execute each tool call
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            
            # Add assistant message and tool results
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            # Model is done, return final response
            return response.content[0].text

# Use the agent
result = run_agent("Is IP 192.168.1.100 malicious? Check our logs too.")
```

---

## 6. Security Guardrails for Agents

### Critical Safety Measures

```
┌─────────────────────────────────────────────────────────┐
│              AGENT SAFETY GUARDRAILS                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🔒 INPUT VALIDATION                                    │
│     • Sanitize all user inputs                          │
│     • Validate IOC formats before lookups               │
│     • Prevent prompt injection                          │
│                                                         │
│  ⚠️ ACTION LIMITS                                       │
│     • Rate limit tool calls                             │
│     • Require approval for destructive actions          │
│     • Set maximum iterations                            │
│                                                         │
│  📝 AUDIT LOGGING                                       │
│     • Log all tool calls and results                    │
│     • Track agent reasoning                             │
│     • Maintain decision trail                           │
│                                                         │
│  🚫 RESTRICTED ACTIONS                                  │
│     • Never auto-delete/quarantine without approval     │
│     • Never auto-block IPs without verification         │
│     • Never execute arbitrary code                      │
│                                                         │
│  ✅ HUMAN-IN-THE-LOOP                                   │
│     • Approval gates for critical actions               │
│     • Analyst review for high-confidence findings       │
│     • Escalation paths for uncertainty                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Implementation

```python
from typing import Callable
from functools import wraps
import logging

# Setup audit logging
audit_logger = logging.getLogger("agent_audit")

def require_approval(action_type: str):
    """Decorator requiring human approval for sensitive actions."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Log the attempted action
            audit_logger.info(f"Action requested: {action_type} - {args}, {kwargs}")
            
            # In production, this would integrate with approval system
            if action_type in ["block_ip", "isolate_host", "disable_account"]:
                approval = request_human_approval(action_type, args, kwargs)
                if not approval:
                    audit_logger.warning(f"Action denied: {action_type}")
                    return {"status": "denied", "reason": "Approval required"}
            
            result = func(*args, **kwargs)
            audit_logger.info(f"Action completed: {action_type} - {result}")
            return result
        return wrapper
    return decorator

@require_approval("block_ip")
def block_ip_at_firewall(ip: str) -> dict:
    """Block IP - requires approval."""
    # Implementation
    pass

@require_approval("isolate_host")  
def isolate_host(hostname: str) -> dict:
    """Isolate host from network - requires approval."""
    # Implementation
    pass

# Rate limiting
from functools import lru_cache
import time

class RateLimiter:
    def __init__(self, calls_per_minute: int = 30):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    def check(self) -> bool:
        now = time.time()
        self.calls = [c for c in self.calls if now - c < 60]
        if len(self.calls) >= self.calls_per_minute:
            return False
        self.calls.append(now)
        return True

rate_limiter = RateLimiter(calls_per_minute=30)

def rate_limited_tool_call(tool_func: Callable, *args, **kwargs):
    if not rate_limiter.check():
        raise Exception("Rate limit exceeded - wait before making more tool calls")
    return tool_func(*args, **kwargs)
```

---

## Comparison Summary

| Pattern | Complexity | Best For | Autonomy Level |
|---------|------------|----------|----------------|
| **Tool-Calling** | Low | Single-step enrichment | Low |
| **ReAct** | Medium | Simple investigations | Medium |
| **Plan-Execute** | Medium-High | Complex investigations | Medium |
| **LangGraph** | High | Workflows with approvals | Configurable |
| **Multi-Agent** | High | Full SOC automation | High (with guards) |

---

## Decision Flowchart

```
                    START
                      │
                      ▼
            ┌─────────────────┐
            │ Single tool     │──Yes──▶ Tool-Calling
            │ call needed?    │
            └─────────────────┘
                      │ No
                      ▼
            ┌─────────────────┐
            │ Simple, linear  │──Yes──▶ ReAct
            │ task?           │
            └─────────────────┘
                      │ No
                      ▼
            ┌─────────────────┐
            │ Complex task    │──Yes──▶ Plan-and-Execute
            │ needs planning? │
            └─────────────────┘
                      │ No
                      ▼
            ┌─────────────────┐
            │ Needs approval  │──Yes──▶ LangGraph
            │ gates/workflow? │
            └─────────────────┘
                      │ No
                      ▼
            ┌─────────────────┐
            │ Multiple        │──Yes──▶ Multi-Agent
            │ specializations?│
            └─────────────────┘
```

---

## Related Resources

- [Lab 05: Threat Intel Agent](../labs/lab05-threat-intel-agent/) - Build a ReAct agent
- [Lab 10: IR Copilot](../labs/lab10-ir-copilot/) - Agent with human-in-the-loop
- [LangChain Guide](../setup/guides/langchain-guide.md) - Comprehensive LangChain/LangGraph guide
- [Security Agent Template](../templates/agents/security_agent_template.py) - Reusable agent code
- [Workshop 7: Multi-Agent](../setup/guides/workshops-guide.md#workshop-7-multi-agent-security-systems) - Hands-on multi-agent lab

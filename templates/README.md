# Templates

Production-ready templates for building AI-powered security tools.

## Directory Structure

```
templates/
├── README.md                           # This file
├── agents/
│   ├── security_agent_template.py      # LangChain security agent template
│   └── rag_agent_template.py           # RAG agent for security docs
├── n8n/
│   ├── README.md                       # n8n workflow documentation
│   ├── ioc_enrichment_workflow.json    # IOC enrichment automation
│   └── alert_triage_workflow.json      # AI alert triage workflow
├── prompts/
│   └── security_prompts.md             # Reusable prompt templates
├── integrations/
│   └── siem_integrations.py            # SIEM API integrations
└── mcp-servers/
    ├── threat-intel-mcp-server.py      # Threat intel MCP server
    └── virustotal-mcp-server.py        # VirusTotal integration
```

## Available Templates

### Agent Templates

#### Security Agent (LangChain)

**File**: `agents/security_agent_template.py`

A production-ready template for building security analysis agents using LangChain.

**Features**:
- ReAct agent pattern implementation
- Tool integration (IP lookup, domain analysis, log query)
- Configurable via dataclass
- Error handling and retry logic

**Usage**:
```python
from security_agent_template import SecurityAgent, AgentConfig

config = AgentConfig(name="InvestigationAgent", verbose=True)
agent = SecurityAgent(config)
result = agent.run("Analyze this IP: 185.143.223.47")
```

#### RAG Agent

**File**: `agents/rag_agent_template.py`

Build knowledge bases for security documentation with semantic search.

**Features**:
- Document loading (Markdown, JSON)
- ChromaDB vector storage
- Semantic search
- LLM-powered Q&A

### n8n Automation Workflows

Ready-to-import n8n workflows for security automation.

#### IOC Enrichment
**File**: `n8n/ioc_enrichment_workflow.json`

Automatically enriches IOCs from VirusTotal, AbuseIPDB, and uses AI for summarization.

#### Alert Triage
**File**: `n8n/alert_triage_workflow.json`

AI-powered alert triage with priority scoring and automatic escalation.

**See**: `n8n/README.md` for full documentation and setup instructions.

### Prompt Templates

**File**: `prompts/security_prompts.md`

Reusable prompt templates for common security AI tasks:

- Log Analysis (parsing, threat detection)
- IOC Analysis (IP, domain, hash)
- Incident Response (triage, summaries)
- Vulnerability Analysis (CVE, prioritization)
- YARA Rule Generation
- Report Generation

### SIEM Integrations

**File**: `integrations/siem_integrations.py`

Integration templates for common SIEM platforms:

- **Elasticsearch** - REST API client
- **Elasticsearch/OpenSearch** - Search and alerts
- **Microsoft Sentinel** - KQL queries and incidents
- **Generic Interface** - Abstract SIEM interface

### MCP Servers

Model Context Protocol (MCP) servers for Claude integration.

#### Threat Intel MCP Server
**File**: `mcp-servers/threat-intel-mcp-server.py`

#### VirusTotal MCP Server
**File**: `mcp-servers/virustotal-mcp-server.py`

## Quick Start

### 1. Copy and Customize

```bash
# Copy template to your project
cp templates/agents/security_agent_template.py my_project/agent.py

# Edit to customize for your use case
```

### 2. Install Dependencies

```bash
pip install langchain langchain-anthropic chromadb python-dotenv
```

### 3. Configure Environment

```bash
# Create .env file
echo "ANTHROPIC_API_KEY=your-key-here" > .env
```

### 4. Run

```python
from agent import SecurityAgent

agent = SecurityAgent()
agent.run("Your query here")
```

## Integration Examples

### Combining Templates

```python
# Use SIEM integration with security agent
from integrations.siem_integrations import SIEMInterface
from agents.security_agent_template import SecurityAgent

# Create SIEM client
siem = SIEMInterface("elastic", host="elastic.local")

# Get alerts and investigate with agent
alerts = siem.get_alerts(severity="high")
agent = SecurityAgent()

for alert in alerts:
    result = agent.run(f"Investigate alert: {alert}")
    print(result)
```

### n8n + Python

```python
import requests

# Trigger n8n workflow from Python
def trigger_enrichment(ioc: str):
    webhook_url = "http://n8n:5678/webhook/enrich-ioc"
    return requests.post(webhook_url, json={"ioc": ioc}).json()
```

## Best Practices

### Security
- Never hardcode API keys
- Validate all inputs
- Sanitize outputs for logging
- Use rate limiting for external APIs

### Performance
- Cache repeated lookups
- Batch API calls when possible
- Use async for I/O-bound operations
- Implement timeouts

### Error Handling
- Catch and log all exceptions
- Provide meaningful error messages
- Implement retry logic for transient failures
- Graceful degradation when services unavailable

## Contributing Templates

To add new templates:

1. Create template file in appropriate directory
2. Include comprehensive docstrings
3. Add usage examples
4. Include error handling
5. Update this README

### Template Requirements

- [ ] Well-documented code
- [ ] Type hints
- [ ] Error handling
- [ ] Usage examples
- [ ] Configuration via environment variables
- [ ] No hardcoded secrets

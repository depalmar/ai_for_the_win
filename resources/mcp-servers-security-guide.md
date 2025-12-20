# MCP Servers for Security Operations

Model Context Protocol (MCP) servers extend LLM capabilities by providing access to external tools, databases, and APIs. This guide covers MCP servers useful for DFIR, offensive security, threat intelligence, and report generation.

---

## What is MCP?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MCP ARCHITECTURE                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────┐      ┌──────────────┐      ┌────────────────────────────┐   │
│   │   LLM    │ ◄──► │  MCP Client  │ ◄──► │     MCP Servers            │   │
│   │ (Claude) │      │  (Host App)  │      │                            │   │
│   └──────────┘      └──────────────┘      │  • Filesystem access       │   │
│                                           │  • Database queries        │   │
│                                           │  • API integrations        │   │
│                                           │  • Tool execution          │   │
│                                           └────────────────────────────┘   │
│                                                                              │
│   Benefits:                                                                  │
│   • LLM can access real-time data                                           │
│   • Execute tools and scripts                                               │
│   • Query databases directly                                                │
│   • Generate and save reports                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## DFIR MCP Servers

### 1. Filesystem MCP

Access and analyze files from the local system.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/evidence",
        "/path/to/reports"
      ]
    }
  }
}
```

**DFIR Use Cases:**
- Read log files and artifacts
- Analyze memory dumps
- Access evidence directories
- Write investigation reports

### 2. SQLite MCP (Evidence Database)

Query SQLite databases commonly found in DFIR:

```json
{
  "mcpServers": {
    "sqlite": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-sqlite",
        "--db-path",
        "/path/to/evidence.db"
      ]
    }
  }
}
```

**DFIR Use Cases:**
- Browser history (Chrome, Firefox, Safari)
- iOS/Android databases
- Windows artifact databases
- Timeline databases (Plaso, etc.)

### 3. Memory Analysis MCP (Custom)

Example custom MCP for Volatility3 integration:

```python
# volatility_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
import subprocess
import json

app = Server("volatility-mcp")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="vol3_pslist",
            description="List running processes from memory dump",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_dump": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_dump"]
            }
        ),
        Tool(
            name="vol3_netscan",
            description="Scan for network connections in memory",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_dump": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_dump"]
            }
        ),
        Tool(
            name="vol3_malfind",
            description="Find hidden/injected code in processes",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_dump": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_dump"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    memory_dump = arguments.get("memory_dump")

    plugin_map = {
        "vol3_pslist": "windows.pslist",
        "vol3_netscan": "windows.netscan",
        "vol3_malfind": "windows.malfind"
    }

    plugin = plugin_map.get(name)
    if not plugin:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    result = subprocess.run(
        ["vol", "-f", memory_dump, plugin, "-r", "json"],
        capture_output=True, text=True
    )

    return [TextContent(type="text", text=result.stdout)]

if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run())
```

---

## Threat Intelligence MCP Servers

### 4. VirusTotal MCP

Query VirusTotal for IOC reputation:

```python
# virustotal_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx
import os

app = Server("virustotal-mcp")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="vt_check_hash",
            description="Check file hash reputation on VirusTotal",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "MD5, SHA1, or SHA256 hash"}
                },
                "required": ["hash"]
            }
        ),
        Tool(
            name="vt_check_ip",
            description="Check IP address reputation",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to check"}
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="vt_check_domain",
            description="Check domain reputation",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to check"}
                },
                "required": ["domain"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        if name == "vt_check_hash":
            resp = await client.get(
                f"{VT_BASE}/files/{arguments['hash']}",
                headers=headers
            )
        elif name == "vt_check_ip":
            resp = await client.get(
                f"{VT_BASE}/ip_addresses/{arguments['ip']}",
                headers=headers
            )
        elif name == "vt_check_domain":
            resp = await client.get(
                f"{VT_BASE}/domains/{arguments['domain']}",
                headers=headers
            )

        data = resp.json()

        # Extract key info
        if "data" in data:
            attrs = data["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return [TextContent(type="text", text=f"""
IOC Analysis Results:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Harmless: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}
            """)]

        return [TextContent(type="text", text=str(data))]
```

### 5. MISP MCP

Query MISP threat intelligence platform:

```python
# misp_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
from pymisp import PyMISP
import os

app = Server("misp-mcp")

misp = PyMISP(
    os.getenv("MISP_URL"),
    os.getenv("MISP_API_KEY"),
    ssl=False
)

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="misp_search_ioc",
            description="Search MISP for IOC",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "IOC value to search"},
                    "type": {"type": "string", "description": "IOC type (ip-dst, domain, md5, etc.)"}
                },
                "required": ["value"]
            }
        ),
        Tool(
            name="misp_get_event",
            description="Get MISP event details",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_id": {"type": "string", "description": "MISP event ID"}
                },
                "required": ["event_id"]
            }
        )
    ]
```

### 6. Shodan MCP

Query Shodan for host information:

```json
{
  "mcpServers": {
    "shodan": {
      "command": "python",
      "args": ["shodan_mcp.py"],
      "env": {
        "SHODAN_API_KEY": "your-api-key"
      }
    }
  }
}
```

---

## Offensive Security MCP Servers

### 7. Nuclei MCP (Vulnerability Scanning)

```python
# nuclei_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
import subprocess
import json

app = Server("nuclei-mcp")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="nuclei_scan",
            description="Run Nuclei vulnerability scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"},
                    "templates": {"type": "string", "description": "Template tags (cves, vulns, etc.)"},
                    "severity": {"type": "string", "description": "Minimum severity (info, low, medium, high, critical)"}
                },
                "required": ["target"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    cmd = ["nuclei", "-u", arguments["target"], "-json"]

    if arguments.get("templates"):
        cmd.extend(["-tags", arguments["templates"]])
    if arguments.get("severity"):
        cmd.extend(["-severity", arguments["severity"]])

    result = subprocess.run(cmd, capture_output=True, text=True)

    findings = []
    for line in result.stdout.strip().split("\n"):
        if line:
            findings.append(json.loads(line))

    return [TextContent(type="text", text=json.dumps(findings, indent=2))]
```

### 8. Nmap MCP

```python
# nmap_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
import nmap

app = Server("nmap-mcp")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap_scan",
            description="Run Nmap port scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "ports": {"type": "string", "description": "Port range (e.g., 1-1000, 22,80,443)"},
                    "scan_type": {"type": "string", "description": "Scan type: quick, full, service"}
                },
                "required": ["target"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    nm = nmap.PortScanner()

    args = "-sV"  # Service detection by default
    if arguments.get("scan_type") == "quick":
        args = "-F"
    elif arguments.get("scan_type") == "full":
        args = "-sV -sC -A"

    ports = arguments.get("ports", "1-1000")

    nm.scan(arguments["target"], ports, arguments=args)

    results = []
    for host in nm.all_hosts():
        host_info = {
            "host": host,
            "state": nm[host].state(),
            "ports": []
        }
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                host_info["ports"].append({
                    "port": port,
                    "state": port_info["state"],
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", "")
                })
        results.append(host_info)

    return [TextContent(type="text", text=json.dumps(results, indent=2))]
```

---

## Report Generation MCP Servers

### 9. Report Generator MCP

Generate professional security reports:

```python
# report_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
from jinja2 import Template
from datetime import datetime
import json

app = Server("report-mcp")

REPORT_TEMPLATES = {
    "incident_report": """
# Incident Report: {{ title }}

**Report ID:** {{ report_id }}
**Date:** {{ date }}
**Analyst:** {{ analyst }}
**Classification:** {{ classification }}

---

## Executive Summary

{{ executive_summary }}

---

## Incident Timeline

| Time | Event | Source |
|------|-------|--------|
{% for event in timeline %}
| {{ event.time }} | {{ event.description }} | {{ event.source }} |
{% endfor %}

---

## Indicators of Compromise

### Network IOCs
{% for ioc in iocs.network %}
- {{ ioc.type }}: `{{ ioc.value }}` - {{ ioc.description }}
{% endfor %}

### File IOCs
{% for ioc in iocs.files %}
- {{ ioc.type }}: `{{ ioc.value }}` - {{ ioc.description }}
{% endfor %}

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
{% for technique in attack_techniques %}
| {{ technique.tactic }} | {{ technique.name }} | {{ technique.id }} | {{ technique.evidence }} |
{% endfor %}

---

## Recommendations

{% for rec in recommendations %}
{{ loop.index }}. **{{ rec.priority }}**: {{ rec.description }}
{% endfor %}

---

## Appendix

### Raw Evidence
```
{{ raw_evidence }}
```
""",

    "vulnerability_report": """
# Vulnerability Assessment Report

**Target:** {{ target }}
**Date:** {{ date }}
**Scope:** {{ scope }}

---

## Executive Summary

- **Critical:** {{ summary.critical }}
- **High:** {{ summary.high }}
- **Medium:** {{ summary.medium }}
- **Low:** {{ summary.low }}

---

## Findings

{% for finding in findings %}
### {{ loop.index }}. {{ finding.title }}

**Severity:** {{ finding.severity }}
**CVSS:** {{ finding.cvss }}
**Affected:** {{ finding.affected }}

**Description:**
{{ finding.description }}

**Remediation:**
{{ finding.remediation }}

---
{% endfor %}

## Risk Matrix

| Vulnerability | Likelihood | Impact | Risk |
|--------------|------------|--------|------|
{% for finding in findings %}
| {{ finding.title }} | {{ finding.likelihood }} | {{ finding.impact }} | {{ finding.severity }} |
{% endfor %}
""",

    "threat_intel_report": """
# Threat Intelligence Report

**Subject:** {{ subject }}
**TLP:** {{ tlp }}
**Date:** {{ date }}

---

## Key Findings

{{ key_findings }}

---

## Threat Actor Profile

- **Name/Alias:** {{ actor.name }}
- **Motivation:** {{ actor.motivation }}
- **Sophistication:** {{ actor.sophistication }}
- **Target Sectors:** {{ actor.targets }}

---

## Tactics, Techniques, and Procedures

{% for ttp in ttps %}
### {{ ttp.tactic }}
- **Technique:** {{ ttp.technique }} ({{ ttp.id }})
- **Procedure:** {{ ttp.procedure }}
{% endfor %}

---

## Indicators of Compromise

```
{% for ioc in iocs %}
{{ ioc.type }}: {{ ioc.value }}
{% endfor %}
```

---

## Recommendations

{{ recommendations }}
"""
}

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="generate_report",
            description="Generate a security report from template",
            inputSchema={
                "type": "object",
                "properties": {
                    "template": {
                        "type": "string",
                        "enum": ["incident_report", "vulnerability_report", "threat_intel_report"],
                        "description": "Report template type"
                    },
                    "data": {
                        "type": "object",
                        "description": "Report data to fill template"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["markdown", "html", "pdf"],
                        "description": "Output format"
                    }
                },
                "required": ["template", "data"]
            }
        ),
        Tool(
            name="save_report",
            description="Save generated report to file",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Report content"},
                    "filename": {"type": "string", "description": "Output filename"},
                    "format": {"type": "string", "description": "File format"}
                },
                "required": ["content", "filename"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "generate_report":
        template_name = arguments["template"]
        data = arguments["data"]

        # Add automatic fields
        data["date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["report_id"] = f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        template = Template(REPORT_TEMPLATES[template_name])
        report = template.render(**data)

        return [TextContent(type="text", text=report)]

    elif name == "save_report":
        with open(arguments["filename"], "w") as f:
            f.write(arguments["content"])
        return [TextContent(type="text", text=f"Report saved to {arguments['filename']}")]
```

### 10. PDF Report MCP

Generate PDF reports with charts:

```python
# pdf_report_mcp.py
from mcp.server import Server
from mcp.types import Tool, TextContent
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import plotly.graph_objects as go
import plotly.io as pio
import io
import base64

app = Server("pdf-report-mcp")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="create_pdf_report",
            description="Create a PDF security report with charts",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "sections": {"type": "array", "items": {"type": "object"}},
                    "charts": {"type": "array", "items": {"type": "object"}},
                    "output_path": {"type": "string"}
                },
                "required": ["title", "sections", "output_path"]
            }
        ),
        Tool(
            name="create_chart",
            description="Create a Plotly chart for reports",
            inputSchema={
                "type": "object",
                "properties": {
                    "chart_type": {"type": "string", "enum": ["pie", "bar", "timeline", "heatmap"]},
                    "data": {"type": "object"},
                    "title": {"type": "string"}
                },
                "required": ["chart_type", "data"]
            }
        )
    ]
```

---

## MCP Configuration for Claude Code

Add to your `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/evidence", "/home/user/reports"]
    },
    "sqlite": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/home/user/cases.db"]
    },
    "virustotal": {
      "command": "python",
      "args": ["/home/user/mcp/virustotal_mcp.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-api-key"
      }
    },
    "reports": {
      "command": "python",
      "args": ["/home/user/mcp/report_mcp.py"]
    }
  }
}
```

---

## Available MCP Servers (Official & Community)

### Official Anthropic MCP Servers

| Server | Description | Install |
|--------|-------------|---------|
| **filesystem** | Read/write local files | `@modelcontextprotocol/server-filesystem` |
| **sqlite** | Query SQLite databases | `@modelcontextprotocol/server-sqlite` |
| **postgres** | Query PostgreSQL | `@modelcontextprotocol/server-postgres` |
| **github** | GitHub API access | `@modelcontextprotocol/server-github` |
| **slack** | Slack integration | `@modelcontextprotocol/server-slack` |
| **puppeteer** | Web automation | `@modelcontextprotocol/server-puppeteer` |
| **brave-search** | Web search | `@modelcontextprotocol/server-brave-search` |

### Community Security MCP Servers

| Server | Description | Use Case |
|--------|-------------|----------|
| **shodan-mcp** | Shodan API | Host reconnaissance |
| **censys-mcp** | Censys API | Certificate/host search |
| **greynoise-mcp** | GreyNoise API | IP noise detection |
| **urlscan-mcp** | URLScan.io | URL analysis |
| **hybrid-analysis-mcp** | Hybrid Analysis | Malware sandbox |

---

## Example Workflows

### DFIR Investigation Workflow

```
1. Use filesystem MCP to read log files
2. Query sqlite MCP for browser history
3. Check IOCs with virustotal MCP
4. Generate incident report with report MCP
5. Save PDF with charts using pdf-report MCP
```

### Threat Hunt Workflow

```
1. Query SIEM via custom MCP
2. Enrich IOCs with threat intel MCPs
3. Correlate with MISP MCP
4. Map to MITRE ATT&CK
5. Generate threat intel report
```

### Vulnerability Assessment Workflow

```
1. Run nmap MCP for port discovery
2. Run nuclei MCP for vuln scanning
3. Query CVE database MCP
4. Generate vulnerability report
5. Create risk matrix visualization
```

---

## Building Custom MCP Servers

### Minimal MCP Server Template

```python
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("my-security-mcp")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="my_tool",
            description="Description of what this tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param1": {"type": "string", "description": "Parameter description"}
                },
                "required": ["param1"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "my_tool":
        # Your logic here
        result = do_something(arguments["param1"])
        return [TextContent(type="text", text=result)]

if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run())
```

### Install MCP SDK

```bash
pip install mcp
```

---

## Resources

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [MCP GitHub](https://github.com/modelcontextprotocol)
- [Anthropic MCP Docs](https://docs.anthropic.com/en/docs/build-with-claude/mcp)
- [MCP Server Examples](https://github.com/modelcontextprotocol/servers)

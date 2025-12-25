#!/usr/bin/env python3
"""
Lab 05: Threat Intelligence Agent - Solution

Complete implementation of AI agent for threat intelligence gathering.

=============================================================================
OVERVIEW
=============================================================================

This lab introduces the concept of AI AGENTS - autonomous systems that can
reason about tasks, use tools, and work toward goals with minimal human
intervention. This is a foundational concept for building AI-powered
security automation.

KEY CONCEPTS:

1. ReAct PATTERN (Reasoning + Acting)
   - The agent thinks about what to do (Thought)
   - Takes an action using a tool (Action)
   - Observes the result (Observation)
   - Repeats until goal is achieved
   - This mimics how human analysts work

2. TOOL USE
   - Agents extend LLM capabilities with external tools
   - Tools provide real-world data (threat intel, CVE lookup, etc.)
   - Tools are defined with clear input/output schemas
   - The LLM decides WHICH tool to use and HOW

3. MEMORY SYSTEMS
   - Short-term: Current conversation context
   - Working memory: Findings gathered during investigation
   - Long-term: Could include past investigations (not in this lab)

4. AUTONOMOUS INVESTIGATION
   - Given IOCs, the agent independently:
     - Looks up each indicator
     - Correlates findings
     - Identifies threat patterns
     - Provides recommendations

LEARNING OBJECTIVES:
- Understand the ReAct agent pattern
- Learn to design tools for agent use
- Practice building memory systems
- Implement multi-step reasoning workflows

REAL-WORLD APPLICATIONS:
- Automated threat triage
- IOC enrichment pipelines
- SOAR playbook execution
- Threat hunting assistance

MITRE ATT&CK TECHNIQUES DEMONSTRATED:
- Gathering adversary infrastructure (IPs, domains)
- Mapping techniques to ATT&CK (T1059, T1053, etc.)
- Understanding threat actor TTPs

=============================================================================
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Load environment variables (API keys)
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

try:
    from langchain.tools import StructuredTool
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

try:
    from langchain_openai import ChatOpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from langchain_google_genai import ChatGoogleGenerativeAI

    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()


# =============================================================================
# Mock Threat Intelligence Data
# =============================================================================
#
# In a production environment, these would be API calls to services like:
# - VirusTotal: File/URL/IP reputation
# - AbuseIPDB: IP address abuse reports
# - Shodan: Internet-connected device data
# - AlienVault OTX: Open threat intelligence
# - MISP: Malware Information Sharing Platform
#
# For this lab, we use mock data to:
# 1. Allow offline development and testing
# 2. Provide consistent, reproducible results
# 3. Demonstrate the data structures used in real APIs
#
# The mock data represents realistic threat intelligence findings,
# including C2 infrastructure, malware hashes, and ATT&CK techniques.
#
# =============================================================================

MOCK_IP_DATA = {
    "185.143.223.47": {
        "ip": "185.143.223.47",
        "is_malicious": True,
        "abuse_score": 95,
        "country": "RU",
        "asn": "AS12345 Evil Corp",
        "threat_types": ["C2", "Cobalt Strike"],
        "first_seen": "2023-06-15",
        "last_seen": "2024-01-15",
        "reports": 47,
    },
    "91.234.99.100": {
        "ip": "91.234.99.100",
        "is_malicious": True,
        "abuse_score": 78,
        "country": "UA",
        "asn": "AS67890 Shady Hosting",
        "threat_types": ["Malware Distribution", "Phishing"],
        "first_seen": "2023-09-01",
        "last_seen": "2024-01-10",
        "reports": 23,
    },
}

MOCK_DOMAIN_DATA = {
    "evil-c2.com": {
        "domain": "evil-c2.com",
        "is_malicious": True,
        "category": "command_and_control",
        "first_seen": "2023-11-20",
        "resolves_to": ["185.143.223.47"],
        "registrar": "Anonymous Registrar",
        "ssl_valid": False,
    },
    "malware-drop.net": {
        "domain": "malware-drop.net",
        "is_malicious": True,
        "category": "malware_distribution",
        "first_seen": "2024-01-05",
        "resolves_to": ["91.234.99.100"],
        "registrar": "Privacy Protect",
        "ssl_valid": True,
    },
}

MOCK_HASH_DATA = {
    "a1b2c3d4e5f6": {
        "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "is_malicious": True,
        "malware_family": "Cobalt Strike Beacon",
        "detection_ratio": "58/72",
        "first_seen": "2024-01-12",
        "file_type": "PE32 Executable",
    }
}

MOCK_CVE_DATA = {
    "CVE-2024-1234": {
        "cve_id": "CVE-2024-1234",
        "description": "Remote code execution vulnerability in Apache HTTP Server",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_products": ["Apache HTTP Server 2.4.x"],
        "exploited_in_wild": True,
        "patch_available": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    }
}

MOCK_MITRE_DATA = {
    "T1059.001": {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "detection": "Monitor PowerShell script block logging, command-line arguments",
        "mitigations": [
            "Disable PowerShell for users who don't need it",
            "Enable AMSI",
        ],
        "related_groups": ["APT29", "APT32", "Wizard Spider"],
    },
    "T1053.005": {
        "technique_id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling to execute malicious code.",
        "detection": "Monitor scheduled task creation via schtasks.exe or Task Scheduler",
        "mitigations": ["Restrict task creation permissions"],
        "related_groups": ["APT28", "FIN7"],
    },
}


# =============================================================================
# Tool Implementations
# =============================================================================
#
# DESIGNING TOOLS FOR AI AGENTS:
#
# Tools are the bridge between the LLM's reasoning and real-world actions.
# Each tool should be:
#
# 1. WELL-DEFINED: Clear name, description, and input schema
#    - The description tells the LLM when to use the tool
#    - The input schema (using Pydantic) validates parameters
#
# 2. SINGLE-PURPOSE: One tool = one capability
#    - ip_lookup for IPs, domain_analysis for domains
#    - Makes it easier for the LLM to choose the right tool
#
# 3. ROBUST: Handle errors gracefully
#    - Return meaningful error messages
#    - Don't crash on invalid input
#
# 4. CONSISTENT OUTPUT: Return structured data
#    - Always return JSON/dict for machine parsing
#    - Include status indicators (is_malicious, confidence, etc.)
#
# PYDANTIC MODELS:
# We use Pydantic BaseModel to define tool input schemas.
# This provides:
# - Automatic validation of inputs
# - Clear documentation for the LLM
# - Type safety
#
# =============================================================================

# Pydantic models define the expected inputs for each tool
# These are used by LangChain to generate tool schemas for the LLM


class IPLookupInput(BaseModel):
    ip: str = Field(description="IPv4 or IPv6 address to look up")


class DomainInput(BaseModel):
    domain: str = Field(description="Domain name to analyze")


class HashInput(BaseModel):
    file_hash: str = Field(description="File hash (MD5, SHA1, or SHA256)")


class CVEInput(BaseModel):
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")


class MITREInput(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., T1059.001)")


# =============================================================================
# Wrapper Classes (for test compatibility)
# =============================================================================


class IOCEnricher:
    """Enrich IOCs with threat intelligence data."""

    def enrich_ip(self, ip: str) -> dict:
        """Enrich IP address with threat data."""
        return lookup_ip(ip)

    def enrich_domain(self, domain: str) -> dict:
        """Enrich domain with threat data."""
        return analyze_domain(domain)

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich file hash with threat data."""
        return check_hash(file_hash)

    def detect_type(self, ioc: str) -> str:
        """Detect the type of IOC."""
        import re

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
            return "ip"
        elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
            return "hash"
        elif "." in ioc and not ioc[0].isdigit():
            return "domain"
        else:
            return "unknown"

    def enrich_batch(self, iocs: list) -> list:
        """Enrich a batch of IOCs."""
        results = []
        for ioc in iocs:
            ioc_type = self.detect_type(ioc)
            if ioc_type == "ip":
                results.append(self.enrich_ip(ioc))
            elif ioc_type == "domain":
                results.append(self.enrich_domain(ioc))
            elif ioc_type == "hash":
                results.append(self.enrich_hash(ioc))
        return results


class ReputationChecker:
    """Check reputation of IOCs."""

    def check_ip(self, ip: str) -> dict:
        """Check IP reputation."""
        result = lookup_ip(ip)
        result["score"] = result.get("threat_score", 0)
        return result

    def check_domain(self, domain: str) -> dict:
        """Check domain reputation."""
        return analyze_domain(domain)


class MITREMapper:
    """Map behaviors to MITRE ATT&CK techniques."""

    def map_technique(self, behavior: str) -> dict:
        """Map a behavior to MITRE technique."""
        behavior_lower = behavior.lower()

        # Simple mapping based on keywords
        if "powershell" in behavior_lower:
            return self.get_technique("T1059.001")
        elif "rdp" in behavior_lower or "remote desktop" in behavior_lower:
            return self.get_technique("T1021.001")
        elif "credential" in behavior_lower:
            return self.get_technique("T1003")
        else:
            return {"technique_id": "Unknown", "name": "Unknown technique"}

    def map_behaviors(self, behaviors: list) -> list:
        """Map multiple behaviors to MITRE techniques."""
        return [self.map_technique(behavior) for behavior in behaviors]

    def get_technique(self, technique_id: str) -> dict:
        """Get MITRE technique details."""
        return get_mitre_technique(technique_id)


class ThreatReport:
    """Generate threat intelligence reports."""

    def __init__(self, data: dict):
        """Initialize with threat data."""
        self.data = data

    def to_json(self) -> str:
        """Convert report to JSON."""
        import json

        return json.dumps(self.data, indent=2)

    def to_markdown(self) -> str:
        """Convert report to Markdown."""
        md = f"# Threat Report\n\n"
        md += f"**Indicator:** {self.data.get('indicator', 'Unknown')}\n\n"
        md += f"**Type:** {self.data.get('type', 'Unknown')}\n\n"
        md += f"**Severity:** {self.data.get('severity', 'Unknown')}\n\n"

        if "description" in self.data:
            md += f"## Description\n\n{self.data['description']}\n\n"

        if "mitre_techniques" in self.data:
            md += f"## MITRE ATT&CK Techniques\n\n"
            for tech in self.data["mitre_techniques"]:
                md += f"- {tech}\n"

        return md


def lookup_ip(ip: str) -> dict:
    """Look up threat intelligence for an IP address."""
    # Check mock data first
    if ip in MOCK_IP_DATA:
        return MOCK_IP_DATA[ip]

    # Return default for unknown IPs
    return {
        "ip": ip,
        "is_malicious": False,
        "abuse_score": 0,
        "country": "Unknown",
        "asn": "Unknown",
        "threat_types": [],
        "message": "No threat intelligence found for this IP",
    }


def analyze_domain(domain: str) -> dict:
    """Analyze a domain for threat indicators."""
    if domain in MOCK_DOMAIN_DATA:
        return MOCK_DOMAIN_DATA[domain]

    return {
        "domain": domain,
        "is_malicious": False,
        "category": "unknown",
        "message": "No threat intelligence found for this domain",
    }


def check_hash(file_hash: str) -> dict:
    """Check file hash against threat intelligence."""
    # Normalize hash
    hash_prefix = file_hash[:12].lower()
    if hash_prefix in MOCK_HASH_DATA:
        return MOCK_HASH_DATA[hash_prefix]

    return {
        "hash": file_hash,
        "is_malicious": False,
        "message": "No threat intelligence found for this hash",
    }


def search_cve(cve_id: str) -> dict:
    """Get details about a CVE."""
    cve_upper = cve_id.upper()
    if cve_upper in MOCK_CVE_DATA:
        return MOCK_CVE_DATA[cve_upper]

    return {"cve_id": cve_id, "message": "CVE not found in database"}


def get_mitre_technique(technique_id: str) -> dict:
    """Get details about a MITRE ATT&CK technique."""
    if technique_id in MOCK_MITRE_DATA:
        return MOCK_MITRE_DATA[technique_id]

    return {
        "technique_id": technique_id,
        "message": "Technique not found in MITRE ATT&CK database",
    }


def get_tools() -> List["StructuredTool"]:
    """Create tool list for the agent."""
    from langchain.tools import StructuredTool

    return [
        StructuredTool.from_function(
            func=lookup_ip,
            name="ip_lookup",
            description="Look up threat intelligence for an IP address. Returns reputation, geolocation, and threat types.",
            args_schema=IPLookupInput,
        ),
        StructuredTool.from_function(
            func=analyze_domain,
            name="domain_analysis",
            description="Analyze a domain for threat indicators. Returns category, registration info, and associated IPs.",
            args_schema=DomainInput,
        ),
        StructuredTool.from_function(
            func=check_hash,
            name="hash_check",
            description="Check if a file hash is associated with known malware.",
            args_schema=HashInput,
        ),
        StructuredTool.from_function(
            func=search_cve,
            name="cve_lookup",
            description="Get details about a CVE vulnerability.",
            args_schema=CVEInput,
        ),
        StructuredTool.from_function(
            func=get_mitre_technique,
            name="mitre_lookup",
            description="Get details about a MITRE ATT&CK technique.",
            args_schema=MITREInput,
        ),
    ]


# =============================================================================
# Agent Memory
# =============================================================================
#
# MEMORY SYSTEMS FOR AGENTS:
#
# Memory is crucial for agents that need to maintain context across multiple
# tool calls and build up knowledge during an investigation.
#
# TYPES OF MEMORY:
#
# 1. CONVERSATION HISTORY (Short-term)
#    - Recent messages between user and agent
#    - Limited to prevent context overflow
#    - Trimmed using a sliding window (max_history)
#
# 2. INVESTIGATION FINDINGS (Working memory)
#    - Results from tool calls stored for correlation
#    - Tracks which IOCs have been investigated
#    - Enables the agent to avoid redundant lookups
#
# 3. CONTEXT GENERATION
#    - Summarizes memory for inclusion in prompts
#    - Helps the agent "remember" what it found
#    - Critical for multi-step investigations
#
# WHY MEMORY MATTERS:
# Without memory, the agent would forget what it learned in previous steps.
# For example, if it looks up an IP and finds it's malicious, it needs to
# remember this when correlating with other findings.
#
# =============================================================================


class AgentMemory:
    """Memory system for the threat intelligence agent."""

    def __init__(self, max_history: int = 20):
        self.max_history = max_history
        self.conversation: List[Dict[str, str]] = []
        self.findings: Dict[str, Dict] = {}
        self.investigated_iocs: set = set()

    def add_message(self, role: str, content: str):
        """Add a message to conversation history."""
        self.conversation.append(
            {"role": role, "content": content, "timestamp": datetime.now().isoformat()}
        )
        # Trim if exceeds max
        if len(self.conversation) > self.max_history:
            self.conversation = self.conversation[-self.max_history :]

    def add_finding(self, ioc: str, ioc_type: str, data: dict):
        """Store an investigation finding."""
        self.findings[ioc] = {
            "type": ioc_type,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        }
        self.investigated_iocs.add(ioc)

    def get_context(self, include_findings: bool = True) -> str:
        """Get formatted context for LLM."""
        context_parts = []

        # Recent conversation
        if self.conversation:
            context_parts.append("Recent conversation:")
            for msg in self.conversation[-5:]:
                context_parts.append(f"  {msg['role']}: {msg['content'][:200]}...")

        # Findings summary
        if include_findings and self.findings:
            context_parts.append("\nInvestigation findings:")
            for ioc, finding in self.findings.items():
                is_malicious = finding["data"].get("is_malicious", "unknown")
                context_parts.append(f"  {ioc}: malicious={is_malicious}")

        return "\n".join(context_parts)

    def is_investigated(self, ioc: str) -> bool:
        return ioc in self.investigated_iocs

    def get_finding(self, ioc: str) -> Optional[dict]:
        return self.findings.get(ioc)


# =============================================================================
# Threat Intelligence Agent
# =============================================================================
#
# THE ReAct AGENT PATTERN:
#
# ReAct (Reasoning + Acting) is a prompting strategy that enables LLMs to
# solve complex tasks by interleaving reasoning and action steps.
#
# THE LOOP:
# 1. THOUGHT: Agent reasons about what to do next
#    "I need to look up this IP to determine if it's malicious..."
#
# 2. ACTION: Agent chooses a tool and provides inputs
#    Action: ip_lookup
#    Action Input: {"ip": "185.143.223.47"}
#
# 3. OBSERVATION: Agent receives tool output
#    Observation: {"is_malicious": true, "threat_types": ["C2"]}
#
# 4. REPEAT: Agent continues until reaching a conclusion
#
# 5. FINAL ANSWER: Agent synthesizes findings into a response
#
# IMPLEMENTATION NOTES:
#
# - MAX_ITERATIONS: Prevents infinite loops (set to 10)
# - PARSING: Extract Action/Action Input from LLM output using regex
# - ERROR HANDLING: Unknown tools or parse failures are handled gracefully
# - MEMORY: Findings are stored for correlation across steps
#
# WHY ReAct WORKS:
# By making the agent's reasoning explicit, we can:
# - Debug agent behavior
# - Guide the reasoning process
# - Ensure systematic investigation
#
# =============================================================================

# Agent system prompt defines its capabilities and expected behavior
AGENT_SYSTEM_PROMPT = """You are a threat intelligence analyst AI agent.

Your capabilities:
1. Investigate indicators of compromise (IOCs)
2. Gather context from multiple threat intelligence sources
3. Correlate findings across different data types
4. Assess threat severity and confidence
5. Provide actionable intelligence and recommendations

Available Tools:
{tools}

IMPORTANT RULES:
1. Always use tools to gather information - never make assumptions
2. Cite confidence levels: HIGH (confirmed by API), MEDIUM (correlated), LOW (inferred)
3. If a tool returns no data, acknowledge this - don't fabricate information
4. Correlate findings when investigating multiple IOCs
5. Always provide actionable recommendations

OUTPUT FORMAT:
When reasoning, use this format:

Thought: [What I need to find out or do next]
Action: [tool_name]
Action Input: {{"parameter": "value"}}

After receiving an observation, continue with another Thought/Action or provide your final answer:

Final Answer: [Your complete analysis and recommendations]

Begin!"""


class ThreatIntelAgent:
    """AI agent for threat intelligence gathering and analysis."""

    def __init__(self, llm=None, provider: str = "auto", tools: List = None, verbose: bool = True):
        """
        Initialize the threat intelligence agent.

        Args:
            llm: Pre-configured LLM instance (optional)
            provider: LLM provider if llm not provided. Options:
                - "auto": Try providers in order (anthropic, openai, gemini)
                - "anthropic": Use Claude
                - "openai": Use GPT-4
                - "gemini": Use Gemini 1.5 Pro
            tools: List of tools for the agent (optional)
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.memory = AgentMemory()
        self.max_iterations = 10

        # Initialize LLM
        if llm is None:
            self.llm = self._setup_llm(provider)
        else:
            self.llm = llm

        # Initialize tools
        if tools is None:
            tools = get_tools()
        self.tools = {t.name: t for t in tools}

        # Format system prompt
        tool_descriptions = self._format_tool_descriptions()
        self.system_prompt = AGENT_SYSTEM_PROMPT.format(tools=tool_descriptions)

    def _setup_llm(self, provider: str):
        """Set up LLM based on provider preference."""
        providers_to_try = []

        if provider == "auto":
            # Try providers in order of preference
            providers_to_try = ["anthropic", "openai", "gemini"]
        else:
            providers_to_try = [provider]

        for prov in providers_to_try:
            try:
                if prov == "anthropic":
                    api_key = os.getenv("ANTHROPIC_API_KEY")
                    if api_key and LANGCHAIN_AVAILABLE:
                        return ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)

                elif prov == "openai":
                    api_key = os.getenv("OPENAI_API_KEY")
                    if api_key and OPENAI_AVAILABLE:
                        return ChatOpenAI(model="gpt-4-turbo", temperature=0)

                elif prov == "gemini":
                    api_key = os.getenv("GOOGLE_API_KEY")
                    if api_key and GEMINI_AVAILABLE:
                        return ChatGoogleGenerativeAI(model="gemini-1.5-pro", temperature=0)

            except Exception as e:
                if self.verbose:
                    console.print(f"[yellow]Failed to initialize {prov}: {e}[/yellow]")
                continue

        raise ValueError(
            "No LLM provider available. Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY"
        )

    def _format_tool_descriptions(self) -> str:
        """Format tool descriptions for the system prompt."""
        descriptions = []
        for name, tool in self.tools.items():
            descriptions.append(f"- {name}: {tool.description}")
        return "\n".join(descriptions)

    def run(self, query: str) -> str:
        """Run the agent on a query."""
        self.memory.add_message("user", query)

        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=query),
        ]

        for iteration in range(self.max_iterations):
            if self.verbose:
                console.print(f"\n[dim]--- Iteration {iteration + 1} ---[/dim]")

            response = self.llm.invoke(messages)
            response_text = response.content

            if self.verbose:
                console.print(f"[blue]Agent:[/blue] {response_text[:300]}...")

            # Check for Final Answer
            if "Final Answer:" in response_text:
                final_answer = self._extract_final_answer(response_text)
                self.memory.add_message("assistant", final_answer)
                return final_answer

            # Parse for Action
            action, action_input = self._parse_action(response_text)

            if action:
                # Execute tool
                observation = self._execute_tool(action, action_input)

                if self.verbose:
                    console.print(f"[green]Tool Result:[/green] {observation[:200]}...")

                # Add to messages for next iteration
                messages.append(AIMessage(content=response_text))
                messages.append(HumanMessage(content=f"Observation: {observation}"))
            else:
                # No action found, prompt to continue
                messages.append(AIMessage(content=response_text))
                messages.append(
                    HumanMessage(
                        content="Please continue with your analysis. Use a tool or provide your Final Answer."
                    )
                )

        return "Max iterations reached. Please refine your query."

    def _parse_action(self, response: str) -> tuple:
        """Parse tool name and arguments from LLM response."""
        action_match = re.search(r"Action:\s*(\w+)", response)
        input_match = re.search(r"Action Input:\s*(\{.*?\})", response, re.DOTALL)

        if action_match and input_match:
            action = action_match.group(1)
            try:
                action_input = json.loads(input_match.group(1))
                return action, action_input
            except json.JSONDecodeError:
                pass

        return None, None

    def _execute_tool(self, tool_name: str, args: dict) -> str:
        """Execute a tool and return results."""
        try:
            tool = self.tools.get(tool_name)
            if not tool:
                return f"Error: Unknown tool '{tool_name}'. Available: {list(self.tools.keys())}"

            result = tool.invoke(args)

            # Store finding in memory
            if tool_name == "ip_lookup":
                self.memory.add_finding(args.get("ip", ""), "ip", result)
            elif tool_name == "domain_analysis":
                self.memory.add_finding(args.get("domain", ""), "domain", result)
            elif tool_name == "hash_check":
                self.memory.add_finding(args.get("file_hash", ""), "hash", result)

            return json.dumps(result, indent=2)

        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"

    def _extract_final_answer(self, response: str) -> str:
        """Extract final answer from response."""
        match = re.search(r"Final Answer:\s*(.*)", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response


# =============================================================================
# Investigation Helpers
# =============================================================================


def investigate_incident(agent: ThreatIntelAgent, iocs: dict) -> str:
    """Investigate an incident given a set of IOCs."""
    ioc_list = []
    if iocs.get("ips"):
        ioc_list.append(f"IP Addresses: {', '.join(iocs['ips'])}")
    if iocs.get("domains"):
        ioc_list.append(f"Domains: {', '.join(iocs['domains'])}")
    if iocs.get("hashes"):
        ioc_list.append(f"File Hashes: {', '.join(iocs['hashes'])}")

    prompt = f"""Investigate this security incident. Here are the IOCs found:

{chr(10).join(ioc_list)}

For each IOC:
1. Look up threat intelligence using the appropriate tool
2. Determine if it's malicious
3. Note any connections between IOCs

After investigating all IOCs:
1. Summarize what type of attack this appears to be
2. Map observed activity to MITRE ATT&CK techniques
3. Assess overall severity (1-10)
4. Provide specific remediation recommendations

Be thorough and cite your sources."""

    return agent.run(prompt)


# =============================================================================
# Main
# =============================================================================


def main():
    console.print(
        Panel.fit(
            "[bold]Lab 05: Threat Intelligence Agent - SOLUTION[/bold]",
            border_style="blue",
        )
    )

    if not LANGCHAIN_AVAILABLE:
        console.print(
            "[red]LangChain not available. Install: pip install langchain langchain-anthropic[/red]"
        )
        return

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        console.print(
            "[yellow]ANTHROPIC_API_KEY not set. Running in demo mode with mock responses.[/yellow]"
        )

    try:
        console.print("\n[yellow]Initializing agent...[/yellow]")
        agent = ThreatIntelAgent(verbose=True)

        # Test 1: Single IP Investigation
        console.print("\n" + "=" * 60)
        console.print("[bold]Test 1: Single IP Investigation[/bold]")
        console.print("=" * 60)

        result = agent.run("Investigate this suspicious IP address: 185.143.223.47")
        console.print("\n[green]Result:[/green]")
        console.print(Markdown(result))

        # Test 2: Multi-IOC Investigation
        console.print("\n" + "=" * 60)
        console.print("[bold]Test 2: Multi-IOC Investigation[/bold]")
        console.print("=" * 60)

        iocs = {
            "ips": ["185.143.223.47", "91.234.99.100"],
            "domains": ["evil-c2.com"],
            "hashes": ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"],
        }
        result = investigate_incident(agent, iocs)
        console.print("\n[green]Result:[/green]")
        console.print(Markdown(result))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()

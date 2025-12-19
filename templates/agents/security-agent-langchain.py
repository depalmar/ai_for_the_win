#!/usr/bin/env python3
"""
Security Agent Starter Template - LangChain

A production-ready template for building security analysis agents
using LangChain and Claude.

Features:
- Multi-tool agent with security-focused capabilities
- Conversation memory
- Structured output parsing
- Rate limiting and error handling
- Async support

Setup:
    pip install langchain langchain-anthropic chromadb httpx tenacity

Usage:
    export ANTHROPIC_API_KEY="your-key"
    python security-agent-langchain.py
"""

import asyncio
import json
import re
import hashlib
from datetime import datetime
from typing import Optional, Any

from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain.tools import Tool, StructuredTool
from langchain.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential


# ============================================================================
# Configuration
# ============================================================================

MODEL_NAME = "claude-sonnet-4-20250514"
MAX_TOKENS = 4096
TEMPERATURE = 0.1  # Low temperature for security analysis


# ============================================================================
# Pydantic Models for Structured Output
# ============================================================================

class IOCExtraction(BaseModel):
    """Structured IOC extraction result."""
    ips: list[str] = Field(default_factory=list, description="IPv4 addresses found")
    domains: list[str] = Field(default_factory=list, description="Domain names found")
    urls: list[str] = Field(default_factory=list, description="URLs found")
    hashes: dict[str, list[str]] = Field(
        default_factory=lambda: {"md5": [], "sha1": [], "sha256": []},
        description="File hashes by type"
    )
    emails: list[str] = Field(default_factory=list, description="Email addresses found")


class ThreatAssessment(BaseModel):
    """Structured threat assessment result."""
    threat_level: str = Field(description="Critical, High, Medium, Low, or Info")
    confidence: float = Field(ge=0, le=1, description="Confidence score 0-1")
    summary: str = Field(description="Brief summary of findings")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK IDs")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions")
    iocs: IOCExtraction = Field(default_factory=IOCExtraction, description="Extracted IOCs")


# ============================================================================
# Tool Definitions
# ============================================================================

def extract_iocs(text: str) -> str:
    """Extract indicators of compromise from text."""
    iocs = IOCExtraction()

    # IPv4 addresses
    iocs.ips = list(set(re.findall(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        text
    )))

    # Domains (simplified pattern)
    iocs.domains = list(set(re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|edu|gov|mil|info|biz|co|uk|de|ru|cn)\b',
        text, re.IGNORECASE
    )))

    # URLs
    iocs.urls = list(set(re.findall(
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        text
    )))

    # MD5 hashes
    iocs.hashes["md5"] = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))

    # SHA1 hashes
    iocs.hashes["sha1"] = list(set(re.findall(r'\b[a-fA-F0-9]{40}\b', text)))

    # SHA256 hashes
    iocs.hashes["sha256"] = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))

    # Emails
    iocs.emails = list(set(re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        text
    )))

    return json.dumps(iocs.model_dump(), indent=2)


def defang_ioc(ioc: str) -> str:
    """Defang an IOC for safe sharing."""
    result = ioc
    result = result.replace("http://", "hxxp://")
    result = result.replace("https://", "hxxps://")
    result = result.replace(".", "[.]")
    result = result.replace("@", "[@]")
    return result


def analyze_hash(hash_value: str) -> str:
    """Analyze a hash value to determine its type and validity."""
    hash_value = hash_value.strip().lower()
    length = len(hash_value)

    if not re.match(r'^[a-f0-9]+$', hash_value):
        return json.dumps({"error": "Invalid hash: contains non-hexadecimal characters"})

    hash_types = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        128: "SHA512"
    }

    hash_type = hash_types.get(length, "Unknown")

    return json.dumps({
        "hash": hash_value,
        "type": hash_type,
        "length": length,
        "valid": hash_type != "Unknown"
    })


def calculate_file_hash(content: str) -> str:
    """Calculate hashes of provided content."""
    content_bytes = content.encode('utf-8')

    return json.dumps({
        "md5": hashlib.md5(content_bytes).hexdigest(),
        "sha1": hashlib.sha1(content_bytes).hexdigest(),
        "sha256": hashlib.sha256(content_bytes).hexdigest()
    })


def check_ip_type(ip: str) -> str:
    """Determine if an IP address is public, private, or special."""
    try:
        parts = [int(p) for p in ip.strip().split(".")]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return json.dumps({"error": "Invalid IP address format"})

        first, second = parts[0], parts[1]

        if first == 10:
            category = "Private (RFC 1918 - 10.0.0.0/8)"
        elif first == 172 and 16 <= second <= 31:
            category = "Private (RFC 1918 - 172.16.0.0/12)"
        elif first == 192 and second == 168:
            category = "Private (RFC 1918 - 192.168.0.0/16)"
        elif first == 127:
            category = "Loopback (127.0.0.0/8)"
        elif first == 169 and second == 254:
            category = "Link-Local (169.254.0.0/16)"
        elif first == 0:
            category = "Reserved (0.0.0.0/8)"
        elif first >= 224 and first <= 239:
            category = "Multicast (224.0.0.0/4)"
        elif first >= 240:
            category = "Reserved (240.0.0.0/4)"
        else:
            category = "Public"

        return json.dumps({
            "ip": ip,
            "category": category,
            "is_public": category == "Public",
            "is_routable": category == "Public"
        })

    except Exception as e:
        return json.dumps({"error": str(e)})


def search_mitre_attack(query: str) -> str:
    """Search MITRE ATT&CK for techniques (simplified local lookup)."""
    # Simplified MITRE ATT&CK database
    techniques = {
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
        "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
        "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
        "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
        "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
        "T1566": {"name": "Phishing", "tactic": "Initial Access"},
        "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
        "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
        "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
        "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
        "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    }

    query_lower = query.lower()
    matches = []

    for tech_id, info in techniques.items():
        if (query_lower in tech_id.lower() or
            query_lower in info["name"].lower() or
            query_lower in info["tactic"].lower()):
            matches.append({
                "technique_id": tech_id,
                "name": info["name"],
                "tactic": info["tactic"],
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
            })

    return json.dumps({
        "query": query,
        "matches": matches[:10],
        "count": len(matches)
    })


# ============================================================================
# Agent Setup
# ============================================================================

def create_security_agent(
    verbose: bool = True,
    memory_window: int = 10
) -> AgentExecutor:
    """Create a security analysis agent with tools and memory."""

    # Initialize LLM
    llm = ChatAnthropic(
        model=MODEL_NAME,
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE
    )

    # Define tools
    tools = [
        Tool(
            name="extract_iocs",
            func=extract_iocs,
            description="""Extract indicators of compromise (IOCs) from text.
            Input: Text that may contain IOCs.
            Output: JSON with IPs, domains, URLs, hashes, and emails found."""
        ),
        Tool(
            name="defang_ioc",
            func=defang_ioc,
            description="""Defang an IOC (URL, domain, IP, email) for safe sharing.
            Input: A single IOC string.
            Output: Defanged version safe for reports and communication."""
        ),
        Tool(
            name="analyze_hash",
            func=analyze_hash,
            description="""Analyze a hash value to determine its type (MD5, SHA1, SHA256).
            Input: A hash string.
            Output: JSON with hash type and validity."""
        ),
        Tool(
            name="calculate_hash",
            func=calculate_file_hash,
            description="""Calculate MD5, SHA1, and SHA256 hashes of text content.
            Input: Text content to hash.
            Output: JSON with all hash values."""
        ),
        Tool(
            name="check_ip_type",
            func=check_ip_type,
            description="""Check if an IP address is public, private, or special.
            Input: An IP address.
            Output: JSON with IP category and routability."""
        ),
        Tool(
            name="search_mitre",
            func=search_mitre_attack,
            description="""Search MITRE ATT&CK for techniques by ID, name, or tactic.
            Input: Search query (technique ID like T1059, or keyword like 'powershell').
            Output: JSON with matching techniques."""
        ),
    ]

    # Create prompt template
    prompt = PromptTemplate.from_template("""You are an expert security analyst assistant.

Your capabilities:
1. Extract and analyze indicators of compromise (IOCs)
2. Map threats to MITRE ATT&CK framework
3. Provide security assessments and recommendations
4. Help with incident investigation

Guidelines:
- Always extract IOCs from provided data
- Map findings to MITRE ATT&CK techniques when relevant
- Provide actionable recommendations
- Defang IOCs when sharing in reports
- Consider the full context of an investigation

Available tools:
{tools}

Tool names: {tool_names}

Previous conversation:
{chat_history}

Current question: {input}

Think step by step and use tools when needed to provide accurate analysis.

{agent_scratchpad}""")

    # Create memory
    memory = ConversationBufferWindowMemory(
        memory_key="chat_history",
        k=memory_window,
        return_messages=True
    )

    # Create agent
    agent = create_react_agent(llm, tools, prompt)

    # Create executor
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=10
    )

    return executor


# ============================================================================
# Main Interface
# ============================================================================

class SecurityAnalysisAgent:
    """High-level interface for the security analysis agent."""

    def __init__(self, verbose: bool = False):
        self.executor = create_security_agent(verbose=verbose)
        self.history = []

    def analyze(self, query: str) -> str:
        """Run analysis on a query."""
        result = self.executor.invoke({"input": query})
        self.history.append({"query": query, "response": result["output"]})
        return result["output"]

    async def analyze_async(self, query: str) -> str:
        """Run analysis asynchronously."""
        result = await self.executor.ainvoke({"input": query})
        self.history.append({"query": query, "response": result["output"]})
        return result["output"]

    def clear_history(self):
        """Clear conversation history."""
        self.executor.memory.clear()
        self.history = []


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Interactive CLI for the security agent."""
    print("=" * 60)
    print("Security Analysis Agent")
    print("=" * 60)
    print("\nCommands:")
    print("  Type your question or paste data for analysis")
    print("  'clear' - Clear conversation history")
    print("  'quit' or 'exit' - Exit the agent")
    print("=" * 60)

    agent = SecurityAnalysisAgent(verbose=True)

    while True:
        try:
            user_input = input("\n[You] > ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["quit", "exit"]:
                print("Goodbye!")
                break

            if user_input.lower() == "clear":
                agent.clear_history()
                print("History cleared.")
                continue

            print("\n[Agent] Analyzing...")
            response = agent.analyze(user_input)
            print(f"\n[Agent] {response}")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\n[Error] {e}")


if __name__ == "__main__":
    main()

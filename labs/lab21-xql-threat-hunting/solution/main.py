#!/usr/bin/env python3
"""
Lab 21: XQL Threat Hunting with AI - Solution

Build AI-assisted threat hunting queries for Cortex XDR using XQL.
"""

import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

# LLM imports - uncomment your preferred provider
# from anthropic import Anthropic
# from openai import OpenAI


class Severity(Enum):
    """Detection rule severity levels."""

    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionRule:
    """Structure for a detection rule."""

    name: str
    description: str
    query: str
    severity: Severity
    mitre_techniques: List[str]
    false_positive_guidance: str


@dataclass
class ValidationResult:
    """Result of XQL query validation."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]


# =============================================================================
# XQL Query Generation
# =============================================================================


def get_xql_system_prompt() -> str:
    """
    Return the system prompt for XQL query generation.

    Creates a comprehensive system prompt that establishes XQL expertise
    and provides syntax guidance.
    """
    return """You are an expert in Cortex XDR XQL (eXtended Query Language) for threat hunting.

XQL Syntax Rules:
1. Always start with: config case_sensitive = false
2. Use pipe (|) to chain operations
3. Dataset declaration: | dataset = <dataset_name>
4. Filtering: | filter <field> = <value> or | filter <field> contains "<string>"
5. Time filtering: | filter _time >= now() - <duration>
6. Event types use ENUM: event_type = ENUM.PROCESS, ENUM.NETWORK, ENUM.FILE, ENUM.REGISTRY

Valid Datasets:
- xdr_data: Main telemetry data (processes, network, files, registry)
- endpoints: Endpoint information
- incidents: Security incidents
- alerts: Generated alerts
- audit_logs: Audit trail

Common Fields:
- action_process_image_name: Process executable name
- action_process_image_command_line: Full command line
- action_process_image_sha256: Process hash
- actor_process_image_name: Parent process name
- action_file_path: File path for file events
- action_remote_ip: Remote IP for network events
- action_remote_port: Remote port for network events
- agent_hostname: Endpoint hostname

Output Format:
- Return ONLY the XQL query, no explanations
- Use proper indentation for readability
- Include time filters when appropriate
- Add limit clause to prevent large result sets"""


def query_from_description(description: str, days: int = 7) -> str:
    """
    Generate an XQL query from a natural language description.

    Args:
        description: Natural language description of what to hunt for
        days: Number of days to look back (default: 7)

    Returns:
        Valid XQL query string
    """
    system_prompt = get_xql_system_prompt()

    user_prompt = f"""Generate an XQL query to: {description}

Requirements:
- Look back {days} days
- Include appropriate filters
- Limit results to 1000 rows
- Use proper ENUM syntax for event types

Return only the XQL query."""

    # Example implementation using Anthropic (uncomment to use)
    # client = Anthropic()
    # response = client.messages.create(
    #     model="claude-sonnet-4-20250514",
    #     max_tokens=1024,
    #     system=system_prompt,
    #     messages=[{"role": "user", "content": user_prompt}]
    # )
    # return response.content[0].text

    # For demo purposes, return a template query
    return f"""config case_sensitive = false
| dataset = xdr_data
| filter _time >= now() - {days}d
| filter event_type = ENUM.PROCESS
// Query for: {description}
| fields agent_hostname, action_process_image_name, action_process_image_command_line, _time
| sort desc _time
| limit 1000"""


# =============================================================================
# Query Validation
# =============================================================================

# Valid XQL datasets
VALID_DATASETS = [
    "xdr_data",
    "endpoints",
    "incidents",
    "alerts",
    "audit_logs",
    "ad_users",
    "ad_computers",
]

# Valid event type ENUMs
VALID_EVENT_TYPES = [
    "ENUM.PROCESS",
    "ENUM.NETWORK",
    "ENUM.FILE",
    "ENUM.REGISTRY",
    "ENUM.LOGIN",
    "EVENT_LOG",
]


def validate_xql_query(query: str) -> ValidationResult:
    """
    Validate an XQL query for correctness.

    Args:
        query: XQL query string to validate

    Returns:
        ValidationResult with errors, warnings, and suggestions
    """
    errors = []
    warnings = []
    suggestions = []

    query_lower = query.lower()

    # Check 1: Dataset validation
    dataset_match = re.search(r"dataset\s*=\s*(\w+)", query_lower)
    if dataset_match:
        dataset = dataset_match.group(1)
        if dataset not in [d.lower() for d in VALID_DATASETS]:
            errors.append(f"Invalid dataset '{dataset}'. Valid: {VALID_DATASETS}")
    else:
        errors.append("No dataset specified. Use '| dataset = xdr_data'")

    # Check 2: Event type ENUM validation
    if "event_type" in query_lower:
        # Check if ENUM is used
        if "event_type" in query_lower and "enum." not in query_lower:
            errors.append("Event type filtering requires ENUM. Use: event_type = ENUM.PROCESS")

    # Check 3: Time filter check
    if "_time" not in query_lower and "now()" not in query_lower:
        warnings.append("No time filter detected. Consider adding: | filter _time >= now() - 7d")

    # Check 4: Config statements
    if "config case_sensitive" not in query_lower:
        suggestions.append("Consider adding: config case_sensitive = false")

    # Check 5: Limit check
    if "limit" not in query_lower:
        warnings.append("No limit clause. Consider adding: | limit 1000")

    # Check 6: Basic syntax - pipes
    if "|" not in query:
        errors.append("XQL queries require pipe (|) operators between stages")

    is_valid = len(errors) == 0

    return ValidationResult(
        is_valid=is_valid, errors=errors, warnings=warnings, suggestions=suggestions
    )


# =============================================================================
# MITRE ATT&CK Mapping
# =============================================================================

# Common technique patterns
ATTACK_PATTERNS = {
    "T1059.001": {
        "name": "PowerShell",
        "keywords": ["powershell", "pwsh", "-enc", "-encodedcommand", "-e ", "-ec "],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "keywords": ["cmd.exe", "cmd /c", "command"],
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "keywords": ["lsass", "sekurlsa", "mimikatz", "procdump"],
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "keywords": [
            "currentversion\\run",
            "runonce",
            "hklm\\software\\microsoft\\windows\\currentversion",
        ],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "keywords": ["schtasks", "/create", "scheduled task"],
    },
    "T1021.002": {
        "name": "SMB/Admin Shares",
        "keywords": ["admin$", "c$", "psexec", "paexec", "\\\\"],
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "keywords": ["certutil", "mshta", "regsvr32", "rundll32", "msiexec"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "keywords": ["vssadmin", "shadowcopy", "bcdedit", "recoveryenabled", "delete shadows"],
    },
    "T1055": {
        "name": "Process Injection",
        "keywords": ["createremotethread", "virtualallocex", "writeprocessmemory", "injection"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "keywords": ["base64", "frombase64", "encodedcommand", "iex", "invoke-expression"],
    },
}


def map_to_attack(query: str) -> List[Dict[str, str]]:
    """
    Map an XQL query to relevant MITRE ATT&CK techniques.

    Args:
        query: XQL query string

    Returns:
        List of dicts with technique_id, name, and confidence
    """
    query_lower = query.lower()
    matches = []

    for technique_id, info in ATTACK_PATTERNS.items():
        keyword_matches = sum(1 for kw in info["keywords"] if kw.lower() in query_lower)

        if keyword_matches > 0:
            # Determine confidence based on number of keyword matches
            if keyword_matches >= 3:
                confidence = "high"
            elif keyword_matches >= 2:
                confidence = "medium"
            else:
                confidence = "low"

            matches.append(
                {
                    "id": technique_id,
                    "name": info["name"],
                    "confidence": confidence,
                    "matched_keywords": keyword_matches,
                }
            )

    # Sort by confidence (high first) and number of matches
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda x: (confidence_order[x["confidence"]], -x["matched_keywords"]))

    return matches


# =============================================================================
# Detection Rule Builder
# =============================================================================


def create_detection_rule(
    query: str,
    name: str,
    description: str,
    severity: Severity = Severity.MEDIUM,
    false_positive_guidance: str = "",
) -> DetectionRule:
    """
    Create a detection rule from an XQL query.

    Args:
        query: Validated XQL query
        name: Rule name
        description: What the rule detects
        severity: Alert severity level
        false_positive_guidance: How to handle false positives

    Returns:
        DetectionRule object with all metadata
    """
    # Validate the query first
    validation = validate_xql_query(query)
    if not validation.is_valid:
        raise ValueError(f"Invalid XQL query: {validation.errors}")

    # Map to MITRE ATT&CK techniques
    techniques = map_to_attack(query)
    technique_ids = [t["id"] for t in techniques]

    # Generate default false positive guidance if not provided
    if not false_positive_guidance:
        false_positive_guidance = (
            "Review the process context and command line arguments. "
            "Check if the activity aligns with normal administrative tasks. "
            "Verify the user and endpoint are authorized for this activity."
        )

    return DetectionRule(
        name=name,
        description=description,
        query=query,
        severity=severity,
        mitre_techniques=technique_ids,
        false_positive_guidance=false_positive_guidance,
    )


def rule_to_json(rule: DetectionRule) -> str:
    """Convert a detection rule to JSON format."""
    return json.dumps(
        {
            "name": rule.name,
            "description": rule.description,
            "query": rule.query,
            "severity": rule.severity.value,
            "mitre_techniques": rule.mitre_techniques,
            "false_positive_guidance": rule.false_positive_guidance,
        },
        indent=2,
    )


# =============================================================================
# Main Demo
# =============================================================================


def main():
    """Demo the XQL threat hunting system."""
    print("=" * 60)
    print("Lab 21: XQL Threat Hunting with AI - Solution")
    print("=" * 60)

    # Test scenarios with expected queries
    scenarios = [
        {
            "description": "Detect encoded PowerShell commands",
            "query": """config case_sensitive = false
| dataset = xdr_data
| filter _time >= now() - 7d
| filter event_type = ENUM.PROCESS
| filter action_process_image_name contains "powershell"
| filter action_process_image_command_line contains "-enc" or action_process_image_command_line contains "-encodedcommand" or action_process_image_command_line contains "frombase64"
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, _time
| sort desc _time
| limit 1000""",
            "severity": Severity.HIGH,
        },
        {
            "description": "Find Mimikatz credential dumping attempts",
            "query": """config case_sensitive = false
| dataset = xdr_data
| filter _time >= now() - 7d
| filter event_type = ENUM.PROCESS
| filter action_process_image_command_line contains "sekurlsa" or action_process_image_command_line contains "mimikatz" or action_process_image_name contains "mimikatz" or action_process_image_command_line contains "lsass"
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, action_process_image_sha256, _time
| sort desc _time
| limit 1000""",
            "severity": Severity.CRITICAL,
        },
        {
            "description": "Hunt for lateral movement using PsExec",
            "query": """config case_sensitive = false
| dataset = xdr_data
| filter _time >= now() - 7d
| filter event_type = ENUM.PROCESS
| filter action_process_image_name in ("psexec.exe", "psexec64.exe", "paexec.exe") or action_process_image_command_line contains "\\\\admin$" or action_process_image_command_line contains "\\\\c$"
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, _time
| sort desc _time
| limit 1000""",
            "severity": Severity.HIGH,
        },
        {
            "description": "Detect ransomware shadow copy deletion",
            "query": """config case_sensitive = false
| dataset = xdr_data
| filter _time >= now() - 7d
| filter event_type = ENUM.PROCESS
| filter action_process_image_command_line contains "vssadmin" and action_process_image_command_line contains "delete" or action_process_image_command_line contains "shadowcopy" or (action_process_image_command_line contains "bcdedit" and action_process_image_command_line contains "recoveryenabled")
| fields agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line, _time
| sort desc _time
| limit 1000""",
            "severity": Severity.CRITICAL,
        },
    ]

    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'='*60}")
        print(f"[Scenario {i}] {scenario['description']}")
        print("=" * 60)

        query = scenario["query"]
        print(f"\nGenerated Query:\n{query}")

        # Validate the query
        validation = validate_xql_query(query)
        print(f"\n[Validation] {'PASSED' if validation.is_valid else 'FAILED'}")
        if validation.errors:
            print(f"  Errors: {validation.errors}")
        if validation.warnings:
            print(f"  Warnings: {validation.warnings}")
        if validation.suggestions:
            print(f"  Suggestions: {validation.suggestions}")

        # Map to MITRE ATT&CK
        techniques = map_to_attack(query)
        print(f"\n[MITRE ATT&CK Mapping]")
        for tech in techniques:
            print(f"  - {tech['id']}: {tech['name']} (confidence: {tech['confidence']})")

        # Create detection rule
        try:
            rule = create_detection_rule(
                query=query,
                name=f"TH-{i:03d}: {scenario['description']}",
                description=scenario["description"],
                severity=scenario["severity"],
            )
            print(f"\n[Detection Rule Created]")
            print(f"  Name: {rule.name}")
            print(f"  Severity: {rule.severity.value}")
            print(f"  Techniques: {rule.mitre_techniques}")
        except ValueError as e:
            print(f"\n[Error] Could not create rule: {e}")


if __name__ == "__main__":
    main()

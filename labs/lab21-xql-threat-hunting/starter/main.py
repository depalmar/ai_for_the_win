#!/usr/bin/env python3
"""
Lab 21: XQL Threat Hunting with AI

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

    TODO: Create a comprehensive system prompt that:
    - Establishes XQL expertise
    - Lists correct syntax patterns
    - Specifies required config statements
    - Includes common field names
    """
    # TODO: Implement this
    pass


def query_from_description(description: str, days: int = 7) -> str:
    """
    Generate an XQL query from a natural language description.

    Args:
        description: Natural language description of what to hunt for
        days: Number of days to look back (default: 7)

    Returns:
        Valid XQL query string

    Example:
        >>> query = query_from_description("Find encoded PowerShell commands")
        >>> print(query)
        config case_sensitive = false
        | dataset = xdr_data
        | filter event_type = ENUM.PROCESS
        ...
    """
    # TODO: Implement this using your preferred LLM
    # 1. Create the system prompt
    # 2. Build the user prompt with the description
    # 3. Call the LLM
    # 4. Extract and return the query
    pass


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

    Checks performed:
    - Valid dataset name
    - Proper ENUM usage for event types
    - Time filter presence
    - Config statements
    - Common syntax issues
    """
    errors = []
    warnings = []
    suggestions = []

    # TODO: Implement validation checks

    # Check 1: Dataset validation
    # Look for "dataset = " and verify it's a valid dataset

    # Check 2: Event type ENUM validation
    # If filtering event_type, ensure ENUM is used

    # Check 3: Time filter check
    # Warn if no time filtering is present

    # Check 4: Config statements
    # Suggest adding config case_sensitive = false if missing

    # Check 5: Limit check
    # Warn if no limit is specified

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
        "keywords": ["powershell", "pwsh", "-enc", "-encodedcommand"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "keywords": ["cmd.exe", "command"],
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "keywords": ["lsass", "sekurlsa", "mimikatz", "procdump"],
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "keywords": ["currentversion\\run", "runonce"],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "keywords": ["schtasks", "/create", "scheduled"],
    },
    "T1021.002": {
        "name": "SMB/Admin Shares",
        "keywords": ["admin$", "c$", "psexec", "paexec"],
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "keywords": [
            "certutil",
            "mshta",
            "regsvr32",
            "rundll32",
            "msiexec",
        ],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "keywords": ["vssadmin", "shadowcopy", "bcdedit", "recoveryenabled"],
    },
}


def map_to_attack(query: str) -> List[Dict[str, str]]:
    """
    Map an XQL query to relevant MITRE ATT&CK techniques.

    Args:
        query: XQL query string

    Returns:
        List of dicts with technique_id, name, and confidence

    Example:
        >>> techniques = map_to_attack(query_with_powershell)
        >>> print(techniques)
        [{"id": "T1059.001", "name": "PowerShell", "confidence": "high"}]
    """
    # TODO: Implement pattern matching against ATTACK_PATTERNS
    # 1. Normalize the query (lowercase)
    # 2. Check for keyword matches
    # 3. Return matched techniques with confidence scores
    pass


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
    # TODO: Implement this
    # 1. Validate the query first
    # 2. Map to MITRE ATT&CK techniques
    # 3. Build and return the DetectionRule
    pass


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
    print("Lab 21: XQL Threat Hunting with AI")
    print("=" * 60)

    # Test scenarios
    scenarios = [
        "Detect encoded PowerShell commands that might indicate malicious activity",
        "Find Mimikatz credential dumping attempts",
        "Hunt for lateral movement using PsExec or similar tools",
        "Detect ransomware indicators like shadow copy deletion",
    ]

    for i, scenario in enumerate(scenarios, 1):
        print(f"\n[Scenario {i}] {scenario}")
        print("-" * 50)

        # TODO: Uncomment when functions are implemented
        # query = query_from_description(scenario)
        # print(f"\nGenerated Query:\n{query}")

        # validation = validate_xql_query(query)
        # print(f"\nValidation: {'PASSED' if validation.is_valid else 'FAILED'}")
        # if validation.errors:
        #     print(f"Errors: {validation.errors}")
        # if validation.suggestions:
        #     print(f"Suggestions: {validation.suggestions}")

        # techniques = map_to_attack(query)
        # print(f"\nMITRE ATT&CK Mapping: {techniques}")

        print("\n(Implement the functions to see results)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Lab 07b: Sigma Rule Fundamentals - Solution

Complete implementation of Sigma rule creation, validation, and conversion.
"""

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()

# Check for optional dependencies
try:
    from sigma.rule import SigmaRule as PySigmaRule

    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False


# =============================================================================
# Test-Compatible SigmaRule Dataclass
# =============================================================================


@dataclass
class SigmaRule:
    """Simple Sigma rule representation for testing."""

    title: str
    description: str
    logsource: dict
    detection: dict
    level: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "experimental"
    author: str = "AI for the Win Labs"
    tags: list = field(default_factory=list)
    falsepositives: list = field(default_factory=list)


def parse_sigma_rule(yaml_content: str) -> SigmaRule:
    """
    Parse a YAML Sigma rule into a SigmaRule object.

    Args:
        yaml_content: YAML string containing the Sigma rule

    Returns:
        SigmaRule object
    """
    data = yaml.safe_load(yaml_content)

    return SigmaRule(
        title=data.get("title", "Unknown"),
        description=data.get("description", ""),
        logsource=data.get("logsource", {}),
        detection=data.get("detection", {}),
        level=data.get("level", "medium"),
        id=data.get("id", str(uuid.uuid4())),
        status=data.get("status", "experimental"),
        author=data.get("author", "Unknown"),
        tags=data.get("tags", []),
        falsepositives=data.get("falsepositives", []),
    )


def match_log_event(rule: SigmaRule, event: dict) -> bool:
    """
    Check if a log event matches a Sigma rule's detection logic.

    This is a simplified matcher that handles basic field matching
    and the |contains modifier.

    Args:
        rule: SigmaRule object
        event: Dictionary representing a log event

    Returns:
        True if event matches, False otherwise
    """
    detection = rule.detection
    condition = detection.get("condition", "selection")

    # Get all selection blocks
    selections = {}
    for key, value in detection.items():
        if key != "condition" and isinstance(value, dict):
            selections[key] = value

    def match_selection(selection: dict, event: dict) -> bool:
        """Check if event matches a selection block."""
        for field_spec, expected in selection.items():
            # Handle modifiers like |contains
            if "|" in field_spec:
                field_name, modifier = field_spec.split("|", 1)
            else:
                field_name = field_spec
                modifier = None

            event_value = event.get(field_name)

            if event_value is None:
                return False

            # Handle list of possible values
            if isinstance(expected, list):
                if modifier == "contains":
                    if not any(str(exp).lower() in str(event_value).lower() for exp in expected):
                        return False
                else:
                    if event_value not in expected:
                        return False
            else:
                if modifier == "contains":
                    if str(expected).lower() not in str(event_value).lower():
                        return False
                else:
                    if event_value != expected:
                        return False

        return True

    # Simple condition parsing - just check if "selection" matches
    if "selection" in selections:
        return match_selection(selections["selection"], event)

    # Try to match any selection
    for sel_name, sel_value in selections.items():
        if match_selection(sel_value, event):
            return True

    return False


try:
    from anthropic import Anthropic

    ANTHROPIC_AVAILABLE = bool(os.getenv("ANTHROPIC_API_KEY"))
except ImportError:
    ANTHROPIC_AVAILABLE = False


# =============================================================================
# Task 1: Mimikatz Detection Rule
# =============================================================================


def create_mimikatz_rule() -> str:
    """
    Create a Sigma rule to detect Mimikatz execution.

    Covers:
    - Known process names
    - Command line patterns
    - Renamed binaries with suspicious cmdline
    """
    rule_id = str(uuid.uuid4())

    rule = f"""title: Mimikatz Credential Theft Tool Execution
id: {rule_id}
status: production
description: |
    Detects execution of Mimikatz credential dumping tool based on
    known process names and command line patterns. Covers renamed binaries.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
author: AI for the Win Labs
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: process_creation
    product: windows

detection:
    # Known Mimikatz process names
    selection_name:
        Image|endswith:
            - '\\mimikatz.exe'
            - '\\mimikatz64.exe'
            - '\\mimi.exe'
            - '\\mimi64.exe'

    # Mimikatz command line patterns (catches renamed binaries)
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'crypto::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'token::elevate'
            - 'vault::cred'
            - 'dpapi::'

    # Short renamed binaries with suspicious cmdline
    selection_renamed:
        Image|endswith:
            - '\\m.exe'
            - '\\mk.exe'
            - '\\mi.exe'
        CommandLine|contains:
            - '::'

    condition: selection_name or selection_cmdline or selection_renamed

falsepositives:
    - Security testing and red team activities
    - Legitimate security tools that use similar patterns

level: critical

tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
"""
    return rule


# =============================================================================
# Task 2: Encoded PowerShell Detection
# =============================================================================


def create_encoded_powershell_rule() -> str:
    """Create a rule for encoded PowerShell detection with modifiers."""
    rule_id = str(uuid.uuid4())

    rule = f"""title: Encoded PowerShell Command Execution
id: {rule_id}
status: production
description: |
    Detects PowerShell execution with encoded commands, commonly used
    by malware, fileless attacks, and adversary toolkits to evade detection.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1027/
author: AI for the Win Labs
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: process_creation
    product: windows

detection:
    selection_exe:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'

    selection_encoded:
        CommandLine|contains:
            - ' -enc '
            - ' -e '
            - ' -ec '
            - ' -encodedcommand '
            - ' -enco '

    selection_hidden:
        CommandLine|contains:
            - '-w hidden'
            - '-window hidden'
            - '-windowstyle hidden'
            - '-nop'
            - '-noprofile'

    selection_download:
        CommandLine|contains:
            - 'downloadstring'
            - 'downloadfile'
            - 'iex'
            - 'invoke-expression'
            - 'frombase64string'

    # Filter legitimate short encoded commands
    filter_short_encoded:
        CommandLine|re: '-e(nc|c|nco)?\s+[A-Za-z0-9+/=]{{1,100}}$'

    condition: selection_exe and (selection_encoded or (selection_hidden and selection_download)) and not filter_short_encoded

falsepositives:
    - Administrative scripts using encoding for special characters
    - Software deployment tools
    - Configuration management systems

level: high

tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
"""
    return rule


# =============================================================================
# Task 3: Credential Dumping Chain
# =============================================================================


def create_credential_dump_chain_rule() -> str:
    """Create a rule for credential dumping attack chain."""
    rule_id = str(uuid.uuid4())

    rule = f"""title: Credential Dumping Attack Chain
id: {rule_id}
status: production
description: |
    Detects various credential dumping techniques including memory dumps,
    SAM database access, and NTDS extraction.
author: AI for the Win Labs
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: process_creation
    product: windows

detection:
    # Procdump LSASS dump
    procdump:
        Image|endswith:
            - '\\procdump.exe'
            - '\\procdump64.exe'
        CommandLine|contains|all:
            - '-ma'
            - 'lsass'

    # Comsvcs.dll MiniDump
    comsvcs:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'

    # SAM/SYSTEM registry save
    reg_save:
        Image|endswith: '\\reg.exe'
        CommandLine|contains:
            - 'save'
            - 'sam'
        CommandLine|contains:
            - 'save'
            - 'system'

    # NTDS.dit extraction
    ntds:
        CommandLine|contains:
            - 'ntdsutil'
            - 'vssadmin'
        CommandLine|contains:
            - 'ntds'
            - 'shadow'

    # Task Manager LSASS dump (GUI)
    taskmgr_dump:
        Image|endswith: '\\taskmgr.exe'
        CommandLine|contains: 'lsass'

    condition: procdump or comsvcs or reg_save or ntds or taskmgr_dump

falsepositives:
    - Legitimate memory dump for troubleshooting
    - Backup operations by administrators

level: critical

tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.003
"""
    return rule


# =============================================================================
# Task 4: LLM-Assisted Rule Generation
# =============================================================================


def generate_sigma_rule(
    description: str,
    mitre_technique: Optional[str] = None,
    severity: str = "high",
) -> str:
    """
    Use LLM to generate a Sigma rule from natural language description.

    Args:
        description: What attack/behavior to detect
        mitre_technique: Optional ATT&CK technique ID
        severity: Rule severity level

    Returns:
        Valid Sigma rule YAML
    """
    if not ANTHROPIC_AVAILABLE:
        return f"# LLM not available - manual rule creation required\n# Description: {description}"

    client = Anthropic()

    prompt = f"""Generate a production-quality Sigma detection rule for:

DETECTION REQUIREMENT:
{description}

{"MITRE ATT&CK Technique: " + mitre_technique if mitre_technique else ""}
Severity Level: {severity}

REQUIREMENTS:
1. Use proper Sigma syntax with all required fields:
   - title, id (UUID format), status, description
   - logsource (category, product)
   - detection (selections and condition)
   - level, tags

2. Use appropriate field modifiers:
   - |endswith for executable paths
   - |contains for command line patterns
   - |contains|all when ALL patterns must match

3. Include realistic false positive guidance

4. Map to MITRE ATT&CK tags (format: attack.tXXXX.XXX)

5. Add author as "AI for the Win Labs" and today's date

Return ONLY valid YAML, no markdown code blocks or explanation."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )

    return response.content[0].text


# =============================================================================
# Task 5: Rule Validation
# =============================================================================


def validate_sigma_rule(yaml_rule: str) -> dict:
    """
    Validate a Sigma rule and provide feedback.

    Returns:
        {
            "valid": bool,
            "errors": list,
            "warnings": list,
            "rule_title": str
        }
    """
    result = {"valid": False, "errors": [], "warnings": [], "rule_title": None}

    if not SIGMA_AVAILABLE:
        result["errors"].append("pySigma not installed")
        return result

    try:
        rule = PySigmaRule.from_yaml(yaml_rule)
        result["valid"] = True
        result["rule_title"] = rule.title

        # Check for best practices
        if not rule.tags:
            result["warnings"].append("No MITRE ATT&CK tags defined")
        if not rule.falsepositives:
            result["warnings"].append("No false positive guidance provided")
        if rule.status == "experimental":
            result["warnings"].append("Rule is marked as experimental")

    except Exception as e:
        result["errors"].append(str(e))

    return result


def convert_to_siem(yaml_rule: str, backend: str = "splunk") -> str:
    """
    Convert Sigma rule to SIEM-specific query.

    Args:
        yaml_rule: Valid Sigma rule YAML
        backend: Target SIEM (splunk, elastic, qradar)

    Returns:
        SIEM query string
    """
    if not SIGMA_AVAILABLE:
        return "# Conversion requires pySigma"

    try:
        rule = PySigmaRule.from_yaml(yaml_rule)

        if backend == "splunk":
            try:
                from sigma.backends.splunk import SplunkBackend
                from sigma.pipelines.splunk import splunk_windows_pipeline

                converter = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
                return converter.convert_rule(rule)[0]
            except ImportError:
                return "# pip install pysigma-backend-splunk"

        elif backend == "elastic":
            try:
                from sigma.backends.elasticsearch import LuceneBackend

                converter = LuceneBackend()
                return converter.convert_rule(rule)[0]
            except ImportError:
                return "# pip install pysigma-backend-elasticsearch"

        else:
            return f"# Backend '{backend}' not supported"

    except Exception as e:
        return f"# Conversion error: {e}"


# =============================================================================
# Demo Rules Library
# =============================================================================

SAMPLE_RULES = {
    "encoded_powershell": create_encoded_powershell_rule,
    "mimikatz": create_mimikatz_rule,
    "credential_dump": create_credential_dump_chain_rule,
}


# =============================================================================
# Main
# =============================================================================


def main():
    """Demonstrate Sigma rule creation and validation."""
    print("=" * 60)
    print("Lab 07b: Sigma Rule Fundamentals - Solution")
    print("=" * 60)

    # Task 1: Create Mimikatz rule
    print("\n📋 Task 1: Mimikatz Detection Rule")
    print("-" * 40)
    mimikatz_rule = create_mimikatz_rule()
    print(mimikatz_rule[:500] + "...")

    # Validate
    if SIGMA_AVAILABLE:
        result = validate_sigma_rule(mimikatz_rule)
        print(f"\n✅ Valid: {result['valid']}")
        if result["warnings"]:
            print(f"⚠️  Warnings: {result['warnings']}")

    # Task 2: Encoded PowerShell
    print("\n📋 Task 2: Encoded PowerShell Rule")
    print("-" * 40)
    ps_rule = create_encoded_powershell_rule()
    print(ps_rule[:500] + "...")

    # Task 3: Credential dump chain
    print("\n📋 Task 3: Credential Dumping Chain")
    print("-" * 40)
    cred_rule = create_credential_dump_chain_rule()
    print(cred_rule[:500] + "...")

    # Task 4: LLM generation
    print("\n📋 Task 4: LLM-Generated Rule")
    print("-" * 40)
    if ANTHROPIC_AVAILABLE:
        llm_rule = generate_sigma_rule(
            "Detect certutil.exe being used to download files from the internet",
            mitre_technique="T1105",
        )
        print(llm_rule[:600] + "...")
    else:
        print("⚠️  Set ANTHROPIC_API_KEY to enable LLM generation")

    # Task 5: Conversion demo
    print("\n📋 Task 5: SIEM Conversion")
    print("-" * 40)
    if SIGMA_AVAILABLE:
        splunk_query = convert_to_siem(mimikatz_rule, "splunk")
        print(f"Splunk SPL:\n{splunk_query[:200]}...")
    else:
        print("⚠️  Install pysigma for conversion: pip install pysigma")

    print("\n" + "=" * 60)
    print("✅ Lab complete! You now know how to create Sigma rules.")
    print("=" * 60)


if __name__ == "__main__":
    main()

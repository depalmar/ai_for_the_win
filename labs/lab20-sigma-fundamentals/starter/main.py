#!/usr/bin/env python3
"""
Lab 07b: Sigma Rule Fundamentals - Starter

Learn to create, validate, and generate Sigma detection rules.

Complete the TODOs to build your Sigma rule creation skills.
"""

import os
import uuid
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# Task 1: Create Your First Sigma Rule
# =============================================================================


def create_mimikatz_rule() -> str:
    """
    Create a Sigma rule to detect Mimikatz execution.

    Mimikatz is a credential theft tool. Detection should cover:
    - Known process names: mimikatz.exe, mimi.exe, mimikatz64.exe
    - Command line patterns: sekurlsa::, privilege::debug, lsadump::
    - Renamed binaries: m.exe, mk.exe (with suspicious cmdline)

    TODO:
    1. Generate a UUID for the rule id
    2. Fill in the logsource (process_creation on windows)
    3. Create selection for process names using |endswith modifier
    4. Create selection for command line patterns using |contains
    5. Define the condition to match either selection
    6. Add MITRE ATT&CK tags (T1003.001 for credential dumping)

    Hint: Use |endswith for Image paths, |contains for CommandLine
    """
    rule_id = str(uuid.uuid4())

    rule = f"""title: Mimikatz Credential Theft Tool Detection
id: {rule_id}
status: experimental
description: |
    TODO: Add description of what this rule detects
author: Your Name
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: # TODO: What type of logs? (process_creation, network, etc.)
    product: # TODO: What OS? (windows, linux, etc.)

detection:
    # Selection for known Mimikatz process names
    selection_name:
        # TODO: Use Image|endswith to match process paths
        # Examples: '\\mimikatz.exe', '\\mimi.exe'
        pass

    # Selection for Mimikatz command line patterns
    selection_cmdline:
        # TODO: Use CommandLine|contains to match patterns
        # Examples: 'sekurlsa::', 'privilege::debug'
        pass

    condition: # TODO: How should selections combine? (or / and)

falsepositives:
    - # TODO: What legitimate activities might trigger this?

level: # TODO: What severity? (informational, low, medium, high, critical)

tags:
    # TODO: Add MITRE ATT&CK tags
    # Format: attack.tactic, attack.technique_id
"""
    return rule


# =============================================================================
# Task 2: Using Field Modifiers
# =============================================================================


def create_encoded_powershell_rule() -> str:
    """
    Create a rule to detect encoded PowerShell execution.

    Common patterns:
    - powershell.exe with -enc, -e, -encodedcommand parameters
    - Hidden window: -w hidden, -windowstyle hidden
    - No profile: -nop, -noprofile
    - Download cradles: downloadstring, iex

    TODO:
    1. Use |endswith for PowerShell executable paths
    2. Use |contains for encoded command parameters
    3. Use |contains|all when ALL patterns must match
    4. Add filter for legitimate short encoded commands
    5. Create a compound condition

    Field modifiers to use:
    - |endswith: matches end of string
    - |contains: matches substring
    - |contains|all: ALL listed values must match
    - |re: regex pattern (use sparingly)
    """
    rule_id = str(uuid.uuid4())

    rule = f"""title: Encoded PowerShell Command Execution
id: {rule_id}
status: experimental
description: Detects PowerShell with encoded command parameter

logsource:
    category: process_creation
    product: windows

detection:
    selection_exe:
        # TODO: Match powershell.exe and pwsh.exe using |endswith

    selection_encoded:
        # TODO: Match encoding parameters using |contains
        # Patterns: ' -enc ', ' -e ', ' -encodedcommand '

    selection_hidden:
        # TODO: Match hidden window parameters

    condition: # TODO: Combine selections appropriately

level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    return rule


# =============================================================================
# Task 3: Correlation / Chain Rules
# =============================================================================


def create_credential_dump_chain_rule() -> str:
    """
    Create a rule that detects credential dumping attack chain.

    This should detect multiple credential dumping techniques:
    1. Procdump targeting LSASS
    2. Comsvcs.dll MiniDump
    3. SAM/SYSTEM registry saves
    4. NTDS.dit extraction

    TODO:
    1. Create selection for each technique
    2. Use |contains|all when process AND cmdline must match
    3. Combine with OR condition (any technique = alert)
    """
    rule_id = str(uuid.uuid4())

    rule = f"""title: Credential Dumping Attack Chain
id: {rule_id}
status: experimental
description: Detects various credential dumping techniques

logsource:
    category: process_creation
    product: windows

detection:
    # TODO: Add selection for procdump -ma lsass

    # TODO: Add selection for comsvcs MiniDump

    # TODO: Add selection for reg save sam/system

    # TODO: Add selection for ntdsutil/vssadmin

    condition: # TODO: OR all selections together

level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
"""
    return rule


# =============================================================================
# Task 4: LLM-Assisted Rule Generation
# =============================================================================


def generate_sigma_rule(
    description: str,
    mitre_technique: Optional[str] = None,
) -> str:
    """
    Use LLM to generate a Sigma rule from natural language.

    TODO:
    1. Import Anthropic client
    2. Create a prompt that instructs the LLM to:
       - Generate valid Sigma YAML syntax
       - Include all required fields
       - Use appropriate modifiers
       - Add MITRE ATT&CK mapping
    3. Call the API and return the response

    Args:
        description: What to detect (e.g., "PsExec remote execution")
        mitre_technique: Optional ATT&CK ID (e.g., "T1569.002")

    Returns:
        Valid Sigma rule YAML string
    """
    # TODO: Check if API key is available
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return f"# API key not set - description was: {description}"

    # TODO: Import and create Anthropic client
    # from anthropic import Anthropic
    # client = Anthropic()

    # TODO: Create prompt for LLM
    prompt = f"""
    # Your prompt here
    # Ask for Sigma rule generation
    # Include requirements for valid syntax
    """

    # TODO: Call API and return response
    # response = client.messages.create(...)
    # return response.content[0].text

    return "# TODO: Implement LLM generation"


# =============================================================================
# Task 5: Rule Validation
# =============================================================================


def validate_sigma_rule(yaml_rule: str) -> dict:
    """
    Validate a Sigma rule for syntax and best practices.

    TODO:
    1. Try to import pySigma (SigmaRule)
    2. Parse the YAML rule
    3. Check for required fields
    4. Return validation result

    Returns:
        {
            "valid": bool,
            "errors": list of error messages,
            "warnings": list of warnings
        }
    """
    result = {"valid": False, "errors": [], "warnings": []}

    # TODO: Try to parse with pySigma
    # try:
    #     from sigma.rule import SigmaRule
    #     rule = SigmaRule.from_yaml(yaml_rule)
    #     result["valid"] = True
    # except Exception as e:
    #     result["errors"].append(str(e))

    # TODO: Add warnings for missing best practices
    # - No tags = warning
    # - No falsepositives = warning

    return result


# =============================================================================
# Main
# =============================================================================


def main():
    """Run the lab exercises."""
    print("=" * 60)
    print("Lab 07b: Sigma Rule Fundamentals - Starter")
    print("=" * 60)

    print("\n📋 Task 1: Create Mimikatz Rule")
    print("-" * 40)
    rule1 = create_mimikatz_rule()
    print(rule1)
    print("\n⚠️  Complete the TODOs in create_mimikatz_rule()")

    print("\n📋 Task 2: Encoded PowerShell Rule")
    print("-" * 40)
    rule2 = create_encoded_powershell_rule()
    print(rule2)
    print("\n⚠️  Complete the TODOs in create_encoded_powershell_rule()")

    print("\n📋 Task 3: Credential Dump Chain")
    print("-" * 40)
    rule3 = create_credential_dump_chain_rule()
    print(rule3)

    print("\n📋 Task 4: LLM Generation")
    print("-" * 40)
    rule4 = generate_sigma_rule("Detect certutil downloading files", "T1105")
    print(rule4)

    print("\n📋 Task 5: Validation")
    print("-" * 40)
    result = validate_sigma_rule(rule1)
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")

    print("\n" + "=" * 60)
    print("Complete the TODOs, then compare with solution/main.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

# Lab 20: Sigma Rule Fundamentals

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Lab 35, Lab 21

Learn to create, test, and generate Sigma detection rules for log-based threat detection.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand Sigma rule syntax and structure
2. Write rules for common attack patterns
3. Use LLMs to generate Sigma rules from descriptions
4. Convert rules to SIEM-specific formats
5. Test rules against sample logs

---

## 📖 Background

### What is Sigma?

**Sigma** is the industry standard for log-based detection rules. It's like YARA for logs:

| Comparison | YARA | Sigma |
|------------|------|-------|
| **Target** | Files/Memory | Logs/Events |
| **Use Case** | Malware detection | Threat detection |
| **Converts to** | File scanners | SIEM queries |

### Why Sigma Matters

```
┌───────────────────────────────────────────────────────────────┐
│                     ONE SIGMA RULE                            │
│                           ↓                                   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌─────────┐ │
│  │Elasticsearch│  │ OpenSearch │  │   Wazuh    │  │  SIEM   │ │
│  │   EQL      │  │  KQL/EQL   │  │   Rules    │  │Queries  │ │
│  └────────────┘  └────────────┘  └────────────┘  └─────────┘ │
└───────────────────────────────────────────────────────────────┘
```

Write once, deploy everywhere. No more manually translating detection logic!

---

## 🔬 Sigma Rule Structure

### Basic Anatomy

```yaml
title: Encoded PowerShell Execution              # What it detects
id: a12b3c4d-5678-9012-abcd-ef1234567890         # Unique identifier
status: production                                # test/experimental/production
description: |
    Detects PowerShell execution with encoded commands,
    commonly used by malware and adversaries
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Your Name
date: 2025/01/02
modified: 2025/01/02

# Log source - CRITICAL: tells converters which logs to query
logsource:
    category: process_creation
    product: windows

# Detection logic
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - ' -e '
    filter_legitimate:
        User|contains: 'SYSTEM'
        CommandLine|contains: 'ConfigurationScript'
    condition: selection and not filter_legitimate

# Context
falsepositives:
    - Legitimate admin scripts using encoding
    - Software deployment tools
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

### Key Components

| Section | Purpose | Required |
|---------|---------|----------|
| `title` | Human-readable name | ✅ Yes |
| `id` | UUID for tracking | ✅ Yes |
| `logsource` | Which logs to search | ✅ Yes |
| `detection` | The actual logic | ✅ Yes |
| `level` | Severity (info→critical) | ✅ Yes |
| `status` | Rule maturity | No |
| `tags` | MITRE ATT&CK mapping | No |
| `falsepositives` | Known FPs | No |

---

## 🔬 Lab Tasks

### Task 1: Write Your First Sigma Rule (15 min)

Create a rule to detect Mimikatz execution:

```python
# starter/main.py

def create_mimikatz_rule() -> str:
    """
    Create a Sigma rule to detect Mimikatz.

    Mimikatz indicators:
    - Process names: mimikatz.exe, mimi.exe, mimikatz64.exe
    - Command line: sekurlsa::, privilege::debug, lsadump::
    - Common renamed: m.exe, mk.exe (with same cmdline)

    TODO:
    1. Define logsource (process_creation, windows)
    2. Create selection for process names
    3. Create selection for command line patterns
    4. Add MITRE ATT&CK tags (T1003.001)
    5. Return valid YAML string
    """
    rule = """
title: Mimikatz Execution Detection
id: # TODO: Generate UUID
status: experimental
description: # TODO: Add description
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        # TODO: Add process name patterns
    selection_cmdline:
        # TODO: Add command line patterns
    condition: # TODO: Define condition
level: critical
tags:
    # TODO: Add MITRE tags
"""
    return rule
```

### Task 2: Detection Modifiers (10 min)

Sigma provides powerful field modifiers:

```yaml
# String modifiers
Image|endswith: '\powershell.exe'      # Ends with
Image|startswith: 'C:\Windows\'         # Starts with
Image|contains: 'temp'                  # Contains
Image|contains|all:                     # Contains ALL
    - 'temp'
    - 'script'

# Case handling
CommandLine|contains: 'MIMIKATZ'        # Case-sensitive
CommandLine|contains|all:               # All must match

# Regex (use sparingly - slow!)
CommandLine|re: '.*-enc\s+[A-Za-z0-9+/=]{20,}'

# Base64 detection
CommandLine|base64offset|contains: 'http'  # Encoded string

# Numeric comparisons
EventID: 4688                           # Exact match
EventID|gt: 4000                        # Greater than
```

**Exercise:** Write detection for encoded PowerShell with base64:

```python
def create_encoded_powershell_rule() -> str:
    """
    Detect PowerShell with base64 encoded commands.

    Patterns to detect:
    - -enc followed by base64 string
    - -encodedcommand parameter
    - FromBase64String in script

    TODO: Use appropriate modifiers
    """
    pass
```

### Task 3: Correlation Rules (10 min)

Detect attack chains with multiple events:

```yaml
title: Potential Credential Dumping Chain
description: Detects sequence of events indicating credential theft

logsource:
    category: process_creation
    product: windows

detection:
    # Stage 1: Privilege escalation tool
    stage1:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
        CommandLine|contains: '-ma'

    # Stage 2: LSASS access
    stage2:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'

    # Combine with timeframe
    condition: stage1 or stage2
    # Note: True correlation requires SIEM-side aggregation

level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Task 4: LLM-Assisted Rule Generation (15 min)

Use AI to generate rules from descriptions:

```python
from anthropic import Anthropic

def generate_sigma_rule(description: str, mitre_technique: str = None) -> str:
    """
    Use LLM to generate a Sigma rule from natural language.

    Args:
        description: What to detect (e.g., "PsExec remote execution")
        mitre_technique: Optional ATT&CK ID (e.g., "T1569.002")

    Returns:
        Valid Sigma rule YAML
    """
    client = Anthropic()

    prompt = f"""Generate a Sigma detection rule for the following:

DETECTION REQUIREMENT:
{description}

{"MITRE ATT&CK: " + mitre_technique if mitre_technique else ""}

REQUIREMENTS:
1. Use proper Sigma syntax (title, id, logsource, detection, level, tags)
2. Include appropriate logsource (category, product)
3. Use field modifiers where appropriate (endswith, contains, etc.)
4. Add realistic false positive guidance
5. Map to MITRE ATT&CK if applicable
6. Set appropriate severity level

Return ONLY the YAML rule, no explanation."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    return response.content[0].text


# Example usage
rule = generate_sigma_rule(
    "Detect certutil.exe downloading files from the internet",
    "T1105"
)
print(rule)
```

### Task 5: Rule Validation & Testing (10 min)

Validate your rules with pySigma:

```python
# pip install pysigma pysigma-backend-elasticsearch

from sigma.rule import SigmaRule
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows

def validate_and_convert(yaml_rule: str) -> dict:
    """
    Validate a Sigma rule and convert to Elasticsearch query.

    Returns:
        {
            "valid": bool,
            "errors": list,
            "elasticsearch": str
        }
    """
    result = {"valid": False, "errors": [], "elasticsearch": None}

    try:
        # Parse rule
        rule = SigmaRule.from_yaml(yaml_rule)
        result["valid"] = True

        # Convert to Elasticsearch
        backend = LuceneBackend(processing_pipeline=ecs_windows())
        result["elasticsearch"] = backend.convert_rule(rule)[0]

    except Exception as e:
        result["errors"].append(str(e))

    return result


def test_rule_against_logs(rule_yaml: str, logs: list) -> list:
    """
    Test a Sigma rule against sample logs.

    Returns list of matching log entries.
    """
    # Parse rule to extract detection logic
    rule = SigmaRule.from_yaml(rule_yaml)

    matches = []
    for log in logs:
        # Simplified matching - real implementation uses backends
        if matches_detection(log, rule.detection):
            matches.append(log)

    return matches
```

---

## 📁 Files

```
Lab 49-sigma-fundamentals/
├── README.md
├── starter/
│   └── main.py          # Exercises with TODOs
├── solution/
│   └── main.py          # Complete solutions
└── rules/
    ├── execution/
    │   ├── encoded_powershell.yml
    │   ├── office_spawn_shell.yml
    │   └── mshta_execution.yml
    ├── credential_access/
    │   ├── mimikatz.yml
    │   ├── lsass_dump.yml
    │   └── sam_access.yml
    └── lateral_movement/
        ├── psexec.yml
        └── wmi_remote.yml
```

---

## 📚 Sample Rules Library

### Execution: Encoded PowerShell

```yaml
title: Encoded PowerShell Command Line
id: f7c4f6a9-4b0d-4b3c-8b5a-6c7d8e9f0a1b
status: production
description: Detects PowerShell with encoded command parameter
author: AI for the Win
date: 2025/01/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -e '
            - ' -encodedcommand '
            - ' -ec '
    filter_short:
        CommandLine|re: '-e(nc)?\s+.{1,50}$'  # Too short = likely legitimate
    condition: selection and not filter_short
falsepositives:
    - Administrative scripts
    - Software deployment
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

### Credential Access: LSASS Memory Dump

```yaml
title: LSASS Memory Dump via Procdump
id: 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: production
description: Detects LSASS memory dumping using Procdump
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
        CommandLine|contains|all:
            - '-ma'
            - 'lsass'
    condition: selection
falsepositives:
    - Legitimate troubleshooting by admins
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Lateral Movement: PsExec

```yaml
title: PsExec Remote Execution
id: 3b4c5d6e-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: production
description: Detects PsExec tool execution for remote commands
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        Image|endswith:
            - '\psexec.exe'
            - '\psexec64.exe'
        CommandLine|contains: '\\'
    selection_service:
        Image|endswith: '\psexesvc.exe'
    condition: selection_tool or selection_service
falsepositives:
    - Legitimate admin tools
    - Software deployment
level: high
tags:
    - attack.lateral_movement
    - attack.t1569.002
    - attack.t1021.002
```

---

## ✅ Success Criteria

- [ ] Created valid Mimikatz detection rule
- [ ] Used appropriate field modifiers
- [ ] Generated rule using LLM
- [ ] Validated rule syntax with pySigma
- [ ] Converted to at least one SIEM format
- [ ] Tested against sample logs

---

## 🚀 Bonus Challenges

1. **Rule Optimization**: Reduce false positives while maintaining detection
2. **Chain Detection**: Create rules that detect multi-stage attacks
3. **Rule Repository**: Build a library of rules for your organization
4. **Auto-Tuning**: Use LLM to suggest filter improvements
5. **SIEM Integration**: Deploy rules to your actual SIEM

---

## 📚 Resources

- [Sigma Repository](https://github.com/SigmaHQ/sigma) - Official rules
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma](https://github.com/SigmaHQ/pySigma) - Python library
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) - Command-line tool
- [MITRE ATT&CK](https://attack.mitre.org/) - Technique mapping

---

> 🌉 **Bridge Lab**: This lab connects YARA (Lab 21) with Detection Pipelines (Lab 23). After completing this, you'll be ready to build production detection systems that output real Sigma rules.

**Next Lab**: [Lab 22 - Vulnerability Scanner AI](../lab22-vuln-scanner-ai/) or continue to [Lab 23 - Detection Pipeline](../lab23-detection-pipeline/)

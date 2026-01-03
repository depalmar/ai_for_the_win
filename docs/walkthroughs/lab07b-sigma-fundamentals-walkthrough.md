# Lab 07b Walkthrough: Sigma Rule Fundamentals

## Overview

This walkthrough guides you through creating Sigma detection rules - the industry standard for vendor-agnostic log-based threat detection. You'll learn to write rules manually, generate them with LLMs, and convert them for any SIEM.

**Time to complete walkthrough:** 35-45 minutes

---

## Step 1: Understanding Sigma's Purpose

### The Problem Sigma Solves

```
WITHOUT SIGMA:
┌─────────────────────────────────────────────────────────────────┐
│  One detection concept = Multiple implementations               │
│                                                                 │
│  "Detect encoded PowerShell"                                    │
│      ↓                                                          │
│  Splunk:   index=windows sourcetype=WinEventLog:Security...    │
│  Elastic:  event.code:4688 AND process.command_line:*-enc*     │
│  Sentinel: SecurityEvent | where CommandLine contains "-enc"   │
│  QRadar:   SELECT * FROM events WHERE LOGSOURCETYPENAME...     │
└─────────────────────────────────────────────────────────────────┘

WITH SIGMA:
┌─────────────────────────────────────────────────────────────────┐
│  One Sigma rule → Automatically converts to any SIEM            │
│                                                                 │
│  encoded_powershell.yml  ──→  Splunk SPL                       │
│                          ──→  Elastic KQL                       │
│                          ──→  Sentinel KQL                      │
│                          ──→  QRadar AQL                        │
└─────────────────────────────────────────────────────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Logsource** | What type of logs to search (process_creation, network, etc.) |
| **Detection** | The actual matching logic |
| **Condition** | How detection elements combine (and, or, not) |
| **Backend** | Target SIEM format (Splunk, Elastic, etc.) |
| **Pipeline** | Field name mappings for specific SIEMs |

---

## Step 2: Anatomy of a Sigma Rule

### Required Fields

```yaml
title: Short descriptive name          # REQUIRED
id: uuid-format-identifier             # REQUIRED (use uuidgen)
status: experimental                   # test/experimental/stable/production
logsource:                             # REQUIRED
    category: process_creation         # Type of log
    product: windows                   # OS/Product
detection:                             # REQUIRED
    selection:
        Field: Value
    condition: selection
level: high                            # REQUIRED: info/low/medium/high/critical
```

### Optional but Recommended

```yaml
description: |
    Detailed explanation of what this rule detects
    and why it's important
references:
    - https://attack.mitre.org/techniques/T1059/
author: Your Name
date: 2025/01/02
modified: 2025/01/02
tags:
    - attack.execution
    - attack.t1059.001
falsepositives:
    - Legitimate admin scripts
    - Specific software that triggers this
```

### Common Error #1: Missing Required Fields

**Symptom:**
```
SigmaRuleError: Rule validation failed - missing required field 'logsource'
```

**Solution:** Ensure all required fields are present:
```yaml
# MINIMUM VALID RULE
title: My Detection Rule
id: 12345678-1234-1234-1234-123456789012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\malware.exe'
    condition: selection
level: high
```

---

## Step 3: Writing Detection Logic

### Basic Selections

```yaml
detection:
    # Exact match
    selection_exact:
        Image: 'C:\Windows\System32\cmd.exe'
    
    # Multiple values (OR)
    selection_multiple:
        Image:
            - 'C:\Windows\System32\cmd.exe'
            - 'C:\Windows\System32\powershell.exe'
    
    # All must match (AND within selection)
    selection_all:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    
    condition: selection_exact or selection_multiple or selection_all
```

### Field Modifiers

Modifiers change how values are matched:

```yaml
# String matching
Image|endswith: '\cmd.exe'           # Path ends with
Image|startswith: 'C:\Temp\'         # Path starts with  
Image|contains: 'temp'               # Contains substring
Image|contains|all:                  # Contains ALL of these
    - 'temp'
    - 'script'

# Case handling (Sigma is case-insensitive by default)
CommandLine|contains: 'MIMIKATZ'     # Matches any case

# Regular expressions (use sparingly - performance impact)
CommandLine|re: '.*-e(nc)?\s+[A-Za-z0-9+/=]{50,}'

# Negation
Image|endswith: '\powershell.exe'
CommandLine|contains:
    - '-enc'
    - '-encoded'
# Then in condition: selection and not filter
```

### Common Error #2: Incorrect Modifier Syntax

**Symptom:**
```
SigmaModifierError: Unknown modifier 'end_with'
```

**Solution:** Use correct modifier names:
```yaml
# WRONG
Image|end_with: '\cmd.exe'
CommandLine|include: 'password'

# CORRECT
Image|endswith: '\cmd.exe'
CommandLine|contains: 'password'
```

---

## Step 4: Building the Mimikatz Rule

### Understanding the Target

Mimikatz indicators:
- **Process names**: `mimikatz.exe`, `mimikatz64.exe`, `mimi.exe`
- **Command line**: `sekurlsa::`, `privilege::debug`, `lsadump::`
- **Renamed copies**: Attackers rename to `m.exe`, `mk.exe` but keep same commands

### Step-by-Step Rule Creation

```yaml
title: Mimikatz Credential Dumping Tool
id: 0eb03d41-79e8-4571-9f15-8973a234b13c
status: production
description: |
    Detects Mimikatz execution via process name or command line arguments.
    Mimikatz is a credential dumping tool commonly used in post-exploitation.
references:
    - https://attack.mitre.org/software/S0002/
    - https://github.com/gentilkiwi/mimikatz
author: AI for the Win
date: 2025/01/02

logsource:
    category: process_creation
    product: windows

detection:
    # Detection 1: Known process names
    selection_names:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimikatz64.exe'
            - '\mimi.exe'
            - '\m.exe'
            - '\mk.exe'
    
    # Detection 2: Characteristic command line patterns
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'privilege::debug'
            - 'lsadump::'
            - 'kerberos::'
            - 'crypto::'
            - 'dpapi::'
            - 'token::'
    
    # Detection 3: Known hashes (if your SIEM captures them)
    selection_hashes:
        Hashes|contains:
            - 'MD5=01A461AD68D11B5B5FCBDC'  # Example - add real hashes
    
    condition: selection_names or selection_cmdline or selection_hashes

falsepositives:
    - Security testing by authorized red teams
    - Penetration testing engagements

level: critical

tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
```

### Why This Works

| Selection | What It Catches |
|-----------|-----------------|
| `selection_names` | Standard and common renamed Mimikatz binaries |
| `selection_cmdline` | Any binary using Mimikatz commands (even renamed) |
| `selection_hashes` | Known Mimikatz file hashes (most comprehensive) |

---

## Step 5: Using LLMs to Generate Rules

### The Prompt Template

```python
def generate_sigma_rule(description: str, context: str = None) -> str:
    """Generate a Sigma rule using an LLM."""
    
    prompt = f"""Generate a Sigma detection rule for the following requirement:

DETECTION REQUIREMENT:
{description}

{f"ADDITIONAL CONTEXT: {context}" if context else ""}

REQUIREMENTS FOR THE RULE:
1. Include all required fields: title, id (use a valid UUID), logsource, detection, level
2. Use appropriate field modifiers (endswith, contains, etc.)
3. Include MITRE ATT&CK tags
4. Add realistic false positives
5. Use proper YAML formatting

Return ONLY the complete YAML rule, no explanations or markdown formatting."""
    
    # Call your LLM here
    response = query_llm(prompt, temperature=0)
    
    # Clean up response
    rule = response.strip()
    if rule.startswith('```'):
        rule = rule.split('```')[1]
        if rule.startswith('yaml'):
            rule = rule[4:]
    
    return rule.strip()
```

### Example: Generating a LOLBin Rule

```python
rule = generate_sigma_rule(
    description="Detect certutil.exe being used to download files from the internet",
    context="certutil.exe is a legitimate Windows tool often abused by attackers to download malicious payloads. Look for -urlcache and -split flags."
)
print(rule)
```

**Expected output:**
```yaml
title: Certutil Download Activity
id: 8a3f5b2c-9d4e-1f6a-7b8c-0d1e2f3a4b5c
status: production
description: |
    Detects certutil.exe being used to download files from external sources.
    This is a common LOLBin technique for payload delivery.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains|all:
            - '-urlcache'
            - '-split'
    alternative:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: selection or alternative
falsepositives:
    - Certificate management by administrators
    - Software updates using certutil
level: high
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion
    - attack.t1218
```

---

## Step 6: Validating and Converting Rules

### Using pySigma

```python
# pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch

from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

def validate_rule(yaml_content: str) -> dict:
    """Validate a Sigma rule and return any errors."""
    result = {
        "valid": False,
        "errors": [],
        "warnings": []
    }
    
    try:
        rule = SigmaRule.from_yaml(yaml_content)
        result["valid"] = True
        result["title"] = rule.title
        result["level"] = str(rule.level)
        result["tags"] = [str(t) for t in rule.tags]
    except Exception as e:
        result["errors"].append(str(e))
    
    return result


def convert_to_splunk(yaml_content: str) -> str:
    """Convert Sigma rule to Splunk SPL query."""
    rule = SigmaRule.from_yaml(yaml_content)
    backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
    queries = backend.convert_rule(rule)
    return queries[0] if queries else ""


def convert_to_elastic(yaml_content: str) -> str:
    """Convert Sigma rule to Elastic query."""
    from sigma.backends.elasticsearch import LuceneBackend
    
    rule = SigmaRule.from_yaml(yaml_content)
    backend = LuceneBackend()
    queries = backend.convert_rule(rule)
    return queries[0] if queries else ""
```

### Example Conversion Output

**Original Sigma:**
```yaml
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
```

**Splunk SPL:**
```spl
Image="*\\powershell.exe" CommandLine="*-enc*"
```

**Elastic Lucene:**
```
process.executable:*\\powershell.exe AND process.command_line:*-enc*
```

### Common Error #3: Pipeline Mismatch

**Symptom:**
```
Field 'Image' not mapped in pipeline
```

**Solution:** Use the correct pipeline for your SIEM:
```python
# For Windows logs in Splunk
from sigma.pipelines.splunk import splunk_windows_pipeline
backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())

# For Windows logs in Elastic
from sigma.pipelines.elasticsearch import ecs_windows_pipeline
backend = LuceneBackend(processing_pipeline=ecs_windows_pipeline())
```

---

## Step 7: Testing Rules Against Logs

### Manual Testing Approach

```python
import yaml
import re

def test_rule_manually(rule_yaml: str, logs: list[dict]) -> list[dict]:
    """
    Simple rule testing without pySigma processing backend.
    Good for understanding; use pySigma for production.
    """
    rule = yaml.safe_load(rule_yaml)
    detection = rule.get('detection', {})
    matches = []
    
    for log in logs:
        if matches_detection(log, detection):
            matches.append(log)
    
    return matches


def matches_detection(log: dict, detection: dict) -> bool:
    """Check if a log matches the detection logic."""
    condition = detection.get('condition', '')
    
    # Get all selections (everything except 'condition')
    selections = {k: v for k, v in detection.items() if k != 'condition'}
    
    # Evaluate each selection
    results = {}
    for name, criteria in selections.items():
        results[name] = matches_selection(log, criteria)
    
    # Evaluate condition (simplified - real parser is more complex)
    # This handles basic "selection1 or selection2 and not filter"
    expr = condition
    for name, matched in results.items():
        expr = expr.replace(name, str(matched))
    
    try:
        return eval(expr)  # Only safe because we control the input
    except:
        return any(results.values())


def matches_selection(log: dict, criteria: dict) -> bool:
    """Check if log matches a selection's criteria."""
    for field_spec, values in criteria.items():
        # Parse field and modifiers
        parts = field_spec.split('|')
        field = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []
        
        log_value = log.get(field, '')
        
        # Ensure values is a list
        if not isinstance(values, list):
            values = [values]
        
        # Apply modifiers
        if 'endswith' in modifiers:
            if not any(str(log_value).lower().endswith(v.lower().lstrip('\\')) 
                      for v in values):
                return False
        elif 'contains' in modifiers:
            if 'all' in modifiers:
                if not all(v.lower() in str(log_value).lower() for v in values):
                    return False
            else:
                if not any(v.lower() in str(log_value).lower() for v in values):
                    return False
        elif 'startswith' in modifiers:
            if not any(str(log_value).lower().startswith(v.lower()) 
                      for v in values):
                return False
        else:
            # Exact match
            if str(log_value) not in [str(v) for v in values]:
                return False
    
    return True
```

### Test Data

```python
test_logs = [
    {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "User": "CORP\\jsmith"
    },
    {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir",
        "User": "CORP\\admin"
    },
    {
        "Image": "C:\\temp\\mimikatz.exe",
        "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "User": "CORP\\attacker"
    }
]

# Test the Mimikatz rule
matches = test_rule_manually(mimikatz_rule, test_logs)
print(f"Matched {len(matches)} logs")
for m in matches:
    print(f"  - {m['Image']}")
```

---

## Step 8: Common Patterns and Templates

### LOLBin Detection Template

```yaml
title: {TOOL_NAME} Suspicious Activity
id: {UUID}
status: experimental
description: Detects suspicious use of {TOOL_NAME}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\{TOOL_NAME}.exe'
        CommandLine|contains:
            - {SUSPICIOUS_FLAG_1}
            - {SUSPICIOUS_FLAG_2}
    filter_legitimate:
        ParentImage|endswith:
            - '\legitimate_parent.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate administrative use
level: medium
tags:
    - attack.{TACTIC}
    - attack.{TECHNIQUE_ID}
```

### Credential Access Detection Template

```yaml
title: Potential Credential Access via {METHOD}
id: {UUID}
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1438'
            - '0x143a'
    filter_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
    condition: selection and not filter_system
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

---

## Key Takeaways

1. **Sigma is vendor-agnostic** - Write once, deploy to any SIEM
2. **Field modifiers are powerful** - Use `endswith`, `contains`, `startswith` for flexible matching
3. **LLMs accelerate rule creation** - But always validate the output
4. **Test rules before deployment** - False positives hurt analyst trust
5. **Map to MITRE ATT&CK** - Makes rules searchable and contextual

---

## Common Mistakes Summary

| Mistake | Solution |
|---------|----------|
| Missing `logsource` | Always specify category and product |
| Wrong modifier syntax | Use `endswith` not `end_with` |
| No false positive filters | Add `filter_*` selections for known good |
| Missing UUID | Use `uuidgen` or Python `uuid.uuid4()` |
| Over-relying on regex | Prefer simpler modifiers for performance |

---

## Next Steps

After completing this lab:
- **Lab 08**: Apply detection to vulnerability scanning
- **Lab 09**: Build a full detection pipeline that outputs Sigma rules
- **Lab 10**: Use Sigma in incident response workflows

---

## Resources

- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma) - Official rules and documentation
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) - Formal syntax definition
- [pySigma Documentation](https://sigmahq-pysigma.readthedocs.io/) - Python library docs
- [MITRE ATT&CK](https://attack.mitre.org/) - Technique reference for tagging
- [Uncoder.io](https://uncoder.io/) - Online Sigma converter

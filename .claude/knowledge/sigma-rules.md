# Sigma Rules Syntax Guide

Sigma is a generic signature format for SIEM systems. This guide covers syntax, modifiers, and conversion patterns.

## Basic Rule Structure

```yaml
title: Rule Title                    # Required: Short descriptive name
id: 12345678-1234-1234-1234-123456789abc  # Required: UUID
status: experimental|test|stable     # Required: Rule maturity
description: |                       # Recommended: Detailed description
  What this rule detects and why
author: Name                         # Recommended: Rule author
date: 2024/01/15                    # Recommended: Creation date
modified: 2024/06/01                # Recommended: Last modification
references:                          # Recommended: External references
  - https://example.com/threat-report
tags:                               # Recommended: ATT&CK mappings
  - attack.execution
  - attack.t1059.001
logsource:                          # Required: Log source definition
  category: process_creation
  product: windows
detection:                          # Required: Detection logic
  selection:
    CommandLine|contains: 'malicious'
  condition: selection
falsepositives:                     # Recommended: Known FPs
  - Legitimate admin activity
level: high                         # Required: critical|high|medium|low|informational
```

## Log Source Definitions

### Windows Process Creation
```yaml
logsource:
  category: process_creation
  product: windows
# Maps to: Sysmon EventID 1, Windows Security 4688
```

### Windows PowerShell
```yaml
logsource:
  product: windows
  service: powershell
# Maps to: PowerShell EventID 4103, 4104
```

### Windows Security
```yaml
logsource:
  product: windows
  service: security
# Maps to: Windows Security Event Log
```

### Windows Sysmon
```yaml
logsource:
  product: windows
  service: sysmon
# Maps to: Sysmon Event Log
```

### Network Connections
```yaml
logsource:
  category: network_connection
  product: windows
# Maps to: Sysmon EventID 3
```

### File Events
```yaml
logsource:
  category: file_event
  product: windows
# Maps to: Sysmon EventID 11, 23
```

### DNS Queries
```yaml
logsource:
  category: dns_query
  product: windows
# Maps to: Sysmon EventID 22
```

### Web/Proxy Logs
```yaml
logsource:
  category: proxy
# Maps to: Proxy/Web gateway logs
```

### Firewall
```yaml
logsource:
  category: firewall
# Maps to: Firewall logs
```

### Linux Process
```yaml
logsource:
  category: process_creation
  product: linux
# Maps to: auditd, syslog
```

## Field Modifiers

### String Modifiers
| Modifier | Description | Example |
|----------|-------------|---------|
| `contains` | Substring match | `CommandLine\|contains: 'mimikatz'` |
| `startswith` | Prefix match | `Image\|startswith: 'C:\Temp'` |
| `endswith` | Suffix match | `Image\|endswith: '.exe'` |
| `base64` | Base64 encoded | `CommandLine\|base64: 'password'` |
| `base64offset` | Base64 with offset | `CommandLine\|base64offset: 'password'` |
| `utf16le` | UTF-16 LE encoding | `CommandLine\|utf16le\|base64: 'cmd'` |
| `utf16be` | UTF-16 BE encoding | `CommandLine\|utf16be: 'test'` |
| `wide` | UTF-16 LE alias | `CommandLine\|wide: 'password'` |
| `re` | Regular expression | `CommandLine\|re: '.*\\.exe$'` |

### Numeric Modifiers
| Modifier | Description | Example |
|----------|-------------|---------|
| `gt` | Greater than | `EventID\|gt: 1000` |
| `gte` | Greater than or equal | `EventID\|gte: 1000` |
| `lt` | Less than | `EventID\|lt: 2000` |
| `lte` | Less than or equal | `EventID\|lte: 2000` |

### List Modifiers
| Modifier | Description | Example |
|----------|-------------|---------|
| `all` | All values must match | `CommandLine\|contains\|all: ['a','b']` |
| `any` | Alias for OR (default) | Implicit |

### Special Modifiers
| Modifier | Description | Example |
|----------|-------------|---------|
| `cidr` | CIDR notation match | `DestinationIp\|cidr: '10.0.0.0/8'` |
| `expand` | Placeholder expansion | `%SystemRoot%` |

## Detection Logic

### Basic Selection
```yaml
detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
  condition: selection
```

### Multiple Values (OR)
```yaml
detection:
  selection:
    EventID:
      - 1
      - 7
      - 11
  condition: selection
```

### Multiple Fields (AND)
```yaml
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
```

### Multiple Selections
```yaml
detection:
  selection1:
    Image|endswith: '\cmd.exe'
  selection2:
    CommandLine|contains: 'whoami'
  condition: selection1 and selection2
```

### Negation (NOT)
```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
  filter:
    User: 'SYSTEM'
  condition: selection and not filter
```

### Complex Conditions
```yaml
detection:
  selection:
    EventID: 1
  keywords:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
  filter_admin:
    User|endswith: '-admin'
  filter_system:
    User: 'SYSTEM'
  condition: selection and keywords and not (filter_admin or filter_system)
```

### Aggregation
```yaml
detection:
  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count() > 10
```

### Grouping
```yaml
detection:
  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count(TargetUserName) by SourceIP > 5
```

## Common Detection Patterns

### Suspicious PowerShell
```yaml
title: Suspicious PowerShell Download Cradle
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'IEX'
      - 'Net.WebClient'
  condition: selection
level: high
```

### Process from Unusual Location
```yaml
title: Process Execution from Suspicious Location
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - '\Temp\'
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
  filter:
    Image|endswith:
      - '\setup.exe'
      - '\installer.exe'
  condition: selection and not filter
level: medium
```

### Encoded Command
```yaml
title: Encoded PowerShell Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
  condition: selection
level: medium
```

### LSASS Access
```yaml
title: LSASS Memory Access for Credential Dumping
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|startswith:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
  filter:
    SourceImage|endswith:
      - '\wmiprvse.exe'
      - '\taskmgr.exe'
  condition: selection and not filter
level: high
```

### Registry Run Key
```yaml
title: Registry Run Key Modification
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 13
    TargetObject|contains:
      - '\CurrentVersion\Run'
      - '\CurrentVersion\RunOnce'
  condition: selection
level: medium
```

### Network Connection to Rare Port
```yaml
title: Outbound Connection to Uncommon Port
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    Initiated: 'true'
    DestinationPort:
      - 4444
      - 5555
      - 6666
      - 8888
      - 9999
  condition: selection
level: medium
```

## Sigma to Query Conversion

### Elasticsearch Query DSL
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"winlog.event_id": 1}},
        {"wildcard": {"process.executable": "*\\\\powershell.exe"}}
      ],
      "filter": [
        {"wildcard": {"process.command_line": "*-enc*"}}
      ]
    }
  }
}
```

### Splunk SPL
```spl
index=windows EventCode=1
| where like(Image, "%\\powershell.exe")
| where like(CommandLine, "%-enc%")
```

### KQL (Kibana)
```kql
event.code: 1
  AND process.executable: *\\powershell.exe
  AND process.command_line: *-enc*
```

### Microsoft Sentinel KQL
```kql
SecurityEvent
| where EventID == 1
| where NewProcessName endswith "\\powershell.exe"
| where CommandLine contains "-enc"
```

## Best Practices

1. **Use UUIDs**: Generate unique IDs for each rule
2. **Tag with ATT&CK**: Map to techniques for context
3. **Document false positives**: Help analysts tune rules
4. **Test before deploying**: Validate in test environment
5. **Use appropriate levels**: Critical for high-fidelity, low for noisy
6. **Keep rules focused**: One rule, one detection goal
7. **Use filters**: Reduce false positives with exclusions

## Resources

- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [sigmac - Sigma Converter](https://github.com/SigmaHQ/sigma/tree/master/tools)
- [pySigma](https://github.com/SigmaHQ/pySigma)
- [Sigma Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)

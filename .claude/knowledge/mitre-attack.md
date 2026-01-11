# MITRE ATT&CK Quick Reference

Quick reference for MITRE ATT&CK framework tactics, techniques, and mappings.

## Tactics (Enterprise)

| ID | Tactic | Description |
|----|--------|-------------|
| TA0043 | Reconnaissance | Gathering information for targeting |
| TA0042 | Resource Development | Establishing resources for operations |
| TA0001 | Initial Access | Getting into the network |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining foothold |
| TA0004 | Privilege Escalation | Gaining higher permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Learning about the environment |
| TA0008 | Lateral Movement | Moving through environment |
| TA0009 | Collection | Gathering target data |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Disrupting availability or integrity |

## Common Techniques by Tactic

### Initial Access (TA0001)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1566 | Phishing | Email attachments, links, Office macros |
| T1566.001 | Spearphishing Attachment | Malicious file attachments |
| T1566.002 | Spearphishing Link | Malicious URLs in emails |
| T1190 | Exploit Public-Facing App | Web server logs, WAF alerts |
| T1133 | External Remote Services | VPN, RDP authentication logs |
| T1078 | Valid Accounts | Anomalous login patterns |
| T1195 | Supply Chain Compromise | Software integrity verification |

### Execution (TA0002)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1059 | Command and Scripting Interpreter | Process creation, script logs |
| T1059.001 | PowerShell | PowerShell logging, encoded commands |
| T1059.003 | Windows Command Shell | cmd.exe process trees |
| T1059.005 | Visual Basic | Office macro execution |
| T1059.006 | Python | Python process spawning |
| T1059.007 | JavaScript | wscript/cscript execution |
| T1204 | User Execution | Process creation from user apps |
| T1047 | WMI | WMI event subscriptions |

### Persistence (TA0003)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1547.001 | Registry Run Keys | Registry modifications |
| T1053 | Scheduled Task/Job | Task scheduler events |
| T1136 | Create Account | New account creation |
| T1543 | Create/Modify System Process | Service creation |
| T1546 | Event Triggered Execution | WMI subscriptions, AppInit DLLs |
| T1505.003 | Web Shell | New files in web directories |

### Defense Evasion (TA0005)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1070 | Indicator Removal | Log clearing, file deletion |
| T1027 | Obfuscated Files | Encoded/packed executables |
| T1036 | Masquerading | Process name anomalies |
| T1055 | Process Injection | Memory anomalies, API calls |
| T1562 | Impair Defenses | Security tool tampering |
| T1112 | Modify Registry | Registry changes |

### Credential Access (TA0006)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1003 | OS Credential Dumping | LSASS access, SAM access |
| T1003.001 | LSASS Memory | Mimikatz patterns |
| T1110 | Brute Force | Failed authentication spikes |
| T1555 | Credentials from Password Stores | Browser credential access |
| T1552 | Unsecured Credentials | File access to credential stores |
| T1558 | Steal or Forge Kerberos Tickets | Kerberoasting patterns |

### Lateral Movement (TA0008)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1021 | Remote Services | RDP, SSH, SMB connections |
| T1021.001 | Remote Desktop Protocol | RDP authentication logs |
| T1021.002 | SMB/Windows Admin Shares | Admin share access |
| T1021.004 | SSH | SSH authentication logs |
| T1570 | Lateral Tool Transfer | File copies to remote systems |
| T1072 | Software Deployment Tools | SCCM, GPO abuse |

### Command and Control (TA0011)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1071 | Application Layer Protocol | HTTP/S, DNS traffic |
| T1071.001 | Web Protocols | Unusual HTTP patterns |
| T1071.004 | DNS | DNS tunneling indicators |
| T1573 | Encrypted Channel | Encrypted C2 traffic |
| T1105 | Ingress Tool Transfer | File downloads |
| T1572 | Protocol Tunneling | Tunneled traffic detection |
| T1090 | Proxy | Proxy/relay patterns |

### Exfiltration (TA0010)
| ID | Technique | Detection Focus |
|----|-----------|-----------------|
| T1041 | Exfiltration Over C2 | Large outbound transfers |
| T1048 | Exfiltration Over Alternative Protocol | DNS, ICMP exfil |
| T1567 | Exfiltration to Cloud Storage | Cloud upload activity |
| T1029 | Scheduled Transfer | Periodic large transfers |

## Detection Queries by Technique

### PowerShell Execution (T1059.001)
```sigma
title: Suspicious PowerShell Execution
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
  keywords:
    ScriptBlockText|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'EncodedCommand'
      - '-enc'
      - 'FromBase64String'
  condition: selection and keywords
```

### LSASS Access (T1003.001)
```sigma
title: LSASS Memory Access
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
  condition: selection
```

### Scheduled Task Creation (T1053.005)
```sigma
title: Scheduled Task Created
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  condition: selection
```

## MITRE ATT&CK Data Sources

| Data Source | Components | Example Events |
|-------------|------------|----------------|
| Process | Creation, Termination | Sysmon 1, Windows 4688 |
| File | Creation, Modification, Deletion | Sysmon 11, 23 |
| Network Traffic | Flow, Content | Zeek, Firewall logs |
| Command | Execution | PowerShell 4104, Bash history |
| Logon Session | Creation, Metadata | Windows 4624, 4625 |
| Windows Registry | Modification | Sysmon 12, 13, 14 |
| Module | Load | Sysmon 7 |
| Network Connection | Creation | Sysmon 3 |

## Mapping Log Sources to ATT&CK

### Windows Event Logs
| Log | Event IDs | Techniques Covered |
|-----|-----------|-------------------|
| Security | 4624, 4625 | T1078, T1110 |
| Security | 4688 | T1059, T1204 |
| Security | 4698 | T1053 |
| PowerShell | 4103, 4104 | T1059.001 |
| Sysmon | 1, 3, 7, 10, 11 | Multiple |

### Network Logs
| Source | Techniques Covered |
|--------|-------------------|
| Firewall | T1071, T1572, T1048 |
| DNS | T1071.004, T1568 |
| Proxy/Web | T1071.001, T1102 |
| IDS/IPS | Multiple |

## Resources

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [CAR Analytics](https://car.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)

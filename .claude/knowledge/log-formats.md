# Common Log Formats Reference

Parsing patterns and field mappings for common security log sources.

## Windows Event Logs

### Security Event Log (Key Events)

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 4624 | Successful Logon | LogonType, TargetUserName, IpAddress |
| 4625 | Failed Logon | LogonType, TargetUserName, IpAddress, FailureReason |
| 4634 | Logoff | TargetUserName, LogonType |
| 4648 | Explicit Credentials Logon | SubjectUserName, TargetUserName, TargetServerName |
| 4672 | Special Privileges Assigned | SubjectUserName, PrivilegeList |
| 4688 | Process Created | NewProcessName, CommandLine, ParentProcessName |
| 4689 | Process Terminated | ProcessName |
| 4698 | Scheduled Task Created | TaskName, TaskContent |
| 4699 | Scheduled Task Deleted | TaskName |
| 4700 | Scheduled Task Enabled | TaskName |
| 4701 | Scheduled Task Disabled | TaskName |
| 4702 | Scheduled Task Updated | TaskName |
| 4720 | User Account Created | TargetUserName, SubjectUserName |
| 4722 | User Account Enabled | TargetUserName |
| 4723 | Password Change Attempt | TargetUserName |
| 4724 | Password Reset Attempt | TargetUserName |
| 4725 | User Account Disabled | TargetUserName |
| 4726 | User Account Deleted | TargetUserName |
| 4728 | Member Added to Global Group | MemberName, TargetUserName |
| 4732 | Member Added to Local Group | MemberName, TargetUserName |
| 4756 | Member Added to Universal Group | MemberName, TargetUserName |
| 4768 | Kerberos TGT Requested | TargetUserName, IpAddress |
| 4769 | Kerberos Service Ticket Requested | TargetUserName, ServiceName |
| 4771 | Kerberos Pre-Auth Failed | TargetUserName, IpAddress |
| 4776 | NTLM Authentication | TargetUserName, Workstation |
| 5140 | Network Share Accessed | ShareName, IpAddress |
| 5145 | Network Share Object Accessed | ShareName, RelativeTargetName |
| 7045 | Service Installed | ServiceName, ImagePath |

### Logon Types
| Type | Description |
|------|-------------|
| 2 | Interactive (local console) |
| 3 | Network (SMB, mapped drives) |
| 4 | Batch (scheduled tasks) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials (RunAs) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

### Sysmon Events

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | Image, CommandLine, ParentImage, User, Hashes |
| 2 | File Creation Time Changed | TargetFilename, PreviousCreationUtcTime |
| 3 | Network Connection | Image, DestinationIp, DestinationPort, Initiated |
| 4 | Sysmon Service State Changed | State |
| 5 | Process Terminated | Image, ProcessGuid |
| 6 | Driver Loaded | ImageLoaded, Hashes, Signed |
| 7 | Image Loaded (DLL) | Image, ImageLoaded, Hashes |
| 8 | CreateRemoteThread | SourceImage, TargetImage, StartAddress |
| 9 | RawAccessRead | Image, Device |
| 10 | Process Access | SourceImage, TargetImage, GrantedAccess |
| 11 | File Create | Image, TargetFilename |
| 12 | Registry Key/Value Create/Delete | Image, TargetObject |
| 13 | Registry Value Set | Image, TargetObject, Details |
| 14 | Registry Key/Value Rename | Image, TargetObject, NewName |
| 15 | FileCreateStreamHash | Image, TargetFilename, Hash |
| 17 | Pipe Created | Image, PipeName |
| 18 | Pipe Connected | Image, PipeName |
| 19 | WMI Event Filter | EventType, Operation, EventNamespace |
| 20 | WMI Event Consumer | EventType, Operation, Destination |
| 21 | WMI Event Consumer to Filter | EventType, Operation, Consumer, Filter |
| 22 | DNS Query | Image, QueryName, QueryResults |
| 23 | File Delete | Image, TargetFilename |
| 24 | Clipboard Change | Image, Archived |
| 25 | Process Tampering | Image, Type |
| 26 | File Delete Logged | Image, TargetFilename |

### PowerShell Logs

| Event ID | Log | Description | Key Fields |
|----------|-----|-------------|------------|
| 4103 | PowerShell Operational | Module Logging | Payload, ContextInfo |
| 4104 | PowerShell Operational | Script Block Logging | ScriptBlockText, Path |
| 400 | PowerShell | Engine Started | HostApplication |
| 600 | PowerShell | Provider Started | ProviderName |

## Linux/Unix Logs

### Syslog Format (RFC 5424)
```
<priority>version timestamp hostname app-name procid msgid structured-data msg
```

Example:
```
<34>1 2024-01-15T12:30:45.123Z server01 sshd 12345 - - Failed password for root from 192.168.1.100 port 22 ssh2
```

### Common Syslog Fields
| Field | Description |
|-------|-------------|
| priority | Facility * 8 + Severity |
| timestamp | ISO 8601 format |
| hostname | Originating host |
| app-name | Application name |
| procid | Process ID |
| msgid | Message type identifier |

### Auth Log (/var/log/auth.log)
```regex
^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<hostname>\S+)\s(?P<service>\S+)(\[(?P<pid>\d+)\])?:\s(?P<message>.*)$
```

Patterns:
```
# Successful SSH login
sshd[1234]: Accepted publickey for user from 192.168.1.100 port 22 ssh2

# Failed SSH login
sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2

# sudo command
sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow
```

### Audit Log (/var/log/audit/audit.log)
```
type=SYSCALL msg=audit(1704912345.123:1234): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=... items=2 ppid=1000 pid=1001 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cat" exe="/bin/cat" key="shadow_access"
```

| Field | Description |
|-------|-------------|
| type | Audit record type |
| msg | Timestamp and serial number |
| syscall | System call number |
| success | Whether syscall succeeded |
| ppid | Parent process ID |
| pid | Process ID |
| auid | Audit user ID (login ID) |
| uid | User ID |
| comm | Command name |
| exe | Executable path |
| key | Audit rule key |

## Web Server Logs

### Apache Combined Log Format
```
%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
```

```regex
^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<useragent>[^"]*)"$
```

Example:
```
192.168.1.100 - admin [15/Jan/2024:12:30:45 +0000] "GET /admin/config.php HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0..."
```

### Nginx Access Log
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

### IIS Log Format (W3C Extended)
```
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

Example:
```
2024-01-15 12:30:45 192.168.1.10 GET /admin/login.aspx - 443 - 10.0.0.100 Mozilla/5.0... - 200 0 0 125
```

## Firewall Logs

### Palo Alto Traffic Log
Key fields:
| Field | Description |
|-------|-------------|
| src | Source IP |
| dst | Destination IP |
| sport | Source port |
| dport | Destination port |
| app | Application identified |
| action | allow/deny/drop |
| rule | Rule name matched |
| bytes_sent | Bytes sent |
| bytes_received | Bytes received |
| session_end_reason | Why session ended |

### iptables Log
```
Jan 15 12:30:45 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
```

```regex
SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*PROTO=(?P<proto>\w+).*SPT=(?P<src_port>\d+).*DPT=(?P<dst_port>\d+)
```

## DNS Logs

### BIND Query Log
```
15-Jan-2024 12:30:45.123 queries: info: client @0x7f1234567890 192.168.1.100#54321 (example.com): query: example.com IN A +E(0)K (192.168.1.1)
```

### Windows DNS Debug Log
```
1/15/2024 12:30:45 PM 0E34 PACKET  00000001234567890 UDP Rcv 192.168.1.100 0001   Q [0001   D   NOERROR] A      (7)example(3)com(0)
```

### Zeek (Bro) DNS Log
| Field | Description |
|-------|-------------|
| ts | Timestamp |
| uid | Connection UID |
| id.orig_h | Source IP |
| id.orig_p | Source port |
| id.resp_h | Destination IP |
| id.resp_p | Destination port |
| proto | Protocol |
| query | DNS query |
| qclass | Query class |
| qtype | Query type |
| rcode | Response code |
| answers | DNS answers |

## Proxy Logs

### Squid Access Log
```
1704912345.123    123 192.168.1.100 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/93.184.216.34 text/html
```

| Field | Description |
|-------|-------------|
| timestamp | Unix epoch |
| elapsed | Request time (ms) |
| client_ip | Client IP |
| result/status | Cache result and HTTP status |
| size | Response size |
| method | HTTP method |
| url | Requested URL |
| hierarchy | How request was fulfilled |
| content_type | MIME type |

### BlueCoat/Symantec Proxy
```
2024-01-15 12:30:45 192.168.1.100 user GET http://example.com/path 200 1234 "Mozilla/5.0" OBSERVED
```

## JSON Log Formats

### Elastic Common Schema (ECS)
```json
{
  "@timestamp": "2024-01-15T12:30:45.123Z",
  "event": {
    "category": ["authentication"],
    "type": ["start"],
    "outcome": "failure"
  },
  "source": {
    "ip": "192.168.1.100",
    "port": 54321
  },
  "destination": {
    "ip": "10.0.0.1",
    "port": 22
  },
  "user": {
    "name": "admin"
  },
  "process": {
    "name": "sshd",
    "pid": 1234
  }
}
```

### CEF (Common Event Format)
```
CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
```

Example:
```
CEF:0|SecurityVendor|SecurityProduct|1.0|100|Malware Detected|10|src=192.168.1.100 dst=10.0.0.1 suser=admin fname=malware.exe
```

| Prefix | Description |
|--------|-------------|
| src | Source IP |
| dst | Destination IP |
| spt | Source port |
| dpt | Destination port |
| suser | Source user |
| duser | Destination user |
| fname | Filename |
| fsize | File size |
| act | Action taken |
| msg | Message |

### LEEF (Log Event Extended Format)
```
LEEF:2.0|Vendor|Product|Version|EventID|delimiter|Extension
```

## Parsing Tips

### Python Regex Parsing
```python
import re
from datetime import datetime

# Apache combined log
pattern = r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'

match = re.match(pattern, log_line)
if match:
    data = match.groupdict()
```

### Grok Patterns (Logstash/OpenSearch)
```
COMBINEDAPACHELOG %{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)
```

### Timestamp Formats
| Format | Example | Python strptime |
|--------|---------|-----------------|
| ISO 8601 | 2024-01-15T12:30:45Z | `%Y-%m-%dT%H:%M:%SZ` |
| Apache | 15/Jan/2024:12:30:45 +0000 | `%d/%b/%Y:%H:%M:%S %z` |
| Syslog | Jan 15 12:30:45 | `%b %d %H:%M:%S` |
| Windows | 1/15/2024 12:30:45 PM | `%m/%d/%Y %I:%M:%S %p` |
| Unix Epoch | 1704912345 | `datetime.fromtimestamp()` |

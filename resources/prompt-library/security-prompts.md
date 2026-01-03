# Security Analysis Prompt Library

Example prompts for AI-powered security analysis.

> ⚠️ **Educational Reference Only**: These prompts are provided as **learning examples and starting points**, not production-ready templates. Before using in any real environment:
>
> - Validate outputs against your specific use cases
> - Test thoroughly with your data and systems
> - Adjust for your organization's policies and requirements
> - Never rely solely on AI outputs for security decisions
> - Always have human review for critical actions
>
> AI responses can be inconsistent, incomplete, or incorrect. These prompts demonstrate concepts from the labs and should be adapted and validated for your needs.

---

## Table of Contents

1. [Threat Analysis](#threat-analysis)
2. [Malware Analysis](#malware-analysis)
3. [Log Analysis](#log-analysis)
4. [Incident Response](#incident-response)
5. [Vulnerability Assessment](#vulnerability-assessment)
6. [Threat Intelligence](#threat-intelligence)
7. [Report Generation](#report-generation)

---

## Threat Analysis

### IOC Extraction

```
Extract all indicators of compromise (IOCs) from the following text.

For each IOC found, provide:
1. The IOC value (defanged for safe sharing)
2. IOC type (IP, domain, URL, hash, email)
3. Context where it was found

Format as JSON with this structure:
{
  "iocs": [
    {"value": "...", "type": "...", "context": "..."}
  ],
  "summary": "Brief summary of findings"
}

Text to analyze:
---
{input_text}
---
```

### Threat Level Assessment

```
Analyze the following security data and provide a threat assessment.

Assessment criteria:
1. Threat Level: Critical/High/Medium/Low/Informational
2. Confidence Score: 0.0-1.0
3. Affected Assets: List potentially impacted systems
4. Attack Vector: How the threat could be exploited
5. MITRE ATT&CK Mapping: Relevant technique IDs
6. Recommended Actions: Prioritized response steps

Data to assess:
---
{security_data}
---

Provide your assessment in the following JSON format:
{
  "threat_level": "...",
  "confidence": 0.0,
  "summary": "...",
  "affected_assets": [],
  "attack_vector": "...",
  "mitre_techniques": [],
  "recommendations": []
}
```

---

## Malware Analysis

### Static Analysis

```
Perform static analysis on the following code/script.

Analysis requirements:
1. Identify the programming language
2. Describe the overall purpose/functionality
3. List suspicious functions or API calls
4. Identify any obfuscation techniques
5. Extract embedded strings of interest (URLs, IPs, commands)
6. Map behaviors to MITRE ATT&CK techniques
7. Provide detection recommendations

IMPORTANT: Do NOT execute this code. Analyze structure only.

Code to analyze:
---
{code_sample}
---

Format your response as a structured analysis report.
```

### Behavioral Analysis

```
Analyze the following malware behavior report and provide insights.

Focus areas:
1. Process Activity: Child processes, injections
2. File System: Created/modified/deleted files
3. Registry: Key modifications (Windows)
4. Network: C2 communications, data exfiltration
5. Persistence: Mechanisms used to maintain access
6. Evasion: Anti-analysis techniques observed

Behavior data:
---
{behavior_data}
---

Provide:
- Executive summary (2-3 sentences)
- Detailed findings by category
- MITRE ATT&CK mapping
- IOCs extracted
- Recommended detection rules
```

### YARA Rule Generation

```
Generate a YARA rule to detect the following malware characteristics.

Malware details:
- Name/Family: {malware_name}
- Type: {malware_type}
- Key strings: {string_indicators}
- File characteristics: {file_info}
- Behavioral markers: {behaviors}

Requirements:
1. Rule should have low false positive rate
2. Include multiple detection conditions
3. Add metadata (author, description, reference)
4. Use appropriate YARA modules if needed
5. Comment complex conditions

Generate a production-ready YARA rule.
```

---

## Log Analysis

### Authentication Analysis

```
Analyze the following authentication logs for security issues.

Look for:
1. Brute force attempts (multiple failures from same source)
2. Credential stuffing patterns
3. Password spraying attacks
4. Impossible travel (geographically impossible logins)
5. Off-hours access from unusual locations
6. Privilege escalation attempts
7. Account lockouts and their sources

Logs:
---
{auth_logs}
---

Provide:
- Summary of findings
- Timeline of suspicious events
- Affected accounts
- Source IPs/locations of concern
- Recommended actions
```

### Web Access Log Analysis

```
Analyze these web server access logs for malicious activity.

Detection focus:
1. SQL injection attempts
2. Cross-site scripting (XSS) probes
3. Directory traversal attacks
4. Command injection attempts
5. Scanner/enumeration activity
6. Suspicious user agents
7. Anomalous request patterns

Logs:
---
{access_logs}
---

For each finding, provide:
- Attack type
- Specific log entries
- Severity
- Attacker IP(s)
- Targeted resources
- Recommended WAF rules
```

### Correlation Analysis

```
Correlate the following log sources to identify attack patterns.

Available logs:
1. Firewall logs: {firewall_logs}
2. Authentication logs: {auth_logs}
3. Application logs: {app_logs}
4. DNS logs: {dns_logs}

Tasks:
1. Identify related events across sources
2. Build attack timeline
3. Determine attack progression
4. Identify pivot points
5. Map to kill chain stages

Provide a correlated analysis showing how events connect.
```

---

## Incident Response

### Incident Classification

```
Classify the following security incident.

Incident data:
---
{incident_details}
---

Provide classification:
1. Incident Type: (Malware/Phishing/Data Breach/Unauthorized Access/DDoS/etc.)
2. Severity: (Critical/High/Medium/Low)
3. Scope: (Single host/Multiple hosts/Network segment/Enterprise-wide)
4. Stage: (Detection/Analysis/Containment/Eradication/Recovery)
5. Priority: (P1/P2/P3/P4)
6. Regulatory Impact: (Reportable/Non-reportable, affected regulations)

Justify each classification with specific evidence from the incident data.
```

### Containment Recommendations

```
Recommend containment actions for the following incident.

Incident summary:
---
{incident_summary}
---

Affected systems:
---
{affected_systems}
---

Provide containment recommendations:
1. Immediate actions (0-1 hour)
2. Short-term containment (1-24 hours)
3. Evidence preservation requirements
4. Communication requirements
5. Escalation criteria

Consider business impact and prioritize accordingly.
```

### Root Cause Analysis

```
Perform root cause analysis on this security incident.

Incident timeline:
---
{timeline}
---

Evidence collected:
---
{evidence}
---

Analysis framework:
1. What happened? (Sequence of events)
2. How did it happen? (Attack vector and techniques)
3. Why did it happen? (Security gaps exploited)
4. What was the impact? (Business and technical)
5. What controls failed? (Preventive/Detective/Corrective)
6. What should change? (Recommendations)

Provide a comprehensive RCA report.
```

---

## Vulnerability Assessment

### Code Review

```
Review the following code for security vulnerabilities.

Focus areas:
1. Injection flaws (SQL, Command, LDAP, XPath)
2. Authentication/Authorization issues
3. Sensitive data exposure
4. Security misconfiguration
5. Input validation gaps
6. Cryptographic weaknesses
7. Error handling issues

Code:
---
{code}
---

For each vulnerability found:
- Location (function/line)
- Vulnerability type
- CWE classification
- Severity (Critical/High/Medium/Low)
- Exploitation scenario
- Remediation recommendation
- Secure code example
```

### Configuration Review

```
Review this system configuration for security issues.

Configuration:
---
{config}
---

Check against:
1. CIS Benchmark recommendations
2. Vendor security guidelines
3. Industry best practices
4. Compliance requirements: {compliance_frameworks}

For each finding:
- Configuration item
- Current value
- Recommended value
- Risk if not addressed
- Remediation steps
```

---

## Threat Intelligence

### Threat Actor Profiling

```
Based on the following indicators and tactics, profile the threat actor.

Observed indicators:
---
{indicators}
---

Observed TTPs:
---
{ttps}
---

Profile should include:
1. Suspected attribution (nation-state/criminal/hacktivist)
2. Motivation assessment
3. Capability level
4. Known aliases/associations
5. Historical campaign alignment
6. Targeting patterns
7. Confidence level with reasoning
```

### Intelligence Report

```
Generate a threat intelligence report from the following raw data.

Source data:
---
{raw_intel}
---

Report structure:
1. Executive Summary (2-3 sentences for leadership)
2. Key Findings (bulleted, prioritized)
3. Threat Details
   - Actor/Campaign information
   - Technical indicators (defanged)
   - Tactics, Techniques, Procedures
4. Impact Assessment
5. Recommended Actions
6. IOC Appendix (structured for ingestion)

Target audience: {audience}
Classification: {classification}
```

---

## Report Generation

### Executive Summary

```
Generate an executive summary of this security analysis for non-technical leadership.

Technical analysis:
---
{technical_analysis}
---

Requirements:
- Maximum 200 words
- No technical jargon
- Focus on business impact
- Clear risk statement
- Actionable recommendations
- Timeline if applicable
```

### Technical Report

```
Generate a detailed technical report from this analysis.

Analysis data:
---
{analysis_data}
---

Report sections:
1. Overview
2. Methodology
3. Technical Findings
   - Detailed observations
   - Evidence references
   - MITRE ATT&CK mapping
4. Impact Analysis
5. Indicators of Compromise
   - Format for SIEM ingestion
6. Remediation Steps
   - Immediate (0-24h)
   - Short-term (1-7 days)
   - Long-term (strategic)
7. Appendices
   - Raw data references
   - Tool outputs
```

---

## System Prompts

### Security Analyst Assistant

```
You are an expert security analyst assistant specializing in threat detection, incident response, and malware analysis.

Your capabilities:
- Extract and analyze indicators of compromise (IOCs)
- Map findings to MITRE ATT&CK framework
- Provide actionable security recommendations
- Generate detection rules (YARA, Sigma, Snort)
- Analyze logs for security anomalies

Guidelines:
- Always defang URLs, IPs, and domains in output (e.g., hxxp://, [.])
- Provide confidence levels for assessments
- Reference specific evidence for conclusions
- Consider false positive potential
- Prioritize recommendations by risk and effort

When analyzing potentially malicious code:
- Describe functionality without enhancing it
- Extract IOCs and TTPs
- Never provide working exploit code
- Focus on detection and defense
```

### Incident Response Coordinator

```
You are an incident response coordinator assisting with security incident management.

Your role:
- Help classify and prioritize incidents
- Guide containment and eradication steps
- Assist with evidence collection requirements
- Coordinate communication templates
- Track incident timeline and actions

Framework alignment:
- NIST Incident Response Lifecycle
- SANS Incident Handler's Handbook
- Organization's IR playbooks

Always consider:
- Evidence preservation requirements
- Chain of custody
- Regulatory notification timelines
- Business continuity impact
- Communication to stakeholders
```

---

## Usage Tips

1. **Be Specific**: Include context about your environment, tools, and constraints
2. **Provide Examples**: Show expected output format when relevant
3. **Set Boundaries**: Specify what you DON'T want (e.g., "don't include...")
4. **Request Structure**: Ask for specific output formats (JSON, markdown, etc.)
5. **Iterate**: Refine prompts based on results

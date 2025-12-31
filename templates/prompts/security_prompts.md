# Security Analysis Prompt Templates

Production-ready prompt templates for security AI applications, with built-in hallucination mitigation.

---

## ⚠️ Critical: Understanding LLM Limitations in Security

### The Hallucination Problem

LLMs can confidently generate **false information**. In security contexts, this is dangerous:

| Hallucination Type | Security Risk | Example |
|--------------------|---------------|---------|
| **Fabricated IOCs** | Blocking legitimate IPs/domains | LLM invents an IP that "looks malicious" |
| **False attribution** | Wrong threat actor, wrong response | "This is definitely APT29" (it's not) |
| **Invented CVEs** | Wasted remediation effort | "CVE-2024-99999 affects your system" (doesn't exist) |
| **Confident misclassification** | Missed attacks or alert fatigue | "This is benign" (it's ransomware) |
| **Made-up MITRE mappings** | Incorrect threat modeling | "This maps to T1999" (not a real technique) |

### Why LLMs Hallucinate

1. **Training data gaps** - Model doesn't know recent threats
2. **Pattern matching gone wrong** - "This looks like X" when it's not
3. **Pressure to answer** - LLMs prefer wrong answers over "I don't know"
4. **Context confusion** - Mixing up details from similar-looking data

### Mitigation Strategies

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HALLUCINATION MITIGATION                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. GROUND IN PROVIDED DATA                                         │
│     "Only use information from the data I provided"                 │
│     "Do not infer or guess"                                         │
│                                                                     │
│  2. REQUIRE CITATIONS                                               │
│     "Quote the exact log line that supports each finding"           │
│     "If you can't cite evidence, mark as [UNVERIFIED]"              │
│                                                                     │
│  3. REQUEST CONFIDENCE LEVELS                                       │
│     "Rate confidence 1-10 for each claim"                           │
│     "For anything below 8, explain what would increase confidence"  │
│                                                                     │
│  4. ENCOURAGE "I DON'T KNOW"                                        │
│     "If uncertain, say 'insufficient data' rather than guessing"    │
│     "It's better to miss something than fabricate"                  │
│                                                                     │
│  5. VERIFY EXTERNALLY                                               │
│     Always validate IOCs against real threat intel                  │
│     Never auto-block based solely on LLM output                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Log Analysis Prompts

### Grounded Log Parser (Anti-Hallucination)

```
You are parsing security logs. IMPORTANT RULES:
- Only extract information EXPLICITLY present in the log
- Do NOT infer, guess, or add context not in the log
- If a field is missing, return null (not a guess)
- Quote the exact text that supports each extraction

Parse this log entry:
{log_entry}

Return JSON with these fields (null if not present):
{
  "timestamp": "exact timestamp from log or null",
  "source_ip": "exact IP from log or null",
  "destination_ip": "exact IP from log or null", 
  "user": "exact username from log or null",
  "action": "exact action from log or null",
  "status": "success/failure as stated, or null",
  "evidence": "quote the relevant part of the log"
}

DO NOT add IPs, users, or details not explicitly in the log text.
```

### Threat Detection with Verification

```
Analyze these logs for security threats. 

CRITICAL INSTRUCTIONS:
1. Only identify threats you can PROVE from the log data
2. For each finding, quote the EXACT log lines as evidence
3. If you're unsure, say "POSSIBLE" not "CONFIRMED"
4. Do not invent IOCs - only report what's in the logs
5. Do not assume MITRE techniques without clear evidence

LOGS:
{logs}

CONTEXT (use only if relevant):
- Normal business hours: {business_hours}
- Known admin accounts: {admin_accounts}
- Internal IP ranges: {internal_ranges}

For each finding, provide:

## Finding [N]
- **Classification**: CONFIRMED THREAT / POSSIBLE THREAT / SUSPICIOUS / BENIGN
- **Confidence**: [1-10] 
- **Evidence**: [Quote exact log lines]
- **Reasoning**: [Why this is suspicious]
- **MITRE ATT&CK**: [Only if clearly applicable, otherwise "Needs verification"]
- **What would increase confidence**: [Additional data needed]

If no threats found, say "No confirmed threats detected" - don't invent issues.
```

---

## IOC Analysis Prompts

### IP Analysis (With Ground Truth Requirements)

```
Analyze this IP address using ONLY the threat intelligence data I provide.

IP: {ip_address}

PROVIDED THREAT INTEL (this is your ONLY source of truth):
{threat_intel_data}

RULES:
- Base your analysis ONLY on the data above
- If the IP isn't in the threat intel, say "No data available"
- Do NOT use your training data to make claims about this IP
- Do NOT invent threat actor names or campaigns

Provide:
1. **Status**: Malicious / Suspicious / Clean / NO DATA AVAILABLE
2. **Confidence**: [1-10, max 7 if data is limited]
3. **Evidence from provided data**: [Quote relevant entries]
4. **What I cannot determine**: [List gaps]
5. **Recommendation**: [Action to take]
6. **Verification needed**: [What to check externally]

IMPORTANT: If you cannot find this IP in the provided data, DO NOT fabricate a reputation. Say "No threat intelligence data available for this IP - recommend checking VirusTotal, AbuseIPDB, or other sources directly."
```

### Hash Analysis (Verification-First)

```
Analyze this file hash using ONLY the provided scan results.

Hash: {hash}
Type: {hash_type}

PROVIDED DATA:
- VirusTotal: {vt_results}
- Sandbox: {sandbox_results}

STRICT RULES:
1. Only report detections that appear in the provided data
2. Do not guess malware family if not in scan results
3. If AV names conflict, report the conflict, don't pick one
4. Quote detection names exactly as provided

Analysis:

## Detection Summary
- **Detected as malicious**: Yes/No (based on provided data)
- **Detection ratio**: [X/Y from VT data, or "not provided"]
- **Malware family**: [Only if consistently identified, otherwise "Inconclusive"]
- **Confidence**: [1-10]

## Behavioral Indicators (from sandbox only)
[List only behaviors from provided sandbox data]
[If no sandbox data: "No sandbox data provided"]

## What I Cannot Determine
[List what would need additional analysis]

## Recommended Actions
[Based only on provided evidence]

DO NOT invent file behaviors, registry keys, or C2 servers not in the data.
```

---

## Incident Response Prompts

### Alert Triage (Realistic Confidence)

```
You are a SOC analyst triaging an alert. Be conservative - false negatives are dangerous, but false positives waste resources.

ALERT:
{alert_json}

CONTEXT:
- Source reliability: {source_reliability}
- Historical false positive rate for this rule: {fp_rate}
- Asset criticality: {asset_criticality}

TRIAGE ANALYSIS:

## Initial Assessment
- **Alert type**: [What the alert is claiming]
- **Data quality**: [Is the alert data complete? What's missing?]

## True Positive Likelihood
- **Estimate**: [X]% 
- **Reasoning**: [Why this percentage - be specific]
- **Factors increasing TP likelihood**: [List]
- **Factors decreasing TP likelihood**: [List]

## Priority Score: [1-10]
- 1-3: Low - investigate within 24 hours
- 4-6: Medium - investigate within 4 hours  
- 7-9: High - investigate within 1 hour
- 10: Critical - immediate response

## Investigation Checklist
1. [ ] [Specific check based on alert type]
2. [ ] [Verify IOCs against threat intel]
3. [ ] [Check for related alerts]
4. [ ] [Validate affected asset]

## Escalation
- **Recommend escalation**: Yes/No
- **Escalate to**: [Team/person]
- **Justification**: [Why or why not]

## What I'm Uncertain About
[List aspects where you'd want human verification]
```

### Incident Summary (Executive-Safe)

```
Create an executive summary of this security incident. 

STRICT REQUIREMENTS:
- Use only facts from the provided data
- Clearly mark anything uncertain as "Under Investigation"
- Do not speculate on threat actor identity unless confirmed
- Do not estimate financial impact unless data supports it

INCIDENT DATA:
Timeline: {timeline}
Affected Systems: {systems}  
Confirmed IOCs: {iocs}
Actions Taken: {actions}

EXECUTIVE SUMMARY:

## What Happened
[2-3 sentences in plain language - no jargon]
[Mark any unconfirmed details as "preliminary" or "under investigation"]

## Business Impact
- **Confirmed impact**: [Only what we know for certain]
- **Potential impact**: [Clearly labeled as potential]
- **Unknown**: [What we're still determining]

## Current Status
- **Containment**: [Complete/In Progress/Not Started]
- **Systems affected**: [Count and criticality]
- **Data exposure**: [Confirmed/Suspected/Unknown]

## What We Know vs. What We're Investigating
| Confirmed | Under Investigation |
|-----------|---------------------|
| [Facts]   | [Open questions]    |

## Decisions Needed
1. [Specific decision with deadline]
2. [Resource requirement]

## Next Update
[When leadership will receive next briefing]

NOTE: This summary is based on information available at [timestamp]. Assessments may change as investigation progresses.
```

---

## YARA Rule Generation

### From Sample Analysis (Conservative)

```
Generate a YARA rule based on this malware analysis.

SAMPLE DATA:
File Info: {file_info}
Strings: {strings}
Behavioral Indicators: {behaviors}
Similar Samples: {similar_samples}

YARA RULE REQUIREMENTS:
1. Use ONLY indicators from the provided data
2. Prefer multiple weak indicators over one strong (reduces false positives)
3. Include confidence-based conditions
4. Add metadata about detection confidence
5. Do NOT guess at strings or behaviors not in the data

Generate rule:

```yara
rule [MalwareName]_[Confidence] {
    meta:
        description = "[What this detects]"
        author = "AI-Generated - REQUIRES HUMAN REVIEW"
        date = "[Today]"
        confidence = "[Low/Medium/High]"
        false_positive_risk = "[Low/Medium/High]"
        reference = "[Source of indicators]"
        
        // IMPORTANT: This rule was AI-generated and should be:
        // 1. Tested against clean file corpus before deployment
        // 2. Reviewed by malware analyst
        // 3. Monitored for false positives in first 7 days
        
    strings:
        // Only strings from provided data
        $s1 = "[exact string from data]"
        $s2 = "[exact string from data]"
        
    condition:
        // Conservative condition to reduce false positives
        [condition logic]
}
```

VALIDATION CHECKLIST:
- [ ] All strings appear in provided sample data
- [ ] Condition requires multiple indicators
- [ ] Rule tested against goodware samples
- [ ] False positive estimate documented
```

---

## Verification Prompts

### Self-Check Prompt (Use After Any Analysis)

```
Review your previous response about {topic}.

For EACH factual claim you made:
1. Quote the exact source data that supports it
2. If you cannot find supporting data, mark as [UNVERIFIED]
3. For any [UNVERIFIED] items, either:
   - Remove the claim, or
   - Clearly label it as speculation

Claims to verify:
{list_of_claims_from_previous_response}

Verification:
| Claim | Source Data Quote | Status |
|-------|-------------------|--------|
| ...   | "..." or N/A      | VERIFIED / UNVERIFIED / SPECULATION |

Corrected response (if needed):
[Revised response with unverified claims removed or labeled]
```

### Confidence Calibration

```
For your analysis of {topic}, provide calibrated confidence:

For each major finding:
1. **Finding**: [What you identified]
2. **Confidence**: [1-10]
3. **What would make this a 10**: [Missing evidence]
4. **What would make this a 1**: [Contradicting evidence]
5. **Alternative explanations**: [Other interpretations of the same data]

Confidence scale:
- 9-10: Would bet my job on this
- 7-8: High confidence, minor uncertainties
- 5-6: More likely than not, but significant unknowns
- 3-4: Possible but speculative
- 1-2: Guess based on limited data

For any finding below 7, recommend specific verification steps.
```

---

## Production Best Practices

### 1. Never Trust, Always Verify

```python
# BAD: Auto-blocking based on LLM output
llm_result = analyze_ip(suspicious_ip)
if llm_result["malicious"]:
    firewall.block(suspicious_ip)  # DANGEROUS!

# GOOD: LLM assists, human/system verifies
llm_result = analyze_ip(suspicious_ip)
if llm_result["malicious"]:
    # Verify against actual threat intel
    vt_result = virustotal.check(suspicious_ip)
    abuse_result = abuseipdb.check(suspicious_ip)
    
    if vt_result.malicious or abuse_result.confidence > 80:
        queue_for_review(suspicious_ip, llm_result, vt_result)
```

### 2. Log Everything for Audit

```python
# Always log LLM reasoning for later review
analysis = {
    "input": sanitized_input,
    "llm_output": response,
    "confidence": response.get("confidence"),
    "action_taken": action,
    "human_verified": False,
    "timestamp": datetime.utcnow()
}
audit_log.write(analysis)
```

### 3. Set Confidence Thresholds

| Action | Minimum Confidence | Additional Requirements |
|--------|-------------------|------------------------|
| Log for review | Any | None |
| Alert analyst | 50%+ | None |
| Auto-quarantine file | 90%+ | 2+ AV detections |
| Block IP | 95%+ | Threat intel confirmation |
| Isolate host | 99%+ | Human approval required |

### 4. Handle "I Don't Know" Gracefully

```python
# Prompt should allow uncertainty
prompt = """
If you cannot determine the answer with confidence, respond:
{"status": "uncertain", "reason": "...", "suggested_next_steps": [...]}

Do not guess. Uncertainty is acceptable and preferred over false confidence.
"""
```

### 5. Regular Calibration

- Track LLM predictions vs. actual outcomes
- Measure false positive / false negative rates
- Adjust confidence thresholds based on real data
- Retrain prompts that consistently fail

---

## Template Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `{log_entry}` | Single log line | `2024-01-15 10:30:00 ERROR auth...` |
| `{logs}` | Multiple log lines | Multi-line string |
| `{ip_address}` | IP to analyze | `192.168.1.100` |
| `{threat_intel_data}` | TI context | JSON from VirusTotal, etc. |
| `{hash}` | File hash | `d41d8cd98f00b204e9800998ecf8427e` |
| `{alert_json}` | SIEM alert | JSON object |
| `{business_hours}` | Normal hours | `09:00-17:00 EST Mon-Fri` |
| `{admin_accounts}` | Known admins | `["admin", "svc_backup"]` |

---

## Quick Reference: Anti-Hallucination Phrases

Include these in your prompts:

```
"Only use information from the data I provided"
"If you cannot find evidence, say 'insufficient data'"
"Quote the exact text that supports each claim"
"Do not infer or guess"
"Mark uncertain items as [NEEDS VERIFICATION]"
"It's better to miss something than fabricate"
"Rate your confidence 1-10 for each finding"
"What would increase your confidence?"
"What alternative explanations exist?"
"If this isn't in the provided data, say so"
```

---

## See Also

- [Lab 00c: Prompt Engineering](../../labs/lab00c-intro-prompt-engineering/) - Hands-on prompting basics
- [Structured Output Parsing](../../docs/guides/structured-output-parsing.md) - Reliable JSON from LLMs
- [LLM Evaluation & Testing](../../docs/guides/llm-evaluation-testing.md) - Measuring LLM accuracy
- [Prompt Injection Defense](../../docs/guides/prompt-injection-defense.md) - Security for LLM inputs

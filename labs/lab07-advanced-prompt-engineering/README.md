# Lab 07: Advanced Prompt Engineering Mastery

Master advanced prompting techniques for production security LLM applications. Learn self-improvement methods, hallucination detection, verification pipelines, and result visualization.

## Learning Objectives

By the end of this lab, you will:
1. Write effective prompts from beginner to expert level
2. Use iterative refinement to improve prompts with LLM feedback
3. Detect and prevent hallucinations in LLM outputs
4. Visualize security data with Plotly
5. Build reliable, production-ready LLM workflows

## Estimated Time

3-4 hours

## Prerequisites

- Python fundamentals (Lab 00a)
- Intro prompt engineering basics (Lab 00c recommended)
- Basic LLM usage experience (Labs 04, 05, or 06)
- API key for Claude, GPT-4, or Gemini

---

## Prompt Development Tools

Before diving in, here are the best tools for developing and testing prompts:

### Interactive Playgrounds (No Code Required)

| Tool | Provider | Best For | Link |
|------|----------|----------|------|
| **Google AI Studio** | Google | Gemini models, visual prompt builder, prompt gallery | [aistudio.google.com](https://aistudio.google.com/) |
| **Anthropic Console** | Anthropic | Claude models, workbench, prompt optimization | [console.anthropic.com](https://console.anthropic.com/) |
| **OpenAI Playground** | OpenAI | GPT models, assistants, fine-tuning | [platform.openai.com/playground](https://platform.openai.com/playground) |
| **Poe** | Quora | Multi-model comparison, quick testing | [poe.com](https://poe.com/) |

### Why Use Interactive Tools First?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROMPT DEVELOPMENT WORKFLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. PROTOTYPE              2. ITERATE                3. PRODUCTIONIZE       │
│  ┌──────────────┐         ┌──────────────┐          ┌──────────────┐       │
│  │ AI Studio /  │   ──►   │ Test edge    │   ──►    │ Move to code │       │
│  │ Playground   │         │ cases in UI  │          │ with API     │       │
│  │              │         │              │          │              │       │
│  │ • Fast       │         │ • Compare    │          │ • Automate   │       │
│  │ • Visual     │         │   outputs    │          │ • Scale      │       │
│  │ • Free tier  │         │ • Tune       │          │ • Integrate  │       │
│  └──────────────┘         └──────────────┘          └──────────────┘       │
│                                                                              │
│  💡 TIP: Don't write code until your prompt works in the playground!        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Google AI Studio Features

Google AI Studio is particularly useful for beginners:

1. **Structured Prompts**: Visual builder with system/user message separation
2. **Prompt Gallery**: Pre-built templates you can customize
3. **Compare Models**: Test Gemini Pro vs Flash side-by-side
4. **Tuning**: Fine-tune models on your examples
5. **Export to Code**: Generate Python/Node.js code when ready

**Quick Start with AI Studio:**
1. Go to [aistudio.google.com](https://aistudio.google.com/)
2. Click "Create new prompt"
3. Choose "Freeform" for experimentation
4. Test your prompts interactively
5. Click "Get code" to export to Python

```python
# Example code exported from AI Studio
import google.generativeai as genai

genai.configure(api_key="YOUR_API_KEY")
model = genai.GenerativeModel('gemini-1.5-pro')

response = model.generate_content("""
You are a security analyst. Analyze this log for threats:
[LOG DATA HERE]
""")
print(response.text)
```

---

## Part 1: Prompt Engineering Fundamentals

### 1.1 The Anatomy of a Good Prompt

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROMPT STRUCTURE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   CONTEXT    │  │    TASK      │  │   FORMAT     │  │  CONSTRAINTS │    │
│  │              │  │              │  │              │  │              │    │
│  │ Who you are  │  │ What to do   │  │ How to       │  │ What to      │    │
│  │ Background   │  │ Specific     │  │ structure    │  │ avoid        │    │
│  │ Domain info  │  │ action       │  │ output       │  │ Limits       │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                              │
│  Example:                                                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ [CONTEXT] You are a senior security analyst reviewing firewall logs.  │ │
│  │ [TASK] Analyze the following log entries for potential threats.       │ │
│  │ [FORMAT] Return findings as JSON with severity, description, IOCs.    │ │
│  │ [CONSTRAINTS] Focus on the last 24 hours. Ignore routine traffic.     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Beginner Prompts

**Level 1: Basic Questions**

```python
# ❌ Weak prompt
prompt = "Is this IP bad?"

# ✅ Better prompt
prompt = "Is the IP address 192.168.1.100 commonly associated with malicious activity?"

# ✅✅ Good prompt
prompt = """
Analyze the IP address 45.33.32.156 for potential threats.

Check for:
- Known malware associations
- Botnet membership
- Spam blacklists
- Geographic anomalies

Provide a risk assessment (low/medium/high) with reasoning.
"""
```

**Level 2: Simple Analysis**

```python
# ❌ Too vague
prompt = "Look at this log"

# ✅ Clear and specific
prompt = """
Analyze this authentication log entry:

Log: Failed password for admin from 10.0.0.5 port 22 ssh2

Answer:
1. What type of event is this?
2. Is this suspicious? Why or why not?
3. What follow-up actions would you recommend?
"""
```

### 1.3 Intermediate Prompts

**Level 3: Structured Output**

```python
prompt = """
You are a security analyst. Extract IOCs from this threat report.

REPORT:
The malware connects to evil-domain.com on port 443. It drops a file
with hash d41d8cd98f00b204e9800998ecf8427e in C:\\Windows\\Temp.
The C2 server IP is 185.220.101.1.

Return a JSON object with this structure:
{
    "domains": ["list of domains"],
    "ips": ["list of IPs"],
    "hashes": [{"type": "md5/sha256", "value": "hash"}],
    "file_paths": ["list of file paths"],
    "ports": [list of ports as integers]
}

Only include IOCs explicitly mentioned. Do not infer or guess.
"""
```

**Level 4: Multi-Step Reasoning**

```python
prompt = """
Analyze this security alert using the following framework:

ALERT:
Multiple failed SSH logins from 10.0.0.50 to server-01, followed by
successful login, then outbound connection to 185.220.101.1:443

ANALYSIS FRAMEWORK:
1. INITIAL ASSESSMENT
   - What happened? (timeline of events)
   - What systems are involved?

2. THREAT EVALUATION
   - What attack technique does this resemble? (reference MITRE ATT&CK)
   - What is the potential impact?

3. INVESTIGATION STEPS
   - What additional data would you gather?
   - What queries would you run?

4. RESPONSE RECOMMENDATIONS
   - Immediate actions (containment)
   - Short-term actions (investigation)
   - Long-term actions (prevention)

Provide your analysis following this structure.
"""
```

### 1.4 Advanced Prompts

**Level 5: Role-Based Expert Analysis**

```python
prompt = """
You are a senior threat intelligence analyst with expertise in APT groups
targeting financial institutions. You have access to MITRE ATT&CK,
VirusTotal reports, and historical campaign data.

SCENARIO:
A financial institution detected unusual PowerShell activity:
- Base64-encoded commands executed via scheduled task
- Outbound HTTPS to .ru domain registered 3 days ago
- LSASS memory access attempts
- WMI persistence mechanism installed

TASK:
1. Profile this potential threat actor
   - What APT groups use these TTPs?
   - Confidence level for each attribution hypothesis

2. Predict next steps
   - Based on known playbooks, what might happen next?
   - What detection opportunities exist?

3. Hunting queries
   - Provide Sigma rules or detection logic
   - Suggest proactive hunting queries

4. Executive summary
   - 2-3 sentence summary for leadership
   - Risk rating with justification

Format as a structured intelligence report.
"""
```

**Level 6: Chain-of-Thought with Verification**

```python
prompt = """
Analyze this potential ransomware incident. Think step by step and
show your reasoning at each stage.

EVIDENCE:
- 500+ files renamed with .encrypted extension in 10 minutes
- Ransom note "README_DECRYPT.txt" found in multiple directories
- vssadmin.exe executed to delete shadow copies
- PowerShell downloading from pastebin.com/raw/abc123
- Registry run key added for persistence

ANALYSIS PROCESS:

STEP 1: Evidence Classification
For each piece of evidence, classify as:
- Definitive indicator (proves ransomware)
- Strong indicator (highly suggestive)
- Weak indicator (could be legitimate)

STEP 2: Attack Timeline Reconstruction
Order the events chronologically and identify the attack phases:
- Initial access
- Execution
- Persistence
- Defense evasion
- Impact

STEP 3: Ransomware Family Identification
Based on the indicators, which ransomware family is most likely?
List your reasoning for each candidate.

STEP 4: Confidence Assessment
Rate your confidence in each conclusion (high/medium/low) and explain why.

STEP 5: Verification Checks
What additional evidence would confirm or refute your analysis?
What could cause false positives?
"""
```

---

## Part 2: Self-Improvement - Asking the LLM to Improve Prompts

### 2.1 The Meta-Prompt Technique

**Ask the LLM to critique and improve your prompt:**

```python
meta_prompt = """
I'm trying to write a prompt for analyzing security logs. Here's my current attempt:

---
CURRENT PROMPT:
"Look at these logs and tell me if there's anything suspicious"
---

Please help me improve this prompt by:

1. CRITIQUE: What's wrong with this prompt?
   - What's unclear or ambiguous?
   - What information is missing?
   - What could go wrong?

2. IMPROVED VERSION: Rewrite the prompt to be more effective
   - Add necessary context
   - Be specific about the task
   - Define the expected output format
   - Add helpful constraints

3. EXPLAIN: Why is the improved version better?
   - What specific changes make it more effective?
"""
```

### 2.2 Iterative Refinement Loop

```python
def iterative_prompt_refinement(initial_prompt: str, task_description: str, iterations: int = 3):
    """
    Use the LLM to iteratively improve a prompt.
    """
    current_prompt = initial_prompt

    for i in range(iterations):
        refinement_request = f"""
        I have a prompt for the following task:
        TASK: {task_description}

        CURRENT PROMPT (version {i + 1}):
        ---
        {current_prompt}
        ---

        Please analyze this prompt and provide:

        1. EFFECTIVENESS SCORE (1-10): How well does this prompt accomplish the task?

        2. WEAKNESSES: List specific problems with this prompt
           - Ambiguities
           - Missing context
           - Unclear instructions
           - Potential for misinterpretation

        3. IMPROVED PROMPT: Write a better version that addresses the weaknesses

        4. CHANGES MADE: Explain what you changed and why

        Return the improved prompt between <improved_prompt> tags.
        """

        response = call_llm(refinement_request)
        current_prompt = extract_between_tags(response, "improved_prompt")

        print(f"=== Iteration {i + 1} ===")
        print(f"Prompt: {current_prompt[:200]}...")

    return current_prompt

# Example usage
initial = "Analyze this log for threats"
task = "Detect potential security incidents in authentication logs and provide actionable findings"
final_prompt = iterative_prompt_refinement(initial, task)
```

### 2.3 Prompt Testing Framework

```python
def test_prompt_robustness(prompt: str, test_cases: list) -> dict:
    """
    Test a prompt against multiple scenarios.
    """
    results = {
        "passed": 0,
        "failed": 0,
        "edge_cases": [],
        "suggestions": []
    }

    evaluation_prompt = f"""
    I want to evaluate a prompt's effectiveness.

    THE PROMPT BEING TESTED:
    ---
    {prompt}
    ---

    TEST CASES:
    {json.dumps(test_cases, indent=2)}

    For each test case, evaluate:
    1. Would the prompt produce the expected output?
    2. Are there edge cases that would fail?
    3. What inputs might cause unexpected behavior?

    Provide:
    - Pass/fail for each test case with explanation
    - Edge cases that weren't covered
    - Suggestions for making the prompt more robust
    """

    return call_llm(evaluation_prompt)

# Example test cases
test_cases = [
    {
        "input": "Normal login from known IP",
        "expected": "Low risk, routine activity"
    },
    {
        "input": "Login at 3 AM from new country",
        "expected": "High risk, geographic anomaly"
    },
    {
        "input": "Empty log entry",
        "expected": "Should handle gracefully, not crash"
    },
    {
        "input": "Malformed timestamp",
        "expected": "Should note parsing issue"
    }
]
```

### 2.4 Prompt Templates Library

```python
# Security Prompt Templates

TEMPLATES = {
    "log_analysis": """
You are a security analyst reviewing {log_type} logs.

CONTEXT:
- Time range: {time_range}
- Systems: {systems}
- Baseline behavior: {baseline}

LOGS:
{logs}

TASK:
Analyze these logs for security concerns.

OUTPUT FORMAT:
1. SUMMARY: One paragraph overview
2. FINDINGS: List each finding with:
   - Severity (Critical/High/Medium/Low/Info)
   - Description
   - Evidence (specific log entries)
   - MITRE ATT&CK technique (if applicable)
3. RECOMMENDATIONS: Prioritized action items
4. FALSE POSITIVE ASSESSMENT: Could any findings be benign?

Be specific and cite evidence from the logs.
""",

    "ioc_extraction": """
Extract all Indicators of Compromise from the following text.

TEXT:
{text}

EXTRACTION RULES:
- Only extract explicitly mentioned IOCs
- Do not infer or guess IOCs
- Validate format (e.g., valid IP ranges, proper hash lengths)
- Note any defanged IOCs (e.g., hxxp, [.], etc.)

OUTPUT FORMAT (JSON):
{{
    "ipv4": [],
    "ipv6": [],
    "domains": [],
    "urls": [],
    "hashes": {{"md5": [], "sha1": [], "sha256": []}},
    "emails": [],
    "file_paths": [],
    "registry_keys": [],
    "cves": []
}}

If no IOCs found for a category, use empty array.
""",

    "threat_assessment": """
Perform a threat assessment on the following security event.

EVENT:
{event}

ASSESSMENT FRAMEWORK:

1. CLASSIFICATION
   - Event type: (malware/intrusion/data exfiltration/insider threat/other)
   - Attack stage: (initial access/execution/persistence/etc.)

2. SEVERITY SCORING
   - Confidentiality impact (1-10)
   - Integrity impact (1-10)
   - Availability impact (1-10)
   - Overall severity: (Critical/High/Medium/Low)

3. THREAT ACTOR ASSESSMENT
   - Likely sophistication level
   - Possible motivations
   - Similar known campaigns

4. BUSINESS IMPACT
   - Affected assets
   - Potential data exposure
   - Regulatory implications

5. CONFIDENCE LEVEL
   - High/Medium/Low
   - What additional data would increase confidence?
"""
}

def use_template(template_name: str, **kwargs) -> str:
    """Fill in a prompt template with provided values."""
    template = TEMPLATES.get(template_name)
    if not template:
        raise ValueError(f"Unknown template: {template_name}")
    return template.format(**kwargs)
```

---

## Part 3: Hallucination Detection and Prevention

### 3.1 Understanding Hallucinations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TYPES OF LLM HALLUCINATIONS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TYPE 1: FACTUAL HALLUCINATIONS                                             │
│  ────────────────────────────                                               │
│  LLM states incorrect facts confidently                                     │
│  Example: "CVE-2024-99999 is a critical vulnerability in Apache"            │
│  (CVE doesn't exist)                                                        │
│                                                                              │
│  TYPE 2: ATTRIBUTION ERRORS                                                 │
│  ───────────────────────────                                                │
│  LLM attributes behavior to wrong source                                    │
│  Example: "This traffic pattern is typical of APT28"                        │
│  (Pattern doesn't match known APT28 TTPs)                                   │
│                                                                              │
│  TYPE 3: FABRICATED DETAILS                                                 │
│  ─────────────────────────                                                  │
│  LLM invents specifics not in the input                                     │
│  Example: Adding IOCs not present in the analyzed text                      │
│                                                                              │
│  TYPE 4: OVERCONFIDENT CONCLUSIONS                                          │
│  ──────────────────────────────────                                         │
│  LLM states uncertain things as facts                                       │
│  Example: "This is definitely ransomware" (when evidence is weak)           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Hallucination Prevention Techniques

**Technique 1: Explicit Grounding**

```python
prompt_with_grounding = """
Analyze the following log entry and identify any threats.

LOG ENTRY:
{log}

CRITICAL INSTRUCTIONS:
- ONLY reference information explicitly present in the log entry above
- If you're uncertain, say "insufficient evidence" rather than guessing
- Do NOT reference external threat intelligence not provided here
- Quote the specific parts of the log that support each finding

For each finding, you MUST:
1. Quote the exact text from the log that supports it
2. Rate your confidence (high/medium/low)
3. Note what additional information would increase confidence
"""
```

**Technique 2: Self-Verification Prompt**

```python
verification_prompt = """
Review your previous analysis for potential errors.

YOUR PREVIOUS ANALYSIS:
{previous_analysis}

ORIGINAL INPUT:
{original_input}

VERIFICATION CHECKLIST:

1. FACTUAL ACCURACY
   - Are all stated facts present in the original input?
   - Did I add any information not in the input?
   - List any claims that cannot be verified from the input

2. LOGICAL CONSISTENCY
   - Do my conclusions follow from the evidence?
   - Are there logical gaps in my reasoning?
   - Could alternative explanations fit the evidence?

3. CONFIDENCE CALIBRATION
   - Did I overstate certainty anywhere?
   - Where should I have said "possibly" or "likely" instead of definitive statements?

4. CORRECTIONS
   - List any corrections needed
   - Provide a revised analysis if errors found

Be critical and thorough. It's better to catch errors now.
"""
```

**Technique 3: Citation Requirements**

```python
prompt_with_citations = """
Analyze this threat report and extract key findings.

REPORT:
{report}

RULES:
1. Every claim must include a citation in brackets [paragraph X, sentence Y]
2. If you cannot cite a source from the report, mark the claim as [INFERENCE]
3. Clearly distinguish between:
   - [STATED]: Directly stated in the report
   - [INFERRED]: Logically derived from stated information
   - [UNCERTAIN]: Possible but not well-supported

Example format:
"The malware uses DNS tunneling for C2 communication [STATED: paragraph 2, sentence 3]"
"This suggests the attacker has internal network access [INFERRED: based on lateral movement in paragraph 4]"
"""
```

### 3.3 Automated Hallucination Detection

```python
import re
from typing import List, Dict, Tuple

class HallucinationDetector:
    def __init__(self, llm_client):
        self.llm = llm_client

    def detect_fabricated_iocs(
        self,
        original_text: str,
        extracted_iocs: Dict[str, List[str]]
    ) -> List[Dict]:
        """Check if extracted IOCs actually appear in the source text."""
        fabrications = []

        for ioc_type, iocs in extracted_iocs.items():
            for ioc in iocs:
                # Normalize for comparison (handle defanging)
                normalized_ioc = self._normalize_ioc(ioc)
                normalized_text = self._normalize_ioc(original_text)

                if normalized_ioc not in normalized_text:
                    fabrications.append({
                        "type": ioc_type,
                        "value": ioc,
                        "issue": "Not found in source text",
                        "severity": "high"
                    })

        return fabrications

    def _normalize_ioc(self, text: str) -> str:
        """Normalize IOCs for comparison (handle defanging)."""
        normalized = text.lower()
        # Handle common defanging
        normalized = normalized.replace("[.]", ".")
        normalized = normalized.replace("hxxp", "http")
        normalized = normalized.replace("[:]", ":")
        return normalized

    def verify_claims(
        self,
        claims: List[str],
        source_text: str
    ) -> List[Dict]:
        """Use LLM to verify if claims are supported by source."""
        verification_prompt = f"""
        Verify each claim against the source text.

        SOURCE TEXT:
        {source_text}

        CLAIMS TO VERIFY:
        {json.dumps(claims, indent=2)}

        For each claim, respond with:
        {{
            "claim": "the claim text",
            "supported": true/false,
            "evidence": "quote from source if supported, or 'not found'",
            "confidence": "high/medium/low"
        }}

        Return as JSON array.
        """
        return self.llm.complete(verification_prompt)

    def cross_reference_check(
        self,
        analysis: str,
        known_facts: Dict
    ) -> List[Dict]:
        """Check analysis against known facts database."""
        check_prompt = f"""
        Cross-reference this analysis against known facts.

        ANALYSIS:
        {analysis}

        KNOWN FACTS DATABASE:
        {json.dumps(known_facts, indent=2)}

        Identify any statements in the analysis that:
        1. Contradict known facts
        2. Make claims about entities not in the database
        3. Attribute characteristics incorrectly

        Return issues as JSON array with:
        - statement: the problematic statement
        - issue_type: contradiction/fabrication/misattribution
        - correction: what should it say
        """
        return self.llm.complete(check_prompt)


# Example usage
detector = HallucinationDetector(llm_client)

# Check extracted IOCs
original_report = "The malware connects to evil.com and 192.168.1.1"
extracted = {
    "domains": ["evil.com", "malware.net"],  # malware.net is fabricated!
    "ips": ["192.168.1.1"]
}
fabrications = detector.detect_fabricated_iocs(original_report, extracted)
print(f"Fabricated IOCs: {fabrications}")
```

### 3.4 Confidence Scoring

```python
def get_analysis_with_confidence(prompt: str, input_data: str) -> Dict:
    """Get analysis with explicit confidence scoring."""

    confidence_prompt = f"""
    {prompt}

    INPUT:
    {input_data}

    IMPORTANT: For each finding or conclusion, you must provide:

    1. The finding/conclusion
    2. Confidence score (0-100%)
    3. Evidence strength:
       - STRONG: Multiple independent indicators
       - MODERATE: Single clear indicator or multiple weak ones
       - WEAK: Circumstantial or incomplete evidence
    4. What would increase confidence

    Format each finding as:
    {{
        "finding": "description",
        "confidence_percent": 85,
        "evidence_strength": "STRONG",
        "supporting_evidence": ["evidence 1", "evidence 2"],
        "confidence_boosters": ["what would increase confidence"]
    }}

    Only report findings with confidence > 30%.
    Clearly separate high-confidence from low-confidence findings.
    """

    return call_llm(confidence_prompt)
```

---

## Part 4: Data Visualization with Plotly

### 4.1 Setting Up Plotly

```python
# Install: pip install plotly pandas

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta
import random
```

### 4.2 Security Event Timeline

```python
def create_event_timeline(events: list) -> go.Figure:
    """
    Create an interactive timeline of security events.

    Args:
        events: List of dicts with 'timestamp', 'event_type', 'severity', 'description'
    """
    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Color map for severity
    color_map = {
        'critical': '#ff0000',
        'high': '#ff6600',
        'medium': '#ffcc00',
        'low': '#00cc00',
        'info': '#0066cc'
    }

    fig = px.scatter(
        df,
        x='timestamp',
        y='event_type',
        color='severity',
        color_discrete_map=color_map,
        size=[20] * len(df),  # Uniform size
        hover_data=['description'],
        title='Security Event Timeline'
    )

    fig.update_layout(
        xaxis_title='Time',
        yaxis_title='Event Type',
        hovermode='closest',
        template='plotly_dark'
    )

    return fig

# Example usage
events = [
    {"timestamp": "2024-01-15 10:00:00", "event_type": "Authentication",
     "severity": "high", "description": "Multiple failed logins from 10.0.0.5"},
    {"timestamp": "2024-01-15 10:05:00", "event_type": "Authentication",
     "severity": "critical", "description": "Successful login after failures"},
    {"timestamp": "2024-01-15 10:10:00", "event_type": "Network",
     "severity": "high", "description": "Outbound C2 connection detected"},
    {"timestamp": "2024-01-15 10:15:00", "event_type": "File System",
     "severity": "critical", "description": "Ransomware encryption started"},
]

fig = create_event_timeline(events)
fig.show()
```

### 4.3 Threat Distribution Dashboard

```python
def create_threat_dashboard(threat_data: dict) -> go.Figure:
    """
    Create a multi-panel threat dashboard.
    """
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            'Threats by Category',
            'Severity Distribution',
            'Threats Over Time',
            'Top Attack Vectors'
        ),
        specs=[
            [{"type": "pie"}, {"type": "bar"}],
            [{"type": "scatter"}, {"type": "bar"}]
        ]
    )

    # Panel 1: Pie chart of threat categories
    categories = threat_data['categories']
    fig.add_trace(
        go.Pie(
            labels=list(categories.keys()),
            values=list(categories.values()),
            name="Categories"
        ),
        row=1, col=1
    )

    # Panel 2: Severity distribution
    severities = threat_data['severities']
    colors = ['#ff0000', '#ff6600', '#ffcc00', '#00cc00']
    fig.add_trace(
        go.Bar(
            x=list(severities.keys()),
            y=list(severities.values()),
            marker_color=colors,
            name="Severity"
        ),
        row=1, col=2
    )

    # Panel 3: Threats over time
    timeline = threat_data['timeline']
    fig.add_trace(
        go.Scatter(
            x=timeline['dates'],
            y=timeline['counts'],
            mode='lines+markers',
            name="Daily Threats",
            line=dict(color='#00ccff')
        ),
        row=2, col=1
    )

    # Panel 4: Top attack vectors
    vectors = threat_data['attack_vectors']
    fig.add_trace(
        go.Bar(
            x=list(vectors.values()),
            y=list(vectors.keys()),
            orientation='h',
            marker_color='#9933ff',
            name="Vectors"
        ),
        row=2, col=2
    )

    fig.update_layout(
        height=700,
        showlegend=False,
        title_text="Security Threat Dashboard",
        template='plotly_dark'
    )

    return fig

# Example data
threat_data = {
    'categories': {
        'Malware': 45,
        'Phishing': 30,
        'Intrusion': 15,
        'Data Exfil': 10
    },
    'severities': {
        'Critical': 10,
        'High': 25,
        'Medium': 40,
        'Low': 25
    },
    'timeline': {
        'dates': pd.date_range(start='2024-01-01', periods=30, freq='D'),
        'counts': [random.randint(5, 50) for _ in range(30)]
    },
    'attack_vectors': {
        'Email': 40,
        'Web': 30,
        'USB': 10,
        'Network': 20
    }
}

fig = create_threat_dashboard(threat_data)
fig.show()
```

### 4.4 Network Graph Visualization

```python
import networkx as nx

def create_attack_path_graph(connections: list) -> go.Figure:
    """
    Visualize lateral movement as a network graph.

    Args:
        connections: List of (source, target, connection_type) tuples
    """
    # Build network graph
    G = nx.DiGraph()
    for source, target, conn_type in connections:
        G.add_edge(source, target, type=conn_type)

    # Get positions using spring layout
    pos = nx.spring_layout(G, k=2, iterations=50)

    # Create edge traces
    edge_traces = []
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]

        color = {
            'ssh': '#00ff00',
            'rdp': '#ff6600',
            'smb': '#ff0000',
            'wmi': '#9933ff'
        }.get(edge[2]['type'], '#ffffff')

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=2, color=color),
                hoverinfo='none'
            )
        )

    # Create node trace
    node_x = [pos[node][0] for node in G.nodes()]
    node_y = [pos[node][1] for node in G.nodes()]

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=list(G.nodes()),
        textposition="top center",
        marker=dict(
            size=30,
            color='#00ccff',
            line=dict(width=2, color='white')
        )
    )

    # Create figure
    fig = go.Figure(data=edge_traces + [node_trace])

    fig.update_layout(
        title='Attack Path Visualization',
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        template='plotly_dark',
        height=600
    )

    return fig

# Example: Lateral movement path
connections = [
    ('Entry Point', 'Workstation-01', 'ssh'),
    ('Workstation-01', 'Server-DB', 'smb'),
    ('Workstation-01', 'Server-App', 'rdp'),
    ('Server-App', 'Domain-Controller', 'wmi'),
    ('Domain-Controller', 'Server-DB', 'smb'),
]

fig = create_attack_path_graph(connections)
fig.show()
```

### 4.5 IOC Relationship Map

```python
def create_ioc_relationship_map(iocs: dict, relationships: list) -> go.Figure:
    """
    Create a Sankey diagram showing IOC relationships.

    Args:
        iocs: Dict of IOC types to lists of values
        relationships: List of (source_ioc, target_ioc, relationship) tuples
    """
    # Build node list
    nodes = []
    node_indices = {}
    idx = 0

    for ioc_type, values in iocs.items():
        for value in values:
            node_key = f"{ioc_type}:{value}"
            nodes.append({"label": value, "type": ioc_type})
            node_indices[node_key] = idx
            idx += 1

    # Build links
    sources = []
    targets = []
    values = []
    labels = []

    for source, target, rel in relationships:
        if source in node_indices and target in node_indices:
            sources.append(node_indices[source])
            targets.append(node_indices[target])
            values.append(1)
            labels.append(rel)

    # Color nodes by type
    type_colors = {
        'ip': '#ff6666',
        'domain': '#66ff66',
        'hash': '#6666ff',
        'email': '#ffff66'
    }
    node_colors = [type_colors.get(n['type'], '#cccccc') for n in nodes]

    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=[n['label'] for n in nodes],
            color=node_colors
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            label=labels
        )
    )])

    fig.update_layout(
        title="IOC Relationship Map",
        template='plotly_dark',
        height=500
    )

    return fig
```

---

## Part 5: Putting It All Together

### 5.1 Complete Analysis Pipeline

```python
class SecurityAnalysisPipeline:
    """
    Complete pipeline: prompt → LLM → verification → visualization
    """

    def __init__(self, llm_client):
        self.llm = llm_client
        self.detector = HallucinationDetector(llm_client)

    def analyze_with_verification(
        self,
        data: str,
        analysis_type: str = "threat_assessment"
    ) -> dict:
        """Run analysis with hallucination detection and visualization."""

        # Step 1: Get analysis using appropriate template
        prompt = use_template(analysis_type, event=data)
        initial_analysis = self.llm.complete(prompt)

        # Step 2: Self-verification
        verification = self.llm.complete(verification_prompt.format(
            previous_analysis=initial_analysis,
            original_input=data
        ))

        # Step 3: Extract and verify IOCs
        iocs = self.extract_iocs(initial_analysis)
        ioc_issues = self.detector.detect_fabricated_iocs(data, iocs)

        # Step 4: Generate confidence scores
        confidence_analysis = get_analysis_with_confidence(
            "Assess the confidence of these findings",
            initial_analysis
        )

        # Step 5: Create visualizations
        visualizations = self.create_visualizations(initial_analysis)

        return {
            "analysis": initial_analysis,
            "verification": verification,
            "iocs": iocs,
            "ioc_issues": ioc_issues,
            "confidence": confidence_analysis,
            "visualizations": visualizations,
            "quality_score": self.calculate_quality_score(ioc_issues, verification)
        }

    def calculate_quality_score(self, ioc_issues: list, verification: str) -> float:
        """Calculate overall quality score for the analysis."""
        score = 100.0

        # Deduct for fabricated IOCs
        score -= len(ioc_issues) * 10

        # Deduct for verification issues
        if "correction" in verification.lower():
            score -= 15
        if "error" in verification.lower():
            score -= 10

        return max(0, score)
```

---

## Exercises

### Exercise 1: Prompt Improvement
Take this weak prompt and improve it using the techniques learned:
```
"Check if this network traffic is bad"
```

### Exercise 2: Build a Hallucination Detector
Create a function that:
1. Takes an LLM analysis and source text
2. Identifies claims not supported by the source
3. Returns a list of potential hallucinations with confidence scores

### Exercise 3: Interactive Dashboard
Build a Plotly dashboard that:
1. Shows a timeline of security events
2. Displays severity distribution
3. Visualizes attack paths
4. Updates interactively based on filters

### Exercise 4: Self-Improving Prompt
Create a system that:
1. Takes a user's task description
2. Generates an initial prompt
3. Tests the prompt on sample inputs
4. Iteratively improves based on results

---

## Resources

- [Anthropic Prompt Engineering Guide](https://docs.anthropic.com/claude/docs/prompt-engineering)
- [OpenAI Best Practices](https://platform.openai.com/docs/guides/prompt-engineering)
- [Plotly Python Documentation](https://plotly.com/python/)
- [LangChain Output Parsers](https://python.langchain.com/docs/modules/model_io/output_parsers/)

---

## What's Next?

You're now ready for:
- **Lab 04**: LLM Log Analysis - Apply these techniques to real security logs
- **Lab 05**: Threat Intel Agent - Build autonomous analysis pipelines

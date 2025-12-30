# Lab 04 Walkthrough: LLM-Powered Log Analysis

## Overview

This walkthrough guides you through building an LLM-powered security log analyzer that extracts IOCs and identifies threats.

**Time to complete walkthrough:** 30 minutes

---

## Step 1: Understanding the Architecture

### What We're Building

```
+----------------+     +----------------+     +----------------+
|  Security      | --> |   LLM Prompt   | --> |   Structured   |
|  Log Entry     |     |   Engineering  |     |   Analysis     |
+----------------+     +----------------+     +----------------+
                              |
                              v
                    +------------------+
                    | - Threat Level   |
                    | - IOCs Extracted |
                    | - MITRE Mapping  |
                    | - Recommendations|
                    +------------------+
```

### Why LLMs for Log Analysis?
- **Context understanding** - Correlates multiple log fields
- **Flexible parsing** - Handles various log formats
- **Natural explanations** - Human-readable analysis
- **IOC extraction** - Identifies indicators without regex rules

---

## Step 2: Setting Up the LLM Client

### Multi-Provider Support

```python
import os
from dotenv import load_dotenv

load_dotenv()

def get_llm_client():
    """Initialize LLM client based on available API key"""

    # Try providers in order of preference
    if os.getenv('ANTHROPIC_API_KEY'):
        from anthropic import Anthropic
        return AnthropicWrapper(Anthropic())

    elif os.getenv('OPENAI_API_KEY'):
        from openai import OpenAI
        return OpenAIWrapper(OpenAI())

    elif os.getenv('GOOGLE_API_KEY'):
        import google.generativeai as genai
        genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
        return GeminiWrapper(genai.GenerativeModel('gemini-2.5-pro'))

    else:
        raise ValueError("No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")


class AnthropicWrapper:
    """Wrapper for Claude API"""

    def __init__(self, client):
        self.client = client

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return response.content[0].text
```

### Common Error #1: API Key Not Found
```
ValueError: No API key found
```

**Solution:** Create `.env` file in project root:
```bash
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

---

## Step 3: Crafting the Analysis Prompt

### The System Prompt

```python
SYSTEM_PROMPT = """You are a senior security analyst specializing in log analysis and threat detection.

Your role is to analyze security logs and provide:
1. Threat assessment (Critical/High/Medium/Low/Info)
2. Extracted IOCs (IPs, domains, hashes, URLs)
3. MITRE ATT&CK technique mapping
4. Recommended response actions

Always respond in valid JSON format matching this schema:
{
    "threat_level": "string",
    "summary": "string",
    "iocs": {
        "ips": ["list of IPs"],
        "domains": ["list of domains"],
        "hashes": ["list of file hashes"],
        "urls": ["list of URLs"]
    },
    "mitre_techniques": [
        {"id": "T1234", "name": "Technique Name", "confidence": "high/medium/low"}
    ],
    "recommendations": ["list of actions"],
    "false_positive_likelihood": "high/medium/low"
}
"""
```

### Why This Structure?
| Component | Purpose |
|-----------|---------|
| Role definition | Sets expertise context |
| Output requirements | Ensures consistent analysis |
| JSON schema | Enables programmatic parsing |
| Confidence levels | Helps prioritization |

---

## Step 4: Building the Analysis Function

### Processing Individual Log Entries

````python
import json

def analyze_log_entry(log_entry: dict, llm_client) -> dict:
    """Analyze a single log entry using LLM"""

    # Format log for analysis
    user_prompt = f"""Analyze this security log entry:

```json
{json.dumps(log_entry, indent=2)}
```

Provide your analysis in the JSON format specified."""

    # Get LLM analysis
    response = llm_client.analyze(SYSTEM_PROMPT, user_prompt)

    # Parse JSON response
    try:
        # Handle markdown code blocks
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0]
        else:
            json_str = response

        analysis = json.loads(json_str)

    except json.JSONDecodeError as e:
        # Fallback for malformed response
        analysis = {
            "threat_level": "Unknown",
            "summary": response,
            "error": f"Failed to parse JSON: {str(e)}"
        }

    return analysis
````

### Common Error #2: JSON Parsing Fails
```
json.JSONDecodeError: Expecting property name enclosed in double quotes
```

**Solution:** Add robust parsing:
```python
import re

def extract_json(text: str) -> dict:
    """Extract JSON from LLM response, handling various formats"""

    # Try direct parsing first
    try:
        return json.loads(text)
    except:
        pass

    # Try extracting from code blocks
    patterns = [
        r'```json\s*(.*?)\s*```',
        r'```\s*(.*?)\s*```',
        r'\{.*\}'  # Last resort: any JSON object
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1) if '```' in pattern else match.group(0))
            except:
                continue

    raise ValueError(f"Could not extract JSON from: {text[:200]}...")
```

---

## Step 5: Batch Processing with Rate Limiting

### Processing Multiple Logs

```python
import time
from typing import List
from tqdm import tqdm

def analyze_logs_batch(logs: List[dict], llm_client,
                       rate_limit: float = 1.0) -> List[dict]:
    """
    Analyze multiple logs with rate limiting

    Args:
        logs: List of log entries
        llm_client: Initialized LLM client
        rate_limit: Seconds between API calls

    Returns:
        List of analysis results
    """
    results = []

    for log in tqdm(logs, desc="Analyzing logs"):
        try:
            analysis = analyze_log_entry(log, llm_client)
            analysis['original_log'] = log
            results.append(analysis)

        except Exception as e:
            results.append({
                'error': str(e),
                'original_log': log
            })

        # Rate limiting
        time.sleep(rate_limit)

    return results


def prioritize_results(results: List[dict]) -> List[dict]:
    """Sort results by threat level"""

    priority = {
        'Critical': 0,
        'High': 1,
        'Medium': 2,
        'Low': 3,
        'Info': 4,
        'Unknown': 5
    }

    return sorted(
        results,
        key=lambda x: priority.get(x.get('threat_level', 'Unknown'), 5)
    )
```

---

## Step 6: IOC Extraction and Enrichment

### Consolidating IOCs

```python
def extract_all_iocs(results: List[dict]) -> dict:
    """Extract and deduplicate IOCs from all results"""

    all_iocs = {
        'ips': set(),
        'domains': set(),
        'hashes': set(),
        'urls': set()
    }

    for result in results:
        iocs = result.get('iocs', {})
        for ioc_type in all_iocs:
            all_iocs[ioc_type].update(iocs.get(ioc_type, []))

    # Convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in all_iocs.items()}


def enrich_iocs(iocs: dict) -> dict:
    """Add context to extracted IOCs"""

    enriched = {}

    for ip in iocs.get('ips', []):
        enriched[ip] = {
            'type': 'ip',
            'value': ip,
            'is_private': is_private_ip(ip),
            'is_known_bad': check_threat_intel(ip)  # Your TI lookup
        }

    for domain in iocs.get('domains', []):
        enriched[domain] = {
            'type': 'domain',
            'value': domain,
            'is_suspicious_tld': domain.split('.')[-1] in ['tk', 'ml', 'ga']
        }

    return enriched


def is_private_ip(ip: str) -> bool:
    """Check if IP is RFC1918 private address"""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False
```

---

## Step 7: Generating the Analysis Report

### Structured Report Generation

```python
def generate_report(results: List[dict], iocs: dict) -> str:
    """Generate markdown analysis report"""

    # Count threat levels
    threat_counts = {}
    for r in results:
        level = r.get('threat_level', 'Unknown')
        threat_counts[level] = threat_counts.get(level, 0) + 1

    report = f"""# Security Log Analysis Report

## Executive Summary

- **Total Logs Analyzed:** {len(results)}
- **Critical Threats:** {threat_counts.get('Critical', 0)}
- **High Threats:** {threat_counts.get('High', 0)}
- **Medium Threats:** {threat_counts.get('Medium', 0)}

## Extracted IOCs

### IP Addresses ({len(iocs.get('ips', []))})
"""

    for ip in iocs.get('ips', []):
        report += f"- `{ip}`\n"

    report += f"""
### Domains ({len(iocs.get('domains', []))})
"""

    for domain in iocs.get('domains', []):
        report += f"- `{domain}`\n"

    report += """
## Detailed Findings

"""

    # Add high-priority findings
    high_priority = [r for r in results
                     if r.get('threat_level') in ['Critical', 'High']]

    for i, finding in enumerate(high_priority, 1):
        report += f"""### Finding {i}: {finding.get('threat_level')}

**Summary:** {finding.get('summary', 'N/A')}

**MITRE Techniques:**
"""
        for tech in finding.get('mitre_techniques', []):
            report += f"- {tech.get('id')}: {tech.get('name')} ({tech.get('confidence')})\n"

        report += f"""
**Recommendations:**
"""
        for rec in finding.get('recommendations', []):
            report += f"- {rec}\n"

        report += "\n---\n\n"

    return report
```

---

## Step 8: Putting It All Together

### Complete Analysis Pipeline

```python
def main():
    """Main analysis pipeline"""

    # Load sample logs
    with open('data/logs/auth_logs.json') as f:
        logs = json.load(f)

    print(f"Loaded {len(logs)} log entries")

    # Initialize LLM client
    llm_client = get_llm_client()

    # Analyze logs
    print("Analyzing logs...")
    results = analyze_logs_batch(logs, llm_client, rate_limit=0.5)

    # Prioritize results
    results = prioritize_results(results)

    # Extract IOCs
    iocs = extract_all_iocs(results)
    print(f"Extracted {sum(len(v) for v in iocs.values())} unique IOCs")

    # Generate report
    report = generate_report(results, iocs)

    # Save report
    with open('analysis_report.md', 'w') as f:
        f.write(report)

    print("Report saved to analysis_report.md")

    # Print high-priority findings
    critical = [r for r in results if r.get('threat_level') == 'Critical']
    if critical:
        print(f"\n!!! {len(critical)} CRITICAL FINDINGS !!!")
        for finding in critical:
            print(f"  - {finding.get('summary', 'N/A')[:100]}...")


if __name__ == '__main__':
    main()
```

---

## Common Mistakes & Solutions

### Mistake 1: Prompt Too Vague
```python
# BAD: Vague prompt
"Analyze this log"

# GOOD: Specific prompt with structure
"""Analyze this security log entry for:
1. Threat indicators
2. IOCs (IPs, domains, hashes)
3. MITRE ATT&CK mapping
Respond in JSON format."""
```

### Mistake 2: Not Handling API Errors
```python
# BAD: No error handling
response = llm_client.analyze(prompt)

# GOOD: Retry with backoff
import time

def analyze_with_retry(llm_client, prompt, max_retries=3):
    for attempt in range(max_retries):
        try:
            return llm_client.analyze(prompt)
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)  # Exponential backoff
```

### Mistake 3: Ignoring False Positives
```python
# Always include false positive assessment
analysis = {
    "threat_level": "High",
    "false_positive_likelihood": "medium",
    "fp_reasoning": "Service account login during maintenance window"
}
```

---

## Extension Exercises

### Exercise A: Add Correlation
```python
def correlate_events(results: List[dict]) -> List[dict]:
    """Find related events across logs"""

    # Group by source IP
    by_ip = {}
    for r in results:
        for ip in r.get('iocs', {}).get('ips', []):
            if ip not in by_ip:
                by_ip[ip] = []
            by_ip[ip].append(r)

    # Find IPs with multiple suspicious events
    correlated = []
    for ip, events in by_ip.items():
        if len(events) > 1:
            correlated.append({
                'ip': ip,
                'event_count': len(events),
                'threat_levels': [e.get('threat_level') for e in events]
            })

    return correlated
```

### Exercise B: Real-time Analysis
```python
import asyncio

async def analyze_stream(log_stream, llm_client):
    """Analyze logs as they arrive"""

    async for log in log_stream:
        analysis = await asyncio.to_thread(
            analyze_log_entry, log, llm_client
        )

        if analysis.get('threat_level') in ['Critical', 'High']:
            await send_alert(analysis)

        yield analysis
```

---

## Key Takeaways

1. **Structured prompts** - Define clear output format
2. **Error handling** - LLM responses can be unpredictable
3. **Rate limiting** - Respect API limits
4. **IOC extraction** - Consolidate and enrich indicators
5. **False positives** - Always assess likelihood

---

## Next Lab

Continue to [Lab 05: Threat Intel Agent](./lab05-walkthrough.md) to build an autonomous investigation agent.

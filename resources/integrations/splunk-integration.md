# Splunk Integration Guide

Integrate AI-powered security analysis with Splunk Enterprise and Splunk Cloud.

```
+-----------------------------------------------------------------------------+
|                      AI + SPLUNK ARCHITECTURE                                |
+-----------------------------------------------------------------------------+
|                                                                             |
|   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    |
|   │   Splunk    │    │   AI/ML     │    │  Automated  │                    |
|   │   Search    │--->│   Analysis  │--->│  Response   │                    |
|   │   Results   │    │   (Claude)  │    │  Actions    │                    |
|   └─────────────┘    └─────────────┘    └─────────────┘                    |
|         ^                  |                   |                            |
|         |                  v                   v                            |
|   ┌─────────────────────────────────────────────────────────┐              |
|   │                    Splunk Platform                       │              |
|   │  • Indexes  • Saved Searches  • Alerts  • Dashboards    │              |
|   └─────────────────────────────────────────────────────────┘              |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Overview

| Component | Description |
|-----------|-------------|
| **Splunk SDK** | Python library for Splunk API |
| **Search API** | Run SPL queries programmatically |
| **Alert Actions** | Trigger AI analysis on alerts |
| **Custom Commands** | Add AI-powered SPL commands |

---

## Part 1: Splunk SDK Setup

### 1.1 Installation

```bash
pip install splunk-sdk
```

### 1.2 Client Configuration

```python
"""
Splunk SDK Client Setup
"""
import splunklib.client as client
import splunklib.results as results
import os

class SplunkClient:
    """Client for Splunk API operations"""

    def __init__(self):
        self.service = client.connect(
            host=os.getenv("SPLUNK_HOST", "localhost"),
            port=int(os.getenv("SPLUNK_PORT", 8089)),
            username=os.getenv("SPLUNK_USERNAME"),
            password=os.getenv("SPLUNK_PASSWORD"),
            # OR use token auth:
            # token=os.getenv("SPLUNK_TOKEN"),
            autologin=True
        )

    def search(self, query: str, **kwargs) -> list:
        """
        Execute SPL search and return results

        Args:
            query: SPL query string
            **kwargs: Additional search parameters

        Returns:
            List of search results
        """
        # Default search parameters
        search_kwargs = {
            "earliest_time": "-24h",
            "latest_time": "now",
            "output_mode": "json",
            **kwargs
        }

        # Ensure query starts with 'search'
        if not query.strip().startswith("search") and not query.strip().startswith("|"):
            query = f"search {query}"

        # Create search job
        job = self.service.jobs.create(query, **search_kwargs)

        # Wait for completion
        while not job.is_done():
            import time
            time.sleep(0.5)

        # Get results
        result_stream = job.results(output_mode="json")
        reader = results.JSONResultsReader(result_stream)

        return [row for row in reader if isinstance(row, dict)]

    def get_saved_searches(self) -> list:
        """Get all saved searches"""
        return [
            {
                "name": ss.name,
                "search": ss["search"],
                "description": ss.get("description", "")
            }
            for ss in self.service.saved_searches
        ]

    def run_saved_search(self, name: str) -> list:
        """Run a saved search by name"""
        saved_search = self.service.saved_searches[name]
        job = saved_search.dispatch()

        while not job.is_done():
            import time
            time.sleep(0.5)

        result_stream = job.results(output_mode="json")
        reader = results.JSONResultsReader(result_stream)

        return [row for row in reader if isinstance(row, dict)]
```

---

## Part 2: AI-Powered Search Analysis

### 2.1 Search Result Enrichment

```python
"""
Enrich Splunk search results with AI analysis
"""
from anthropic import Anthropic
import json

class SplunkAIAnalyzer:
    """AI-powered Splunk search analysis"""

    def __init__(self, splunk_client: SplunkClient, llm_client: Anthropic):
        self.splunk = splunk_client
        self.llm = llm_client

    def analyze_search_results(self, query: str, results: list) -> dict:
        """
        Analyze Splunk search results using LLM

        Args:
            query: Original SPL query
            results: Search results

        Returns:
            AI analysis of results
        """
        prompt = f"""Analyze these Splunk search results for security implications.

SPL Query:
```
{query}
```

Results ({len(results)} events):
```json
{json.dumps(results[:50], indent=2)}
```

Provide:
1. Summary of findings
2. Security-relevant observations
3. Potential threats or anomalies detected
4. Recommended follow-up queries
5. Suggested response actions

Respond in JSON format:
{{
    "summary": "string",
    "threat_level": "critical/high/medium/low/info",
    "observations": ["list of observations"],
    "anomalies": ["list of anomalies"],
    "follow_up_queries": ["SPL queries for further investigation"],
    "recommendations": ["list of actions"]
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except json.JSONDecodeError:
            return {"raw_analysis": response.content[0].text}

    def intelligent_search(self, natural_query: str) -> dict:
        """
        Convert natural language to SPL and analyze results

        Args:
            natural_query: Natural language description of what to find

        Returns:
            SPL query, results, and analysis
        """
        # Generate SPL from natural language
        spl_prompt = f"""Convert this natural language query to Splunk SPL:

"{natural_query}"

Requirements:
- Use appropriate indexes (main, security, windows, etc.)
- Include time range if mentioned
- Use proper field extractions
- Optimize for performance

Return only the SPL query, no explanation."""

        spl_response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": spl_prompt}]
        )

        spl_query = spl_response.content[0].text.strip()

        # Execute search
        try:
            results = self.splunk.search(spl_query)
        except Exception as e:
            return {
                "error": str(e),
                "generated_spl": spl_query
            }

        # Analyze results
        analysis = self.analyze_search_results(spl_query, results)

        return {
            "natural_query": natural_query,
            "spl_query": spl_query,
            "result_count": len(results),
            "results_sample": results[:10],
            "analysis": analysis
        }
```

### 2.2 Detection Rule Analysis

```python
"""
Analyze and improve Splunk detection rules with AI
"""

class DetectionRuleAnalyzer:
    """AI-powered detection rule analysis"""

    def __init__(self, splunk_client: SplunkClient, llm_client: Anthropic):
        self.splunk = splunk_client
        self.llm = llm_client

    def analyze_detection_rule(self, rule_name: str, rule_spl: str) -> dict:
        """Analyze a detection rule for effectiveness"""

        prompt = f"""Analyze this Splunk detection rule for security effectiveness.

Rule Name: {rule_name}
SPL:
```
{rule_spl}
```

Evaluate:
1. Detection coverage - what threats does it catch?
2. False positive potential - what legitimate activity might trigger it?
3. Evasion techniques - how could attackers bypass it?
4. Performance impact - is it efficient?
5. MITRE ATT&CK mapping - which techniques does it detect?

Provide:
- Effectiveness score (1-10)
- Improvements to reduce false positives
- Improvements to catch evasion
- Suggested additional rules for coverage gaps

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def generate_detection_rule(self, threat_description: str) -> dict:
        """Generate a detection rule from threat description"""

        prompt = f"""Create a Splunk detection rule for this threat:

"{threat_description}"

Provide:
1. Rule name
2. SPL query
3. Description
4. MITRE ATT&CK mapping
5. Severity level
6. False positive guidance
7. Response actions

Format as JSON:
{{
    "rule_name": "string",
    "spl": "string",
    "description": "string",
    "mitre_techniques": ["T1234"],
    "severity": "critical/high/medium/low",
    "false_positives": ["list of potential FPs"],
    "response_actions": ["list of actions"]
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_response": response.content[0].text}
```

---

## Part 3: Pre-Built SPL Queries

### Security Analytics Queries

```python
"""
Pre-built SPL queries for common security use cases
"""

SECURITY_QUERIES = {
    "brute_force_detection": """
        index=security sourcetype=WinEventLog:Security EventCode=4625
        | stats count by src_ip, user, dest
        | where count > 10
        | sort -count
    """,

    "lateral_movement": """
        index=security sourcetype=WinEventLog:Security
        (EventCode=4624 OR EventCode=4648)
        Logon_Type IN (3, 10)
        | stats count by src_ip, dest, user
        | where count > 5
        | sort -count
    """,

    "powershell_suspicious": """
        index=security sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:PowerShell
        | search CommandLine="*-enc*" OR CommandLine="*bypass*"
            OR CommandLine="*downloadstring*" OR CommandLine="*invoke-expression*"
        | table _time, host, user, CommandLine
    """,

    "data_exfiltration": """
        index=network sourcetype=firewall action=allowed direction=outbound
        | stats sum(bytes_out) as total_bytes by src_ip, dest_ip
        | where total_bytes > 100000000
        | sort -total_bytes
    """,

    "dns_tunneling": """
        index=network sourcetype=dns
        | eval query_length=len(query)
        | where query_length > 50
        | stats count by src_ip, query
        | where count > 100
    """,

    "persistence_mechanisms": """
        index=security sourcetype=WinEventLog:Security
        (EventCode=4698 OR EventCode=4699 OR EventCode=7045)
        | table _time, host, user, TaskName, ServiceName
    """,

    "credential_dumping": """
        index=security sourcetype=WinEventLog:Security
        | search process_name IN ("mimikatz*", "procdump*", "comsvcs.dll")
            OR CommandLine="*sekurlsa*" OR CommandLine="*lsass*"
        | table _time, host, user, process_name, CommandLine
    """
}


class SecuritySearchLibrary:
    """Library of security-focused Splunk searches"""

    def __init__(self, splunk_client: SplunkClient):
        self.splunk = splunk_client
        self.queries = SECURITY_QUERIES

    def run_security_search(self, search_name: str, **kwargs) -> list:
        """Run a pre-built security search"""
        if search_name not in self.queries:
            raise ValueError(f"Unknown search: {search_name}")

        query = self.queries[search_name]
        return self.splunk.search(query, **kwargs)

    def run_all_security_searches(self) -> dict:
        """Run all security searches and compile results"""
        results = {}

        for name, query in self.queries.items():
            try:
                results[name] = {
                    "query": query,
                    "results": self.splunk.search(query),
                    "status": "success"
                }
            except Exception as e:
                results[name] = {
                    "query": query,
                    "error": str(e),
                    "status": "failed"
                }

        return results
```

---

## Part 4: Alert Integration

### Webhook Alert Action

```python
"""
Flask webhook to receive Splunk alerts and process with AI
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

# Initialize AI analyzer
llm_client = Anthropic()

@app.route('/splunk/alert', methods=['POST'])
def handle_splunk_alert():
    """Webhook endpoint for Splunk alert actions"""

    alert_data = request.json

    # Extract alert details
    alert_name = alert_data.get('search_name', 'Unknown')
    results = alert_data.get('results', [])
    result_count = alert_data.get('result_count', 0)

    # Analyze with AI
    analysis = analyze_alert(alert_name, results)

    # Take action based on analysis
    if analysis.get('threat_level') in ['critical', 'high']:
        # Trigger escalation
        escalate_alert(alert_name, analysis)

    return jsonify({
        "status": "processed",
        "alert": alert_name,
        "analysis": analysis
    })


def analyze_alert(alert_name: str, results: list) -> dict:
    """Analyze alert results with AI"""

    prompt = f"""Analyze this Splunk security alert:

Alert: {alert_name}
Results: {json.dumps(results[:20], indent=2)}

Determine:
1. Threat level (critical/high/medium/low)
2. Is this a true positive or likely false positive?
3. What immediate actions should be taken?
4. What additional investigation is needed?

Respond in JSON format."""

    response = llm_client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    try:
        return json.loads(response.content[0].text)
    except:
        return {"raw_analysis": response.content[0].text}


def escalate_alert(alert_name: str, analysis: dict):
    """Escalate high-priority alerts"""
    # Send to Slack, PagerDuty, email, etc.
    print(f"ESCALATING: {alert_name}")
    print(f"Analysis: {analysis}")
```

---

## Part 5: Environment Setup

### Environment Variables

```bash
# .env file
SPLUNK_HOST=your-splunk-instance.com
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-password
# OR for token auth:
SPLUNK_TOKEN=your-api-token

ANTHROPIC_API_KEY=your-anthropic-key
```

### Docker Compose (Development)

```yaml
# docker-compose.yml
version: '3.8'
services:
  splunk:
    image: splunk/splunk:latest
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=changeme
    ports:
      - "8000:8000"
      - "8089:8089"
    volumes:
      - splunk-data:/opt/splunk/var

  ai-analyzer:
    build: .
    environment:
      - SPLUNK_HOST=splunk
      - SPLUNK_PORT=8089
      - SPLUNK_USERNAME=admin
      - SPLUNK_PASSWORD=changeme
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    depends_on:
      - splunk

volumes:
  splunk-data:
```

---

## Resources

- [Splunk SDK for Python](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/)
- [SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [MITRE ATT&CK for Splunk](https://splunkbase.splunk.com/app/4617/)

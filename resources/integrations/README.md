# Security Platform Integration Patterns

Generic patterns for integrating AI-powered security tools with enterprise platforms.

> 💡 **Platform-Agnostic**: These patterns work with any SIEM, SOAR, or threat intelligence platform. Adapt the API calls for your specific environment.

```
+-----------------------------------------------------------------------------+
|                     AI SECURITY INTEGRATION PATTERNS                         |
+-----------------------------------------------------------------------------+
|                                                                             |
|   DATA SOURCES           PROCESSING              OUTPUTS                    |
|   ┌──────────┐          ┌──────────┐          ┌──────────┐                 |
|   │ SIEM     │          │ AI/ML    │          │ Enriched │                 |
|   │ Logs     │ -------> │ Analysis │ -------> │ Alerts   │                 |
|   │ EDR      │          │ Claude   │          │ Reports  │                 |
|   │ Network  │          │ GPT      │          │ Actions  │                 |
|   └──────────┘          └──────────┘          └──────────┘                 |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Integration Patterns

### Pattern 1: Alert Enrichment

Add AI-powered context to security alerts from any platform.

```python
"""
Alert Enrichment Pattern

Works with any SIEM/SOAR that provides alert data via API.
"""
import json
from anthropic import Anthropic

client = Anthropic()

def enrich_alert(alert_data: dict) -> dict:
    """Enrich a security alert with AI analysis."""

    prompt = f"""Analyze this security alert and provide:
1. Severity assessment (1-10)
2. MITRE ATT&CK techniques (if applicable)
3. Recommended investigation steps
4. Potential false positive indicators

Alert data:
{json.dumps(alert_data, indent=2)}

Respond in JSON format."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse and merge with original alert
    enrichment = json.loads(response.content[0].text)
    return {**alert_data, "ai_enrichment": enrichment}


# Example usage with generic alert structure
sample_alert = {
    "id": "ALERT-001",
    "timestamp": "2025-01-02T10:30:00Z",
    "source": "endpoint",
    "rule": "Suspicious PowerShell Execution",
    "host": "workstation-42",
    "command": "powershell -enc SQBFAFgAIAAoA..."
}

enriched = enrich_alert(sample_alert)
print(json.dumps(enriched, indent=2))
```

### Pattern 2: Automated Triage

AI-driven alert prioritization for any alert queue.

```python
"""
Automated Triage Pattern

Prioritizes alerts based on context, not just rule severity.
"""

def triage_alerts(alerts: list[dict]) -> list[dict]:
    """Triage a batch of alerts using AI."""

    prompt = f"""You are a SOC analyst triaging security alerts.

For each alert, assign:
- priority: critical/high/medium/low
- reasoning: brief explanation
- action: investigate/monitor/close

Alerts:
{json.dumps(alerts, indent=2)}

Respond as JSON array with same alert IDs."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )

    triage_results = json.loads(response.content[0].text)

    # Merge triage back into alerts
    triage_map = {t["id"]: t for t in triage_results}
    for alert in alerts:
        if alert["id"] in triage_map:
            alert["triage"] = triage_map[alert["id"]]

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: priority_order.get(a.get("triage", {}).get("priority", "low"), 3))

    return alerts
```

### Pattern 3: Threat Hunting Query Generation

Generate platform-specific hunt queries from natural language.

```python
"""
Threat Hunting Pattern

Generates queries for your specific platform.
"""

def generate_hunt_queries(
    hypothesis: str,
    platform: str = "generic",
    timeframe: str = "7d"
) -> list[dict]:
    """Generate threat hunting queries from a hypothesis."""

    prompt = f"""Generate threat hunting queries for: {hypothesis}

Platform: {platform}
Timeframe: {timeframe}

For each query provide:
- name: descriptive name
- description: what it looks for
- query: the actual query syntax
- expected_results: what findings would indicate

If platform is 'generic', provide pseudo-query that can be adapted.

Respond as JSON array."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(response.content[0].text)


# Example
queries = generate_hunt_queries(
    hypothesis="Detect potential credential dumping via LSASS access",
    platform="generic",
    timeframe="24h"
)
```

### Pattern 4: Response Recommendation

AI-assisted response decisions with human confirmation.

```python
"""
Response Recommendation Pattern

Suggests actions but requires human approval.
"""

def recommend_response(alert: dict, context: dict = None) -> dict:
    """Generate response recommendations for an alert."""

    prompt = f"""As a security analyst, recommend response actions for this alert.

Alert:
{json.dumps(alert, indent=2)}

{"Additional context: " + json.dumps(context, indent=2) if context else ""}

Provide:
1. immediate_actions: list of urgent steps
2. investigation_steps: deeper analysis needed
3. containment_options: if threat is confirmed
4. escalation_criteria: when to escalate
5. confidence: how confident in this being a true positive (0-100)

Important: These are RECOMMENDATIONS requiring human review."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    recommendations = json.loads(response.content[0].text)
    recommendations["requires_human_approval"] = True
    recommendations["auto_execute"] = False

    return recommendations
```

## Adapting for Your Platform

### SIEM Integration

```python
# Generic SIEM client interface
class SIEMClient:
    """Abstract SIEM client - implement for your platform."""

    def query(self, query: str, timeframe: str) -> list[dict]:
        """Execute a search query."""
        raise NotImplementedError

    def get_alerts(self, filters: dict = None) -> list[dict]:
        """Retrieve alerts matching filters."""
        raise NotImplementedError

    def update_alert(self, alert_id: str, updates: dict) -> bool:
        """Update an alert with enrichment data."""
        raise NotImplementedError
```

### SOAR Integration

```python
# Generic SOAR client interface
class SOARClient:
    """Abstract SOAR client - implement for your platform."""

    def create_case(self, alert: dict) -> str:
        """Create a case from an alert."""
        raise NotImplementedError

    def run_playbook(self, playbook_id: str, inputs: dict) -> dict:
        """Execute an automated playbook."""
        raise NotImplementedError

    def add_note(self, case_id: str, note: str) -> bool:
        """Add analysis notes to a case."""
        raise NotImplementedError
```

## Lab Integration

These patterns enhance the following labs:

| Lab    | Pattern                 | Enhancement                          |
| ------ | ----------------------- | ------------------------------------ |
| Lab 04 | Alert Enrichment        | Add AI analysis to log parsing       |
| Lab 05 | Query Generation        | Generate IOC lookups                 |
| Lab 09 | Automated Triage        | Prioritize detection pipeline output |
| Lab 10 | Response Recommendation | IR Copilot decision support          |

## Best Practices

1. **Always require human approval** for automated responses
2. **Log all AI decisions** for audit trails
3. **Set confidence thresholds** before taking action
4. **Test in non-production** environments first
5. **Monitor for drift** in AI recommendations over time

## Resources

- [OCSF Schema](https://schema.ocsf.io/) - Open Cybersecurity Schema Framework
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) - Threat intelligence standards
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques

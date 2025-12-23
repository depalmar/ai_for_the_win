# Cortex XSIAM & XDR Integration Guide

Integrate AI-powered security tools with Palo Alto Networks Cortex XSIAM and XDR platforms.

```
+-----------------------------------------------------------------------------+
|                    AI + XSIAM/XDR INTEGRATION ARCHITECTURE                   |
+-----------------------------------------------------------------------------+
|                                                                             |
|  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  |
|  │   Cortex    │    │    AI/ML    │    │   Claude/   │    │   Custom    │  |
|  │  XSIAM/XDR  │<-->│   Models    │<-->│    LLM      │<-->│   Actions   │  |
|  │   Alerts    │    │  Detection  │    │  Analysis   │    │  Playbooks  │  |
|  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  |
|         |                  |                  |                  |          |
|         v                  v                  v                  v          |
|  ┌─────────────────────────────────────────────────────────────────────┐   |
|  │                     UNIFIED SECURITY OPERATIONS                      │   |
|  │  • Automated Triage  • Threat Enrichment  • Response Orchestration  │   |
|  └─────────────────────────────────────────────────────────────────────┘   |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Overview

| Platform | Description | Use Cases |
|----------|-------------|-----------|
| **Cortex XSIAM** | AI-driven SOC platform | Alert correlation, automated investigation, SOAR |
| **Cortex XDR** | Extended detection & response | Endpoint detection, network analytics, cloud security |

---

## Part 1: Cortex XDR Integration

### 1.1 Authentication Setup

```python
"""
Cortex XDR API Authentication
"""
import hashlib
import secrets
import requests
from datetime import datetime, timezone

class CortexXDRClient:
    """Client for Cortex XDR API"""

    def __init__(self, api_key: str, api_key_id: str, fqdn: str):
        """
        Initialize XDR client

        Args:
            api_key: API key from XDR Settings
            api_key_id: API key ID
            fqdn: Your XDR instance FQDN (e.g., api-xyz.xdr.us.paloaltonetworks.com)
        """
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.base_url = f"https://{fqdn}"

    def _generate_headers(self) -> dict:
        """Generate authentication headers with nonce"""
        nonce = secrets.token_hex(32)
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Create auth string
        auth_string = f"{self.api_key}{nonce}{timestamp}"
        auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()

        return {
            "x-xdr-auth-id": str(self.api_key_id),
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": str(timestamp),
            "Authorization": auth_hash,
            "Content-Type": "application/json"
        }

    def get_incidents(self, filters: list = None,
                      search_from: int = 0,
                      search_to: int = 100) -> dict:
        """
        Get incidents from XDR

        Args:
            filters: List of filter conditions
            search_from: Starting index
            search_to: Ending index
        """
        endpoint = f"{self.base_url}/public_api/v1/incidents/get_incidents"

        payload = {
            "request_data": {
                "search_from": search_from,
                "search_to": search_to,
                "sort": {
                    "field": "creation_time",
                    "keyword": "desc"
                }
            }
        }

        if filters:
            payload["request_data"]["filters"] = filters

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_alerts(self, filters: list = None,
                   search_from: int = 0,
                   search_to: int = 100) -> dict:
        """Get alerts from XDR"""
        endpoint = f"{self.base_url}/public_api/v1/alerts/get_alerts"

        payload = {
            "request_data": {
                "search_from": search_from,
                "search_to": search_to,
                "sort": {
                    "field": "creation_time",
                    "keyword": "desc"
                }
            }
        }

        if filters:
            payload["request_data"]["filters"] = filters

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_endpoint_details(self, endpoint_id: str) -> dict:
        """Get detailed information about an endpoint"""
        endpoint = f"{self.base_url}/public_api/v1/endpoints/get_endpoint"

        payload = {
            "request_data": {
                "endpoint_id_list": [endpoint_id]
            }
        }

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def isolate_endpoint(self, endpoint_id: str) -> dict:
        """Isolate an endpoint from the network"""
        endpoint = f"{self.base_url}/public_api/v1/endpoints/isolate"

        payload = {
            "request_data": {
                "endpoint_id_list": [endpoint_id]
            }
        }

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()


# Example usage
def example_xdr_usage():
    """Example: Fetch and analyze XDR incidents"""
    import os

    client = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID"),
        fqdn=os.getenv("XDR_FQDN")
    )

    # Get high-severity incidents
    incidents = client.get_incidents(
        filters=[
            {
                "field": "severity",
                "operator": "in",
                "value": ["high", "critical"]
            }
        ]
    )

    return incidents
```

### 1.2 AI-Powered Alert Enrichment

```python
"""
Enrich XDR alerts using LLM analysis
"""
from anthropic import Anthropic
import json

class XDRAlertEnricher:
    """Enrich XDR alerts with AI analysis"""

    def __init__(self, xdr_client: CortexXDRClient, anthropic_client: Anthropic):
        self.xdr = xdr_client
        self.llm = anthropic_client

    def enrich_alert(self, alert: dict) -> dict:
        """
        Enrich a single alert with LLM analysis

        Returns:
            Enriched alert with AI analysis
        """
        # Build context for LLM
        prompt = f"""Analyze this Cortex XDR security alert and provide:
1. Threat assessment (Critical/High/Medium/Low)
2. Attack stage (Initial Access, Execution, Persistence, etc.)
3. Recommended immediate actions
4. Related MITRE ATT&CK techniques
5. Potential false positive indicators

Alert Data:
```json
{json.dumps(alert, indent=2)}
```

Respond in JSON format:
{{
    "threat_assessment": "string",
    "attack_stage": "string",
    "confidence": "high/medium/low",
    "mitre_techniques": [
        {{"id": "T1234", "name": "Technique", "tactic": "Tactic"}}
    ],
    "immediate_actions": ["action1", "action2"],
    "investigation_queries": ["query1", "query2"],
    "false_positive_indicators": ["indicator1"],
    "summary": "Brief analysis summary"
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse LLM response
        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            analysis = {"raw_analysis": response.content[0].text}

        # Combine original alert with analysis
        enriched = {
            "original_alert": alert,
            "ai_analysis": analysis,
            "enrichment_timestamp": datetime.now(timezone.utc).isoformat()
        }

        return enriched

    def batch_enrich_alerts(self, alerts: list) -> list:
        """Enrich multiple alerts"""
        enriched = []
        for alert in alerts:
            try:
                enriched.append(self.enrich_alert(alert))
            except Exception as e:
                enriched.append({
                    "original_alert": alert,
                    "enrichment_error": str(e)
                })
        return enriched

    def prioritize_alerts(self, enriched_alerts: list) -> list:
        """Sort alerts by AI-determined priority"""
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

        return sorted(
            enriched_alerts,
            key=lambda x: priority_order.get(
                x.get("ai_analysis", {}).get("threat_assessment", "Low"),
                4
            )
        )
```

### 1.3 Automated Response Actions

```python
"""
Automated response based on AI analysis
"""

class XDRAutoResponder:
    """Automated response actions for XDR alerts"""

    def __init__(self, xdr_client: CortexXDRClient):
        self.xdr = xdr_client

        # Response policies by threat level
        self.response_policies = {
            "Critical": {
                "auto_isolate": True,
                "block_hash": True,
                "notify_soc": True,
                "create_ticket": True
            },
            "High": {
                "auto_isolate": False,
                "block_hash": True,
                "notify_soc": True,
                "create_ticket": True
            },
            "Medium": {
                "auto_isolate": False,
                "block_hash": False,
                "notify_soc": True,
                "create_ticket": False
            },
            "Low": {
                "auto_isolate": False,
                "block_hash": False,
                "notify_soc": False,
                "create_ticket": False
            }
        }

    def execute_response(self, enriched_alert: dict) -> dict:
        """Execute automated response based on AI analysis"""

        analysis = enriched_alert.get("ai_analysis", {})
        threat_level = analysis.get("threat_assessment", "Low")
        policy = self.response_policies.get(threat_level, {})

        actions_taken = []

        # Get endpoint ID from alert
        alert = enriched_alert.get("original_alert", {})
        endpoint_id = alert.get("endpoint_id")

        # Execute policy actions
        if policy.get("auto_isolate") and endpoint_id:
            try:
                self.xdr.isolate_endpoint(endpoint_id)
                actions_taken.append({
                    "action": "endpoint_isolated",
                    "endpoint_id": endpoint_id,
                    "success": True
                })
            except Exception as e:
                actions_taken.append({
                    "action": "endpoint_isolated",
                    "endpoint_id": endpoint_id,
                    "success": False,
                    "error": str(e)
                })

        if policy.get("block_hash"):
            file_hash = alert.get("file_sha256")
            if file_hash:
                actions_taken.append({
                    "action": "hash_blocked",
                    "hash": file_hash,
                    "success": True  # Implement actual blocking
                })

        if policy.get("notify_soc"):
            actions_taken.append({
                "action": "soc_notified",
                "channel": "slack",  # or email, PagerDuty, etc.
                "success": True
            })

        return {
            "alert_id": alert.get("alert_id"),
            "threat_level": threat_level,
            "policy_applied": policy,
            "actions_taken": actions_taken
        }
```

---

## Part 2: Cortex XSIAM Integration

### 2.1 XSIAM API Client

```python
"""
Cortex XSIAM API Integration
"""

class CortexXSIAMClient:
    """Client for Cortex XSIAM API"""

    def __init__(self, api_key: str, api_key_id: str, fqdn: str):
        """
        Initialize XSIAM client

        Args:
            api_key: API key from XSIAM Settings
            api_key_id: API key ID
            fqdn: Your XSIAM instance FQDN
        """
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.base_url = f"https://{fqdn}"

    def _generate_headers(self) -> dict:
        """Generate authentication headers"""
        nonce = secrets.token_hex(32)
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        auth_string = f"{self.api_key}{nonce}{timestamp}"
        auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()

        return {
            "x-xdr-auth-id": str(self.api_key_id),
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": str(timestamp),
            "Authorization": auth_hash,
            "Content-Type": "application/json"
        }

    def run_xql_query(self, query: str,
                      start_time: int = None,
                      end_time: int = None) -> dict:
        """
        Run XQL (XSIAM Query Language) query

        Args:
            query: XQL query string
            start_time: Start time in milliseconds
            end_time: End time in milliseconds
        """
        endpoint = f"{self.base_url}/public_api/v1/xql/start_xql_query"

        # Default to last 24 hours
        if not end_time:
            end_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        if not start_time:
            start_time = end_time - (24 * 60 * 60 * 1000)

        payload = {
            "request_data": {
                "query": query,
                "tenants": [],
                "timeframe": {
                    "from": start_time,
                    "to": end_time
                }
            }
        }

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_query_results(self, query_id: str) -> dict:
        """Get results of an XQL query"""
        endpoint = f"{self.base_url}/public_api/v1/xql/get_query_results"

        payload = {
            "request_data": {
                "query_id": query_id,
                "format": "json"
            }
        }

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_assets(self, filters: list = None) -> dict:
        """Get asset inventory"""
        endpoint = f"{self.base_url}/public_api/v1/assets/get_assets"

        payload = {
            "request_data": {}
        }

        if filters:
            payload["request_data"]["filters"] = filters

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def create_incident(self, name: str, description: str,
                       severity: str, alert_ids: list = None) -> dict:
        """Create a new incident"""
        endpoint = f"{self.base_url}/public_api/v1/incidents/create_incident"

        payload = {
            "request_data": {
                "incident_name": name,
                "description": description,
                "severity": severity
            }
        }

        if alert_ids:
            payload["request_data"]["alert_id_list"] = alert_ids

        response = requests.post(
            endpoint,
            headers=self._generate_headers(),
            json=payload
        )
        response.raise_for_status()
        return response.json()
```

### 2.2 XQL Queries for Threat Hunting

```python
"""
Pre-built XQL queries for AI-powered threat hunting
"""

class XSIAMThreatHunter:
    """AI-assisted threat hunting with XSIAM"""

    # Pre-built XQL queries for common threats
    HUNT_QUERIES = {
        "lateral_movement": """
            dataset = xdr_data
            | filter event_type = "NETWORK"
            | filter dst_port in (445, 135, 3389, 5985, 5986)
            | comp count() as connection_count by src_ip, dst_ip, dst_port
            | filter connection_count > 10
            | sort desc connection_count
        """,

        "suspicious_powershell": """
            dataset = xdr_data
            | filter event_type = "PROCESS"
            | filter process_name ~= "powershell"
            | filter cmdline ~= "(encoded|bypass|hidden|downloadstring|invoke-expression)"
            | fields timestamp, endpoint_name, username, cmdline
            | sort desc timestamp
        """,

        "c2_beaconing": """
            dataset = xdr_data
            | filter event_type = "NETWORK"
            | filter direction = "OUTBOUND"
            | comp count() as beacon_count,
                   avg(bytes_sent) as avg_bytes,
                   stddev(timestamp) as timing_variance
              by src_ip, dst_ip, dst_port
            | filter beacon_count > 100
            | filter timing_variance < 5000
            | sort desc beacon_count
        """,

        "credential_access": """
            dataset = xdr_data
            | filter event_type = "PROCESS"
            | filter process_name in ("mimikatz", "procdump", "comsvcs.dll")
               or cmdline ~= "(lsass|sekurlsa|credentials)"
            | fields timestamp, endpoint_name, username, process_name, cmdline
            | sort desc timestamp
        """,

        "persistence_mechanisms": """
            dataset = xdr_data
            | filter event_type in ("REGISTRY", "FILE", "SCHEDULED_TASK")
            | filter registry_key ~= "(Run|RunOnce|Services)"
               or file_path ~= "(Startup|Tasks)"
            | fields timestamp, endpoint_name, event_type, registry_key, file_path
            | sort desc timestamp
        """,

        "data_exfiltration": """
            dataset = xdr_data
            | filter event_type = "NETWORK"
            | filter direction = "OUTBOUND"
            | comp sum(bytes_sent) as total_bytes by src_ip, dst_ip
            | filter total_bytes > 100000000
            | sort desc total_bytes
        """
    }

    def __init__(self, xsiam_client: CortexXSIAMClient, llm_client):
        self.xsiam = xsiam_client
        self.llm = llm_client

    def run_hunt(self, hunt_type: str) -> dict:
        """Run a predefined hunt query"""
        if hunt_type not in self.HUNT_QUERIES:
            raise ValueError(f"Unknown hunt type: {hunt_type}")

        query = self.HUNT_QUERIES[hunt_type]
        result = self.xsiam.run_xql_query(query)

        # Get query ID and fetch results
        query_id = result.get("reply", {}).get("query_id")
        if query_id:
            import time
            time.sleep(2)  # Wait for query to complete
            return self.xsiam.get_query_results(query_id)

        return result

    def analyze_hunt_results(self, hunt_type: str, results: dict) -> dict:
        """Analyze hunt results with LLM"""

        prompt = f"""Analyze these {hunt_type} threat hunting results from Cortex XSIAM.

Results:
```json
{json.dumps(results, indent=2)[:5000]}
```

Provide:
1. Key findings summary
2. High-risk indicators requiring immediate investigation
3. Recommended follow-up XQL queries
4. MITRE ATT&CK mapping
5. Response recommendations

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

    def generate_custom_query(self, description: str) -> str:
        """Use LLM to generate custom XQL query"""

        prompt = f"""Generate an XQL query for Cortex XSIAM based on this description:

"{description}"

XQL syntax reference:
- dataset = xdr_data (main dataset)
- filter, comp, fields, sort are main operators
- Use ~= for regex matching
- Use in() for list matching
- comp count(), sum(), avg() for aggregations

Return only the XQL query, no explanation."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text.strip()
```

### 2.3 XSIAM Playbook Integration

```python
"""
Integrate AI analysis with XSIAM playbooks
"""

class XSIAMPlaybookIntegration:
    """Connect AI models with XSIAM SOAR playbooks"""

    def __init__(self, xsiam_client: CortexXSIAMClient):
        self.xsiam = xsiam_client

    def create_ai_enrichment_action(self, alert_data: dict,
                                     ai_analysis: dict) -> dict:
        """
        Format AI analysis for XSIAM playbook consumption

        This output can be used in XSIAM playbook automations
        """
        return {
            "action_type": "ai_enrichment",
            "input": {
                "alert_id": alert_data.get("alert_id"),
                "alert_name": alert_data.get("name"),
                "original_severity": alert_data.get("severity")
            },
            "output": {
                "ai_threat_level": ai_analysis.get("threat_assessment"),
                "ai_confidence": ai_analysis.get("confidence"),
                "mitre_techniques": ai_analysis.get("mitre_techniques", []),
                "recommended_actions": ai_analysis.get("immediate_actions", []),
                "investigation_queries": ai_analysis.get("investigation_queries", []),
                "summary": ai_analysis.get("summary")
            },
            "recommendations": {
                "escalate": ai_analysis.get("threat_assessment") in ["Critical", "High"],
                "auto_remediate": ai_analysis.get("confidence") == "high",
                "human_review": ai_analysis.get("confidence") == "low"
            }
        }

    def trigger_playbook(self, playbook_id: str,
                        incident_id: str,
                        input_data: dict) -> dict:
        """Trigger an XSIAM playbook with AI-generated input"""

        # This would integrate with XSIAM's SOAR capabilities
        # Implementation depends on specific XSIAM configuration

        return {
            "status": "triggered",
            "playbook_id": playbook_id,
            "incident_id": incident_id,
            "input_provided": input_data
        }
```

---

## Part 3: Complete Integration Pipeline

### 3.1 End-to-End AI-Enhanced SOC Pipeline

```python
"""
Complete XSIAM/XDR + AI integration pipeline
"""

class AIPoweredSOC:
    """AI-enhanced Security Operations Center pipeline"""

    def __init__(self, xdr_client, xsiam_client, llm_client):
        self.xdr = xdr_client
        self.xsiam = xsiam_client
        self.llm = llm_client

        # Initialize components
        self.enricher = XDRAlertEnricher(xdr_client, llm_client)
        self.responder = XDRAutoResponder(xdr_client)
        self.hunter = XSIAMThreatHunter(xsiam_client, llm_client)

    def process_alert_queue(self, max_alerts: int = 50) -> list:
        """Process pending alerts through AI pipeline"""

        # 1. Fetch new alerts from XDR
        alerts_response = self.xdr.get_alerts(
            filters=[
                {"field": "status", "operator": "eq", "value": "new"}
            ],
            search_to=max_alerts
        )

        alerts = alerts_response.get("reply", {}).get("alerts", [])

        processed = []
        for alert in alerts:
            # 2. Enrich with AI
            enriched = self.enricher.enrich_alert(alert)

            # 3. Execute automated response
            response = self.responder.execute_response(enriched)

            # 4. Create incident if high severity
            if enriched.get("ai_analysis", {}).get("threat_assessment") in ["Critical", "High"]:
                incident = self.xsiam.create_incident(
                    name=f"AI-Detected: {alert.get('name', 'Unknown Threat')}",
                    description=enriched.get("ai_analysis", {}).get("summary", ""),
                    severity=enriched.get("ai_analysis", {}).get("threat_assessment", "medium").lower(),
                    alert_ids=[alert.get("alert_id")]
                )
                response["incident_created"] = incident

            processed.append({
                "alert": alert,
                "enrichment": enriched,
                "response": response
            })

        return processed

    def run_scheduled_hunts(self) -> dict:
        """Run all threat hunts and analyze results"""

        hunt_results = {}

        for hunt_type in XSIAMThreatHunter.HUNT_QUERIES.keys():
            try:
                results = self.hunter.run_hunt(hunt_type)
                analysis = self.hunter.analyze_hunt_results(hunt_type, results)

                hunt_results[hunt_type] = {
                    "raw_results": results,
                    "ai_analysis": analysis
                }
            except Exception as e:
                hunt_results[hunt_type] = {"error": str(e)}

        return hunt_results

    def generate_daily_report(self) -> str:
        """Generate AI-powered daily security report"""

        # Gather data
        incidents = self.xsiam.get_incidents(search_to=100)

        prompt = f"""Generate a daily security operations report based on this data.

Incidents (last 24 hours):
```json
{json.dumps(incidents, indent=2)[:8000]}
```

Include:
1. Executive Summary (3-4 sentences)
2. Key Metrics (incidents by severity, resolution time, etc.)
3. Notable Threats
4. Trends and Patterns
5. Recommendations

Format as markdown."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text
```

---

## Part 4: Configuration

### Environment Variables

```bash
# .env file
XDR_API_KEY=your-xdr-api-key
XDR_API_KEY_ID=your-api-key-id
XDR_FQDN=api-xyz.xdr.us.paloaltonetworks.com

XSIAM_API_KEY=your-xsiam-api-key
XSIAM_API_KEY_ID=your-xsiam-key-id
XSIAM_FQDN=api-xyz.xsiam.paloaltonetworks.com

ANTHROPIC_API_KEY=your-anthropic-key
```

### Required Permissions

| API Key Scope | Required For |
|---------------|--------------|
| `incidents:read` | Fetching incidents |
| `incidents:write` | Creating incidents |
| `alerts:read` | Fetching alerts |
| `endpoints:read` | Endpoint details |
| `endpoints:write` | Isolation actions |
| `xql:read` | Running queries |

---

## Part 5: Lab Integration

These integrations work with the following labs:

| Lab | Integration Use Case |
|-----|---------------------|
| Lab 04 | Log analysis with XSIAM data |
| Lab 05 | Threat intel agent querying XDR |
| Lab 09 | Detection pipeline feeding XDR |
| Lab 10 | IR Copilot with XDR actions |
| Lab 14 | C2 detection with XQL queries |
| Lab 15 | Lateral movement detection in XDR |

---

## Resources

- [Cortex XDR API Documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-API-Reference)
- [Cortex XSIAM Documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM)
- [XQL Language Reference](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-XQL-Language-Reference)
- [XSOAR Marketplace](https://xsoar.pan.dev/marketplace)

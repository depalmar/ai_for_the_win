# Elastic Security Integration Guide

Integrate AI-powered security analysis with Elastic Security (ELK Stack).

```
+-----------------------------------------------------------------------------+
|                      AI + ELASTIC SECURITY ARCHITECTURE                      |
+-----------------------------------------------------------------------------+
|                                                                             |
|   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    |
|   │ Elasticsearch│    │   AI/ML     │    │   Kibana    │                    |
|   │   Indices   │--->│   Analysis  │--->│ Dashboards  │                    |
|   │   Alerts    │    │   (Claude)  │    │   Actions   │                    |
|   └─────────────┘    └─────────────┘    └─────────────┘                    |
|         ^                  |                   |                            |
|         |                  v                   v                            |
|   ┌─────────────────────────────────────────────────────────┐              |
|   │                  Elastic Stack                           │              |
|   │  • Detection Rules  • ML Jobs  • Cases  • Timeline      │              |
|   └─────────────────────────────────────────────────────────┘              |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Overview

| Component | Description |
|-----------|-------------|
| **Elasticsearch** | Distributed search and analytics engine |
| **Kibana Security** | SIEM UI, detection rules, case management |
| **Elastic Agent** | Unified data collection |
| **ML Jobs** | Anomaly detection, rare entity analysis |

---

## Part 1: Elasticsearch Client Setup

### 1.1 Installation

```bash
pip install elasticsearch>=8.0.0
```

### 1.2 Client Configuration

```python
"""
Elasticsearch Client Setup for Security Operations
"""
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import os
import json

class ElasticSecurityClient:
    """Client for Elastic Security operations"""

    def __init__(self):
        """Initialize Elasticsearch client"""

        # Cloud deployment
        if os.getenv("ELASTIC_CLOUD_ID"):
            self.es = Elasticsearch(
                cloud_id=os.getenv("ELASTIC_CLOUD_ID"),
                api_key=os.getenv("ELASTIC_API_KEY")
            )
        # Self-hosted
        else:
            self.es = Elasticsearch(
                hosts=[os.getenv("ELASTIC_HOST", "https://localhost:9200")],
                api_key=os.getenv("ELASTIC_API_KEY"),
                verify_certs=os.getenv("ELASTIC_VERIFY_CERTS", "true").lower() == "true",
                ca_certs=os.getenv("ELASTIC_CA_CERTS")
            )

        # Verify connection
        if not self.es.ping():
            raise ConnectionError("Failed to connect to Elasticsearch")

    def search(self, index: str, query: dict, size: int = 100) -> list:
        """
        Execute Elasticsearch query

        Args:
            index: Index pattern (e.g., "logs-*", ".alerts-security*")
            query: Elasticsearch DSL query
            size: Maximum results to return

        Returns:
            List of matching documents
        """
        response = self.es.search(
            index=index,
            query=query,
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}]
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def get_security_alerts(self,
                           status: str = "open",
                           severity: list = None,
                           time_range: str = "24h") -> list:
        """
        Get security alerts from Elastic Security

        Args:
            status: Alert status (open, acknowledged, closed)
            severity: List of severities to filter
            time_range: Time range (e.g., "24h", "7d")
        """
        # Parse time range
        now = datetime.utcnow()
        if time_range.endswith("h"):
            start_time = now - timedelta(hours=int(time_range[:-1]))
        elif time_range.endswith("d"):
            start_time = now - timedelta(days=int(time_range[:-1]))
        else:
            start_time = now - timedelta(hours=24)

        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat()}}},
                    {"term": {"kibana.alert.workflow_status": status}}
                ]
            }
        }

        if severity:
            query["bool"]["must"].append({
                "terms": {"kibana.alert.severity": severity}
            })

        return self.search(".alerts-security.alerts-*", query)

    def get_detection_rules(self) -> list:
        """Get all enabled detection rules"""
        response = self.es.search(
            index=".kibana_security_solution*",
            query={
                "bool": {
                    "must": [
                        {"term": {"type": "alert"}},
                        {"term": {"alert.enabled": True}}
                    ]
                }
            },
            size=1000
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def search_events(self,
                     index_pattern: str = "logs-*",
                     kql_query: str = None,
                     lucene_query: str = None,
                     time_range: str = "24h",
                     size: int = 100) -> list:
        """
        Search security events using KQL or Lucene

        Args:
            index_pattern: Index pattern to search
            kql_query: Kibana Query Language query
            lucene_query: Lucene query string
            time_range: Time range for search
        """
        now = datetime.utcnow()
        if time_range.endswith("h"):
            start_time = now - timedelta(hours=int(time_range[:-1]))
        elif time_range.endswith("d"):
            start_time = now - timedelta(days=int(time_range[:-1]))
        else:
            start_time = now - timedelta(hours=24)

        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat()}}}
                ]
            }
        }

        if lucene_query:
            query["bool"]["must"].append({
                "query_string": {"query": lucene_query}
            })
        elif kql_query:
            # KQL to Lucene conversion (simplified)
            query["bool"]["must"].append({
                "query_string": {"query": kql_query}
            })

        return self.search(index_pattern, query, size)

    def create_case(self, title: str, description: str,
                   severity: str = "medium", tags: list = None) -> dict:
        """Create a security case"""
        case_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None}
        }

        # Use Kibana Cases API
        response = self.es.perform_request(
            "POST",
            "/api/cases",
            body=case_data,
            headers={"kbn-xsrf": "true"}
        )

        return response
```

---

## Part 2: AI-Powered Alert Analysis

### 2.1 Alert Enrichment

```python
"""
Enrich Elastic Security alerts with AI analysis
"""
from anthropic import Anthropic

class ElasticAIAnalyzer:
    """AI-powered Elastic Security analysis"""

    def __init__(self, elastic_client: ElasticSecurityClient, llm_client: Anthropic):
        self.elastic = elastic_client
        self.llm = llm_client

    def analyze_alert(self, alert: dict) -> dict:
        """
        Analyze a security alert using LLM

        Args:
            alert: Elastic Security alert document

        Returns:
            AI analysis with threat assessment
        """
        # Extract relevant alert fields
        alert_summary = {
            "rule_name": alert.get("kibana.alert.rule.name"),
            "severity": alert.get("kibana.alert.severity"),
            "risk_score": alert.get("kibana.alert.risk_score"),
            "mitre_tactics": alert.get("kibana.alert.rule.threat", []),
            "host": alert.get("host.name"),
            "user": alert.get("user.name"),
            "process": alert.get("process.name"),
            "command_line": alert.get("process.command_line"),
            "source_ip": alert.get("source.ip"),
            "destination_ip": alert.get("destination.ip"),
            "file_path": alert.get("file.path"),
            "timestamp": alert.get("@timestamp")
        }

        prompt = f"""Analyze this Elastic Security alert and provide a security assessment.

Alert Details:
```json
{json.dumps(alert_summary, indent=2, default=str)}
```

Full Alert Context (first 3000 chars):
```json
{json.dumps(alert, indent=2, default=str)[:3000]}
```

Provide:
1. Threat assessment (Critical/High/Medium/Low)
2. Is this likely a true positive or false positive? Why?
3. Attack stage in the kill chain
4. Recommended immediate actions
5. Suggested investigation queries (EQL or KQL)
6. Related MITRE ATT&CK techniques

Respond in JSON format:
{{
    "threat_level": "string",
    "confidence": "high/medium/low",
    "true_positive_likelihood": "high/medium/low",
    "reasoning": "string",
    "attack_stage": "string",
    "immediate_actions": ["list"],
    "investigation_queries": [
        {{"type": "eql|kql", "query": "string", "purpose": "string"}}
    ],
    "mitre_techniques": [{{"id": "T1234", "name": "string"}}],
    "iocs_extracted": ["list of IOCs"],
    "summary": "string"
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            analysis = {"raw_analysis": response.content[0].text}

        return {
            "original_alert": alert_summary,
            "ai_analysis": analysis,
            "analyzed_at": datetime.utcnow().isoformat()
        }

    def correlate_alerts(self, alerts: list) -> dict:
        """
        Correlate multiple alerts to identify attack patterns
        """
        prompt = f"""Analyze these {len(alerts)} Elastic Security alerts for correlation and attack patterns.

Alerts:
```json
{json.dumps(alerts[:20], indent=2, default=str)}
```

Identify:
1. Are these alerts part of the same attack campaign?
2. What is the likely attack progression?
3. Which host/user accounts are most compromised?
4. What is the overall threat level?
5. Timeline of the attack

Respond in JSON format:
{{
    "correlated": true/false,
    "campaign_likelihood": "high/medium/low",
    "attack_progression": ["stage1", "stage2", ...],
    "compromised_assets": {{
        "hosts": ["list"],
        "users": ["list"],
        "risk_level": "string"
    }},
    "overall_threat_level": "string",
    "timeline": [
        {{"timestamp": "string", "event": "string", "significance": "string"}}
    ],
    "recommended_response": ["action1", "action2"],
    "summary": "string"
}}
"""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}
```

### 2.2 Detection Rule Generation

```python
"""
AI-powered detection rule generation for Elastic Security
"""

class DetectionRuleGenerator:
    """Generate Elastic Security detection rules with AI"""

    def __init__(self, llm_client: Anthropic):
        self.llm = llm_client

    def generate_eql_rule(self, threat_description: str) -> dict:
        """
        Generate EQL detection rule from threat description

        Args:
            threat_description: Natural language description of the threat

        Returns:
            Complete Elastic detection rule
        """
        prompt = f"""Create an Elastic Security detection rule using EQL for this threat:

"{threat_description}"

EQL (Event Query Language) syntax:
- process where process.name == "cmd.exe"
- sequence by host.id [process where ...] [network where ...]
- Use | for pipes, and for boolean AND
- Common fields: process.name, process.command_line, file.path, network.direction

Provide a complete rule in JSON format:
{{
    "name": "Rule name",
    "description": "Detailed description",
    "risk_score": 50,
    "severity": "medium",
    "type": "eql",
    "query": "EQL query here",
    "language": "eql",
    "threat": [
        {{
            "framework": "MITRE ATT&CK",
            "tactic": {{
                "id": "TA0001",
                "name": "Initial Access"
            }},
            "technique": [
                {{
                    "id": "T1566",
                    "name": "Phishing"
                }}
            ]
        }}
    ],
    "tags": ["tag1", "tag2"],
    "false_positives": ["List of potential false positives"],
    "references": ["https://..."],
    "author": ["AI Security Assistant"],
    "license": "Elastic License v2"
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

    def generate_kql_rule(self, threat_description: str) -> dict:
        """Generate KQL-based detection rule"""

        prompt = f"""Create an Elastic Security detection rule using KQL for this threat:

"{threat_description}"

KQL (Kibana Query Language) syntax:
- field: value
- field: (value1 OR value2)
- field: * (wildcard)
- field >= value (comparisons)
- NOT field: value

Provide a complete rule in JSON format with type "query" and language "kuery".
Include MITRE ATT&CK mapping, severity, risk_score, and false positive guidance.
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

## Part 3: Pre-Built Detection Queries

### EQL Queries for Threat Hunting

```python
"""
Pre-built EQL queries for common threats
"""

EQL_QUERIES = {
    "credential_dumping": '''
        process where process.name : ("mimikatz.exe", "procdump.exe", "comsvcs.dll") or
        process.command_line : ("*sekurlsa*", "*lsass*", "*minidump*")
    ''',

    "powershell_suspicious": '''
        process where process.name : "powershell.exe" and
        process.command_line : ("*-enc*", "*bypass*", "*hidden*", "*downloadstring*", "*invoke-expression*")
    ''',

    "lateral_movement_psexec": '''
        sequence by host.id with maxspan=1m
            [process where process.name : "services.exe"]
            [process where process.parent.name : "services.exe" and
             process.name : ("cmd.exe", "powershell.exe")]
    ''',

    "persistence_scheduled_task": '''
        process where process.name : "schtasks.exe" and
        process.command_line : ("*/create*", "*/change*") and
        process.command_line : ("*powershell*", "*cmd*", "*.exe*")
    ''',

    "defense_evasion_timestomp": '''
        file where event.action : "modification" and
        file.mtime < file.ctime
    ''',

    "exfiltration_large_upload": '''
        network where network.direction : "outbound" and
        network.bytes > 10000000
    ''',

    "ransomware_file_encryption": '''
        sequence by host.id, user.name with maxspan=5m
            [file where event.action : "creation" and
             file.extension : ("encrypted", "locked", "crypto", "enc")]
            [file where event.action : "creation" and
             file.name : ("*readme*", "*decrypt*", "*ransom*")]
    ''',

    "c2_beaconing": '''
        sequence by source.ip, destination.ip with maxspan=1h
            [network where network.direction : "outbound"] with runs=10
    '''
}


class ThreatHunter:
    """AI-assisted threat hunting with Elastic"""

    def __init__(self, elastic_client: ElasticSecurityClient, llm_client: Anthropic):
        self.elastic = elastic_client
        self.llm = llm_client
        self.queries = EQL_QUERIES

    def run_hunt(self, hunt_name: str, time_range: str = "7d") -> dict:
        """Run a predefined threat hunt"""
        if hunt_name not in self.queries:
            raise ValueError(f"Unknown hunt: {hunt_name}")

        query = self.queries[hunt_name]

        # Execute EQL query
        response = self.elastic.es.eql.search(
            index="logs-*",
            query=query,
            filter={"range": {"@timestamp": {"gte": f"now-{time_range}"}}}
        )

        return {
            "hunt_name": hunt_name,
            "query": query,
            "hits": response.get("hits", {}).get("total", {}).get("value", 0),
            "events": response.get("hits", {}).get("events", [])
        }

    def analyze_hunt_results(self, hunt_name: str, results: dict) -> dict:
        """Analyze threat hunt results with AI"""

        prompt = f"""Analyze these threat hunting results from Elastic Security.

Hunt Type: {hunt_name}
Query: {results.get('query')}
Results Found: {results.get('hits')}

Sample Events:
```json
{json.dumps(results.get('events', [])[:10], indent=2, default=str)}
```

Provide:
1. Assessment of findings
2. True positive vs false positive likelihood
3. Hosts/users requiring investigation
4. Recommended follow-up actions
5. Additional hunt queries to run

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}

    def generate_hunt_query(self, description: str) -> str:
        """Generate custom EQL hunt query from description"""

        prompt = f"""Generate an EQL (Event Query Language) query for Elastic Security:

"{description}"

EQL syntax examples:
- process where process.name == "cmd.exe"
- sequence by host.id [event1] [event2]
- process.command_line : "*pattern*" (wildcard match)

Return only the EQL query, no explanation."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text.strip()
```

---

## Part 4: ML Job Integration

### Anomaly Detection Jobs

```python
"""
Integrate Elastic ML anomaly detection with AI analysis
"""

class ElasticMLAnalyzer:
    """Analyze Elastic ML job results with AI"""

    def __init__(self, elastic_client: ElasticSecurityClient, llm_client: Anthropic):
        self.elastic = elastic_client
        self.llm = llm_client

    def get_anomalies(self, job_id: str, threshold: float = 75.0) -> list:
        """
        Get anomalies from ML job

        Args:
            job_id: ML job identifier
            threshold: Minimum anomaly score
        """
        response = self.elastic.es.ml.get_records(
            job_id=job_id,
            body={
                "sort": [{"record_score": {"order": "desc"}}],
                "size": 100
            }
        )

        return [
            record for record in response.get("records", [])
            if record.get("record_score", 0) >= threshold
        ]

    def analyze_anomalies(self, job_id: str, anomalies: list) -> dict:
        """Analyze ML anomalies with AI"""

        prompt = f"""Analyze these anomalies from Elastic ML job "{job_id}".

Anomalies:
```json
{json.dumps(anomalies[:20], indent=2, default=str)}
```

Provide:
1. Which anomalies are likely security threats vs. benign?
2. Root cause analysis for top anomalies
3. Correlation between anomalies
4. Recommended investigation steps
5. Tuning recommendations for the ML job

Respond in JSON format."""

        response = self.llm.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except:
            return {"raw_analysis": response.content[0].text}
```

---

## Part 5: Environment Setup

### Environment Variables

```bash
# .env file

# Elastic Cloud
ELASTIC_CLOUD_ID=your-deployment:base64string
ELASTIC_API_KEY=your-api-key

# OR Self-hosted
ELASTIC_HOST=https://localhost:9200
ELASTIC_API_KEY=your-api-key
ELASTIC_VERIFY_CERTS=true
ELASTIC_CA_CERTS=/path/to/ca.crt

# AI
ANTHROPIC_API_KEY=your-anthropic-key
```

### Docker Compose (Development)

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
    ports:
      - "9200:9200"
    volumes:
      - es-data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=changeme
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  ai-analyzer:
    build: .
    environment:
      - ELASTIC_HOST=http://elasticsearch:9200
      - ELASTIC_API_KEY=${ELASTIC_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    depends_on:
      - elasticsearch

volumes:
  es-data:
```

---

## Resources

- [Elasticsearch Python Client](https://elasticsearch-py.readthedocs.io/)
- [EQL Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
- [Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/index.html)
- [Detection Rules Repository](https://github.com/elastic/detection-rules)

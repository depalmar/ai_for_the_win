# Security Platform Integrations

Integrate AI-powered security tools with enterprise security platforms.

```
+-----------------------------------------------------------------------------+
|                     AI SECURITY INTEGRATIONS                                 |
+-----------------------------------------------------------------------------+
|                                                                             |
|   SIEM/XDR              SOAR                  THREAT INTEL                  |
|   ┌──────────┐         ┌──────────┐          ┌──────────┐                  |
|   │ XSIAM    │         │ XSOAR    │          │ MISP     │                  |
|   │ XDR      │<------->│ Playbooks│<-------->│ VirusTotal│                 |
|   │ Splunk   │    AI   │ Cortex   │    AI    │ Shodan   │                  |
|   │ Elastic  │         │ Tines    │          │ GreyNoise│                  |
|   └──────────┘         └──────────┘          └──────────┘                  |
|         |                   |                      |                        |
|         +-------------------+----------------------+                        |
|                             |                                               |
|                    +----------------+                                       |
|                    |   AI/ML Core   |                                       |
|                    | Claude, GPT    |                                       |
|                    | Custom Models  |                                       |
|                    +----------------+                                       |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Available Integration Guides

| Platform | Guide | Use Cases |
|----------|-------|-----------|
| **Cortex XSIAM/XDR** | [xsiam-xdr-integration.md](./xsiam-xdr-integration.md) | Alert enrichment, threat hunting, automated response |
| **Splunk** | [splunk-integration.md](./splunk-integration.md) | Log analysis, detection engineering, SIEM integration |
| **Elastic Security** | [elastic-integration.md](./elastic-integration.md) | ELK stack, detection rules, ML anomaly detection |

## Quick Start

### 1. Choose Your Platform

```bash
# Set up environment for your platform
cp .env.example .env

# Add platform-specific credentials
echo "XDR_API_KEY=your-key" >> .env
# OR
echo "SPLUNK_TOKEN=your-token" >> .env
# OR
echo "ELASTIC_API_KEY=your-key" >> .env
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt

# Platform-specific packages
pip install splunk-sdk          # For Splunk
pip install elasticsearch       # For Elastic
pip install cortex-xdr-sdk      # For XDR (unofficial)
```

### 3. Run Integration Tests

```bash
# Test your integration
python scripts/test_integrations.py --platform xdr
python scripts/test_integrations.py --platform splunk
python scripts/test_integrations.py --platform elastic
```

## Integration Patterns

### Pattern 1: Alert Enrichment

```python
# Enrich alerts from any platform with AI
from integrations import AlertEnricher

enricher = AlertEnricher(llm_client)
enriched = enricher.enrich(alert_data)
```

### Pattern 2: Automated Response

```python
# AI-driven response decisions
from integrations import ResponseOrchestrator

orchestrator = ResponseOrchestrator(platform_client, llm_client)
actions = orchestrator.decide_response(enriched_alert)
orchestrator.execute(actions)
```

### Pattern 3: Threat Hunting

```python
# AI-assisted threat hunting
from integrations import ThreatHunter

hunter = ThreatHunter(siem_client, llm_client)
queries = hunter.generate_hunt_queries("APT29 lateral movement")
results = hunter.execute_hunts(queries)
analysis = hunter.analyze_results(results)
```

## Lab Integration

These integrations enhance the following labs:

| Lab | Integration | Enhancement |
|-----|-------------|-------------|
| Lab 04 | Splunk/Elastic | Real SIEM data instead of samples |
| Lab 05 | All platforms | Live threat intel feeds |
| Lab 09 | XSIAM/XDR | Production detection pipeline |
| Lab 10 | SOAR | Automated playbook execution |
| Lab 14 | Network tools | Live C2 detection |

## Contributing

To add a new integration:

1. Create `{platform}-integration.md` in this directory
2. Follow the existing guide format
3. Include working code examples
4. Add platform to the table above
5. Submit PR

## Resources

- [Palo Alto Cortex Documentation](https://docs-cortex.paloaltonetworks.com/)
- [Splunk Developer Documentation](https://dev.splunk.com/)
- [Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/index.html)

# n8n Security Automation Templates

Ready-to-use n8n workflows for security automation. Import these into your n8n instance.

> ⚠️ **DISCLAIMER**: These are example templates for educational purposes. Configure credentials and test thoroughly before production use.

## Available Workflows

| Workflow | Description | Triggers | Status |
|----------|-------------|----------|--------|
| [IOC Enrichment](#ioc-enrichment) | Auto-enrich IOCs from multiple sources | Webhook | ✅ Ready |
| [Alert Triage](#alert-triage) | AI-powered alert triage and prioritization | Webhook | ✅ Ready |
| [Threat Intel Feed](#threat-intel-feed) | Aggregate and process threat intel feeds | Schedule | 📋 Planned |
| [Incident Response](#incident-response) | Automated IR workflow with escalation | Webhook | 📋 Planned |
| [Vulnerability Notifications](#vulnerability-notifications) | Alert on new critical CVEs | Schedule | 📋 Planned |

## Setup Instructions

1. **Install n8n**:
   ```bash
   npm install n8n -g
   # or with Docker
   docker run -it --rm --name n8n -p 5678:5678 n8nio/n8n
   ```

2. **Configure Credentials**:
   - OpenAI/Anthropic API for AI nodes
   - VirusTotal, AbuseIPDB, etc. for enrichment
   - Slack/Teams for notifications
   - Your SIEM API for log queries

3. **Import Workflows**:
   - Go to n8n → Workflows → Import
   - Select the JSON file for the workflow

## Workflow Details

### IOC Enrichment

Automatically enriches IOCs (IPs, domains, hashes) from multiple threat intelligence sources.

**Nodes:**
- Webhook trigger (receives IOC)
- VirusTotal lookup
- AbuseIPDB lookup
- OTX AlienVault lookup
- AI summarization
- Slack notification

**Use Case:** Integrate with your SIEM to auto-enrich alerts

### Alert Triage

Uses AI to analyze and prioritize security alerts.

**Nodes:**
- Webhook trigger (receives alert)
- AI analysis (Claude/GPT)
- Priority scoring
- Ticket creation (Jira/ServiceNow)
- Slack notification

**Use Case:** Reduce analyst fatigue by pre-triaging alerts

### Threat Intel Feed

Aggregates multiple threat intel feeds and identifies relevant threats.

**Nodes:**
- Scheduled trigger (hourly)
- Multiple feed sources
- Deduplication
- AI relevance scoring
- Database storage
- Summary notification

### Incident Response

Automated IR workflow with human-in-the-loop escalation.

**Nodes:**
- Webhook trigger
- Severity assessment
- Auto-containment (conditional)
- Analyst notification
- Ticket creation
- Evidence collection
- Timeline generation

### Vulnerability Notifications

Monitors for new critical vulnerabilities affecting your stack.

**Nodes:**
- Scheduled trigger (daily)
- NVD API query
- Tech stack matching
- AI impact analysis
- Slack/Email alerts
- Ticket creation (critical only)

## Best Practices

1. **Test in Dev First**: Always test workflows in a dev environment
2. **Use Credentials**: Never hardcode API keys in workflows
3. **Error Handling**: Add error handlers to all workflows
4. **Rate Limiting**: Respect API rate limits with delays
5. **Logging**: Enable workflow execution logging
6. **Versioning**: Export and version control your workflows

## Integration Examples

### With Python Scripts

```python
import requests

# Trigger n8n workflow via webhook
def trigger_enrichment(ioc: str, ioc_type: str):
    webhook_url = "http://n8n.local:5678/webhook/enrich-ioc"
    response = requests.post(webhook_url, json={
        "ioc": ioc,
        "type": ioc_type
    })
    return response.json()
```

### With SIEM (Splunk Example)

```
| search index=alerts severity=high
| eval webhook_payload=json_object("alert_id", alert_id, "title", title)
| sendalert n8n_webhook param.url="http://n8n:5678/webhook/alert-triage"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Webhook not triggering | Check n8n is running and port is accessible |
| API errors | Verify credentials and rate limits |
| Workflow stuck | Check execution logs and error handlers |
| Missing data | Verify webhook payload format |

## Contributing

Want to add a workflow? Please:
1. Use the existing workflows as templates
2. Include `meta` object with description and disclaimer
3. Add error handling nodes
4. Document required credentials
5. Submit a PR with the workflow JSON and README updates

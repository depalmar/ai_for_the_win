# Lab 08: Vulnerability Prioritizer - Solution Walkthrough

## Overview

Build an AI-powered vulnerability prioritization system that analyzes CVSS scores, asset context, and threat intelligence to recommend remediation priorities.

**Time:** 2-3 hours
**Difficulty:** Intermediate

---

## Task 1: Vulnerability Data Ingestion

### Loading CVE Data

```python
import json
import requests
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    published_date: datetime
    affected_products: list[str]
    cwe_id: Optional[str] = None
    exploit_available: bool = False
    in_the_wild: bool = False

class VulnerabilityLoader:
    def __init__(self, nvd_api_key: str = None):
        self.nvd_api_key = nvd_api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def load_from_scan(self, scan_file: str) -> list[Vulnerability]:
        """Load vulnerabilities from scanner output (Nessus, Qualys, etc.)."""
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)

        vulns = []
        for item in scan_data.get('vulnerabilities', []):
            vuln = Vulnerability(
                cve_id=item['cve_id'],
                description=item.get('description', ''),
                cvss_score=item.get('cvss_score', 0.0),
                cvss_vector=item.get('cvss_vector', ''),
                published_date=datetime.fromisoformat(item.get('published', '2024-01-01')),
                affected_products=item.get('affected_products', []),
                cwe_id=item.get('cwe_id'),
                exploit_available=item.get('exploit_available', False)
            )
            vulns.append(vuln)

        return vulns

    def enrich_from_nvd(self, cve_id: str) -> dict:
        """Fetch additional details from NVD API."""
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key

        try:
            response = requests.get(
                f"{self.base_url}?cveId={cve_id}",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get('vulnerabilities'):
                cve_data = data['vulnerabilities'][0]['cve']
                return {
                    'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                    'references': [ref['url'] for ref in cve_data.get('references', [])],
                    'weaknesses': [w.get('description', [{}])[0].get('value')
                                  for w in cve_data.get('weaknesses', [])]
                }
        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")

        return {}

# Load vulnerabilities
loader = VulnerabilityLoader()
vulns = loader.load_from_scan("scan_results.json")
print(f"Loaded {len(vulns)} vulnerabilities")
```

---

## Task 2: Asset Context Integration

### Mapping Vulnerabilities to Assets

```python
@dataclass
class Asset:
    hostname: str
    ip_address: str
    asset_type: str  # server, workstation, network_device, etc.
    criticality: str  # critical, high, medium, low
    environment: str  # production, staging, development
    owner: str
    services: list[str]
    data_classification: str  # pii, financial, public, internal

class AssetManager:
    def __init__(self, asset_inventory_file: str):
        with open(asset_inventory_file, 'r') as f:
            self.assets = {a['hostname']: Asset(**a) for a in json.load(f)}

    def get_asset(self, hostname: str) -> Optional[Asset]:
        return self.assets.get(hostname)

    def calculate_asset_risk_multiplier(self, asset: Asset) -> float:
        """Calculate risk multiplier based on asset context."""
        multiplier = 1.0

        # Criticality factor
        criticality_factors = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5
        }
        multiplier *= criticality_factors.get(asset.criticality, 1.0)

        # Environment factor
        env_factors = {
            'production': 1.5,
            'staging': 1.0,
            'development': 0.5
        }
        multiplier *= env_factors.get(asset.environment, 1.0)

        # Data classification factor
        data_factors = {
            'pii': 2.0,
            'financial': 2.0,
            'internal': 1.0,
            'public': 0.5
        }
        multiplier *= data_factors.get(asset.data_classification, 1.0)

        return multiplier

# Load assets
asset_mgr = AssetManager("asset_inventory.json")

# Example calculation
asset = asset_mgr.get_asset("web-prod-01")
if asset:
    multiplier = asset_mgr.calculate_asset_risk_multiplier(asset)
    print(f"Asset: {asset.hostname}, Multiplier: {multiplier}")
```

---

## Task 3: Threat Intelligence Enrichment

### Checking Exploit Availability

```python
class ThreatIntelEnricher:
    def __init__(self):
        self.exploit_db_url = "https://www.exploit-db.com/search"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.kev_list = self._load_kev()

    def _load_kev(self) -> set:
        """Load CISA Known Exploited Vulnerabilities list."""
        try:
            response = requests.get(self.cisa_kev_url, timeout=10)
            data = response.json()
            return {v['cveID'] for v in data.get('vulnerabilities', [])}
        except Exception:
            return set()

    def enrich_vulnerability(self, vuln: Vulnerability) -> dict:
        """Add threat intelligence context to vulnerability."""
        enrichment = {
            'in_kev': vuln.cve_id in self.kev_list,
            'exploit_maturity': self._assess_exploit_maturity(vuln),
            'threat_actors': self._get_threat_actors(vuln.cve_id),
            'epss_score': self._get_epss_score(vuln.cve_id)
        }

        return enrichment

    def _assess_exploit_maturity(self, vuln: Vulnerability) -> str:
        """Assess exploit maturity level."""
        if vuln.cve_id in self.kev_list:
            return "weaponized"  # Actively exploited
        elif vuln.exploit_available:
            return "poc_available"  # PoC exists
        elif vuln.cvss_score >= 9.0:
            return "likely_soon"  # High-value target
        else:
            return "theoretical"

    def _get_epss_score(self, cve_id: str) -> float:
        """Get EPSS (Exploit Prediction Scoring System) score."""
        try:
            response = requests.get(
                f"https://api.first.org/data/v1/epss?cve={cve_id}",
                timeout=5
            )
            data = response.json()
            if data.get('data'):
                return float(data['data'][0].get('epss', 0))
        except Exception:
            pass
        return 0.0

    def _get_threat_actors(self, cve_id: str) -> list[str]:
        """Check if CVE is associated with known threat actors."""
        # In production, integrate with MISP, AlienVault, etc.
        known_actors = {
            'CVE-2021-44228': ['APT41', 'Lazarus', 'Multiple'],
            'CVE-2023-22515': ['Storm-0062'],
            'CVE-2024-3400': ['UTA0218']
        }
        return known_actors.get(cve_id, [])

# Enrich vulnerabilities
enricher = ThreatIntelEnricher()

for vuln in vulns[:5]:
    intel = enricher.enrich_vulnerability(vuln)
    print(f"{vuln.cve_id}: KEV={intel['in_kev']}, EPSS={intel['epss_score']:.3f}")
```

---

## Task 4: Risk Scoring Algorithm

### Combined Risk Calculation

```python
class RiskScorer:
    def __init__(self, asset_manager: AssetManager, enricher: ThreatIntelEnricher):
        self.asset_manager = asset_manager
        self.enricher = enricher

    def calculate_risk_score(self, vuln: Vulnerability, hostname: str) -> dict:
        """Calculate comprehensive risk score."""

        # Base CVSS score (0-10)
        base_score = vuln.cvss_score

        # Asset context multiplier
        asset = self.asset_manager.get_asset(hostname)
        asset_multiplier = 1.0
        if asset:
            asset_multiplier = self.asset_manager.calculate_asset_risk_multiplier(asset)

        # Threat intelligence factors
        intel = self.enricher.enrich_vulnerability(vuln)

        # Exploit availability multiplier
        exploit_multipliers = {
            'weaponized': 2.0,      # In CISA KEV
            'poc_available': 1.5,   # Public PoC exists
            'likely_soon': 1.2,     # High likelihood
            'theoretical': 1.0      # No known exploit
        }
        exploit_multiplier = exploit_multipliers.get(intel['exploit_maturity'], 1.0)

        # EPSS boost (probability of exploitation in next 30 days)
        epss_multiplier = 1.0 + intel['epss_score']

        # Calculate final score (capped at 100)
        risk_score = min(100, base_score * asset_multiplier * exploit_multiplier * epss_multiplier)

        # Determine priority
        if risk_score >= 80 or intel['in_kev']:
            priority = 'CRITICAL'
            sla_days = 1
        elif risk_score >= 60:
            priority = 'HIGH'
            sla_days = 7
        elif risk_score >= 40:
            priority = 'MEDIUM'
            sla_days = 30
        else:
            priority = 'LOW'
            sla_days = 90

        return {
            'cve_id': vuln.cve_id,
            'hostname': hostname,
            'base_cvss': base_score,
            'risk_score': round(risk_score, 2),
            'priority': priority,
            'sla_days': sla_days,
            'factors': {
                'asset_multiplier': asset_multiplier,
                'exploit_multiplier': exploit_multiplier,
                'epss_score': intel['epss_score'],
                'in_kev': intel['in_kev'],
                'threat_actors': intel['threat_actors']
            }
        }

# Score vulnerabilities
scorer = RiskScorer(asset_mgr, enricher)

scored_vulns = []
for vuln in vulns:
    # Assume hostname comes from scan data
    score = scorer.calculate_risk_score(vuln, "web-prod-01")
    scored_vulns.append(score)

# Sort by risk score
scored_vulns.sort(key=lambda x: x['risk_score'], reverse=True)

print("\nTop 10 Vulnerabilities by Risk:")
for v in scored_vulns[:10]:
    print(f"{v['priority']:8} | {v['risk_score']:5.1f} | {v['cve_id']} | {v['hostname']}")
```

---

## Task 5: AI-Powered Recommendations

### Generating Remediation Guidance

```python
import anthropic

class RemediationAdvisor:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def generate_recommendations(self, scored_vuln: dict,
                                 vuln: Vulnerability) -> dict:
        """Generate AI-powered remediation recommendations."""

        prompt = f"""You are a vulnerability management expert. Provide remediation guidance for this vulnerability:

## Vulnerability Details
- CVE ID: {vuln.cve_id}
- Description: {vuln.description}
- CVSS Score: {vuln.cvss_score}
- CWE: {vuln.cwe_id}
- Affected Products: {', '.join(vuln.affected_products)}

## Risk Context
- Calculated Risk Score: {scored_vuln['risk_score']}/100
- Priority: {scored_vuln['priority']}
- SLA: {scored_vuln['sla_days']} days
- In CISA KEV: {scored_vuln['factors']['in_kev']}
- EPSS Score: {scored_vuln['factors']['epss_score']:.3f}
- Known Threat Actors: {scored_vuln['factors']['threat_actors']}

## Asset Context
- Hostname: {scored_vuln['hostname']}
- Asset Multiplier: {scored_vuln['factors']['asset_multiplier']}

Provide:
1. **Immediate Actions** (what to do right now)
2. **Remediation Steps** (detailed fix instructions)
3. **Compensating Controls** (if patching isn't immediately possible)
4. **Verification Steps** (how to confirm the fix)
5. **Risk Acceptance Criteria** (when risk acceptance might be appropriate)

Be specific and actionable."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )

        return {
            'cve_id': vuln.cve_id,
            'recommendations': response.content[0].text,
            'generated_at': datetime.now().isoformat()
        }

# Generate recommendations for top vulnerabilities
advisor = RemediationAdvisor()

for scored in scored_vulns[:3]:
    vuln = next(v for v in vulns if v.cve_id == scored['cve_id'])
    rec = advisor.generate_recommendations(scored, vuln)
    print(f"\n{'='*60}")
    print(f"Recommendations for {rec['cve_id']}")
    print(f"{'='*60}")
    print(rec['recommendations'])
```

### Expected Output
```
============================================================
Recommendations for CVE-2024-3400
============================================================

## 1. Immediate Actions
- **Isolate affected devices**: If possible, temporarily remove Palo Alto firewalls running vulnerable PAN-OS versions from direct internet exposure
- **Enable threat prevention**: Ensure Threat Prevention signatures are updated and enabled
- **Monitor for exploitation**: Check logs for indicators of command injection attempts

## 2. Remediation Steps
1. Identify all Palo Alto devices running PAN-OS 10.2, 11.0, or 11.1
2. Download the appropriate hotfix from Palo Alto support portal
3. Schedule maintenance window (critical - do within 24 hours)
4. Apply hotfix following Palo Alto's upgrade procedures
5. Reboot device if required
6. Verify version after upgrade

## 3. Compensating Controls
If immediate patching isn't possible:
- Disable GlobalProtect gateway/portal features temporarily
- Implement strict IP allowlisting for management interfaces
- Deploy virtual patching via IPS rules
- Increase logging verbosity for affected services

## 4. Verification Steps
- Run `show system info` to confirm patched version
- Review logs for any exploitation attempts during vulnerability window
- Conduct vulnerability scan to confirm remediation
- Test GlobalProtect functionality post-patch

## 5. Risk Acceptance Criteria
Risk acceptance is NOT recommended for this vulnerability because:
- Actively exploited in the wild (CISA KEV)
- Remote code execution with no authentication required
- Edge device with high exposure
- Nation-state threat actors actively targeting
```

---

## Task 6: Reporting Dashboard

### Generating Executive Summary

```python
class VulnerabilityReporter:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def generate_executive_summary(self, scored_vulns: list[dict]) -> str:
        """Generate executive summary of vulnerability posture."""

        # Calculate statistics
        total = len(scored_vulns)
        critical = sum(1 for v in scored_vulns if v['priority'] == 'CRITICAL')
        high = sum(1 for v in scored_vulns if v['priority'] == 'HIGH')
        medium = sum(1 for v in scored_vulns if v['priority'] == 'MEDIUM')
        low = sum(1 for v in scored_vulns if v['priority'] == 'LOW')
        kev_count = sum(1 for v in scored_vulns if v['factors']['in_kev'])

        avg_risk = sum(v['risk_score'] for v in scored_vulns) / total if total else 0

        stats = {
            'total': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'kev_count': kev_count,
            'avg_risk_score': round(avg_risk, 1)
        }

        # Top 5 for executive attention
        top_5 = scored_vulns[:5]

        prompt = f"""Generate an executive summary for this vulnerability report:

## Statistics
- Total Vulnerabilities: {stats['total']}
- Critical: {stats['critical']}
- High: {stats['high']}
- Medium: {stats['medium']}
- Low: {stats['low']}
- In CISA KEV (actively exploited): {stats['kev_count']}
- Average Risk Score: {stats['avg_risk_score']}/100

## Top 5 Vulnerabilities Requiring Immediate Attention
{json.dumps(top_5, indent=2)}

Write a 2-3 paragraph executive summary that:
1. Summarizes the current vulnerability posture
2. Highlights the most urgent risks
3. Provides clear recommendations for leadership
4. Uses non-technical language appropriate for executives"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Generate report
reporter = VulnerabilityReporter()
summary = reporter.generate_executive_summary(scored_vulns)
print(summary)
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Missing asset data | Implement default risk multipliers |
| API rate limits | Cache NVD/EPSS responses |
| Stale threat intel | Schedule regular KEV updates |
| Too many criticals | Adjust scoring thresholds |
| Missing CVSS data | Use EPSS as fallback metric |

---

## Next Steps

- Integrate with ticketing system (Jira, ServiceNow)
- Build automated patching workflows
- Add trend analysis over time
- Create SLA compliance reporting
- Implement vulnerability grouping by root cause

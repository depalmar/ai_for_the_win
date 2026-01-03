# Lab 08: AI-Powered Vulnerability Scanner

Build an intelligent vulnerability scanner that uses AI for assessment and prioritization.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Integrate AI with vulnerability scanning tools
2. Use LLMs for CVE analysis and explanation
3. Build intelligent prioritization systems
4. Generate remediation recommendations
5. Create executive-friendly vulnerability reports

---

## ⏱️ Estimated Time

90-120 minutes (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 04-06
- Understanding of CVEs and CVSS
- Basic networking knowledge

### Required Libraries

```bash
pip install langchain langchain-anthropic requests
pip install python-nmap  # Optional: for live scanning
pip install rich pandas
```

---

## 📖 Background

### AI Enhancement Points

```
Traditional Scanner          AI-Enhanced Scanner
──────────────────          ─────────────────────
CVE ID: CVE-2024-1234  ───► What does this mean for MY environment?
CVSS: 9.8             ───► How likely is exploitation in MY context?
Affected: Apache 2.4  ───► What's the fastest remediation path?
                      ───► What compensating controls can I use?
                      ───► Which vulns should I fix FIRST?
```

### Prioritization Factors

| Factor | Traditional | AI-Enhanced |
|--------|-------------|-------------|
| Severity | CVSS only | CVSS + context |
| Exploitability | EPSS score | Live threat intel |
| Impact | Generic | Asset-specific |
| Remediation | Patch exists Y/N | Effort estimation |

---

## 🔬 Lab Tasks

### Task 1: Vulnerability Data Ingestion (15 min)

```python
class VulnDataLoader:
    """Load vulnerability scan results."""
    
    def load_nessus_csv(self, filepath: str) -> List[dict]:
        """
        Load Nessus scan results.
        
        TODO:
        1. Parse CSV export
        2. Extract key fields (CVE, CVSS, host, port)
        3. Normalize data format
        4. Return vulnerability list
        """
        pass
    
    def load_nuclei_json(self, filepath: str) -> List[dict]:
        """
        Load Nuclei scan results.
        
        TODO:
        1. Parse JSON output
        2. Map severity levels
        3. Extract template info
        4. Return vulnerability list
        """
        pass
    
    def enrich_with_cve_data(self, vulns: List[dict]) -> List[dict]:
        """
        Enrich vulnerabilities with NVD data.
        
        TODO:
        1. Query NVD API for each CVE
        2. Add descriptions, references
        3. Add EPSS scores
        4. Return enriched list
        """
        pass
```

### Task 2: AI Analysis Engine (25 min)

```python
class VulnAnalyzer:
    """AI-powered vulnerability analysis."""
    
    def __init__(self, llm):
        self.llm = llm
    
    def analyze_vulnerability(self, vuln: dict, context: dict) -> dict:
        """
        Deep analysis of a single vulnerability.
        
        Args:
            vuln: Vulnerability data
            context: Environment context (asset type, criticality, etc.)
            
        Returns:
            Analysis including:
            - Plain English explanation
            - Attack scenario
            - Exploitation likelihood
            - Business impact
            - Remediation steps
            
        TODO:
        1. Format vuln data for LLM
        2. Include environment context
        3. Generate comprehensive analysis
        4. Parse structured response
        """
        pass
    
    def assess_exploitability(
        self, 
        vuln: dict, 
        threat_intel: dict = None
    ) -> dict:
        """
        Assess real-world exploitability.
        
        TODO:
        1. Check for public exploits
        2. Analyze attack complexity
        3. Consider threat actor interest
        4. Return exploitability score and rationale
        """
        pass
    
    def generate_remediation_plan(
        self,
        vuln: dict,
        constraints: dict = None
    ) -> dict:
        """
        Generate remediation recommendations.
        
        Args:
            constraints: {"no_downtime": True, "budget": "low", ...}
            
        TODO:
        1. Identify remediation options:
           - Patch
           - Compensating controls
           - Configuration changes
           - Network segmentation
        2. Rank by effectiveness and effort
        3. Provide step-by-step instructions
        """
        pass
```

### Task 3: Intelligent Prioritization (20 min)

```python
class VulnPrioritizer:
    """Prioritize vulnerabilities intelligently."""
    
    def __init__(self, llm, asset_inventory: dict = None):
        self.llm = llm
        self.assets = asset_inventory or {}
    
    def calculate_risk_score(self, vuln: dict, asset: dict) -> float:
        """
        Calculate contextual risk score.
        
        Factors:
        - CVSS base score
        - Asset criticality
        - Exposure (internet-facing?)
        - Compensating controls
        - Threat intel (active exploitation?)
        
        TODO:
        1. Weight each factor
        2. Calculate composite score
        3. Return 0-100 risk score
        """
        pass
    
    def prioritize_vulns(
        self,
        vulns: List[dict],
        strategy: str = "risk_based"
    ) -> List[dict]:
        """
        Prioritize vulnerability list.
        
        Strategies:
        - risk_based: By calculated risk score
        - quick_wins: Easy fixes with high impact
        - critical_first: Critical/High severity first
        - asset_based: By asset importance
        
        TODO:
        1. Calculate scores for each vuln
        2. Apply selected strategy
        3. Return sorted list with explanations
        """
        pass
    
    def create_remediation_roadmap(
        self,
        vulns: List[dict],
        timeline: str = "30_days"
    ) -> dict:
        """
        Create phased remediation plan.
        
        TODO:
        1. Group vulns by priority
        2. Estimate remediation effort
        3. Create weekly/daily plan
        4. Include milestones
        """
        pass
```

### Task 4: Report Generation (20 min)

```python
class VulnReporter:
    """Generate vulnerability reports."""
    
    def __init__(self, llm):
        self.llm = llm
    
    def generate_executive_summary(
        self,
        vulns: List[dict],
        analyses: List[dict]
    ) -> str:
        """
        Generate executive summary.
        
        TODO:
        1. Summarize overall risk posture
        2. Highlight top risks
        3. Provide key recommendations
        4. Use non-technical language
        5. Include metrics and trends
        """
        pass
    
    def generate_technical_report(
        self,
        vulns: List[dict],
        analyses: List[dict]
    ) -> str:
        """
        Generate detailed technical report.
        
        TODO:
        1. List all vulnerabilities
        2. Include technical details
        3. Provide remediation steps
        4. Add verification procedures
        """
        pass
    
    def generate_ticket_content(self, vuln: dict, analysis: dict) -> dict:
        """
        Generate content for ticketing system.
        
        Returns:
            {
                "title": "...",
                "description": "...",
                "priority": "...",
                "assignee_hint": "...",
                "remediation_steps": [...]
            }
        """
        pass
```

### Task 5: Integration Pipeline (15 min)

```python
def scan_and_analyze(
    scan_file: str,
    asset_context: dict,
    output_format: str = "markdown"
) -> str:
    """
    Complete vulnerability assessment pipeline.
    
    TODO:
    1. Load scan results
    2. Enrich with CVE data
    3. Analyze each vulnerability
    4. Prioritize findings
    5. Generate report
    """
    pass
```

---

## 📁 Files

```
lab08-vuln-scanner-ai/
├── README.md
├── starter/
│   ├── main.py
│   ├── loader.py
│   ├── analyzer.py
│   ├── prioritizer.py
│   └── reporter.py
├── solution/
│   └── main.py
├── data/
│   ├── sample_nessus.csv
│   ├── sample_nuclei.json
│   └── asset_inventory.json
└── reports/
    └── sample_report.md
```

---

## 📊 Sample Asset Context

```json
{
    "assets": {
        "web-server-01": {
            "type": "web_server",
            "criticality": "high",
            "data_classification": "confidential",
            "internet_facing": true,
            "owner": "web-team",
            "compensating_controls": ["WAF", "IDS"]
        },
        "db-server-01": {
            "type": "database",
            "criticality": "critical",
            "data_classification": "restricted",
            "internet_facing": false,
            "owner": "dba-team",
            "compensating_controls": ["network_segmentation"]
        }
    }
}
```

---

## 🧪 Sample Output

```markdown
# Vulnerability Assessment Report
Generated: 2024-01-15

## Executive Summary

Your environment has **47 vulnerabilities** across 12 systems.
- **4 Critical** requiring immediate attention
- **12 High** to address within 7 days
- **21 Medium** to address within 30 days

### Top Risks

1. **CVE-2024-1234** on web-server-01 (Risk Score: 95/100)
   - Remote code execution in Apache
   - Internet-facing, actively exploited
   - **Recommended Action**: Patch immediately or enable WAF rule

2. **CVE-2024-5678** on db-server-01 (Risk Score: 88/100)
   - SQL injection in MySQL
   - Contains sensitive data
   - **Recommended Action**: Apply patch during maintenance window

### Remediation Roadmap

**Week 1 (Critical)**
- [ ] Patch Apache on web-server-01
- [ ] Apply MySQL update on db-server-01

**Week 2-3 (High)**
- [ ] Update OpenSSL on all servers
- [ ] Disable SMBv1 on Windows systems
...
```

---

## ✅ Success Criteria

- [ ] Scan results load correctly
- [ ] CVE enrichment works
- [ ] AI analysis provides actionable insights
- [ ] Prioritization considers context
- [ ] Reports are clear and professional
- [ ] Remediation steps are specific

---

## 🚀 Bonus Challenges

1. **Live Scanning**: Integrate with Nmap/Nuclei for real scans
2. **Trend Analysis**: Track vulnerabilities over time
3. **Automation**: Auto-create Jira tickets
4. **Compliance Mapping**: Map to CIS/NIST controls
5. **Attack Path**: Model attack chains between vulns

---

## 📚 Resources

- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [EPSS Model](https://www.first.org/epss/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---

> **Stuck?** See the [Lab 08 Walkthrough](../../docs/walkthroughs/lab08-vuln-scanner-ai-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 09 - Threat Detection Pipeline](../lab09-detection-pipeline/)


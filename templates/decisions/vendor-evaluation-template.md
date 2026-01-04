# AI Security Tool Evaluation Template

A generic framework for evaluating AI-powered security tools. This template provides technical criteria to assess any AI security solution—without recommending specific vendors.

> **Note:** This is an educational self-assessment framework similar to those published by SANS, CISA, and MITRE. It contains no vendor names, comparisons, or rankings.

---

## How to Use This Template

1. **Before evaluating:** Define your specific requirements and success criteria
2. **During evaluation:** Score each criterion (0-3) based on vendor responses and demos
3. **After evaluation:** Weight sections by importance to your organization
4. **Document:** Keep records of your evaluation for compliance and future reference

### Scoring Guide

| Score | Meaning |
|-------|---------|
| 0 | Does not meet requirement |
| 1 | Partially meets requirement |
| 2 | Meets requirement |
| 3 | Exceeds requirement |
| N/A | Not applicable to your use case |

---

## Section 1: Security Capabilities

### 1.1 Core Security Functions

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Addresses your specific use case (triage, detection, analysis, etc.) | | |
| Integrates with your existing security stack | | |
| Supports your data sources (SIEM, EDR, cloud logs, etc.) | | |
| Provides actionable outputs (not just scores) | | |
| Allows customization for your environment | | |

### 1.2 Detection Quality

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Published false positive rates (in similar environments) | | |
| Published false negative rates (critical) | | |
| Detection coverage mapped to MITRE ATT&CK | | |
| Handles novel/unknown threats (not just signatures) | | |
| Performance on your sample data (if tested) | | |

### 1.3 Human-in-the-Loop

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Configurable approval workflows for high-risk actions | | |
| Clear escalation paths to human analysts | | |
| Analyst can override AI decisions | | |
| Feedback mechanism to improve AI over time | | |
| Audit trail of all AI decisions | | |

---

## Section 2: AI/ML Transparency

### 2.1 Explainability

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Explains why decisions were made (not just scores) | | |
| Provides evidence for conclusions | | |
| Confidence levels included with predictions | | |
| Can reconstruct decision logic for audits | | |
| Documentation of model limitations | | |

### 2.2 Model Information

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Discloses AI/ML approach used (ML, LLM, hybrid) | | |
| Training data sources described | | |
| Model update frequency communicated | | |
| Version control for model changes | | |
| Performance metrics provided | | |

### 2.3 LLM-Specific (if applicable)

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Prompt injection defenses documented | | |
| Guardrails against harmful outputs | | |
| Hallucination mitigation strategies | | |
| Jailbreak resistance testing | | |
| Context window limitations disclosed | | |

---

## Section 3: Data Privacy and Security

### 3.1 Data Handling

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Clear documentation of what data is collected | | |
| Data minimization practices | | |
| PII/sensitive data detection and handling | | |
| Data residency options (geographic location) | | |
| Customer data isolation (multi-tenancy) | | |

### 3.2 Data Transmission and Storage

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Encryption in transit (TLS 1.2+) | | |
| Encryption at rest | | |
| Data retention policies documented | | |
| Data deletion capabilities (right to erasure) | | |
| Backup and recovery procedures | | |

### 3.3 Third-Party AI Providers

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Discloses which AI providers are used (if any) | | |
| Data sharing with AI providers documented | | |
| AI provider data retention policies | | |
| Option to use on-premises/private AI | | |
| Contractual protections with AI providers | | |

---

## Section 4: Compliance and Governance

### 4.1 Certifications and Standards

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| SOC 2 Type II certification | | |
| ISO 27001 certification | | |
| FedRAMP authorization (if government) | | |
| HIPAA compliance (if healthcare) | | |
| PCI-DSS compliance (if payment data) | | |

### 4.2 Regulatory Alignment

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| GDPR Article 22 compliance (automated decisions) | | |
| NIST AI RMF alignment | | |
| EU AI Act readiness (high-risk AI) | | |
| Industry-specific requirements met | | |
| Audit support and documentation | | |

### 4.3 Governance Features

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Role-based access control | | |
| Comprehensive audit logging | | |
| Policy enforcement capabilities | | |
| Change management controls | | |
| Incident response documentation | | |

---

## Section 5: Operational Considerations

### 5.1 Integration and Deployment

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| API availability and documentation | | |
| Integration with your SIEM/SOAR | | |
| Deployment options (cloud, on-prem, hybrid) | | |
| Implementation timeline reasonable | | |
| Professional services available | | |

### 5.2 Reliability and Performance

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Published SLA (uptime guarantee) | | |
| Performance at your scale | | |
| Latency acceptable for your use case | | |
| Graceful degradation during outages | | |
| Disaster recovery capabilities | | |

### 5.3 Maintenance and Support

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Support availability (24/7, business hours) | | |
| Response time SLAs | | |
| Documentation quality | | |
| Training resources available | | |
| Community or user forums | | |

---

## Section 6: Cost and Scalability

### 6.1 Pricing Model

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Pricing model clearly documented | | |
| Costs predictable at your scale | | |
| No hidden fees (overage, support, etc.) | | |
| Free trial or POC available | | |
| Flexible contract terms | | |

### 6.2 Scalability

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Can handle your current volume | | |
| Can scale to 2-3x current volume | | |
| Pricing scales reasonably | | |
| Performance maintained at scale | | |
| Multi-region support (if needed) | | |

### 6.3 Total Cost of Ownership

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Implementation costs reasonable | | |
| Training costs included or reasonable | | |
| Ongoing maintenance costs clear | | |
| Integration costs estimated | | |
| Exit costs understood (data export, etc.) | | |

---

## Section 7: AI-Specific Security Risks

### 7.1 Attack Surface Assessment

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Prompt injection defenses (for LLM-based tools) | | |
| Adversarial input handling | | |
| Model extraction protections | | |
| Training data poisoning safeguards | | |
| Rate limiting and abuse prevention | | |

### 7.2 Failure Modes

| Criterion | Score (0-3) | Notes |
|-----------|-------------|-------|
| Behavior during AI model failures documented | | |
| Fallback mechanisms when AI unavailable | | |
| Alerting for AI anomalies | | |
| Recovery procedures documented | | |
| Incident response for AI-specific attacks | | |

---

## Evaluation Summary

### Section Scores

| Section | Raw Score | Max Score | Percentage | Weight | Weighted Score |
|---------|-----------|-----------|------------|--------|----------------|
| 1. Security Capabilities | | | | | |
| 2. AI/ML Transparency | | | | | |
| 3. Data Privacy and Security | | | | | |
| 4. Compliance and Governance | | | | | |
| 5. Operational Considerations | | | | | |
| 6. Cost and Scalability | | | | | |
| 7. AI-Specific Security Risks | | | | | |
| **TOTAL** | | | | | |

### Critical Requirements (Must-Have)

List any criteria that are non-negotiable for your organization:

1. _________________________________________________
2. _________________________________________________
3. _________________________________________________
4. _________________________________________________
5. _________________________________________________

### Strengths Identified

- 
- 
- 

### Concerns or Gaps

- 
- 
- 

### Questions for Follow-Up

- 
- 
- 

---

## Evaluation Metadata

| Field | Value |
|-------|-------|
| Evaluation Date | |
| Evaluator(s) | |
| Solution Evaluated | |
| Version/Release Evaluated | |
| Use Case Being Assessed | |
| Evaluation Method | Demo / POC / Documentation Review / Interview |

---

## References

This template aligns with:

- [NIST AI Risk Management Framework (AI RMF)](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP LLM Top 10](https://owasp.org/www-project-llm-security/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [ISO/IEC 42001 AI Management System](https://www.iso.org/standard/81230.html)

---

*This template is part of the [AI for the Win](../../README.md) training program. It is provided for educational purposes and should be customized for your organization's specific needs.*

*Last updated: January 2026*

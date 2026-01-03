# Lab 00d Walkthrough: AI in Security Operations

## Overview

This walkthrough helps you understand where AI fits in security operations, its limitations, and responsible deployment. No API keys required.

**Time to complete:** 45-60 minutes

---

## Exercise 1: AI Suitability Assessment

### When AI Works Well

AI excels at tasks that are:

| Characteristic | Example |
|----------------|---------|
| **High volume** | 10,000 alerts/day |
| **Pattern-based** | Malware clustering |
| **Repetitive** | IOC extraction |
| **Well-defined** | Binary classification |

### When AI Struggles

AI struggles with tasks that require:

| Characteristic | Example |
|----------------|---------|
| **Context** | "Should we notify the CEO?" |
| **Judgment** | "Is this violation intentional?" |
| **Accountability** | "Who approved this action?" |
| **Novelty** | Zero-day attack patterns |

### Decision Framework

```
                    High Volume?
                    /          \
                  YES          NO
                  /              \
        Pattern-based?      Human does it
        /           \
      YES           NO
      /               \
  AI Suitable    Needs Human
```

### Exercise Examples

| Task | AI Suitable? | Why |
|------|--------------|-----|
| Review 5,000 daily firewall alerts | ✅ Yes | High volume, pattern-based |
| Decide to notify CEO about breach | ❌ No | Requires organizational context |
| Cluster malware by behavior | ✅ Yes | Pattern recognition at scale |
| Approve emergency network isolation | ❌ No | High-stakes, needs human judgment |

---

## Exercise 2: AI Security Risks

### Risk Categories

#### 1. Model Limitations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **False negatives** | Missed attacks | Defense in depth, human review |
| **False positives** | Alert fatigue | Tuning, confidence thresholds |
| **Concept drift** | Degraded accuracy | Regular retraining, monitoring |

#### 2. Adversarial Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Evasion** | Attackers bypass detection | Ensemble models, signatures |
| **Poisoning** | Corrupted training data | Data validation, provenance |
| **Model theft** | Attackers learn weaknesses | Access controls, rate limiting |

#### 3. Operational Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Over-reliance** | Skills atrophy | Regular manual exercises |
| **Lack of explainability** | Can't justify decisions | Interpretable models, audit logs |
| **Bias** | Unfair outcomes | Diverse training data, testing |

### Exercise Scenarios

**Scenario**: LLM-based alert summarizer hallucinates IOCs

```
Risks:
├── Analysts waste time on fake IOCs
├── Wrong containment actions taken
└── Trust in AI tools erodes

Mitigations:
├── Human verification for all IOCs
├── Cross-reference with raw data
└── Confidence thresholds for automation
```

---

## Exercise 3: Human-in-the-Loop

### Decision Matrix

```
                    REVERSIBLE?
                   YES        NO
              ┌─────────┬─────────┐
    LOW       │ Auto    │ Auto +  │
    IMPACT    │ OK      │ Log     │
              ├─────────┼─────────┤
    HIGH      │ Human   │ Human   │
    IMPACT    │ Approve │ Required│
              └─────────┴─────────┘
```

### Action Classification

| Action | Human Required? | Reasoning |
|--------|-----------------|-----------|
| Block C2 IP | Depends | OK if on blocklist, human for infrastructure IPs |
| Isolate endpoint | Yes | Business impact, could be false positive |
| Add detection rule | Yes | Could cause false positives |
| Send Slack alert | No | Informational only |
| Disable user account | Yes | Impacts user, needs verification |

### Implementing HITL

```python
def handle_alert(alert, ai_assessment):
    if ai_assessment.confidence > 0.95 and alert.reversible:
        # High confidence, reversible → auto-action
        execute_action(alert.recommended_action)
        log_action(alert, "auto")
    else:
        # Low confidence or irreversible → human review
        queue_for_review(alert, ai_assessment)
        notify_analyst(alert.priority)
```

---

## Exercise 4: AI Integration Design

### SOC Alert Triage System

**Challenge**: 10,000 alerts/day, 5 analysts, 8 hours each

```
Without AI:
  10,000 alerts ÷ 40 analyst-hours = 250 alerts/hour
  = 4.2 alerts/minute = 14 seconds/alert
  
  Result: Superficial triage, missed threats

With AI:
  AI triages 95% → 500 alerts for human review
  500 alerts ÷ 40 hours = 12.5 alerts/hour
  = 4.8 minutes/alert
  
  Result: Deep investigation of real threats
```

### Design Questions

#### 1. What type of AI?

| Approach | Pros | Cons |
|----------|------|------|
| ML Classification | Fast, consistent | Needs labeled data |
| LLM Analysis | Flexible, explainable | Slower, costs money |
| Rules + ML Hybrid | Best of both | Complex to maintain |

#### 2. What training data?

- 6+ months of historical alerts
- Analyst disposition labels
- Alert metadata and enrichments
- True/false positive outcomes

#### 3. How to validate?

```
Validation Strategy:
├── Holdout test set (20% of data)
├── A/B testing (AI vs human baseline)
├── Human review of AI decisions (sampling)
└── Metric monitoring (precision, recall, drift)
```

#### 4. What needs human approval?

```
Auto-allowed:
├── Priority scoring
├── Alert enrichment
├── Slack notifications
└── Ticket creation

Human required:
├── Containment actions
├── Account disabling
├── Executive notifications
└── Critical system changes
```

---

## Quick Reference Card

### AI in Security: Decision Guide

```
┌─────────────────────────────────────────────────────┐
│  GOOD FOR AI               │  NEEDS HUMANS          │
├─────────────────────────────────────────────────────┤
│  ✓ High volume triage      │  ✗ Executive decisions │
│  ✓ Pattern matching        │  ✗ Legal/compliance    │
│  ✓ IOC extraction          │  ✗ Containment actions │
│  ✓ Alert enrichment        │  ✗ Customer comms      │
│  ✓ Log summarization       │  ✗ Root cause analysis │
│  ✓ Threat intel parsing    │  ✗ Policy exceptions   │
└─────────────────────────────────────────────────────┘
```

### Risk Mitigation Checklist

- [ ] Human review for high-impact actions
- [ ] Confidence thresholds for automation
- [ ] Regular model retraining schedule
- [ ] Adversarial testing program
- [ ] Explainability for audit trail
- [ ] Fallback procedures if AI fails
- [ ] Skills maintenance for analysts

---

## Key Takeaways

1. **AI augments, doesn't replace** - Humans stay in the loop
2. **Match AI to the task** - Volume + patterns = good fit
3. **Plan for failure** - AI will make mistakes
4. **Validate continuously** - Models drift over time
5. **Maintain accountability** - Humans own decisions
6. **Provider choice is flexible** - All labs work with Claude, GPT-4, Gemini, or local models

---

## Next Steps

Continue to:
- [Lab 01: Phishing Classifier](./lab01-walkthrough.md) - Build your first ML model
- [Lab 04: LLM Log Analysis](./lab04-walkthrough.md) - Apply LLMs to security
- [Lab 10: IR Copilot](./lab10-walkthrough.md) - Build an AI assistant

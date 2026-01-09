# AI for Security Leaders: Quick Reference Guide

A concise guide for security managers and executives who need to understand AI capabilities, make informed investment decisions, and lead AI-enabled security teams—without becoming ML engineers.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What AI Can and Cannot Do in Security](#what-ai-can-and-cannot-do-in-security)
3. [Decision Framework: When to Invest in AI](#decision-framework-when-to-invest-in-ai)
4. [Questions to Ask Before Implementing AI](#questions-to-ask-before-implementing-ai)
5. [Key Metrics for AI Security Programs](#key-metrics-for-ai-security-programs)
6. [Risk Considerations](#risk-considerations)
7. [Building AI-Ready Teams](#building-ai-ready-teams)
8. [Resources for Deeper Learning](#resources-for-deeper-learning)

---

## Executive Summary

### The One-Page Version

**What AI is good at in security:**

- Processing high volumes of alerts faster than humans
- Finding patterns in large datasets (logs, network traffic)
- Extracting structured data from unstructured text (IOCs from reports)
- Summarizing and explaining technical findings
- Suggesting investigation steps based on patterns

**What AI is NOT good at (yet):**

- Making high-stakes containment decisions autonomously
- Understanding your specific business context
- Replacing human judgment on novel threats
- Guaranteeing zero false positives/negatives
- Operating without oversight

**The key principle:** AI handles volume; humans provide judgment.

### Quick Decision Framework

```
Should you invest in AI for security?

┌─────────────────────────────────────────────────────────────────┐
│ START: What problem are you solving?                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ "Too many alerts"                                               │
│   └─► Have you tuned detection rules first?                     │
│       ├─► No → Do that first (cheaper, faster impact)           │
│       └─► Yes, still drowning → AI triage may help              │
│                                                                 │
│ "Investigations take too long"                                  │
│   └─► Is it a tooling problem or volume problem?                │
│       ├─► Tooling → Better SOAR/queries may help first          │
│       └─► Volume → AI enrichment may help                       │
│                                                                 │
│ "We're missing threats"                                         │
│   └─► Is it a visibility gap or analysis gap?                   │
│       ├─► Visibility → Fix logging/coverage first               │
│       └─► Analysis → ML anomaly detection may help              │
│                                                                 │
│ "Our team is burned out"                                        │
│   └─► Is it alert volume or organizational factors?             │
│       ├─► Organizational → Address shifts, scope, priorities    │
│       └─► Volume → AI triage may reduce toil                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## What AI Can and Cannot Do in Security

### Realistic Expectations by Task

| Security Task                   | AI Suitability | Notes                                                     |
| ------------------------------- | -------------- | --------------------------------------------------------- |
| **Alert triage**                | High           | Pattern matching at scale, but sample human review needed |
| **Log correlation**             | High           | Finding connections in large datasets                     |
| **IOC extraction**              | High           | Parsing unstructured text into structured data            |
| **Threat report summarization** | High           | Natural language understanding                            |
| **Threat hunting hypothesis**   | Medium         | Can suggest, but needs human validation                   |
| **Incident investigation**      | Medium         | Assists but doesn't replace analyst judgment              |
| **Malware classification**      | Medium-High    | Good for known families, weaker on novel samples          |
| **Containment decisions**       | Low            | High stakes, business impact requires human approval      |
| **Executive communication**     | Low            | Requires organizational context humans provide            |
| **Legal/compliance decisions**  | Low            | Human accountability required                             |

### ML vs LLM: When to Use Each

| Approach                                            | Best For                                         | Cost                    | Speed        |
| --------------------------------------------------- | ------------------------------------------------ | ----------------------- | ------------ |
| **Traditional ML** (classifiers, anomaly detection) | High-volume structured data, real-time detection | Very low per prediction | Milliseconds |
| **Large Language Models** (GPT, Claude)             | Unstructured text, reasoning, generation         | Higher per prediction   | Seconds      |
| **Hybrid** (ML filter → LLM analysis)               | Production pipelines, cost optimization          | Optimized               | Varies       |

**Rule of thumb:** Use ML for volume, LLM for depth.

---

## Decision Framework: When to Invest in AI

### Prerequisites Checklist

Before investing in AI, ensure these foundations are in place:

- [ ] **Asset inventory** is reasonably complete
- [ ] **Logging coverage** meets your visibility needs
- [ ] **Detection rules** are tuned (not generating excessive false positives)
- [ ] **Incident response processes** are documented
- [ ] **Team has bandwidth** to implement and maintain AI tools
- [ ] **Budget exists** for ongoing API costs or infrastructure

### Investment Decision Matrix

| Your Situation                      | Recommendation                        |
| ----------------------------------- | ------------------------------------- |
| Foundations incomplete              | Address fundamentals first            |
| Small team (1-3), manageable volume | Start with LLM for enrichment only    |
| Medium team (4-10), high volume     | Consider ML triage + LLM analysis     |
| Large team (10+), enterprise scale  | Full pipeline with checkpoints        |
| Sensitive/classified data           | Evaluate local/on-premise models      |
| Limited budget                      | Use free tiers, local models (Ollama) |

### Build vs Buy Considerations

| Factor                 | Build In-House         | Buy/SaaS                  |
| ---------------------- | ---------------------- | ------------------------- |
| **Customization**      | Full control           | Limited to vendor options |
| **Time to value**      | Months                 | Days to weeks             |
| **Maintenance**        | Your responsibility    | Vendor responsibility     |
| **Data privacy**       | You control            | Review vendor policies    |
| **Cost (initial)**     | Lower (API costs)      | Higher (licensing)        |
| **Cost (ongoing)**     | API + engineering time | Subscription              |
| **Expertise required** | ML/AI skills needed    | Less technical            |

---

## Questions to Ask Before Implementing AI

### Questions for Your Team

1. **What specific problem will AI solve?** (Be precise, not "improve security")
2. **How will we measure success?** (Define metrics before implementation)
3. **What happens when AI is wrong?** (False positives and false negatives)
4. **Who reviews AI decisions?** (Human-in-the-loop requirements)
5. **How will we maintain this?** (Models degrade, prompts need tuning)
6. **What's our rollback plan?** (If AI fails, how do we operate?)

### Questions for Vendors

1. **What data do you send to AI providers?** (Privacy implications)
2. **How is the model trained?** (On whose data? How often updated?)
3. **What are the false positive/negative rates?** (In environments like ours)
4. **How does pricing scale?** (Per alert, per user, per endpoint?)
5. **What happens during AI outages?** (Failover capabilities)
6. **How do you handle prompt injection attacks?** (LLM security)
7. **What compliance certifications do you have?** (SOC 2, ISO 27001, etc.)

### Questions for Yourself

1. **Am I solving a real problem or chasing a trend?**
2. **Have I tried simpler solutions first?**
3. **Does my team have capacity to implement this well?**
4. **What's the cost of getting this wrong?**

---

## Key Metrics for AI Security Programs

### Operational Metrics

| Metric                         | What It Measures                         | Target Direction       |
| ------------------------------ | ---------------------------------------- | ---------------------- |
| **Mean Time to Triage (MTTT)** | How fast alerts are initially assessed   | Decrease               |
| **Alert-to-Analyst Ratio**     | Volume per analyst after AI filtering    | Decrease               |
| **False Positive Rate**        | Alerts incorrectly flagged as threats    | Decrease               |
| **False Negative Rate**        | Real threats missed by AI                | Minimize (critical)    |
| **Auto-close Rate**            | Alerts closed without human review       | Monitor (not maximize) |
| **Escalation Accuracy**        | % of escalations that are true positives | Increase               |

### Quality Metrics

| Metric                       | What It Measures                    | Target Direction     |
| ---------------------------- | ----------------------------------- | -------------------- |
| **Human Override Rate**      | How often analysts disagree with AI | Monitor trends       |
| **Time Savings per Analyst** | Hours saved on routine tasks        | Increase             |
| **Investigation Depth**      | Evidence collected per incident     | Maintain or increase |
| **Detection Coverage**       | % of attack techniques detectable   | Increase             |

### Warning Signs

- **Auto-close rate increasing without validation** → May be missing threats
- **Human override rate very low** → Analysts may be rubber-stamping AI
- **Human override rate very high** → AI may not be well-tuned
- **False negative rate unknown** → You're flying blind

---

## Risk Considerations

### AI-Specific Risks

| Risk                   | Description                                | Mitigation                      |
| ---------------------- | ------------------------------------------ | ------------------------------- |
| **Prompt injection**   | Attackers manipulate AI via crafted inputs | Input validation, sandboxing    |
| **Data leakage**       | Sensitive data sent to AI providers        | Data minimization, local models |
| **Model manipulation** | Adversarial inputs evade detection         | Ensemble models, human review   |
| **Over-reliance**      | Analysts stop thinking critically          | Maintain human oversight        |
| **Vendor lock-in**     | Dependency on single AI provider           | Multi-provider strategy         |
| **Cost overruns**      | API costs exceed budget                    | Usage monitoring, limits        |

### Compliance Considerations

| Regulation      | AI Implications                                             |
| --------------- | ----------------------------------------------------------- |
| **GDPR**        | Right to explanation (Art. 22), data processing limits      |
| **HIPAA**       | PHI in prompts requires BAAs with AI providers              |
| **PCI-DSS**     | Cardholder data handling, audit requirements                |
| **SOX**         | Explainability for AI-assisted financial security decisions |
| **EU AI Act**   | High-risk AI classification, transparency requirements      |
| **NIST AI RMF** | Voluntary risk management framework                         |

---

## Building AI-Ready Teams

### Skills to Develop

| Skill                   | Who Needs It                 | How to Develop              |
| ----------------------- | ---------------------------- | --------------------------- |
| **Prompt engineering**  | All analysts                 | Labs 02, 04 in this course |
| **ML fundamentals**     | Senior analysts, engineers   | Labs 04, 01-03             |
| **AI tool evaluation**  | Managers, architects         | Lab 05, this guide         |
| **AI security testing** | Red team, security engineers | Labs 17, 20                 |

### Team Structure Considerations

- **Don't create an "AI team" in isolation** — Integrate AI skills across existing roles
- **Designate AI champions** — 1-2 people who stay current on AI developments
- **Maintain traditional skills** — AI augments, doesn't replace, security fundamentals
- **Plan for maintenance** — Someone needs to own prompt tuning, model monitoring

### Change Management

1. **Start small** — Pilot with one use case, one team
2. **Measure before and after** — Establish baseline metrics
3. **Get analyst buy-in** — They're the users, involve them early
4. **Communicate wins and failures** — Build trust through transparency
5. **Iterate** — AI implementations improve with feedback

---

## Resources for Deeper Learning

### In This Course

| Resource                                                                            | What You'll Learn                | Time      |
| ----------------------------------------------------------------------------------- | -------------------------------- | --------- |
| [Lab 05: AI in Security Operations](../../labs/lab05-ai-in-security-operations/)  | Comprehensive strategic overview | 1-2 hours |
| [Lab 04: ML Concepts Primer](../../labs/lab04-ml-concepts-primer/)                | What ML can/can't do             | 1-2 hours |
| [Lab 02: Intro to Prompt Engineering](../../labs/lab02-intro-prompt-engineering/) | How LLMs work                    | 1-2 hours |
| [Lab 04: LLM Log Analysis](../../labs/lab15-llm-log-analysis/)                      | Hands-on LLM experience          | 2-3 hours |
| [Security Compliance Guide](./security-compliance-guide.md)                         | SOC 2, GDPR, NIST mapping        | Reference |
| [Cost Management Guide](./cost-management.md)                                       | Budget planning                  | Reference |

### External Resources

**Frameworks and Standards:**

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — Voluntary AI risk management
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial ML threat framework
- [OWASP LLM Top 10](https://owasp.org/www-project-llm-security/) — LLM security risks

**Industry Reports:**

- SANS Detection & Response Survey (annual) — SOC challenges and trends
- Gartner Hype Cycle for Security Operations — Technology maturity assessment
- Splunk State of Security Report — Practitioner insights

**Books for Leaders:**

- "AI-Powered Cybersecurity" by Dr. Raef Meeuwisse — Strategic overview
- "The CISO's Guide to AI" — Executive-level AI security strategy

---

## Quick Reference Card

### AI Investment Readiness Checklist

```
□ Clear problem statement (not "use AI")
□ Baseline metrics established
□ Foundations in place (logging, detection tuning, processes)
□ Team capacity for implementation and maintenance
□ Budget for ongoing costs (API, infrastructure, training)
□ Human-in-the-loop requirements defined
□ Rollback plan if AI fails
□ Compliance requirements understood
```

### Red Flags When Evaluating AI Solutions

- Promises to "eliminate" false positives or "guarantee" detection
- No discussion of human oversight requirements
- Vague about data handling and privacy
- Can't explain how the AI works at a high level
- No metrics on false negative rates
- Pricing that scales unpredictably

### Golden Rules for Security AI

1. **AI augments humans, doesn't replace them**
2. **Start with clear problems, not cool technology**
3. **Measure before and after, or you're guessing**
4. **Human oversight scales with decision impact**
5. **Models degrade — plan for maintenance**
6. **Simpler solutions may work better**

---

## Next Steps

1. **Assess your readiness** using the checklist above
2. **Complete Lab 05** for a deeper strategic understanding
3. **Try Lab 04** for hands-on LLM experience (2-3 hours)
4. **Evaluate one specific use case** using the decision framework
5. **Pilot small**, measure results, then expand

---

_This guide is part of the [AI for the Win](../../README.md) training program — a hands-on course for security practitioners building AI-powered tools._

_Last updated: January 2026_

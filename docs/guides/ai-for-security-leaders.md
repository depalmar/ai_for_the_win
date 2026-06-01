# AI for Security Leaders: Quick Reference Guide

A concise guide for security managers and executives who need to understand AI capabilities, make informed investment decisions, and lead AI-enabled security teams—without becoming ML engineers.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What AI Can and Cannot Do in Security](#what-ai-can-and-cannot-do-in-security)
3. [AI in Practice: Example Scenarios](#ai-in-practice-example-scenarios)
4. [Decision Framework: When to Invest in AI](#decision-framework-when-to-invest-in-ai)
5. [Questions to Ask Before Implementing AI](#questions-to-ask-before-implementing-ai)
6. [Key Metrics for AI Security Programs](#key-metrics-for-ai-security-programs)
7. [Risk Considerations](#risk-considerations)
8. [Securing Your Organization's AI Use](#securing-your-organizations-ai-use)
9. [Building AI-Ready Teams](#building-ai-ready-teams)
10. [Resources for Deeper Learning](#resources-for-deeper-learning)

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

### By the Numbers (2022–2026)

The case for (and against) AI in the SOC is now measurable. A few data points worth bringing to a budget conversation:

| The problem AI targets | The reported payoff |
| --- | --- |
| SOC teams field **~960 alerts/day at typical orgs, 3,000+ at large enterprises**¹; orgs average **2,992 alerts/day and still leave ~63% unaddressed**.² | **60% of AI adopters** cut investigation time by **≥25%**; 21% cut it by **>50%**.³ |
| False positives are the **#1 detection challenge** — SANS 2025 found **73%** rank them top, and 60%+ hit them frequently.⁴ | Orgs using AI + automation **extensively** saved **$1.9M per breach** and shortened the breach lifecycle by **80 days**.⁵ |
| **71% of SOC analysts** report some burnout; **64%** say they're likely to switch jobs within a year.⁶ | Global average breach cost **fell to $4.44M** in 2025 (from $4.88M), driven by faster AI-assisted containment — though the **U.S. average rose to a record $10.22M**.⁵ |

> **Read these as direction, not guarantees.** Figures span 2022–2026 and several are vendor-sponsored surveys with differing methodologies — the burnout numbers (⁶) are from a 2022 survey of 468 analysts and may understate or overstate today. The same reports show AI without governance creates *new* costs — see [Securing Your Organization's AI Use](#securing-your-organizations-ai-use). Full sources under [Resources](#resources-for-deeper-learning).

### Quick Decision Framework

Start from the problem, not the technology. Green = AI may genuinely help; amber = fix the cheaper fundamental first.

```mermaid
flowchart TD
    START["What problem<br/>are you solving?"]
    START --> A["Too many alerts"]
    START --> B["Investigations<br/>take too long"]
    START --> C["We're missing<br/>threats"]
    START --> D["Team is<br/>burned out"]

    A --> A1{"Detection rules<br/>tuned first?"}
    A1 -->|No| A2["Do that first<br/>(cheaper, faster)"]
    A1 -->|"Yes, still drowning"| A3["AI triage<br/>may help"]

    B --> B1{"Tooling or<br/>volume problem?"}
    B1 -->|Tooling| B2["Better SOAR /<br/>queries first"]
    B1 -->|Volume| B3["AI enrichment<br/>may help"]

    C --> C1{"Visibility gap or<br/>analysis gap?"}
    C1 -->|Visibility| C2["Fix logging /<br/>coverage first"]
    C1 -->|Analysis| C3["ML anomaly<br/>detection may help"]

    D --> D1{"Alert volume or<br/>org factors?"}
    D1 -->|Organizational| D2["Address shifts,<br/>scope, priorities"]
    D1 -->|Volume| D3["AI triage<br/>may reduce toil"]

    classDef ai fill:#bbf7d0,stroke:#15803d,color:#0f172a;
    classDef first fill:#fde68a,stroke:#b45309,color:#0f172a;
    class A3,B3,C3,D3 ai;
    class A2,B2,C2,D2 first;
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

The same table, plotted by **how much volume** the task involves versus **how much human judgment** the decision carries. The top-right is where AI pays off first; the bottom is where a human stays accountable:

```mermaid
quadrantChart
    title AI Suitability in Security Operations
    x-axis "Low Volume" --> "High Volume"
    y-axis "High-Stakes Judgment" --> "Routine Pattern Work"
    quadrant-1 "Automate (AI-led)"
    quadrant-2 "Human-led"
    quadrant-3 "Human decides"
    quadrant-4 "AI assists, human approves"
    "Alert triage": [0.85, 0.85]
    "Log correlation": [0.8, 0.78]
    "IOC extraction": [0.72, 0.9]
    "Report summary": [0.6, 0.82]
    "Malware classification": [0.65, 0.6]
    "Threat hunting": [0.45, 0.55]
    "Incident investigation": [0.5, 0.4]
    "Containment": [0.4, 0.12]
    "Exec communication": [0.25, 0.18]
    "Legal/compliance": [0.2, 0.1]
```

### ML vs LLM: When to Use Each

| Approach                                            | Best For                                         | Cost                    | Speed        |
| --------------------------------------------------- | ------------------------------------------------ | ----------------------- | ------------ |
| **Traditional ML** (classifiers, anomaly detection) | High-volume structured data, real-time detection | Very low per prediction | Milliseconds |
| **Large Language Models** (Claude, GPT, Gemini)     | Unstructured text, reasoning, generation         | Higher per prediction   | Seconds      |
| **Hybrid** (ML filter → LLM analysis)               | Production pipelines, cost optimization          | Optimized               | Varies       |

**Rule of thumb:** Use ML for volume, LLM for depth.

---

## AI in Practice: Example Scenarios

Frameworks are abstract; these short scenarios show what the principles look like on a real team. Each maps to a hands-on lab or command in this course so your analysts can try it.

### 1. The hybrid triage pipeline (the "AI handles volume" pattern)

A mid-size SOC drowning in ~2,500 alerts/day puts a cheap ML classifier in front of an LLM:

1. **ML filter** scores every alert in milliseconds and auto-suppresses the obvious noise (e.g., known-benign scanner traffic), cutting volume ~70%.
2. **LLM enrichment** takes the survivors, pulls in asset context and threat intel, and drafts a plain-language summary plus suggested next steps.
3. **Analyst** reviews only the enriched, prioritized queue and owns the decision to escalate or close.

*Why it works:* each layer does what it's cheapest at. *Watch:* track the ML layer's false-negative rate — suppression is where real threats get silently lost. → *Try it: [Lab 23: Detection Pipeline](../../labs/lab23-detection-pipeline/), [Lab 13: ML vs LLM](../../labs/lab13-ml-vs-llm/).*

### 2. Turning a threat report into action (the "extract structure from text" pattern)

An analyst pastes a 20-page threat-intel PDF into an LLM-backed workflow and gets back a clean table of IOCs (IPs, domains, hashes), mapped MITRE ATT&CK techniques, and a one-paragraph "does this affect us?" summary checked against the asset inventory — in minutes instead of an afternoon. → *Try it: `/ioc-extractor` and `/threat-intel`, [Lab 16: Threat Intel Agent](../../labs/lab16-threat-intel-agent/).*

### 3. A cautionary tale (when oversight slips)

A team proud of its rising auto-close rate quietly stopped sampling closed alerts. Three months later, an incident traced back to a category the model had been auto-closing with high confidence — the alerts were real, the model was wrong, and no human ever looked. The fix wasn't "less AI"; it was restoring a small **random human-review sample** of auto-closed alerts and watching the false-negative rate. *This is exactly the failure the [Warning Signs](#warning-signs) and metrics below are designed to catch.*

---

## Decision Framework: When to Invest in AI

Most organizations don't decide "AI or not" once — they move along a maturity curve. As of 2025, ~**87% of orgs** are somewhere on this path; the rough distribution looks like this (Gurucul, *Pulse of the AI SOC 2025*, n=739). The three buckets sum to that 87% — the remaining ~13% are **not adopting at all** (not "mature"). Use it to locate yourself and set a realistic next step rather than skipping ahead:

```mermaid
flowchart LR
    A["Evaluating<br/>use cases<br/>~22%"] --> B["Targeted<br/>pilots<br/>~34%"]
    B --> C["AI across<br/>multiple workflows<br/>~31%"]
    C -.-> D["Measured ROI<br/>+ governance<br/>(your goal)"]
    style A fill:#e2e8f0,stroke:#475569,color:#0f172a
    style B fill:#bfdbfe,stroke:#1d4ed8,color:#0f172a
    style C fill:#bbf7d0,stroke:#15803d,color:#0f172a
    style D fill:#fde68a,stroke:#b45309,color:#0f172a,stroke-dasharray: 4 3
```

*(The dashed final state is the operating goal, not a bucket Gurucul measures.)*

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

> **Don't overlook local / open-source models.** For sensitive, regulated, or air-gapped environments, self-hosted open-weight families (Llama, Mistral, Qwen, DeepSeek — run via Ollama, vLLM, etc.) keep data entirely inside your boundary — no prompts leave the network, sidestepping much of the data-leakage and shadow-AI risk discussed later. The trade-off is that *you* own the GPUs, updates, and tuning. This course's labs are provider-agnostic and run against local models, so teams can prototype without sending a single byte to an external API.

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

### What It Actually Costs (a worked example)

Leaders ask "how much?" and get vague answers. Here's an order-of-magnitude model for **LLM-based alert triage**. Plug in *current* provider prices — they change often, so treat the rates below as illustrative, not quotes. (See the [Cost Management Guide](./cost-management.md) for live numbers.)

Assume **2,500 alerts/day** and a triage prompt of roughly **3K input + 500 output tokens** each.

| Approach | Tokens/day (rough) | Illustrative monthly cost\* | Notes |
| --- | --- | --- | --- |
| **LLM on every alert** | ~7.5M in / 1.25M out | **$$$** | Simplest, but you pay to read noise |
| **Hybrid: ML filter → LLM** | ~2.25M in / 0.38M out (after ~70% filtered) | **~⅓ of above** | The ML pre-filter is near-free per prediction |
| **Local / open-source model** | n/a (self-hosted) | Infra + ops time, no per-token fee | Best for sensitive data; you own the GPUs and tuning |

\* *Multiply your tokens by the model's per-million input/output price. A cheaper mid-tier model can be 10–20× less than a frontier model for the same volume — so **routing easy alerts to a small model and only escalating hard ones to a frontier model** is often the biggest single cost lever.*

**The leadership takeaway:** the dominant cost driver isn't the model's sticker price — it's **how many tokens you send and which model you send them to.** Filter first, route by difficulty, and reserve frontier models for the hard cases. Don't forget the *non-token* costs: engineering time, prompt/eval maintenance, and monitoring.

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
| **Model deprecation / drift** | Providers retire models or change behavior on upgrade, silently shifting detection quality | Pin versions; re-run eval suite before adopting a new model; track provider deprecation notices |
| **Cost overruns**      | API costs exceed budget                    | Usage monitoring, limits        |

### Compliance Considerations

| Regulation      | AI Implications                                             |
| --------------- | ----------------------------------------------------------- |
| **GDPR**        | Restrictions on solely automated decision-making (Art. 22), with related transparency/"logic involved" obligations under Arts. 13–15; data-processing limits |
| **HIPAA**       | PHI in prompts requires BAAs with AI providers              |
| **PCI-DSS**     | Cardholder data handling, audit requirements                |
| **SOX**         | Explainability for AI-assisted financial security decisions |
| **EU AI Act**   | Risk-tiered obligations on a phased calendar (see below); high-risk systems require risk management, human oversight, logging, transparency, and cybersecurity |
| **NIST AI RMF** | Voluntary framework; the **Generative AI Profile (NIST AI 600-1, July 2024)** adds 12 GenAI-specific risk categories |

**EU AI Act — the dates a security leader actually needs.** Obligations phase in over several years. A "Digital Omnibus" proposed in Nov 2025 would defer the high-risk deadline; the Parliament and Council reached **provisional political agreement on 7 May 2026**, but until it is **formally adopted** (expected before Aug 2026) the original **2 Aug 2026** date remains binding law — keep preparing against it. Confirm specifics with counsel:

```mermaid
timeline
    title EU AI Act Key Dates for Security Leaders
    Feb 2025 : Prohibited "unacceptable risk" systems banned
    Aug 2025 : General-purpose AI (GPAI) obligations apply
    Aug 2026 : High-risk (Annex III) obligations apply — unless deferred
    Dec 2027 : New high-risk date IF Omnibus is adopted (provisional, May 2026; 2028 for embedded systems)
```

---

## Securing Your Organization's AI Use

Most of this guide is about **AI the SOC uses**. But by 2025 every security leader has a second mandate: **governing the AI the rest of the organization is already using** — often without telling you. This is now a measurable source of breach cost, not a hypothetical.

### Why this is on your desk now

From IBM's *Cost of a Data Breach 2025*:

- **1 in 5 organizations** reported a breach traced to **shadow AI** (unsanctioned AI tools), adding ~**$670K** to the average breach cost.
- **13% of organizations** reported a breach of their **own AI models or applications** — and **97% of those lacked basic AI access controls**.
- **63%** of breached organizations had **no AI governance policy** (or one still in draft).
- In shadow-AI breaches, compromised customer PII jumped to roughly **two-thirds** of cases.

The takeaway: the fastest-growing AI risk for most orgs isn't an exotic adversarial attack — it's **employees pasting sensitive data into unsanctioned tools** and **AI features shipped without access controls**.

### A starter checklist for AI governance

```
□ Inventory AI use — sanctioned tools AND shadow AI (browser extensions, copilots, pasted prompts)
□ Acceptable-use policy — what data may/may not go into which AI tools
□ Access controls on internal AI apps — authn/authz, least privilege, rate limits
□ Data-loss controls — DLP rules for prompts; block/sanction risky endpoints
□ Vendor due diligence — data retention, training-on-your-data, sub-processors
□ Logging & monitoring — who is using which AI tool, with what data
□ Incident playbook — what to do when sensitive data leaks into a model
□ Map to a framework — OWASP LLM / Agentic Top 10, NIST AI 600-1, MITRE ATLAS
```

### Don't forget agentic AI

As teams adopt AI **agents** that take actions (run queries, call APIs, touch ticketing/EDR), the blast radius of a single prompt-injection or over-permissioned tool grows sharply. OWASP's 2025 work splits **"excessive agency"** into three root causes worth designing against: excessive **functionality**, excessive **permissions**, and excessive **autonomy** (high-impact actions with no human in the loop). Scope agent tools narrowly, run them with least privilege, and keep a human approval step on anything destructive or outward-facing. → *See [Lab 49: LLM Red Teaming](../../labs/lab49-llm-red-teaming/) and [Lab 43: RAG Security](../../labs/lab43-rag-security/).*

**Give agents their own identity.** The single highest-leverage control for "least agency" is treating each agent as a first-class identity — its own account, **scoped** credentials, and **short-lived** tokens — rather than handing it a shared service account with broad standing access. Most enterprises get this wrong today. Scope per task, log every tool call, and expire credentials aggressively.

**Mind the tool protocol.** As agents increasingly connect to tools via the **Model Context Protocol (MCP)**, the MCP server/gateway becomes a new trust boundary — it brokers what an agent can reach. Treat it like any other privileged integration: authenticate clients, allow-list tools, and log calls. (MCP-specific risks appear in the OWASP Agentic Top 10.)

### The other half: attackers use AI too

A guide that covers *defensive* AI without *offensive* AI is half the picture. The same capabilities compressing your investigation time are compressing the attacker's timeline:

- IBM's *Cost of a Data Breach 2025* found **16% of breaches involved AI-driven attacks**, most commonly to scale **phishing and social engineering** (AI-generated phishing was ~37% of those incidents).⁵
- Generative AI has cut the time to craft a convincing phishing email **from ~16 hours to ~5 minutes** — a step-change in attacker throughput, not just quality.⁵

The leadership implication isn't panic; it's that **detection and user-reporting baselines built for human-paced phishing need re-tuning for machine-paced volume**, and that identity/MFA-resistant social engineering deserves renewed attention. Your AI-assisted defenses are, in part, a response to AI-assisted offense.

---

## Building AI-Ready Teams

### Skills to Develop

| Skill                   | Who Needs It                 | How to Develop              |
| ----------------------- | ---------------------------- | --------------------------- |
| **Prompt engineering**  | All analysts                 | Labs 02, 15 in this course |
| **ML fundamentals**     | Senior analysts, engineers   | Labs 04, 13                |
| **AI tool evaluation**  | Managers, architects         | Lab 05, this guide         |
| **AI security testing** | Red team, security engineers | Labs 40, 43, 49            |

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

### A 30/60/90-Day Starter Plan

A concrete first quarter that front-loads measurement and keeps risk low:

| Phase | Focus | Key actions |
| --- | --- | --- |
| **Days 1–30: Baseline** | Know your starting point | Pick **one** high-volume use case (usually alert triage). Capture baseline metrics (MTTT, alert-to-analyst ratio, false-positive rate). Confirm the [prerequisites](#prerequisites-checklist) are met. Stand up a quick AI acceptable-use policy. |
| **Days 31–60: Pilot** | Prove it on a slice | Run AI on a *subset* of traffic with a human reviewing **every** output. Compare against baseline. Track human override and false-negative rates from day one. |
| **Days 61–90: Decide** | Measure, then expand or stop | Review pilot metrics honestly. If it helps, expand scope and add sampling-based oversight; if not, document why and stop. Either way, write down what you learned. |

**Rule:** don't scale a use case until you can show a before/after number. No baseline, no expansion.

---

## Resources for Deeper Learning

### In This Course

| Resource                                                                            | What You'll Learn                | Time      |
| ----------------------------------------------------------------------------------- | -------------------------------- | --------- |
| [Lab 05: AI in Security Operations](../../labs/lab05-ai-in-security-operations/)  | Comprehensive strategic overview | 1-2 hours |
| [Lab 04: ML Concepts Primer](../../labs/lab04-ml-concepts-primer/)                | What ML can/can't do             | 1-2 hours |
| [Lab 02: Intro to Prompt Engineering](../../labs/lab02-intro-prompt-engineering/) | How LLMs work                    | 1-2 hours |
| [Lab 15: LLM Log Analysis](../../labs/lab15-llm-log-analysis/)                      | Hands-on LLM experience          | 2-3 hours |
| [Security Compliance Guide](./security-compliance-guide.md)                         | SOC 2, GDPR, NIST mapping        | Reference |
| [Cost Management Guide](./cost-management.md)                                       | Budget planning                  | Reference |
| [Security-to-AI Glossary](../../resources/security-to-ai-glossary.md)               | Plain-language AI terms (RAG, agentic, prompt injection, MTTR…) | Reference |

### External Resources

**Frameworks and Standards:**

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/) — The current edition; prompt injection remains #1, with an expanded "excessive agency" entry
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — Released Dec 2025; companion list for AI systems that plan, act, and use tools autonomously
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and the [Generative AI Profile (NIST AI 600-1)](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) — Voluntary risk management; the GenAI profile adds 12 GenAI-specific risk categories
- [NIST IR 8596 — Cybersecurity Framework Profile for AI](https://csrc.nist.gov/) (preliminary draft, Dec 2025) — CSF-aligned guidance for security leaders mapping AI risk to existing programs
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial ML / AI threat framework (the ATT&CK analog for AI systems)
- [EU AI Act — official timeline](https://artificialintelligenceact.eu/implementation-timeline/) — Phased obligations through 2026–2028 (see Omnibus status above)

**Industry Reports & Sources (cited above):**

- **¹** [The State of AI in the SOC 2025](https://thehackernews.com/2025/09/the-state-of-ai-in-soc-2025-insights.html) (Prophet Security, n=282 security leaders) — alert volume (~960/day typical, 3,000+ large enterprise)
- **²** [Vectra AI, *2026 State of Threat Detection & Response*](https://www.vectra.ai/resources/2026-state-of-threat-detection) (Feb 2026, n=1,450) — 2,992 alerts/day, 63% unaddressed
- **³** [Gurucul, *Pulse of the AI SOC 2025*](https://gurucul.com/blog/2025-pulse-of-the-ai-soc-ai-enters-the-equation/) (Aug 2025, n=739) — adoption maturity; 60% cut investigation time ≥25%
- **⁴** [SANS 2025 Detection & Response Survey](https://www.sans.org/) (Dec 2025, sponsored by Stamus Networks) — false positives are the #1 detection challenge (73%)
- **⁵** [IBM, *Cost of a Data Breach 2025*](https://www.ibm.com/reports/data-breach) (Ponemon Institute, n=600 orgs, breaches Mar 2024–Feb 2025) — $1.9M saved with extensive AI/automation; global $4.44M, U.S. record $10.22M; shadow-AI and governance gaps
- **⁶** [Tines, *Voice of the SOC Analyst*](https://www.tines.com/reports/voice-of-the-soc-analyst/) (Mar 2022, n=468 analysts at 500+-employee firms) — 71% report some burnout, 64% likely to switch jobs within a year

> **Methodology note:** several of these are vendor-sponsored surveys with differing samples and definitions. Treat all figures as directional and validate against your own baseline. The burnout numbers (⁶) are from 2022 and may not reflect today's SOC.

**Further reading for leaders** (primary reports beat generic books):

- *IBM Cost of a Data Breach 2025*, *Verizon DBIR 2025*, *Mandiant M-Trends 2025*, and the *WEF Global Cybersecurity Outlook 2026* — current, data-rich, and free

---

## Quick Reference Card

### AI Investment Readiness Checklist

Foundations come from the [Prerequisites Checklist](#prerequisites-checklist) above (logging, detection tuning, processes, capacity, budget). Once those are met, confirm you're *decision*-ready:

```
□ Clear problem statement (not "use AI")
□ Baseline metrics established (you can show before/after)
□ Human-in-the-loop requirements defined
□ Rollback plan if AI fails
□ Compliance requirements understood
□ AI governance / acceptable-use policy in place
```

### Red Flags When Evaluating AI Solutions

- Promises to "eliminate" false positives or "guarantee" detection
- No discussion of human oversight requirements
- Vague about data handling and privacy
- Can't explain how the AI works at a high level
- No metrics on false negative rates
- Pricing that scales unpredictably

### Procurement Clauses to Require

Contract language is where governance becomes enforceable. Push for these in any AI vendor agreement:

```
□ Data non-training — your prompts/data are NOT used to train vendor models (opt-out in writing)
□ Sub-processor disclosure — who else touches your data, and notice before changes
□ Model-version pinning — you control when model versions change (no silent upgrades)
□ Prompt-and-response logging — you can access logs of what was sent and returned
□ Data deletion SLAs — defined retention and deletion timelines on request/termination
□ Security attestations — SOC 2 / ISO 27001, plus AI-specific controls
□ Incident notification — breach/leak notification terms that cover AI-handled data
```

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
3. **Try Lab 15** for hands-on LLM experience (2-3 hours)
4. **Evaluate one specific use case** using the decision framework
5. **Pilot small**, measure results, then expand

---

_This guide is part of the [AI for the Win](../../README.md) training program — a hands-on course for security practitioners building AI-powered tools._

### Changelog

- **May 2026 (rev. 2):** Corrected "By the Numbers" source attributions (Vectra for alert volume, Tines 2022 for burnout); added U.S. $10.22M breach figure and IBM methodology; updated EU AI Act Omnibus status (provisional, not yet binding); fixed GDPR Art. 22 framing; added offensive-AI, agentic-identity, MCP, and procurement-clause sections; corrected the maturity diagram; refreshed OWASP Agentic and added NIST IR 8596.
- **May 2026:** Added 2025–2026 stats, diagrams, cost model, 30/60/90-day plan, shadow-AI/governance section; refreshed OWASP/NIST/EU references.

_Last updated: May 2026_

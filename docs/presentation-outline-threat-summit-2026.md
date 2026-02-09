# Presentation Outline: Leveraging Agents and LLMs to Design and Solve Cyber Capture The Flags

**Conference:** 2026 Threat Summit: The Year of Threat Intel
**Format:** Presentation (Case Study) | 25 minutes
**Focus:** AI
**TLP:** None

---

## Timing Plan (25 minutes total)

| Segment | Duration | Cumulative | Notes |
|---------|----------|------------|-------|
| Opening Hook | 2 min | 0:02 | Live demo or result screenshot |
| The Shift: AI + CTFs | 3 min | 0:05 | Framing the problem space |
| **Q&A Checkpoint 1** | **1 min** | **0:06** | *"Before I dive in -- anyone here run CTFs or used AI agents?"* |
| Designing CTFs with AI | 5 min | 0:11 | Architecture, generation, modularity |
| Solving CTFs with Agents | 6 min | 0:17 | Techniques, demos, LLM comparisons |
| **Q&A Checkpoint 2** | **2 min** | **0:19** | *"Pause -- questions on design vs. solving?"* |
| Real-World Implications | 3 min | 0:22 | Attack applications, defensive takeaways |
| Limitations & Future | 2 min | 0:24 | What agents still can't do, where CTFs go |
| Closing + Final Q&A | 1 min | 0:25 | Resources, contact, remaining questions |

---

## Slide-by-Slide Outline

### 1. Title Slide (0:00 -- 0:30)

- **Title:** Leveraging Agents and LLMs to Design and Solve Cyber Capture The Flags
- **Speakers:** Panel of AI and Security Researchers
- **Conference:** 2026 Threat Summit
- Key visual: An agent loop diagram overlaid on a CTF challenge

---

### 2. Opening Hook (0:30 -- 2:00)

**Goal:** Grab attention -- show the end result first.

- Show a 30-second screen recording or screenshot of an AI agent autonomously solving a CTF challenge
  - Example: Agent reads challenge README, examines `auth_logs.json`, identifies brute-force pattern, extracts the flag
- **Key stat:** "Our agent framework solved X/18 challenges autonomously across beginner, intermediate, and advanced tiers"
- **Punchline:** "The question is no longer *can* AI solve CTFs. It's *how* -- and what that means for all of us."

---

### 3. The Shift: From "Can AI?" to "How Do I Get AI?" (2:00 -- 5:00)

**Goal:** Frame why this matters to a threat intel audience.

- **The landscape shift:**
  - 2024: "Can AI solve a CTF?" -- novelty experiments
  - 2025: "How do I get AI to solve CTFs?" -- agent frameworks, tool use, prompt engineering
  - 2026: Agents are routinely competitive -- what does this mean for defenders?
- **Why CTFs are the perfect testbed:**
  - Bounded problems with clear success criteria (FLAG{...})
  - Span the full security domain: log analysis, DFIR, threat intel, ML security, cloud
  - Measurable -- points, tiers, time-to-solve
- **Our platform:** "AI for the Win" -- 50+ labs, 18 CTF challenges, 4 capstone projects
  - 3 difficulty tiers: Beginner (100 pts), Intermediate (250 pts), Advanced (500 pts)
  - Categories: Log Analysis, Email Analysis, Threat Intel, ML, Network Analysis, DFIR, Cloud Security, AI Security

> **Q&A Checkpoint 1 (5:00 -- 6:00):** "Quick pulse check -- who in the room has run a CTF before? Who has used an AI agent for security work? Great -- keep those experiences in mind."

---

### 4. Designing CTFs with AI: The Modular Architecture (6:00 -- 11:00)

**Goal:** Show how AI was leveraged to *create* the challenges, and how modularity enables extensibility.

#### 4a. AI-Assisted Challenge Design (2 min)

- Used LLMs (Claude, GPT) as co-designers:
  - Generating realistic attack scenarios from threat actor TTP profiles
  - Creating authentic log data, network artifacts, forensic evidence
  - Designing progressive hint systems that teach without giving away answers
- **Example:** `generate_ctf_data.py` -- parameterized generator that takes:
  - `--actor apt29` (threat actor profile)
  - `--scenario beacon` (C2 beacon traffic, auth logs, malware samples, incident timelines)
  - `--flag FLAG{...}` (embedded flag)
  - Outputs realistic, randomized challenge data grounded in real-world TTPs
- AI helped review challenges for solvability, difficulty calibration, and red herrings

#### 4b. Modular Architecture: Built to Extend (3 min)

- **Three-layer modularity:**

```
Layer 1: Threat Actor TTP Database
   └── Actor profiles (APT28, APT29, Lazarus, FIN7, LockBit, etc.)
   └── Campaign data (SolarWinds, MOVEit, Colonial Pipeline)
   └── Attack chain templates (double extortion, supply chain, BEC)

Layer 2: Challenge Generation Engine
   └── Scenario generators (beacon, auth_logs, malware, incident)
   └── Flag embedding strategies (plain text, encoded, split, pattern)
   └── Difficulty scaling (noise ratio, red herrings, multi-artifact correlation)

Layer 3: Challenge Framework
   └── Consistent structure: README.md + challenge/ + hints/ + solution/
   └── Automated flag verification (SHA-256 hash comparison)
   └── Gamification (points, ranks, achievements, specialization badges)
```

- **Why modularity matters:**
  - Add a new threat actor -> instantly generate new challenges
  - Add a new scenario type (e.g., supply chain, container escape) -> plug into existing actors
  - Swap difficulty parameters without rewriting challenges
  - Community contributions follow the same template
- **Multi-provider LLM support:** Anthropic, OpenAI, Google, Ollama -- challenges aren't locked to one vendor
  - Shared `llm_config.py` auto-detects provider, configures token limits per task type
  - Same challenge, different agent -- compare LLM capabilities directly

---

### 5. Solving CTFs with Agents: Techniques That Work (11:00 -- 17:00)

**Goal:** The core technical content -- how agents actually solve these challenges.

#### 5a. Agent Prompting (1.5 min)

- **System prompt design matters enormously:**
  - Role assignment: "You are a security analyst conducting a CTF investigation"
  - Explicit methodology: OODA loop (Observe, Orient, Decide, Act)
  - Output format constraints: "Always search for FLAG{ pattern before complex analysis"
  - Domain context injection: MITRE ATT&CK mappings, IOC formats, encoding schemes
- **Prompt iteration is the real skill:**
  - First attempt rarely works -- refine based on agent behavior
  - "Be specific" >> "be clever" -- detailed context beats creative prompting

#### 5b. Tool Use & Function Calling (2 min)

- **Tools transform LLMs from thinkers into doers:**
  - File reading tools (parse JSON, CSV, text artifacts)
  - Decoding tools (Base64, hex, URL encoding, ROT13)
  - Analysis tools (regex search, pattern matching, statistical analysis)
  - Correlation tools (cross-reference IOCs across multiple data sources)
- **Tool definition quality is critical:**
  - Clear descriptions drive correct tool selection
  - Input schema validation prevents garbage-in
  - Example from our agent template:

```python
TOOLS = [
    {
        "name": "check_ip_reputation",
        "description": "Check if an IP address is known to be malicious. "
                       "Use this when the user asks about an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to check (e.g., '8.8.8.8')"
                }
            },
            "required": ["ip_address"]
        }
    }
]
```

- **The agent loop:** Think -> Select Tool -> Execute -> Observe -> Repeat until done

#### 5c. Skills/Commands & Agent Patterns (1 min)

- **ReAct (Reason + Act):** Best for straightforward CTF challenges -- think, use tool, observe, respond
- **Plan-and-Execute:** Better for complex multi-artifact challenges (e.g., Advanced-05: Full IR Scenario with 7 artifact files across endpoint + network + threat intel)
- **Multi-Agent:** Specialized roles -- one agent for log analysis, another for decoding, a coordinator agent
- Matching the right pattern to the right challenge difficulty is key

#### 5d. LLM Capabilities: Not All Models Are Equal (1.5 min)

- **Comparative observations across providers:**
  - Claude (Sonnet/Opus): Strong at structured reasoning, multi-step analysis, tool use discipline
  - GPT-5: Excellent at pattern recognition, creative problem-solving
  - Gemini: Good at large context windows, multi-modal analysis
  - Local models (Llama 3.3): Viable for beginner challenges, struggle with complex correlation
- **Key differentiators for CTF solving:**
  - Context window size (how much challenge data fits)
  - Tool calling reliability (does it actually call the right tool?)
  - Reasoning depth (can it chain 5+ logical steps?)
  - Instruction following (does it stay on task or hallucinate?)

> **Q&A Checkpoint 2 (17:00 -- 19:00):** "Let me pause here -- we've covered how we designed and how agents solve. Questions on either side before we talk about what this means in the real world?"

---

### 6. Real-World Attack Implications (19:00 -- 22:00)

**Goal:** Connect CTF findings to real-world offensive/defensive concerns.

- **What agents can already do that matters:**
  - Autonomous reconnaissance and log analysis
  - Pattern recognition across large datasets (finding needles in haystacks)
  - Encoding/decoding and data extraction at speed
  - Multi-step attack chain reconstruction
- **Offensive implications:**
  - If agents can solve security challenges autonomously, they can also *execute* attack steps
  - Lower barrier to entry -- script-kiddie-to-agent-kiddie pipeline
  - Autonomous vulnerability discovery and exploitation chains
  - AI-powered social engineering (phishing, pretexting) is already here
- **Defensive takeaways:**
  - Use AI agents as force multipliers for your SOC (triage, hunting, correlation)
  - Red-team your own defenses with AI agents before adversaries do
  - CTFs are the ideal training ground -- bounded risk, measurable outcomes
  - Human-in-the-loop remains critical for high-stakes decisions (containment, attribution)

---

### 7. Current Limitations & The Future of AI + CTFs (22:00 -- 24:00)

**Goal:** Honest assessment of where agents fall short and where this is heading.

- **What agents still struggle with:**
  - Multi-artifact correlation requiring creative leaps (Advanced challenges)
  - Steganography and non-obvious encoding schemes
  - Ambiguous or misleading data (red herrings)
  - Domain-specific intuition (e.g., "this pattern *looks like* APT29")
  - Maintaining long reasoning chains without losing the thread
- **How CTFs might evolve:**
  - Anti-AI challenge design: adversarial challenges that exploit agent weaknesses
  - Human-AI teaming categories: measured collaboration between analyst and agent
  - Dynamic challenges that change based on solver behavior
  - Agent-vs-agent competitions: red team agents vs. blue team agents
- **The broader trend:**
  - Agents will get better -- rapidly
  - The defenders who learn to wield AI agents today will have a decisive advantage
  - Security education must evolve to include agent literacy

---

### 8. Closing & Resources (24:00 -- 25:00)

- **Key takeaways (rule of three):**
  1. AI agents can both *design* and *solve* security CTFs today -- modularity is the force multiplier
  2. Agent prompting, tool use, and pattern matching are the core techniques -- and they map directly to real-world attacks
  3. CTFs are the ideal, bounded environment to develop your AI agent skills before the stakes are real
- **Resources:**
  - GitHub: `depalmar/ai_for_the_win` -- 50+ labs, 18 CTF challenges, open source
  - All challenges work with Claude, GPT, Gemini, or local models
  - Speaker contact info / LinkedIn
- **Final Q&A:** "Remaining questions?"

---

## Question Interjection Strategy

The 25-minute format is tight. Here is the strategy for weaving in audience engagement without derailing timing:

### Checkpoint 1 (at ~5:00) -- Calibration Question
- **Purpose:** Gauge audience experience level, build rapport
- **Technique:** Simple show-of-hands, no extended discussion
- **Fallback if no hands:** "That's fine -- you'll see why this matters in 5 minutes"
- **Time budget:** 1 minute max

### Checkpoint 2 (at ~17:00) -- Technical Depth Check
- **Purpose:** Address questions on the core technical content before pivoting to implications
- **Technique:** Take 1-2 questions, promise to follow up on others after
- **Fallback if no questions:** "Great, let's talk about why defenders should care"
- **Time budget:** 2 minutes max

### Closing Q&A (at ~24:30)
- **Purpose:** Wrap up with audience-driven topics
- **Technique:** "We have about 30 seconds for one quick question, otherwise find us after"
- **Fallback:** Direct to GitHub repo and contact info

### Handling Long Questions
- Acknowledge: "Great question --"
- Redirect: "Let me give you the short answer and we can go deep after the session"
- Park: "That deserves more than 30 seconds -- let's connect right after"

---

## Speaker Notes & Preparation Checklist

### Demo Preparation
- [ ] Record a screen capture of agent solving beginner-01 (Log Detective) as backup
- [ ] Prepare live demo environment with API key configured
- [ ] Have `generate_ctf_data.py` ready to show modular generation
- [ ] Pre-load challenge outputs for quick reference if live demo fails

### Slide Design Notes
- Use the project's ASCII art diagrams -- they resonate with security audiences
- Keep code snippets minimal on slides; use the tool definition example from Section 5b
- Include the architecture layer diagram from Section 4b as a visual
- Show the agent loop diagram (Think -> Act -> Observe) as a recurring motif

### Audience-Specific Angles
- **Threat Intel audience:** Emphasize TTP database driving challenge generation, MITRE ATT&CK mapping
- **Red teamers:** Emphasize autonomous solving, offensive implications
- **Blue teamers:** Emphasize agent-assisted investigation, SOC force multiplication
- **Managers:** Emphasize measurable outcomes (points, solve rates, time comparisons)

### Contingency Plans
- **Demo fails:** Switch to pre-recorded video or static screenshots
- **Running long:** Cut Section 7 (Limitations) to 1 minute, summarize with bullet points
- **Running short:** Expand Q&A Checkpoint 2 to 3 minutes, deeper dive into LLM comparison
- **Hostile question ("isn't this helping attackers?"):** "CTFs are a controlled environment. The techniques we're showing are already being used offensively. Our goal is to help defenders keep pace."

---

## Appendix: Challenge Examples for Slides

### Beginner Example (for Section 4a)
**Challenge: Log Detective** (100 pts)
- Input: `auth_logs.json` with brute-force attack pattern embedded
- Agent reads logs, identifies failed login burst, finds successful compromise, extracts flag from pattern
- Flag: `FLAG{backup_admin_156_02}`

### Advanced Example (for Section 5c)
**Challenge: Full IR Scenario** (500 pts)
- Input: 7 artifact files across endpoint (registry, scheduled tasks, prefetch), network (firewall, proxy, DNS), and threat intel
- Flag is split across 4 artifact categories -- requires correlation
- Agent must: read all artifacts, correlate timestamps, identify attack chain, reassemble flag parts
- Tests Plan-and-Execute pattern vs. simple ReAct

### Generation Example (for Section 4a)
```bash
# Generate C2 beacon traffic based on APT29 TTPs
python generate_ctf_data.py --actor apt29 --scenario beacon \
    --flag "FLAG{C2_HUNT3R}" --num-events 50 --pretty

# Generate auth logs with brute force pattern
python generate_ctf_data.py --actor apt28 --scenario auth_logs \
    --flag "FLAG{BRUT3_F0RC3}" --output challenge_data.json
```

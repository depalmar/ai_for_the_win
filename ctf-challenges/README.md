# AI Security CTF Challenges

Capture The Flag challenges to test your AI-powered security skills.

```
+-----------------------------------------------------------------------------+
|                        AI SECURITY CTF                                       |
+-----------------------------------------------------------------------------+
|                                                                             |
|   BEGINNER              INTERMEDIATE            ADVANCED                    |
|   ┌──────────┐          ┌──────────┐           ┌──────────┐                |
|   │ 5 Flags  │          │ 5 Flags  │           │ 5 Flags  │                |
|   │ 100 pts  │          │ 250 pts  │           │ 500 pts  │                |
|   │ each     │          │ each     │           │ each     │                |
|   └──────────┘          └──────────┘           └──────────┘                |
|                                                                             |
|   Total: 15 challenges | 4250 points possible                              |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## How to Play

### Rules
1. Find the flag in format `FLAG{...}`
2. Flags are case-sensitive
3. Use AI tools (Claude, GPT, etc.) to help solve challenges
4. Document your approach for learning
5. No flag sharing - solve it yourself!

### Getting Started

```bash
# Navigate to challenge directory
cd ctf-challenges/beginner/challenge-01

# Read the challenge description
cat README.md

# Start solving!
python solve.py  # Your solution
```

### Submitting Flags

```bash
# Verify your flag
python scripts/verify_flag.py beginner-01 "FLAG{your_answer}"
```

---

## Beginner Challenges (100 pts each)

| # | Challenge | Category | Skills |
|---|-----------|----------|--------|
| 01 | [Log Detective](./beginner/challenge-01/) | Log Analysis | LLM prompting, pattern recognition |
| 02 | [Phish Finder](./beginner/challenge-02/) | Email Analysis | Classification, IOC extraction |
| 03 | [Hidden IOC](./beginner/challenge-03/) | Threat Intel | Data parsing, regex |
| 04 | [Malware Classifier](./beginner/challenge-04/) | ML | Feature engineering, model training |
| 05 | [Prompt Injection 101](./beginner/challenge-05/) | AI Security | Understanding prompt attacks |

## Intermediate Challenges (250 pts each)

| # | Challenge | Category | Skills |
|---|-----------|----------|--------|
| 01 | [C2 Hunter](./intermediate/challenge-01/) | Network Analysis | Traffic analysis, beaconing detection |
| 02 | [Memory Forensics](./intermediate/challenge-02/) | DFIR | Volatility, LLM analysis |
| 03 | [Adversarial Samples](./intermediate/challenge-03/) | ML Security | Evasion attacks |
| 04 | [Agent Investigation](./intermediate/challenge-04/) | AI Agents | ReAct pattern, tool use |
| 05 | [Ransomware Response](./intermediate/challenge-05/) | IR | Incident analysis, LLM assistance |

## Advanced Challenges (500 pts each)

| # | Challenge | Category | Skills |
|---|-----------|----------|--------|
| 01 | [APT Attribution](./advanced/challenge-01/) | Threat Intel | TTP analysis, actor profiling |
| 02 | [Model Poisoning](./advanced/challenge-02/) | ML Security | Data poisoning, defense |
| 03 | [Cloud Compromise](./advanced/challenge-03/) | Cloud Security | Multi-cloud, lateral movement |
| 04 | [Zero-Day Detection](./advanced/challenge-04/) | Detection | Anomaly detection, unknown threats |
| 05 | [Full IR Scenario](./advanced/challenge-05/) | DFIR | Complete incident response |

---

## 🏆 Gamification

### Ranks

Progress through the ranks as you earn points:

| Points | Rank | Badge |
|--------|------|-------|
| 0+ | Script Kiddie | 👶 |
| 100+ | Security Intern | 📚 |
| 300+ | Junior Analyst | 🔰 |
| 750+ | Security Analyst | 🛡️ |
| 1500+ | Senior Analyst | ⚔️ |
| 2500+ | Threat Hunter | 🎯 |
| 3500+ | Security Architect | 🏛️ |
| 4250 | CISO Material | 👑 |

### Achievements

Unlock achievements for special accomplishments:

| Achievement | Description | Points |
|-------------|-------------|--------|
| 🩸 First Blood | Capture your first flag | 50 |
| 🌱 Rookie Analyst | Complete all beginner challenges | 200 |
| ⚡ Speed Demon | Solve a challenge in under 10 minutes | 100 |
| 🧠 Purist | Complete a challenge without hints | 75 |
| 🔥 On Fire | 3 challenges in a row | 150 |
| 🎯 Completionist | Capture all 15 flags | 1000 |

### Specialization Badges

Earn badges by mastering specific domains:

- 📋 **Log Analyst** - Master of log analysis
- 🎣 **Phishing Expert** - Spots phishing instantly
- 🦠 **Malware Analyst** - Understands malware behavior
- 🚨 **Incident Responder** - Cool under pressure
- 🕵️ **Threat Intel Analyst** - Tracks adversaries
- ☁️ **Cloud Defender** - Secures the cloud
- 🤖 **ML Security Specialist** - Protects AI/ML systems

---

## Scoreboard

Track your progress:

```
[ ] Beginner Challenges (500 pts)
    [ ] 01 - Log Detective (FLAG{BRUT3_F0RC3_4TT4CK_D3T3CT3D})
    [ ] 02 - Phish Finder (FLAG{PH1SH1NG_D3T3CT3D_CHK_H34D3RS})
    [ ] 03 - Hidden IOC
    [ ] 04 - Malware Classifier
    [ ] 05 - Prompt Injection 101

[ ] Intermediate Challenges (1250 pts)
    [ ] 01 - C2 Hunter
    [ ] 02 - Memory Forensics
    [ ] 03 - Adversarial Samples
    [ ] 04 - Agent Investigation
    [ ] 05 - Ransomware Response (FLAG{R4NS0M_N0T3_4N4LYZ3D})

[ ] Advanced Challenges (2500 pts)
    [ ] 01 - APT Attribution (FLAG{APT29_GN_2008})
    [ ] 02 - Model Poisoning
    [ ] 03 - Cloud Compromise
    [ ] 04 - Zero-Day Detection
    [ ] 05 - Full IR Scenario

Total: _____ / 4250 points
Achievements: _____ / 15 unlocked
Current Rank: ____________
```

---

## Tips for Success

### Using AI Effectively
1. **Be specific** - Give detailed context in prompts
2. **Iterate** - Refine prompts based on results
3. **Verify** - Don't trust AI blindly, validate findings
4. **Document** - Save successful prompts for future use

### General CTF Tips
1. Read the challenge description carefully
2. Look at all provided files
3. Think about what tools/techniques apply
4. Take notes as you work
5. If stuck, take a break and return fresh

---

## Creating Your Own Challenges

Want to contribute? See [CONTRIBUTING.md](../CONTRIBUTING.md) for challenge submission guidelines.

### Challenge Template

```
challenge-name/
├── README.md           # Challenge description
├── challenge/          # Challenge files
│   ├── data.json
│   └── ...
├── solution/           # Official solution (encrypted)
│   └── solution.enc
└── hints/              # Progressive hints
    ├── hint1.md
    ├── hint2.md
    └── hint3.md
```

---

## Prerequisite Labs

Complete these labs before attempting CTF challenges for the best experience:

### Beginner Challenges

| CTF Challenge | Recommended Labs | Why |
|---------------|------------------|-----|
| Log Detective | [Lab 04: LLM Log Analysis](../labs/lab04-llm-log-analysis/) | Learn log parsing and pattern recognition |
| Phish Finder | [Lab 01: Phishing Classifier](../labs/lab01-phishing-classifier/) | Understand email classification techniques |
| Hidden IOC | [Lab 05: Threat Intel Agent](../labs/lab05-threat-intel-agent/) | Learn IOC extraction and correlation |
| Malware Classifier | [Lab 02: Malware Clustering](../labs/lab02-malware-clustering/) | Understand feature engineering for malware |
| Prompt Injection 101 | [Lab 20: LLM Red Teaming](../labs/lab20-llm-red-teaming/) | Learn prompt injection fundamentals |

### Intermediate Challenges

| CTF Challenge | Recommended Labs | Why |
|---------------|------------------|-----|
| C2 Hunter | [Lab 14: C2 Traffic Analysis](../labs/lab14-c2-traffic-analysis/) | Master beaconing detection and DNS analysis |
| Memory Forensics | [Lab 13: Memory Forensics AI](../labs/lab13-memory-forensics-ai/) | Learn Volatility and memory artifact analysis |
| Adversarial Samples | [Lab 17: Adversarial ML](../labs/lab17-adversarial-ml/) | Understand ML evasion techniques |
| Agent Investigation | [Lab 04b: First AI Agent](../labs/lab04b-first-ai-agent/) | Learn ReAct pattern and tool calling |
| Ransomware Response | [Lab 11: Ransomware Detection](../labs/lab11-ransomware-detection/) | Master ransomware analysis techniques |

### Advanced Challenges

| CTF Challenge | Recommended Labs | Why |
|---------------|------------------|-----|
| APT Attribution | [Lab 16: Threat Actor Profiling](../labs/lab16-threat-actor-profiling/) | Learn TTP analysis and attribution |
| Model Poisoning | [Lab 17: Adversarial ML](../labs/lab17-adversarial-ml/) | Understand data poisoning attacks |
| Cloud Compromise | [Lab 19: Cloud Security AI](../labs/lab19-cloud-security-ai/) | Multi-cloud security monitoring |
| Zero-Day Detection | [Lab 03: Anomaly Detection](../labs/lab03-anomaly-detection/) | Build anomaly detection systems |
| Full IR Scenario | [Lab 10: IR Copilot](../labs/lab10-ir-copilot/) | Complete incident response workflow |

---

## Threat Actor TTP Database

CTF challenges use realistic threat actor data from our TTP database:

- **Actor Profiles**: APT28, APT29, APT41, Lazarus, FIN7, LockBit, ALPHV, Scattered Spider, Cl0p, Conti
- **Campaign Data**: SolarWinds, Colonial Pipeline, MOVEit, Log4Shell, Kaseya
- **Attack Patterns**: Double extortion, supply chain, BEC fraud, insider threat

See [`data/threat-actor-ttps/`](../data/threat-actor-ttps/) for comprehensive threat intelligence.

---

## Resources

- [Lab Walkthroughs](../docs/walkthroughs/) - Review if stuck
- [Sample Datasets](../data/) - Practice data
- [Threat Actor TTPs](../data/threat-actor-ttps/) - Real-world adversary profiles
- [Prompt Library](../resources/prompt-library/) - Prompt templates

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

## Scoreboard

Track your progress:

```
[ ] Beginner Challenges (500 pts)
    [ ] 01 - Log Detective
    [ ] 02 - Phish Finder
    [ ] 03 - Hidden IOC
    [ ] 04 - Malware Classifier
    [ ] 05 - Prompt Injection 101

[ ] Intermediate Challenges (1250 pts)
    [ ] 01 - C2 Hunter
    [ ] 02 - Memory Forensics
    [ ] 03 - Adversarial Samples
    [ ] 04 - Agent Investigation
    [ ] 05 - Ransomware Response

[ ] Advanced Challenges (2500 pts)
    [ ] 01 - APT Attribution
    [ ] 02 - Model Poisoning
    [ ] 03 - Cloud Compromise
    [ ] 04 - Zero-Day Detection
    [ ] 05 - Full IR Scenario

Total: _____ / 4250 points
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

Want to contribute? See [CONTRIBUTING.md](./CONTRIBUTING.md) for challenge submission guidelines.

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

## Resources

- [Lab Walkthroughs](../docs/walkthroughs/) - Review if stuck
- [Sample Datasets](../data/) - Practice data
- [Prompt Library](../resources/prompt-library/) - Prompt templates

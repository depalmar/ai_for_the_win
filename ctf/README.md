# Capture The Flag (CTF) Challenges

Practice your security skills with these CTF challenges designed to complement the lab exercises.

## Flag Format

All flags in this course follow this format:
```
FLAG{some_text_here}
```

## Challenge Tiers

### Beginner Challenges (100 pts each)
For those who have completed the foundational labs.

| Challenge | Prerequisite Labs | Skills Tested |
|-----------|-------------------|---------------|
| [01: Log Detective](beginner/01-log-detective/) | Lab 04 | Log analysis, pattern recognition |
| [02: Phish Finder](beginner/02-phish-finder/) | Lab 01 | Email classification, IOC extraction |

### Intermediate Challenges (250 pts each)
For those who have completed multiple core labs.

| Challenge | Prerequisite Labs | Skills Tested |
|-----------|-------------------|---------------|
| [01: C2 Hunter](intermediate/01-c2-hunter/) | Lab 14 | Beaconing detection, DNS tunneling |
| [02: Memory Forensics](intermediate/02-memory-forensics/) | Lab 13 | Process injection, shellcode analysis |
| [03: Adversarial Samples](intermediate/03-adversarial-samples/) | Lab 17 | ML evasion, PE analysis |
| [04: Agent Investigation](intermediate/04-agent-investigation/) | Lab 05 | Prompt injection, ReAct debugging |
| [05: Ransomware Response](intermediate/05-ransomware-response/) | Lab 11 | Crypto analysis, key recovery |

### Advanced Challenges (500 pts each)
For those ready for real-world complexity.

| Challenge | Prerequisite Labs | Skills Tested |
|-----------|-------------------|---------------|
| [01: APT Attribution](advanced/01-apt-attribution/) | Lab 16 | TTP mapping, threat actor profiling |
| [02: Model Poisoning](advanced/02-model-poisoning/) | Lab 17 | Backdoor detection, data poisoning |
| [03: Cloud Compromise](advanced/03-cloud-compromise/) | Lab 19 | Multi-cloud forensics, IAM analysis |
| [04: Zero-Day Hunt](advanced/04-zero-day-hunt/) | Lab 03 | Behavioral anomaly detection |
| [05: Full IR Scenario](advanced/05-full-ir-scenario/) | Lab 10 | Complete incident response lifecycle |

## Quick Stats

| Tier | Challenges | Total Points |
|------|------------|--------------|
| Beginner | 2 | 200 |
| Intermediate | 5 | 1,250 |
| Advanced | 5 | 2,500 |
| **Total** | **12** | **3,950** |

## Tips for Success

1. **Read the challenge description carefully** - hints are often embedded
2. **Check all provided files** - flags can be anywhere
3. **Try the obvious first** - search for "FLAG{" before complex analysis
4. **Use the labs as reference** - techniques from labs apply to CTFs
5. **Take notes** - track what you've tried
6. **Use hints if stuck** - they cost points but help you learn

## Scoring

- Each challenge has a point value based on difficulty
- Hints reduce points but teach important concepts
- No penalty for incorrect submissions
- Time is not tracked (learn at your own pace)

## Recommended Order

```
Beginner 01-02 → Intermediate 01-05 → Advanced 01-05
     ↓                  ↓                    ↓
 Build core        Apply skills         Master complex
 analysis          to harder            multi-phase
 skills            scenarios            investigations
```

## Getting Help

- Review the prerequisite labs before attempting challenges
- Use AI assistants to help with decoding and analysis
- Check challenge hints (costs points but teaches concepts)

## Creating Your Own Challenges

Want to contribute CTF challenges? See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

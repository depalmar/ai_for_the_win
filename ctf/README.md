# Capture The Flag (CTF) Challenges

Practice your security skills with these CTF challenges designed to complement the lab exercises.

## Flag Format

All flags in this course follow this format:
```
FLAG{some_text_here}
```

## Challenge Tiers

### Beginner Challenges (100 pts each)
For those who have completed the foundational labs (00a-00i).

| Challenge | Prerequisite Labs | Difficulty | API Key |
|-----------|-------------------|------------|---------|
| [01: Log Detective](beginner/01-log-detective/) | Lab 04 | Easy | Optional |
| [02: Phish Finder](beginner/02-phish-finder/) | Lab 01 | Easy | No |
| [03: Hidden IOC](beginner/03-hidden-ioc/) | Lab 00a, 05 | Easy | Optional |
| [04: Malware Classifier](beginner/04-malware-classifier/) | Lab 02 | Easy | No |
| [05: Prompt Injection](beginner/05-prompt-injection/) | Lab 00c | Easy | No |

### Intermediate Challenges (250 pts each)
For those who have completed multiple core labs.

| Challenge | Prerequisite Labs | Difficulty | API Key |
|-----------|-------------------|------------|---------|
| [01: C2 Hunter](intermediate/01-c2-hunter/) | Lab 04, 14 | Medium | Optional |
| [02: Memory Forensics](intermediate/02-memory-forensics/) | Lab 13 | Medium | No |
| [03: Adversarial Samples](intermediate/03-adversarial-samples/) | Lab 17 | Medium | No |
| [04: Agent Investigation](intermediate/04-agent-investigation/) | Lab 05 | Medium | Optional |
| [05: Ransomware Response](intermediate/05-ransomware-response/) | Lab 11 | Medium | No |

### Advanced Challenges (500 pts each)
For those ready for real-world complexity.

| Challenge | Prerequisite Labs | Difficulty | API Key |
|-----------|-------------------|------------|---------|
| [01: APT Attribution](advanced/01-apt-attribution/) | Lab 16 | Hard | Optional |
| [02: Model Poisoning](advanced/02-model-poisoning/) | Lab 17 | Hard | No |
| [03: Cloud Compromise](advanced/03-cloud-compromise/) | Lab 19 | Hard | Optional |
| [04: Zero-Day Hunt](advanced/04-zero-day-hunt/) | Lab 03 | Hard | No |
| [05: Full IR Scenario](advanced/05-full-ir-scenario/) | Lab 10 | Hard | Optional |

## Quick Stats

| Tier | Challenges | Total Points |
|------|------------|--------------|
| Beginner | 5 | 500 |
| Intermediate | 5 | 1,250 |
| Advanced | 5 | 2,500 |
| **Total** | **15** | **4,250** |

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
Beginner 01-05 → Intermediate 01-05 → Advanced 01-05
     ↓                  ↓                    ↓
 Build core        Apply skills         Master complex
 analysis          to harder            multi-phase
 skills            scenarios            investigations
```

## Getting Help

- Review [Lab 00i: CTF Fundamentals](../labs/lab00i-ctf-fundamentals/) for CTF strategies
- Review the prerequisite labs before attempting challenges
- Use AI assistants to help with decoding and analysis
- Check challenge hints (costs points but teaches concepts)

## Creating Your Own Challenges

Want to contribute CTF challenges? See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

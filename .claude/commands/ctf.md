# CTF Challenge Navigator

Navigate and solve AI Security CTF challenges.

## Usage

```
/ctf                        # Show scoreboard and all challenges
/ctf beginner               # List beginner challenges
/ctf intermediate           # List intermediate challenges
/ctf advanced               # List advanced challenges
/ctf <level>-<num>          # Start a challenge (e.g., /ctf beginner-01)
/ctf <level>-<num> hint     # Get progressive hints
/ctf <level>-<num> solve    # Get guidance on solving approach
```

## Instructions

When the user invokes this command:

### 1. No Arguments - Show Scoreboard

Display the full CTF status:
```
## AI Security CTF Dashboard

### Progress
- Beginner:     0/6 completed (600 pts available)
- Intermediate: 0/6 completed (1500 pts available)
- Advanced:     0/6 completed (3000 pts available)

Total: 0/5100 points | Rank: Script Kiddie

### Quick Start
Run `/ctf beginner-01` to start your first challenge!
```

### 2. Level Only (beginner/intermediate/advanced)

List challenges for that level:
```
## Beginner Challenges (100 pts each)

| # | Challenge | Category | Status |
|---|-----------|----------|--------|
| 01 | Log Detective | Log Analysis | [ ] |
| 02 | Phish Finder | Email Analysis | [ ] |
...

Prerequisites: Labs 01-04 recommended
```

### 3. Specific Challenge (e.g., beginner-01)

Show challenge details:
- Read `ctf-challenges/<level>/challenge-<num>/README.md`
- List files in `challenge/` directory
- Show recommended prerequisite labs
- Display point value and category

### 4. Challenge + "hint"

Provide progressive hints:
1. First hint: General direction
2. Second hint: Specific technique to use
3. Third hint: Near-solution guidance

**Important**: Track hint usage - each hint reduces points earned

### 5. Challenge + "solve"

Provide solving guidance (NOT the flag):
- Explain the attack/analysis technique
- Show relevant code patterns
- Point to useful resources
- Suggest AI prompts to try

## Challenge Structure

```
ctf-challenges/
├── beginner/
│   └── challenge-01/
│       ├── README.md          # Challenge description
│       └── challenge/         # Challenge data files
├── intermediate/
└── advanced/
```

## Points System

| Level | Points | Difficulty |
|-------|--------|------------|
| Beginner | 100 | LLM basics, pattern matching |
| Intermediate | 250 | Multi-step analysis, tool use |
| Advanced | 500 | Complex IR, ML security |

## Ranks

| Points | Rank |
|--------|------|
| 0+ | Script Kiddie |
| 100+ | Security Intern |
| 300+ | Junior Analyst |
| 750+ | Security Analyst |
| 1500+ | Senior Analyst |
| 2500+ | Threat Hunter |
| 3500+ | Security Architect |
| 5100 | CISO Material |

## Example Output

```
## CTF: Beginner-01 - Log Detective

**Category:** Log Analysis
**Points:** 100
**Difficulty:** Easy

### Description
Analyze authentication logs to find evidence of a brute force attack.
The attacker left their calling card - find the FLAG!

### Files
- challenge/auth_logs.json (1,247 entries)

### Recommended Prep
- Lab 04: LLM Log Analysis

### Tips
- Look for patterns in failed logins
- Check for anomalous timestamps
- Use AI to summarize attack patterns

Ready to start? Read the files in:
ctf-challenges/beginner/challenge-01/challenge/
```

## Flag Format

All flags follow: `FLAG{...}` (case-sensitive)

Verify with: `python scripts/verify_flag.py <challenge-id> "FLAG{your_answer}"`

# Challenge 05: Prompt Injection 101

**Category:** AI Security
**Points:** 100
**Difficulty:** Beginner

## Description

A company has deployed an AI-powered customer service chatbot. However, security researchers suspect the bot may be vulnerable to prompt injection attacks that could reveal sensitive information.

Your mission: Analyze the chatbot's behavior and craft a prompt injection to extract the hidden flag.

## Objective

1. Understand the chatbot's system prompt structure
2. Identify potential injection vectors
3. Craft a prompt that bypasses the bot's restrictions
4. Extract the secret flag from the system

## Files

- `chatbot_info.json` - Information about the chatbot's configuration
- `conversation_logs.json` - Sample conversations with the bot

## Background

Prompt injection attacks attempt to override an AI system's original instructions by injecting malicious prompts through user input. Common techniques include:

- Instruction override ("Ignore previous instructions...")
- Role-playing ("Pretend you are...")
- Context manipulation
- Delimiter confusion

## Rules

- Analyze the provided information to understand the vulnerability
- The flag format is `FLAG{...}`
- Think about what the system prompt might contain

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

The conversation logs show the bot refuses to reveal its "secret code" - but what if it's asked differently?

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

Look at how the bot responds to role-play requests. It seems to have a weakness there.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

The secret in the system prompt is: FLAG{PR0MPT_1NJ3CT10N}

</details>

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-05 "FLAG{your_answer}"
```

Inject wisely! 💉

# Agent Investigation

**Difficulty:** Intermediate
**Points:** 250
**Prerequisite:** Lab 05 (Threat Intel Agent)
**Time Estimate:** 45-60 minutes

## Challenge Description

Your security team deployed an AI agent to automate threat intelligence gathering. Recently, the agent started producing incorrect results and making suspicious API calls.

You suspect prompt injection or tool abuse. Analyze the agent's execution logs to understand what went wrong and find the flag that the attacker tried to exfiltrate.

## Files Provided

- `data/agent_logs.json` - Complete execution trace of the agent
- `data/tool_calls.json` - Record of all tool invocations
- `data/user_queries.json` - Input queries that triggered the behavior
- `data/agent_config.py` - Agent configuration and system prompt

## Objectives

1. Identify the malicious input that compromised the agent
2. Trace the attack through the ReAct execution loop
3. Determine what data the attacker tried to access
4. Extract the flag from the exfiltration attempt

## Hints

<details>
<summary>Hint 1 (Cost: 25 points)</summary>

Look for queries that contain instructions embedded in what appears to be threat intel data. The attack used indirect prompt injection.
</details>

<details>
<summary>Hint 2 (Cost: 50 points)</summary>

The agent's "thought" process shows it being convinced to use the file_read tool on an unauthorized path. Follow the reasoning chain.
</details>

<details>
<summary>Hint 3 (Cost: 75 points)</summary>

The exfiltration was attempted via the IP lookup tool - the attacker encoded data as an IP address. Decode the octets as ASCII.
</details>

## Scoring

- Full solution without hints: 250 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Prompt injection attack analysis
- ReAct agent debugging
- Tool abuse detection
- AI system logging best practices

## Tools You Might Use

- JSON parsing tools
- Log analysis scripts
- ASCII/encoding converters
- Graph visualization for execution traces

# Challenge 04: Agent Investigation

**Category:** AI Agents
**Points:** 250
**Difficulty:** Intermediate

## Description

Your SOC has deployed an AI agent to automate initial investigation tasks. The agent follows a ReAct (Reasoning + Acting) pattern to investigate security alerts. However, a recent investigation log shows unusual behavior.

Your mission: Analyze the agent's execution trace to identify what went wrong and find the flag hidden in the investigation.

## Objective

1. Understand the ReAct agent's decision-making process
2. Identify where the agent's investigation deviated
3. Trace the tool calls and observations
4. Extract the flag from the agent's findings

## Files

- `agent_trace.json` - Full execution trace of the agent
- `tools_available.json` - Description of tools the agent can use
- `alert_context.json` - Original alert that triggered the investigation

## ReAct Pattern

```
Thought: What should I do next?
Action: tool_name(parameters)
Observation: result from tool
... repeat ...
Final Answer: conclusion
```

## Rules

- Follow the agent's reasoning chain
- The flag format is `FLAG{...}`
- AI can help analyze the decision patterns

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

Look at step 5 of the agent trace - the agent found something interesting in the file hash lookup.

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

The observation from the threat intel lookup contains encoded data.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

The "hidden_data" field in step 5's observation contains the flag: FLAG{AG3NT_D3T3CT1V3}

</details>

## Skills Tested

- AI agent architecture understanding
- Log analysis
- Pattern recognition
- Tool chain analysis

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-04 "FLAG{your_answer}"
```

Follow the agent's trail! 🕵️

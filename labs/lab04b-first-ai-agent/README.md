# Lab 04b: Your First AI Agent

A gentle introduction to AI agents before diving into the full threat intelligence agent in Lab 05.

---

## Overview

| | |
|---|---|
| **Difficulty** | Beginner-Intermediate |
| **Time** | 45-60 minutes |
| **Prerequisites** | Lab 04 (LLM Log Analysis) |
| **API Keys Required** | Yes (Anthropic, OpenAI, or Google) |

## Learning Objectives

By the end of this lab, you will understand:

1. What makes an "agent" different from a simple LLM call
2. The concept of "tools" that LLMs can use
3. How to build a simple agent that decides which tool to use
4. The ReAct pattern (Reason + Act) at a basic level
5. When agents are useful vs. overkill

> 🎯 **Bridge Lab**: This lab bridges Lab 04 (single LLM calls) and Lab 05 (full ReAct agent with memory and multiple tools). If Lab 05 feels too complex, start here.

---

## Part 1: What is an AI Agent?

### Simple LLM vs. Agent

```
SIMPLE LLM CALL (Lab 04):
┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │────▶│   LLM   │────▶│ Response│
│  Input  │     │         │     │         │
└─────────┘     └─────────┘     └─────────┘
     One input, one output, done.


AI AGENT (This Lab):
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │────▶│   LLM   │────▶│  Tool   │────▶│   LLM   │────▶ Response
│  Input  │     │ (Think) │     │ (Act)   │     │(Reflect)│
└─────────┘     └─────────┘     └─────────┘     └─────────┘
     LLM decides what tool to use, uses it, then responds.
```

### Key Differences

| Aspect | Simple LLM | Agent |
|--------|-----------|-------|
| **Tools** | None | Can use external tools (APIs, databases, etc.) |
| **Decision Making** | Just responds | Decides *what action* to take |
| **Multiple Steps** | Single response | Can take multiple actions |
| **Real Data** | Only knows training data | Can fetch live information |

### The ReAct Pattern (Simplified)

```
ReAct = Reasoning + Acting

1. REASON: "The user wants to check if an IP is malicious. 
            I should use the IP reputation tool."
            
2. ACT:    Call ip_reputation_tool("8.8.8.8")

3. OBSERVE: Tool returns: {"reputation": "clean", "owner": "Google"}

4. REASON: "The IP is clean, owned by Google. I can now respond."

5. RESPOND: "8.8.8.8 is a clean IP address owned by Google DNS."
```

---

## Part 2: Building Your First Agent

### Step 1: Define Your Tools

Tools are functions the LLM can call. Let's create two simple security tools:

```python
# starter/main.py
import os
import json
from anthropic import Anthropic

# Initialize client
client = Anthropic()

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================

def check_ip_reputation(ip_address: str) -> dict:
    """
    Check if an IP address is known to be malicious.
    In production, this would call VirusTotal, AbuseIPDB, etc.
    """
    # Simulated database of known bad IPs
    known_bad_ips = {
        "185.220.101.1": {"reputation": "malicious", "category": "Tor Exit Node"},
        "45.33.32.156": {"reputation": "malicious", "category": "Scanner"},
        "192.168.1.1": {"reputation": "clean", "category": "Private IP"},
        "8.8.8.8": {"reputation": "clean", "category": "Google DNS"},
    }
    
    if ip_address in known_bad_ips:
        return known_bad_ips[ip_address]
    else:
        return {"reputation": "unknown", "category": "Not in database"}


def check_hash_reputation(file_hash: str) -> dict:
    """
    Check if a file hash is known to be malicious.
    In production, this would call VirusTotal, etc.
    """
    # Simulated database of known bad hashes
    known_bad_hashes = {
        "44d88612fea8a8f36de82e1278abb02f": {
            "reputation": "malicious", 
            "malware_family": "EICAR Test File"
        },
        "e3b0c44298fc1c149afbf4c8996fb924": {
            "reputation": "clean", 
            "malware_family": None,
            "note": "Empty file hash"
        },
    }
    
    # Normalize hash to lowercase
    file_hash = file_hash.lower()
    
    if file_hash in known_bad_hashes:
        return known_bad_hashes[file_hash]
    else:
        return {"reputation": "unknown", "malware_family": None}


# Define tools for Claude
TOOLS = [
    {
        "name": "check_ip_reputation",
        "description": "Check if an IP address is known to be malicious. Use this when the user asks about an IP address.",
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
    },
    {
        "name": "check_hash_reputation",
        "description": "Check if a file hash (MD5, SHA1, SHA256) is known to be malicious. Use this when the user asks about a file hash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {
                    "type": "string",
                    "description": "The file hash to check"
                }
            },
            "required": ["file_hash"]
        }
    }
]
```

### Step 2: Build the Agent Loop

```python
# =============================================================================
# AGENT LOGIC
# =============================================================================

def run_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and return the result as a string."""
    if tool_name == "check_ip_reputation":
        result = check_ip_reputation(tool_input["ip_address"])
    elif tool_name == "check_hash_reputation":
        result = check_hash_reputation(tool_input["file_hash"])
    else:
        result = {"error": f"Unknown tool: {tool_name}"}
    
    return json.dumps(result, indent=2)


def simple_agent(user_query: str) -> str:
    """
    A simple agent that can use tools to answer security questions.
    
    This is the core agent loop:
    1. Send user query to LLM with available tools
    2. If LLM wants to use a tool, execute it
    3. Send tool result back to LLM
    4. Return final response
    """
    print(f"\n{'='*60}")
    print(f"USER QUERY: {user_query}")
    print(f"{'='*60}\n")
    
    messages = [{"role": "user", "content": user_query}]
    
    # Step 1: Initial LLM call with tools
    print("🤔 Agent thinking...")
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system="You are a security analyst assistant. Use the available tools to help answer questions about IP addresses and file hashes. Be concise and helpful.",
        tools=TOOLS,
        messages=messages
    )
    
    # Step 2: Check if LLM wants to use a tool
    while response.stop_reason == "tool_use":
        # Find the tool use block
        tool_use_block = None
        for block in response.content:
            if block.type == "tool_use":
                tool_use_block = block
                break
        
        if tool_use_block:
            tool_name = tool_use_block.name
            tool_input = tool_use_block.input
            
            print(f"🔧 Agent decided to use tool: {tool_name}")
            print(f"   Input: {tool_input}")
            
            # Step 3: Execute the tool
            tool_result = run_tool(tool_name, tool_input)
            print(f"📊 Tool result: {tool_result}")
            
            # Step 4: Send result back to LLM
            messages.append({"role": "assistant", "content": response.content})
            messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_block.id,
                    "content": tool_result
                }]
            })
            
            # Get next response
            print("🤔 Agent reflecting on tool result...")
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system="You are a security analyst assistant. Use the available tools to help answer questions about IP addresses and file hashes. Be concise and helpful.",
                tools=TOOLS,
                messages=messages
            )
    
    # Extract final text response
    final_response = ""
    for block in response.content:
        if hasattr(block, "text"):
            final_response += block.text
    
    print(f"\n✅ AGENT RESPONSE: {final_response}\n")
    return final_response
```

### Step 3: Test Your Agent

```python
# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Test 1: IP Address Query
    simple_agent("Is the IP address 185.220.101.1 safe?")
    
    # Test 2: Hash Query  
    simple_agent("Check if this hash is malicious: 44d88612fea8a8f36de82e1278abb02f")
    
    # Test 3: Clean IP
    simple_agent("What can you tell me about 8.8.8.8?")
    
    # Test 4: Unknown - agent should say it doesn't know
    simple_agent("Is 1.2.3.4 a bad IP?")
```

---

## Part 3: Understanding What Happened

### The Agent Decision Process

When you run the agent, watch the output carefully:

```
==============================================================
USER QUERY: Is the IP address 185.220.101.1 safe?
==============================================================

🤔 Agent thinking...
🔧 Agent decided to use tool: check_ip_reputation    ← LLM CHOSE the tool
   Input: {'ip_address': '185.220.101.1'}
📊 Tool result: {"reputation": "malicious", "category": "Tor Exit Node"}
🤔 Agent reflecting on tool result...

✅ AGENT RESPONSE: The IP address 185.220.101.1 is NOT safe. 
   It's flagged as malicious and categorized as a Tor Exit Node...
```

**Key insight**: The LLM *decided* to use the IP reputation tool based on the question. It wasn't hardcoded!

### What Makes This an "Agent"?

1. **Tool Selection**: The LLM chose which tool to use (or no tool at all)
2. **Reasoning**: It interpreted the user's question and matched it to a tool
3. **Reflection**: After getting tool results, it formulated a helpful response
4. **Autonomy**: You didn't tell it *how* to answer - it figured it out

---

## Part 4: Exercises

### Exercise 1: Add a New Tool

Add a `check_domain_reputation` tool that checks if a domain is malicious.

```python
# TODO: Create a check_domain_reputation function
# TODO: Add it to the TOOLS list
# TODO: Handle it in run_tool()
```

<details>
<summary>Hint</summary>

Follow the same pattern as `check_ip_reputation`:
1. Create a function with simulated data
2. Add a tool definition to TOOLS with proper schema
3. Add an elif branch in run_tool()

</details>

### Exercise 2: Handle Multiple Tools

Ask a question that might need both IP and hash checking:

```python
simple_agent("I found a suspicious file with hash 44d88612fea8a8f36de82e1278abb02f that connected to 185.220.101.1. Is this malicious?")
```

Does the agent use both tools? Why or why not?

### Exercise 3: When NOT to Use Tools

Ask a general security question:

```python
simple_agent("What is a SQL injection attack?")
```

The agent should answer from its training data without using tools. Verify this happens.

---

## Part 5: Comparing to Lab 05

Now that you understand the basics, here's how Lab 05 builds on this:

| This Lab (04b) | Lab 05 (Threat Intel Agent) |
|----------------|----------------------------|
| 2 simple tools | 5+ tools (VirusTotal, MISP, etc.) |
| No memory | Conversation memory |
| Single question | Multi-turn investigation |
| Basic tool calling | Full ReAct with reasoning traces |
| Simulated data | Real API integrations |
| ~100 lines | ~500+ lines |

**When you're ready**: Move to Lab 05 to build a full-featured threat intelligence agent!

---

## Key Takeaways

1. **Agents = LLMs + Tools + Decision Making** - The LLM decides which tools to use
2. **ReAct Pattern** - Reason about what to do, Act by using a tool, Observe the result
3. **Tool Definitions Matter** - Clear descriptions help the LLM choose correctly
4. **Not Always Needed** - Simple questions don't need agents; use them when you need real-time data or actions

---

## Next Steps

| If you want to... | Go to... |
|-------------------|----------|
| Build a full threat intel agent | [Lab 05: Threat Intel Agent](../lab05-threat-intel-agent/) |
| Learn about embeddings first | [Lab 06b: Embeddings & Vectors](../lab06b-embeddings-vectors/) |
| Build a RAG system | [Lab 06: Security RAG](../lab06-security-rag/) |

---

## Resources

- [Anthropic Tool Use Documentation](https://docs.anthropic.com/en/docs/build-with-claude/tool-use)
- [OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)
- [ReAct Paper](https://arxiv.org/abs/2210.03629) - The original ReAct research
- [AI Agent Architectures](../../resources/ai-agent-architectures.md) - Deeper dive into agent patterns

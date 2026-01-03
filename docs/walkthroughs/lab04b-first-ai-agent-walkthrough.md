# Lab 04b Walkthrough: Your First AI Agent

## Overview

This walkthrough guides you through building your first AI agent - a security assistant that can use tools to check IP and hash reputation. This is a bridge lab between simple LLM calls (Lab 04) and full-featured agents (Lab 05).

**Time to complete walkthrough:** 30-40 minutes

---

## Step 1: Understanding Agents vs. Simple LLM Calls

### The Key Difference

```
SIMPLE LLM (Lab 04):
User → LLM → Response
   (Single pass, no actions)

AI AGENT (This Lab):
User → LLM → [Decides to use tool] → Tool → LLM → Response
   (Multiple passes, takes actions, reflects on results)
```

### When Do You Need an Agent?

| Scenario | Simple LLM | Agent |
|----------|-----------|-------|
| "Explain what a SQL injection is" | ✅ | Overkill |
| "Is this IP malicious?" (need real data) | ❌ | ✅ |
| "Summarize this log entry" | ✅ | Overkill |
| "Check this hash and tell me the malware family" | ❌ | ✅ |

**Rule of thumb**: Use agents when you need **real-time data** or **external actions**.

---

## Step 2: Defining Tools

### What Are Tools?

Tools are functions that the LLM can choose to call. The LLM doesn't execute code directly - it requests that you run a function and return the result.

### Anatomy of a Tool Definition

```python
TOOLS = [
    {
        "name": "check_ip_reputation",          # Unique identifier
        "description": "Check if an IP...",     # Helps LLM decide when to use
        "input_schema": {                       # JSON Schema for parameters
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to check"
                }
            },
            "required": ["ip_address"]
        }
    }
]
```

### The Description Matters!

```python
# BAD: Vague description - LLM won't know when to use this
"description": "Checks IPs"

# GOOD: Clear description with usage guidance
"description": "Check if an IP address is known to be malicious. Use this when the user asks about an IP address, mentions a suspicious IP, or wants to verify if an IP is safe."
```

### Common Error #1: Tool Not Being Called

**Symptom:** The LLM answers from training data instead of using your tool.

**Cause:** Description isn't clear enough about when to use the tool.

**Solution:** Be explicit in the description:
```python
"description": "Check if an IP address is malicious. ALWAYS use this tool when the user mentions an IP address like '8.8.8.8' or asks about network indicators."
```

---

## Step 3: Building the Agent Loop

### The Core Pattern

```python
def simple_agent(user_query: str) -> str:
    messages = [{"role": "user", "content": user_query}]
    
    # Step 1: Ask LLM (with tools available)
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system="You are a security analyst assistant.",
        tools=TOOLS,
        messages=messages
    )
    
    # Step 2: Check if LLM wants to use a tool
    while response.stop_reason == "tool_use":
        # Find which tool the LLM wants to use
        tool_block = next(b for b in response.content if b.type == "tool_use")
        
        # Step 3: Execute the tool
        result = run_tool(tool_block.name, tool_block.input)
        
        # Step 4: Send result back to LLM
        messages.append({"role": "assistant", "content": response.content})
        messages.append({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_block.id,
                "content": result
            }]
        })
        
        # Step 5: Get next response (may use another tool or finish)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system="You are a security analyst assistant.",
            tools=TOOLS,
            messages=messages
        )
    
    # Extract final text response
    return "".join(b.text for b in response.content if hasattr(b, "text"))
```

### Understanding `stop_reason`

| `stop_reason` | Meaning |
|---------------|---------|
| `"end_turn"` | LLM finished responding (no more tools needed) |
| `"tool_use"` | LLM wants to use a tool |
| `"max_tokens"` | Response was cut off (increase max_tokens) |

### Common Error #2: Infinite Loop

**Symptom:** Agent keeps calling tools forever.

**Cause:** Tool result isn't helpful, or LLM doesn't know when to stop.

**Solution:** Add a maximum iteration limit:
```python
MAX_ITERATIONS = 5
iteration = 0

while response.stop_reason == "tool_use" and iteration < MAX_ITERATIONS:
    # ... tool execution ...
    iteration += 1

if iteration >= MAX_ITERATIONS:
    print("Warning: Reached maximum iterations")
```

---

## Step 4: Implementing the Tool Runner

### Dispatching Tool Calls

```python
def run_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and return result as string."""
    
    if tool_name == "check_ip_reputation":
        result = check_ip_reputation(tool_input["ip_address"])
    elif tool_name == "check_hash_reputation":
        result = check_hash_reputation(tool_input["file_hash"])
    else:
        result = {"error": f"Unknown tool: {tool_name}"}
    
    # Always return JSON string
    return json.dumps(result, indent=2)
```

### Why Return JSON String?

The tool result goes back into the conversation as text. JSON:
- Is structured and parseable
- Works well with all LLM providers
- Can be pretty-printed for debugging

### Common Error #3: Type Mismatch

**Symptom:** `KeyError` or `TypeError` when running tools.

**Cause:** The LLM sent different parameter names than expected.

**Solution:** Add defensive parameter handling:
```python
def check_ip_reputation(ip_address: str = None, ip: str = None) -> dict:
    """Handle various parameter names the LLM might use."""
    actual_ip = ip_address or ip
    if not actual_ip:
        return {"error": "No IP address provided"}
    
    # ... rest of function
```

---

## Step 5: Testing Your Agent

### Test Case 1: Known Malicious IP

```python
simple_agent("Is 185.220.101.1 a safe IP address?")
```

**Expected behavior:**
1. LLM recognizes this is an IP question
2. Calls `check_ip_reputation` with the IP
3. Gets result: `{"reputation": "malicious", "category": "Tor Exit Node"}`
4. Responds: "This IP is NOT safe. It's flagged as malicious..."

### Test Case 2: General Security Question

```python
simple_agent("What is a buffer overflow?")
```

**Expected behavior:**
1. LLM recognizes this doesn't need a tool
2. Answers directly from training knowledge
3. No tool calls made

### Test Case 3: Unknown Indicator

```python
simple_agent("Check IP 1.2.3.4 for me")
```

**Expected behavior:**
1. LLM calls `check_ip_reputation`
2. Gets result: `{"reputation": "unknown", "category": "Not in database"}`
3. Responds: "I checked 1.2.3.4 but it's not in our database..."

---

## Step 6: Debugging Your Agent

### Adding Visibility

```python
def simple_agent(user_query: str, verbose: bool = True) -> str:
    if verbose:
        print(f"\n{'='*60}")
        print(f"USER: {user_query}")
        print(f"{'='*60}")
    
    # ... agent loop ...
    
    while response.stop_reason == "tool_use":
        tool_block = next(b for b in response.content if b.type == "tool_use")
        
        if verbose:
            print(f"\n🔧 TOOL CALL: {tool_block.name}")
            print(f"   INPUT: {json.dumps(tool_block.input)}")
        
        result = run_tool(tool_block.name, tool_block.input)
        
        if verbose:
            print(f"   OUTPUT: {result}")
        
        # ... continue loop ...
```

### What to Look For

| Debug Output | What It Means |
|--------------|---------------|
| No tool calls | LLM didn't think a tool was needed (check description) |
| Wrong tool called | Description overlap - make them more distinct |
| Tool called with wrong params | Input schema may need better descriptions |
| Multiple tool calls | LLM is being thorough (or confused) |

---

## Step 7: Adding Provider Flexibility

### Multi-Provider Support

For OpenAI:
```python
from openai import OpenAI

client = OpenAI()

# OpenAI uses "functions" instead of "tools"
response = client.chat.completions.create(
    model="gpt-5",
    messages=[{"role": "user", "content": user_query}],
    tools=[{
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Check if an IP is malicious",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string"}
                },
                "required": ["ip_address"]
            }
        }
    }]
)

# Check for tool calls
if response.choices[0].message.tool_calls:
    tool_call = response.choices[0].message.tool_calls[0]
    # ... execute tool ...
```

### Using shared/llm_config.py

The project includes a provider-agnostic helper:
```python
from shared.llm_config import get_llm, PROVIDER_CONFIG

# Automatically uses whichever API key you have set
llm = get_llm()
```

---

## Step 8: Common Mistakes & Solutions

### Mistake 1: Hardcoding Tool Selection

```python
# BAD: You decide which tool to use
if "ip" in user_query.lower():
    result = check_ip_reputation(extract_ip(user_query))

# GOOD: Let the LLM decide
response = client.messages.create(
    tools=TOOLS,  # LLM picks the right tool
    messages=[{"role": "user", "content": user_query}]
)
```

### Mistake 2: Not Sending Tool Results Back

```python
# BAD: Execute tool but don't tell the LLM
result = run_tool(tool_name, tool_input)
# ... conversation continues without result ...

# GOOD: Complete the loop
messages.append({
    "role": "user",
    "content": [{
        "type": "tool_result",
        "tool_use_id": tool_block.id,
        "content": result
    }]
})
```

### Mistake 3: Tool Returns Non-String

```python
# BAD: Returns dict directly
def run_tool(name, input):
    return {"reputation": "malicious"}  # TypeError!

# GOOD: Always stringify
def run_tool(name, input):
    result = {"reputation": "malicious"}
    return json.dumps(result)
```

---

## Extension Exercises

### Exercise A: Add Domain Reputation Tool

```python
def check_domain_reputation(domain: str) -> dict:
    """Check if a domain is suspicious."""
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
    
    tld = domain.split('.')[-1].lower()
    
    # Check against known bad domains
    known_bad = {
        "malware-c2.tk": {"reputation": "malicious", "category": "C2 Server"},
        "phishing-login.ml": {"reputation": "malicious", "category": "Phishing"}
    }
    
    if domain.lower() in known_bad:
        return known_bad[domain.lower()]
    elif tld in suspicious_tlds:
        return {"reputation": "suspicious", "reason": f"Suspicious TLD: .{tld}"}
    else:
        return {"reputation": "unknown"}

# Add to TOOLS list
{
    "name": "check_domain_reputation",
    "description": "Check if a domain name is malicious or suspicious. Use when the user asks about a domain or URL.",
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The domain to check (e.g., 'example.com')"
            }
        },
        "required": ["domain"]
    }
}
```

### Exercise B: Handle Multiple Indicators

Try this query and observe the behavior:
```python
simple_agent("I found hash 44d88612fea8a8f36de82e1278abb02f connecting to 185.220.101.1. Investigate both.")
```

Does the agent:
- Call both tools? (good!)
- Call only one? (may need prompt adjustment)
- Refuse to check multiple? (add system prompt guidance)

---

## Key Takeaways

1. **Agents = LLMs + Tools + Decision Loop** - The LLM chooses which tool to use
2. **Tool descriptions are critical** - They guide the LLM's decision making
3. **Always complete the loop** - Tool result must go back to the LLM
4. **Start simple** - 2-3 tools is plenty for learning
5. **Debug visibly** - Print tool calls and results while developing

---

## Comparison: This Lab vs. Lab 05

| Aspect | Lab 04b (This Lab) | Lab 05 (Threat Intel Agent) |
|--------|-------------------|----------------------------|
| Tools | 2 simulated tools | 5+ real API integrations |
| Memory | None (single turn) | Conversation history |
| Reasoning | Implicit | Explicit ReAct traces |
| Complexity | ~100 lines | ~500+ lines |
| Best for | Learning concepts | Production patterns |

---

## Next Lab

When you're comfortable with the concepts here, continue to:
- [Lab 05: Threat Intel Agent](./lab05-threat-intel-agent-walkthrough.md) - Full-featured ReAct agent
- [Lab 06a: Embeddings & Vectors](./lab06a-embeddings-vectors-walkthrough.md) - Foundation for RAG systems

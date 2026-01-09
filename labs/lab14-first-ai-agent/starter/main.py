#!/usr/bin/env python3
"""
Lab 04b: Your First AI Agent - Starter Code

This lab teaches you to build a simple AI agent that can use tools.
Complete the TODOs to make the agent work!

Run: python main.py
"""

import json
import os

from anthropic import Anthropic

# Initialize client
client = Anthropic()

# =============================================================================
# TOOL FUNCTIONS
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
            "malware_family": "EICAR Test File",
        },
        "e3b0c44298fc1c149afbf4c8996fb924": {
            "reputation": "clean",
            "malware_family": None,
            "note": "Empty file hash",
        },
    }

    file_hash = file_hash.lower()

    if file_hash in known_bad_hashes:
        return known_bad_hashes[file_hash]
    else:
        return {"reputation": "unknown", "malware_family": None}


# TODO Exercise 1: Add a check_domain_reputation function
# def check_domain_reputation(domain: str) -> dict:
#     """Check if a domain is known to be malicious."""
#     pass


# =============================================================================
# TOOL DEFINITIONS FOR CLAUDE
# =============================================================================

TOOLS = [
    {
        "name": "check_ip_reputation",
        "description": "Check if an IP address is known to be malicious. Use this when the user asks about an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to check (e.g., '8.8.8.8')",
                }
            },
            "required": ["ip_address"],
        },
    },
    # TODO: Add the check_hash_reputation tool definition
    # Hint: Follow the same pattern as check_ip_reputation above
    # {
    #     "name": "check_hash_reputation",
    #     "description": "...",
    #     "input_schema": {...}
    # }
]


# =============================================================================
# AGENT LOGIC
# =============================================================================


def run_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and return the result as a string."""
    if tool_name == "check_ip_reputation":
        result = check_ip_reputation(tool_input["ip_address"])
    # TODO: Add elif for check_hash_reputation
    # elif tool_name == "check_hash_reputation":
    #     result = check_hash_reputation(tool_input["file_hash"])
    else:
        result = {"error": f"Unknown tool: {tool_name}"}

    return json.dumps(result, indent=2)


def simple_agent(user_query: str) -> str:
    """
    A simple agent that can use tools to answer security questions.

    TODO: Complete the agent loop:
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

    # TODO: Make the API call to Claude with tools
    # response = client.messages.create(
    #     model="claude-sonnet-4-20250514",
    #     max_tokens=1024,
    #     system="You are a security analyst assistant...",
    #     tools=TOOLS,
    #     messages=messages
    # )

    # TODO: Check if response.stop_reason == "tool_use"
    # If so, extract tool name and input, run the tool,
    # and send the result back to Claude

    # TODO: Extract and return the final text response

    return "TODO: Implement agent logic"


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    # Test 1: IP Address Query
    result = simple_agent("Is the IP address 185.220.101.1 safe?")
    print(f"Result: {result}")

    # Uncomment these after implementing hash checking:
    # simple_agent("Check if this hash is malicious: 44d88612fea8a8f36de82e1278abb02f")
    # simple_agent("What can you tell me about 8.8.8.8?")

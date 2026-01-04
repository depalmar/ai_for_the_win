#!/usr/bin/env python3
"""
Lab 04b: Your First AI Agent - Solution

A simple AI agent that can use tools to answer security questions.

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
    known_bad_ips = {
        "185.220.101.1": {"reputation": "malicious", "category": "Tor Exit Node"},
        "45.33.32.156": {"reputation": "malicious", "category": "Scanner"},
        "192.168.1.1": {"reputation": "clean", "category": "Private IP"},
        "8.8.8.8": {"reputation": "clean", "category": "Google DNS"},
        "1.1.1.1": {"reputation": "clean", "category": "Cloudflare DNS"},
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
        "5d41402abc4b2a76b9719d911017c592": {
            "reputation": "clean",
            "malware_family": None,
            "note": "MD5 of 'hello'",
        },
    }

    file_hash = file_hash.lower()

    if file_hash in known_bad_hashes:
        return known_bad_hashes[file_hash]
    else:
        return {"reputation": "unknown", "malware_family": None}


def check_domain_reputation(domain: str) -> dict:
    """
    Check if a domain is known to be malicious.
    In production, this would call VirusTotal, URLhaus, etc.
    """
    known_bad_domains = {
        "malware.testcategory.com": {"reputation": "malicious", "category": "Malware Distribution"},
        "phishing-test.com": {"reputation": "malicious", "category": "Phishing"},
        "google.com": {"reputation": "clean", "category": "Search Engine"},
        "microsoft.com": {"reputation": "clean", "category": "Technology"},
    }

    domain = domain.lower().strip()

    if domain in known_bad_domains:
        return known_bad_domains[domain]
    else:
        return {"reputation": "unknown", "category": "Not in database"}


def get_system_info() -> dict:
    """
    Get basic system information.
    Useful for security context in agent responses.
    """
    import platform
    import socket

    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": platform.python_version(),
        "architecture": platform.machine(),
    }


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
    {
        "name": "check_hash_reputation",
        "description": "Check if a file hash (MD5, SHA1, SHA256) is known to be malicious. Use this when the user asks about a file hash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "The file hash to check"}
            },
            "required": ["file_hash"],
        },
    },
    {
        "name": "check_domain_reputation",
        "description": "Check if a domain name is known to be malicious. Use this when the user asks about a domain or URL.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain to check (e.g., 'example.com')",
                }
            },
            "required": ["domain"],
        },
    },
]


# =============================================================================
# AGENT LOGIC
# =============================================================================


def run_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and return the result as a string."""
    if tool_name == "check_ip_reputation":
        result = check_ip_reputation(tool_input["ip_address"])
    elif tool_name == "check_hash_reputation":
        result = check_hash_reputation(tool_input["file_hash"])
    elif tool_name == "check_domain_reputation":
        result = check_domain_reputation(tool_input["domain"])
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
        system="""You are a security analyst assistant. Use the available tools to help answer questions about IP addresses, file hashes, and domains. 

Guidelines:
- Use tools when the user asks about specific IOCs (IPs, hashes, domains)
- For general security questions, answer from your knowledge
- Be concise and helpful
- If a tool returns 'unknown', say so honestly""",
        tools=TOOLS,
        messages=messages,
    )

    # Step 2: Check if LLM wants to use a tool (may need multiple rounds)
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
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_block.id,
                            "content": tool_result,
                        }
                    ],
                }
            )

            # Get next response
            print("🤔 Agent reflecting on tool result...")
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system="""You are a security analyst assistant. Use the available tools to help answer questions about IP addresses, file hashes, and domains. Be concise and helpful.""",
                tools=TOOLS,
                messages=messages,
            )

    # Extract final text response
    final_response = ""
    for block in response.content:
        if hasattr(block, "text"):
            final_response += block.text

    print(f"\n✅ AGENT RESPONSE: {final_response}\n")
    return final_response


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Lab 04b: Your First AI Agent - Solution")
    print("=" * 60)

    # Test 1: IP Address Query (should use check_ip_reputation)
    simple_agent("Is the IP address 185.220.101.1 safe?")

    # Test 2: Hash Query (should use check_hash_reputation)
    simple_agent("Check if this hash is malicious: 44d88612fea8a8f36de82e1278abb02f")

    # Test 3: Clean IP (should use check_ip_reputation)
    simple_agent("What can you tell me about 8.8.8.8?")

    # Test 4: Unknown IP (should use tool but return unknown)
    simple_agent("Is 1.2.3.4 a bad IP?")

    # Test 5: Domain Query (should use check_domain_reputation)
    simple_agent("Is phishing-test.com safe to visit?")

    # Test 6: General question (should NOT use tools)
    simple_agent("What is a SQL injection attack?")

    # Test 7: Multiple IOCs (may use multiple tools)
    simple_agent(
        "I found a file with hash 44d88612fea8a8f36de82e1278abb02f connecting to 185.220.101.1. Is this suspicious?"
    )

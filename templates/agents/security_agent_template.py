#!/usr/bin/env python3
"""
Security Agent Template

A reusable template for building LangChain-based security agents.
Customize the tools and system prompt for your specific use case.
"""

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain.tools import Tool
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    from langchain_core.prompts import PromptTemplate

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Install langchain: pip install langchain langchain-anthropic")


# =============================================================================
# Agent Configuration
# =============================================================================


@dataclass
class AgentConfig:
    """Configuration for the security agent."""

    name: str = "SecurityAgent"
    model: str = "claude-sonnet-4-20250514"
    temperature: float = 0
    max_iterations: int = 10
    verbose: bool = True


# =============================================================================
# Tool Definitions - Customize these for your agent
# =============================================================================


def lookup_ip(ip: str) -> str:
    """Look up threat intelligence for an IP address."""
    # TODO: Implement actual TI lookup
    return f"IP {ip}: No threat data found (implement TI integration)"


def query_logs(query: str) -> str:
    """Query security logs/SIEM."""
    # TODO: Implement actual log query
    return f"Query '{query}': No results (implement SIEM integration)"


def get_asset_info(hostname: str) -> str:
    """Get information about an asset."""
    # TODO: Implement actual asset lookup
    return f"Asset {hostname}: Not found (implement asset inventory)"


def create_tools() -> List[Tool]:
    """Create the tools available to the agent."""
    return [
        Tool(
            name="lookup_ip",
            func=lookup_ip,
            description="Look up threat intelligence for an IP address. Input: IP address string.",
        ),
        Tool(
            name="query_logs",
            func=query_logs,
            description="Query security logs or SIEM. Input: search query string.",
        ),
        Tool(
            name="get_asset_info",
            func=get_asset_info,
            description="Get information about an asset by hostname. Input: hostname string.",
        ),
    ]


# =============================================================================
# System Prompt Template
# =============================================================================

SYSTEM_PROMPT = """You are a Security Agent assistant. Your role is to help security analysts investigate alerts and respond to incidents.

You have access to the following tools:
{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Guidelines:
1. Always gather context before making conclusions
2. Cite evidence for your findings
3. Suggest next steps when appropriate
4. Map findings to MITRE ATT&CK when relevant

Question: {input}
{agent_scratchpad}"""


# =============================================================================
# Agent Class
# =============================================================================


class SecurityAgent:
    """A reusable security agent template."""

    def __init__(self, config: AgentConfig = None):
        self.config = config or AgentConfig()
        self.tools = create_tools()
        self.llm = None
        self.agent = None
        self.executor = None

        if LANGCHAIN_AVAILABLE:
            self._initialize()

    def _initialize(self):
        """Initialize the agent components."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        self.llm = ChatAnthropic(model=self.config.model, temperature=self.config.temperature)

        prompt = PromptTemplate.from_template(SYSTEM_PROMPT)

        self.agent = create_react_agent(llm=self.llm, tools=self.tools, prompt=prompt)

        self.executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=self.config.verbose,
            max_iterations=self.config.max_iterations,
            handle_parsing_errors=True,
        )

    def run(self, query: str) -> str:
        """Run the agent with a query."""
        if not self.executor:
            return "Agent not initialized. Check LangChain installation and API key."

        result = self.executor.invoke({"input": query})
        return result.get("output", str(result))

    def add_tool(self, tool: Tool):
        """Add a new tool to the agent."""
        self.tools.append(tool)
        if LANGCHAIN_AVAILABLE:
            self._initialize()


# =============================================================================
# Usage Example
# =============================================================================


def main():
    """Example usage of the security agent template."""
    print("Security Agent Template")
    print("=" * 40)

    # Create agent with default config
    config = AgentConfig(name="InvestigationAgent", verbose=True)

    agent = SecurityAgent(config)

    # Example queries
    queries = [
        "Look up the IP address 192.168.1.100",
        "Search logs for failed login attempts",
        "Get info about WORKSTATION-42",
    ]

    for query in queries:
        print(f"\nQuery: {query}")
        print("-" * 40)
        result = agent.run(query)
        print(f"Result: {result}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Lab 05: Threat Intelligence Agent - Agent Module

Implement the ReAct agent for threat intelligence gathering.
"""

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# LangChain imports
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from tools import get_tools

# =============================================================================
# Agent System Prompt
# =============================================================================

AGENT_SYSTEM_PROMPT = """You are a threat intelligence analyst AI agent.

Your capabilities:
1. Investigate indicators of compromise (IOCs)
2. Gather context from multiple threat intelligence sources
3. Correlate findings across different data types
4. Assess threat severity and confidence
5. Provide actionable intelligence and recommendations

Available Tools:
{tools}

IMPORTANT RULES:
1. Always use tools to gather information - never make assumptions
2. Cite confidence levels: HIGH (confirmed by API), MEDIUM (correlated), LOW (inferred)
3. If a tool returns no data, acknowledge this - don't fabricate information
4. Correlate findings when investigating multiple IOCs
5. Always provide actionable recommendations

OUTPUT FORMAT:
When reasoning, use this format:

Thought: [What I need to find out or do next]
Action: [tool_name]
Action Input: {{"parameter": "value"}}

After receiving an observation, continue with another Thought/Action or provide your final answer:

Final Answer: [Your complete analysis and recommendations]

Begin!"""


# =============================================================================
# Agent Memory Class
# =============================================================================


class AgentMemory:
    """
    Memory system for the threat intelligence agent.

    TODO:
    1. Store conversation history (messages)
    2. Store investigation findings (IOC -> data)
    3. Track which IOCs have been investigated
    4. Implement context window management
    """

    def __init__(self, max_history: int = 20):
        """
        Initialize agent memory.

        Args:
            max_history: Maximum conversation turns to keep
        """
        self.max_history = max_history
        self.conversation: List[Dict[str, str]] = []
        self.findings: Dict[str, Dict] = {}
        self.investigated_iocs: set = set()

    def add_message(self, role: str, content: str):
        """
        Add a message to conversation history.

        Args:
            role: 'user', 'assistant', or 'tool'
            content: Message content

        TODO:
        1. Append message to conversation
        2. Trim if exceeds max_history
        """
        # YOUR CODE HERE
        pass

    def add_finding(self, ioc: str, ioc_type: str, data: dict):
        """
        Store an investigation finding.

        Args:
            ioc: The indicator value
            ioc_type: 'ip', 'domain', 'hash', etc.
            data: The threat intelligence data

        TODO:
        1. Store finding with metadata
        2. Mark IOC as investigated
        """
        # YOUR CODE HERE
        pass

    def get_context(self, include_findings: bool = True) -> str:
        """
        Get formatted context for LLM.

        Args:
            include_findings: Whether to include stored findings

        Returns:
            Formatted context string

        TODO:
        1. Format conversation history
        2. Optionally include findings summary
        """
        # YOUR CODE HERE
        pass

    def is_investigated(self, ioc: str) -> bool:
        """Check if IOC was already investigated."""
        return ioc in self.investigated_iocs

    def get_finding(self, ioc: str) -> Optional[dict]:
        """Get stored finding for an IOC."""
        return self.findings.get(ioc)

    def clear(self):
        """Clear all memory."""
        self.conversation = []
        self.findings = {}
        self.investigated_iocs = set()


# =============================================================================
# Threat Intelligence Agent
# =============================================================================


class ThreatIntelAgent:
    """
    AI agent for threat intelligence gathering and analysis.

    Uses the ReAct pattern:
    - Reason about what to do
    - Act by using tools
    - Observe the results
    - Repeat until task is complete
    """

    def __init__(self, llm=None, tools: List = None, verbose: bool = True):
        """
        Initialize the agent.

        Args:
            llm: Language model (creates default if None)
            tools: List of tools (uses default if None)
            verbose: Whether to print reasoning steps

        TODO:
        1. Initialize LLM if not provided
        2. Load tools if not provided
        3. Create memory instance
        4. Format system prompt with tool descriptions
        """
        self.verbose = verbose
        self.memory = AgentMemory()
        self.max_iterations = 10

        # Initialize LLM
        # YOUR CODE HERE
        # if llm is None:
        #     self.llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        # else:
        #     self.llm = llm

        # Initialize tools
        # YOUR CODE HERE
        # if tools is None:
        #     tools = get_tools()
        # self.tools = {t.name: t for t in tools}

        # Format system prompt
        # YOUR CODE HERE
        # tool_descriptions = self._format_tool_descriptions()
        # self.system_prompt = AGENT_SYSTEM_PROMPT.format(tools=tool_descriptions)

        pass

    def _format_tool_descriptions(self) -> str:
        """Format tool descriptions for the system prompt."""
        descriptions = []
        for name, tool in self.tools.items():
            descriptions.append(f"- {name}: {tool.description}")
        return "\n".join(descriptions)

    def run(self, query: str) -> str:
        """
        Run the agent on a query.

        Args:
            query: User's question or task

        Returns:
            Agent's final response

        TODO:
        1. Add query to memory
        2. Start reasoning loop
        3. Parse LLM response for Thought/Action/Final Answer
        4. Execute tools when Action is specified
        5. Feed observations back to LLM
        6. Continue until Final Answer or max iterations
        """
        # YOUR CODE HERE

        # Add query to memory
        # self.memory.add_message("user", query)

        # Build initial messages
        # messages = [
        #     SystemMessage(content=self.system_prompt),
        #     HumanMessage(content=query)
        # ]

        # Reasoning loop
        # for iteration in range(self.max_iterations):
        #     if self.verbose:
        #         print(f"\n--- Iteration {iteration + 1} ---")
        #
        #     # Get LLM response
        #     response = self.llm.invoke(messages)
        #     response_text = response.content
        #
        #     if self.verbose:
        #         print(f"Agent: {response_text[:500]}...")
        #
        #     # Check for Final Answer
        #     if "Final Answer:" in response_text:
        #         final_answer = self._extract_final_answer(response_text)
        #         self.memory.add_message("assistant", final_answer)
        #         return final_answer
        #
        #     # Parse for Action
        #     action, action_input = self._parse_action(response_text)
        #
        #     if action:
        #         # Execute tool
        #         observation = self._execute_tool(action, action_input)
        #
        #         if self.verbose:
        #             print(f"Tool Result: {observation[:300]}...")
        #
        #         # Add to messages for next iteration
        #         messages.append(AIMessage(content=response_text))
        #         messages.append(HumanMessage(content=f"Observation: {observation}"))
        #     else:
        #         # No action found, ask to continue
        #         messages.append(AIMessage(content=response_text))
        #         messages.append(HumanMessage(content="Please continue with your analysis. Use a tool or provide your Final Answer."))

        # return "Max iterations reached. Please refine your query."

        pass

    def _parse_action(self, response: str) -> tuple:
        """
        Parse tool name and arguments from LLM response.

        Args:
            response: LLM response text

        Returns:
            Tuple of (action_name, action_input_dict)

        TODO:
        1. Look for "Action:" line
        2. Look for "Action Input:" line
        3. Parse JSON from action input
        4. Return (action_name, input_dict) or (None, None)
        """
        # YOUR CODE HERE

        # action_match = re.search(r'Action:\s*(\w+)', response)
        # input_match = re.search(r'Action Input:\s*(\{.*?\})', response, re.DOTALL)

        # if action_match and input_match:
        #     action = action_match.group(1)
        #     try:
        #         action_input = json.loads(input_match.group(1))
        #         return action, action_input
        #     except json.JSONDecodeError:
        #         pass

        # return None, None

        pass

    def _execute_tool(self, tool_name: str, args: dict) -> str:
        """
        Execute a tool and return results.

        Args:
            tool_name: Name of the tool to execute
            args: Arguments to pass to the tool

        Returns:
            Tool execution result as string

        TODO:
        1. Look up tool by name
        2. Execute with arguments
        3. Handle errors gracefully
        4. Store finding in memory if applicable
        """
        # YOUR CODE HERE

        # try:
        #     tool = self.tools.get(tool_name)
        #     if not tool:
        #         return f"Error: Unknown tool '{tool_name}'. Available tools: {list(self.tools.keys())}"
        #
        #     result = tool.invoke(args)
        #
        #     # Store finding if it's an IOC lookup
        #     if tool_name in ['ip_lookup', 'domain_analysis', 'hash_check']:
        #         ioc = args.get('ip') or args.get('domain') or args.get('file_hash')
        #         if ioc:
        #             self.memory.add_finding(ioc, tool_name, result)
        #
        #     return json.dumps(result, indent=2)
        #
        # except Exception as e:
        #     return f"Error executing {tool_name}: {str(e)}"

        pass

    def _extract_final_answer(self, response: str) -> str:
        """Extract final answer from response."""
        match = re.search(r"Final Answer:\s*(.*)", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response


# =============================================================================
# Investigation Helpers
# =============================================================================


def investigate_incident(agent: ThreatIntelAgent, iocs: dict) -> str:
    """
    Investigate an incident given a set of IOCs.

    Args:
        agent: Configured ThreatIntelAgent
        iocs: Dict with keys: ips, domains, hashes

    Returns:
        Complete investigation report

    TODO:
    1. Format IOCs into investigation prompt
    2. Run agent
    3. Return report
    """

    ioc_list = []
    if iocs.get("ips"):
        ioc_list.append(f"IP Addresses: {', '.join(iocs['ips'])}")
    if iocs.get("domains"):
        ioc_list.append(f"Domains: {', '.join(iocs['domains'])}")
    if iocs.get("hashes"):
        ioc_list.append(f"File Hashes: {', '.join(iocs['hashes'])}")

    prompt = f"""Investigate this security incident. Here are the IOCs found:

{chr(10).join(ioc_list)}

For each IOC:
1. Look up threat intelligence using the appropriate tool
2. Determine if it's malicious
3. Note any connections between IOCs

After investigating all IOCs:
1. Summarize what type of attack this appears to be
2. Map observed activity to MITRE ATT&CK techniques
3. Assess overall severity (1-10)
4. Provide specific remediation recommendations

Be thorough and cite your sources."""

    return agent.run(prompt)


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()

    console.print(
        Panel.fit("[bold]Lab 05: Threat Intelligence Agent[/bold]", border_style="blue")
    )

    # Initialize agent
    console.print("\n[yellow]Initializing agent...[/yellow]")

    try:
        agent = ThreatIntelAgent(verbose=True)

        # Test single IOC
        console.print("\n[bold]Test 1: Single IP Investigation[/bold]")
        result = agent.run("Investigate this IP address: 185.143.223.47")
        console.print(Markdown(result))

        # Test multi-IOC investigation
        console.print("\n[bold]Test 2: Multi-IOC Investigation[/bold]")
        iocs = {
            "ips": ["185.143.223.47", "91.234.99.100"],
            "domains": ["evil-c2.com"],
            "hashes": [
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            ],
        }
        result = investigate_incident(agent, iocs)
        console.print(Markdown(result))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(
            "\n[yellow]Hint: Complete the TODO sections to make the agent work![/yellow]"
        )

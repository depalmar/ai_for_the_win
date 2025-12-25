#!/usr/bin/env python3
"""
Lab 10: Incident Response Copilot Agent - Starter Code

Build an AI copilot that assists analysts throughout the incident response lifecycle.
"""

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()


# =============================================================================
# Task 1: Copilot Tools
# =============================================================================


class CopilotTools:
    """Tools available to the IR Copilot."""

    def __init__(self, siem_data: dict = None):
        self.siem_data = siem_data or {}
        self.hosts = {}
        self.threat_intel = {}
        self.blocked_iocs = []
        self.isolated_hosts = []
        self.disabled_accounts = []

    def query_siem(self, query: str, time_range: str = "24h") -> List[dict]:
        """
        Query SIEM for events.

        TODO:
        1. Parse natural language query
        2. Filter events by host, user, or event type
        3. Apply time range filter
        4. Return matching events
        """
        # YOUR CODE HERE
        pass

    def get_host_info(self, hostname: str) -> dict:
        """
        Get information about a host.

        TODO:
        1. Look up host in inventory
        2. Get recent events for host
        3. Return host information
        """
        # YOUR CODE HERE
        pass

    def lookup_ioc(self, ioc: str, ioc_type: str = None) -> dict:
        """
        Look up IOC in threat intelligence.

        TODO:
        1. Detect IOC type if not provided
        2. Query threat intelligence
        3. Return assessment
        """
        # YOUR CODE HERE
        pass

    def get_alert_details(self, alert_id: str) -> dict:
        """
        Get full details of an alert.

        TODO:
        1. Look up alert by ID
        2. Get associated events
        3. Return full context
        """
        # YOUR CODE HERE
        pass

    def isolate_host(self, hostname: str, confirm: bool = False) -> dict:
        """
        Isolate host from network.

        TODO:
        1. Validate hostname
        2. Check confirmation
        3. Execute isolation (simulated)
        4. Return result
        """
        # YOUR CODE HERE
        pass

    def block_ioc(self, ioc: str, block_type: str = "all") -> dict:
        """
        Block IOC at perimeter.

        TODO:
        1. Validate IOC
        2. Add to block list
        3. Return confirmation
        """
        # YOUR CODE HERE
        pass

    def disable_account(self, username: str, confirm: bool = False) -> dict:
        """
        Disable user account.

        TODO:
        1. Validate username
        2. Check confirmation
        3. Execute disable (simulated)
        4. Return result
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 2: Agent State Management
# =============================================================================


@dataclass
class IRCopilotState:
    """State maintained throughout conversation."""

    messages: List[dict] = field(default_factory=list)
    current_incident: Optional[dict] = None
    investigated_iocs: List[dict] = field(default_factory=list)
    actions_taken: List[dict] = field(default_factory=list)
    pending_confirmations: List[dict] = field(default_factory=list)
    timeline_events: List[dict] = field(default_factory=list)
    context: dict = field(default_factory=dict)


class CopilotStateManager:
    """Manage copilot state across conversations."""

    def __init__(self):
        self.state = IRCopilotState()

    def set_incident(self, incident: dict):
        """
        Set current incident context.

        TODO:
        1. Validate incident structure
        2. Update state
        3. Initialize timeline
        """
        # YOUR CODE HERE
        pass

    def add_message(self, role: str, content: str):
        """
        Add message to history.

        TODO:
        1. Create message dict
        2. Add timestamp
        3. Append to history
        """
        # YOUR CODE HERE
        pass

    def add_ioc(self, ioc: str, result: dict):
        """
        Record investigated IOC.

        TODO:
        1. Create IOC record
        2. Check for duplicates
        3. Add to list
        """
        # YOUR CODE HERE
        pass

    def request_confirmation(self, action: dict) -> str:
        """
        Add action pending user confirmation.

        TODO:
        1. Generate confirmation ID
        2. Store action details
        3. Return confirmation ID
        """
        # YOUR CODE HERE
        pass

    def confirm_action(self, action_id: str) -> Optional[dict]:
        """
        Confirm and execute pending action.

        TODO:
        1. Find pending action
        2. Remove from pending
        3. Return action for execution
        """
        # YOUR CODE HERE
        pass

    def add_to_timeline(self, event: dict):
        """
        Add event to incident timeline.

        TODO:
        1. Add timestamp if missing
        2. Sort by time
        3. Append to timeline
        """
        # YOUR CODE HERE
        pass

    def record_action(self, action: dict):
        """
        Record completed action.

        TODO:
        1. Add timestamp
        2. Append to actions_taken
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 3: Build the Copilot Agent
# =============================================================================


class IRCopilot:
    """Incident Response Copilot Agent."""

    def __init__(self, llm=None, tools: CopilotTools = None):
        self.llm = llm
        self.tools = tools or CopilotTools()
        self.state_manager = CopilotStateManager()
        self.system_prompt = self._create_system_prompt()

    def _create_system_prompt(self) -> str:
        """
        Create copilot system prompt.

        TODO:
        1. Define copilot role
        2. List capabilities
        3. Set guidelines for responses
        """
        # YOUR CODE HERE
        pass

    def chat(self, message: str) -> str:
        """
        Process user message and respond.

        TODO:
        1. Add message to history
        2. Check for pending confirmations
        3. Determine intent
        4. Execute relevant tools
        5. Generate response
        """
        # YOUR CODE HERE
        pass

    def _determine_intent(self, message: str) -> str:
        """
        Classify user intent.

        TODO:
        1. Use LLM to classify intent
        2. Return intent category
        """
        # YOUR CODE HERE
        pass

    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """
        Execute a tool and return results.

        TODO:
        1. Map tool name to method
        2. Execute with args
        3. Return result
        """
        # YOUR CODE HERE
        pass

    def _format_response(self, tool_results: List[dict], intent: str) -> str:
        """
        Format tool results into natural response.

        TODO:
        1. Summarize findings
        2. Provide recommendations
        3. Suggest next steps
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 4: Playbook Integration
# =============================================================================


class PlaybookExecutor:
    """Execute IR playbooks with copilot assistance."""

    def __init__(self, copilot: IRCopilot, playbooks_dir: str = None):
        self.copilot = copilot
        self.playbooks = self._load_playbooks(playbooks_dir) if playbooks_dir else {}

    def _load_playbooks(self, directory: str) -> dict:
        """
        Load playbook definitions.

        TODO:
        1. Find playbook files
        2. Parse YAML/JSON
        3. Return as dict
        """
        # YOUR CODE HERE
        pass

    def suggest_playbook(self, incident: dict) -> str:
        """
        Suggest appropriate playbook for incident.

        TODO:
        1. Analyze incident type
        2. Match to available playbooks
        3. Return recommendation
        """
        # YOUR CODE HERE
        pass

    def execute_playbook(
        self, playbook_name: str, incident: dict, auto_approve: bool = False
    ) -> dict:
        """
        Execute playbook steps.

        TODO:
        1. Load playbook
        2. Execute each step
        3. Return execution summary
        """
        # YOUR CODE HERE
        pass

    def get_next_step(self, playbook_name: str, current_step: int) -> Optional[dict]:
        """
        Get next playbook step with guidance.

        TODO:
        1. Look up playbook
        2. Get step at index
        3. Return step details
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 5: Documentation Generator
# =============================================================================


class IncidentDocumenter:
    """Generate incident documentation."""

    def __init__(self, llm=None, state_manager: CopilotStateManager = None):
        self.llm = llm
        self.state = state_manager

    def generate_timeline(self) -> str:
        """
        Generate chronological timeline.

        TODO:
        1. Get events from state
        2. Sort by timestamp
        3. Format as table
        """
        # YOUR CODE HERE
        pass

    def generate_technical_report(self) -> str:
        """
        Generate technical incident report.

        TODO:
        1. Gather all evidence
        2. Format sections
        3. Include IOCs and actions
        """
        # YOUR CODE HERE
        pass

    def generate_executive_summary(self) -> str:
        """
        Generate executive summary.

        TODO:
        1. Summarize incident
        2. Focus on business impact
        3. Keep non-technical
        """
        # YOUR CODE HERE
        pass

    def generate_lessons_learned(self) -> str:
        """
        Generate lessons learned document.

        TODO:
        1. Analyze what happened
        2. Identify improvements
        3. Create action items
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    console.print(Panel.fit("[bold]Lab 10: Incident Response Copilot[/bold]", border_style="blue"))

    if not LANGCHAIN_AVAILABLE:
        console.print("[yellow]LangChain not available. Running in demo mode.[/yellow]")

    # Sample SIEM data
    sample_siem_data = {
        "events": [
            {
                "timestamp": "2024-01-15T09:15:00Z",
                "host": "WORKSTATION-42",
                "event_type": "authentication",
                "user": "jsmith",
                "details": "User login successful",
            },
            {
                "timestamp": "2024-01-15T09:23:00Z",
                "host": "WORKSTATION-42",
                "event_type": "process",
                "user": "jsmith",
                "process": "powershell.exe",
                "command_line": "powershell -enc SGVsbG8gV29ybGQ=",
                "details": "Encoded PowerShell execution",
            },
            {
                "timestamp": "2024-01-15T09:24:00Z",
                "host": "WORKSTATION-42",
                "event_type": "network",
                "user": "jsmith",
                "dest_ip": "185.143.223.47",
                "dest_port": 443,
                "details": "Outbound connection to suspicious IP",
            },
            {
                "timestamp": "2024-01-15T09:25:00Z",
                "host": "WORKSTATION-42",
                "event_type": "scheduled_task",
                "user": "jsmith",
                "task_name": "WindowsUpdate",
                "details": "New scheduled task created",
            },
        ],
        "alerts": [
            {
                "alert_id": "ALT-2024-0042",
                "timestamp": "2024-01-15T09:24:30Z",
                "host": "WORKSTATION-42",
                "severity": "HIGH",
                "title": "Suspicious PowerShell Activity",
                "description": "Encoded PowerShell command followed by C2 connection",
            }
        ],
    }

    # Initialize tools
    tools = CopilotTools(siem_data=sample_siem_data)

    # Initialize copilot
    llm = None
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key and LANGCHAIN_AVAILABLE:
        llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        console.print("[green]LLM initialized[/green]")

    copilot = IRCopilot(llm=llm, tools=tools)

    # Demo conversation
    console.print("\n[yellow]Sample IR Copilot Conversation:[/yellow]")

    demo_messages = [
        "We got an alert about suspicious PowerShell on WORKSTATION-42",
        "Look up the IP that was contacted",
        "Isolate the host",
    ]

    for msg in demo_messages:
        console.print(f"\n[bold blue]Analyst:[/bold blue] {msg}")
        response = copilot.chat(msg)

        if response:
            console.print(f"\n[bold green]Copilot:[/bold green]")
            console.print(Panel(response or "Complete the TODO sections to enable response"))
        else:
            console.print("[red]No response - complete the TODO sections[/red]")

    console.print("\n" + "=" * 60)
    console.print("Complete the TODO sections to enable the IR Copilot!")


if __name__ == "__main__":
    main()

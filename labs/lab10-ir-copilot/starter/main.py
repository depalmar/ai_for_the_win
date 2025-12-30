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
        # TODO: Ask your AI assistant:
        # "Write Python code to query SIEM events. Parse the natural language query string
        # to extract keywords for host, user, or event_type. Filter self.siem_data['events']
        # by matching these fields. Apply the time_range parameter to filter by timestamp.
        # Return the list of matching event dictionaries."
        #
        # Then review and test the generated code.
        pass

    def get_host_info(self, hostname: str) -> dict:
        """
        Get information about a host.

        TODO:
        1. Look up host in inventory
        2. Get recent events for host
        3. Return host information
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to retrieve host information. Look up the hostname in
        # self.hosts inventory. Filter self.siem_data['events'] to get recent events
        # for this host. Return a dictionary containing host details and associated events."
        #
        # Then review and test the generated code.
        pass

    def lookup_ioc(self, ioc: str, ioc_type: str = None) -> dict:
        """
        Look up IOC in threat intelligence.

        TODO:
        1. Detect IOC type if not provided
        2. Query threat intelligence
        3. Return assessment
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to look up an Indicator of Compromise (IOC). If ioc_type
        # is not provided, auto-detect whether the IOC is an IP address, domain, hash,
        # or URL using regex patterns. Query self.threat_intel for matching entries.
        # Return a dictionary with the IOC, its type, and a threat assessment."
        #
        # Then review and test the generated code.
        pass

    def get_alert_details(self, alert_id: str) -> dict:
        """
        Get full details of an alert.

        TODO:
        1. Look up alert by ID
        2. Get associated events
        3. Return full context
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to retrieve alert details. Search self.siem_data['alerts']
        # for an alert matching the alert_id. Get associated events from self.siem_data['events']
        # that match the alert's host and time window. Return a dictionary containing
        # the alert details and related events for full context."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to isolate a host from the network. Validate that hostname
        # is a non-empty string. If confirm is False, return a dict requesting confirmation.
        # If confirm is True, add the hostname to self.isolated_hosts and return a success
        # dict with the hostname and isolation timestamp (simulated operation)."
        #
        # Then review and test the generated code.
        pass

    def block_ioc(self, ioc: str, block_type: str = "all") -> dict:
        """
        Block IOC at perimeter.

        TODO:
        1. Validate IOC
        2. Add to block list
        3. Return confirmation
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to block an IOC at the network perimeter. Validate that
        # the ioc string is not empty. Add a dictionary containing the ioc, block_type,
        # and timestamp to self.blocked_iocs. Return a confirmation dict with the
        # blocked IOC details."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to disable a user account. Validate that username is a
        # non-empty string. If confirm is False, return a dict requesting confirmation.
        # If confirm is True, add the username to self.disabled_accounts and return
        # a success dict with the username and disable timestamp (simulated operation)."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to set the current incident context. Validate that the
        # incident dict contains required fields (e.g., id, title, severity). Set
        # self.state.current_incident to the incident. Initialize self.state.timeline_events
        # with an entry marking the incident start time."
        #
        # Then review and test the generated code.
        pass

    def add_message(self, role: str, content: str):
        """
        Add message to history.

        TODO:
        1. Create message dict
        2. Add timestamp
        3. Append to history
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to add a message to conversation history. Create a dict
        # with 'role' (user/assistant), 'content', and 'timestamp' (current datetime
        # in ISO format). Append this message to self.state.messages."
        #
        # Then review and test the generated code.
        pass

    def add_ioc(self, ioc: str, result: dict):
        """
        Record investigated IOC.

        TODO:
        1. Create IOC record
        2. Check for duplicates
        3. Add to list
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to record an investigated IOC. Create a dict containing
        # the 'ioc' string, 'result' dict, and 'timestamp'. Check if this IOC already
        # exists in self.state.investigated_iocs to avoid duplicates. If not a duplicate,
        # append to the list."
        #
        # Then review and test the generated code.
        pass

    def request_confirmation(self, action: dict) -> str:
        """
        Add action pending user confirmation.

        TODO:
        1. Generate confirmation ID
        2. Store action details
        3. Return confirmation ID
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to queue an action for user confirmation. Generate a unique
        # confirmation ID using uuid.uuid4(). Create a dict with 'id', 'action' details,
        # and 'timestamp'. Append to self.state.pending_confirmations. Return the
        # confirmation ID string."
        #
        # Then review and test the generated code.
        pass

    def confirm_action(self, action_id: str) -> Optional[dict]:
        """
        Confirm and execute pending action.

        TODO:
        1. Find pending action
        2. Remove from pending
        3. Return action for execution
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to confirm a pending action. Search self.state.pending_confirmations
        # for an action matching the action_id. If found, remove it from pending_confirmations
        # and return the action dict. If not found, return None."
        #
        # Then review and test the generated code.
        pass

    def add_to_timeline(self, event: dict):
        """
        Add event to incident timeline.

        TODO:
        1. Add timestamp if missing
        2. Sort by time
        3. Append to timeline
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to add an event to the incident timeline. If the event
        # dict doesn't have a 'timestamp' key, add the current datetime. Append
        # the event to self.state.timeline_events, then sort the list by timestamp
        # in chronological order."
        #
        # Then review and test the generated code.
        pass

    def record_action(self, action: dict):
        """
        Record completed action.

        TODO:
        1. Add timestamp
        2. Append to actions_taken
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to record a completed action. Add a 'timestamp' key
        # to the action dict with the current datetime in ISO format. Append the
        # action to self.state.actions_taken."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to create a system prompt for an IR Copilot. Return a
        # multi-line string that defines the copilot's role as an incident response
        # assistant, lists available capabilities (SIEM queries, IOC lookups, host
        # isolation, account disabling), and sets guidelines for clear, actionable
        # security-focused responses."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to process a user message in the IR Copilot. Add the
        # message to history using self.state_manager.add_message(). Check if the
        # message confirms a pending action. Call self._determine_intent() to classify
        # the intent. Based on intent, call self._execute_tool() with appropriate
        # arguments. Use self._format_response() to generate and return a natural
        # language response."
        #
        # Then review and test the generated code.
        pass

    def _determine_intent(self, message: str) -> str:
        """
        Classify user intent.

        TODO:
        1. Use LLM to classify intent
        2. Return intent category
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to classify the user's intent from their message. If
        # self.llm is available, use it to classify the intent into categories like
        # 'query_siem', 'lookup_ioc', 'isolate_host', 'get_alert', 'block_ioc', or
        # 'general_question'. If no LLM, use keyword matching as a fallback. Return
        # the intent category string."
        #
        # Then review and test the generated code.
        pass

    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """
        Execute a tool and return results.

        TODO:
        1. Map tool name to method
        2. Execute with args
        3. Return result
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to execute a copilot tool by name. Create a mapping dict
        # from tool names ('query_siem', 'get_host_info', 'lookup_ioc', 'get_alert_details',
        # 'isolate_host', 'block_ioc', 'disable_account') to their corresponding methods
        # on self.tools. Look up and call the appropriate method with **args. Return
        # the result dict, or an error dict if the tool is not found."
        #
        # Then review and test the generated code.
        pass

    def _format_response(self, tool_results: List[dict], intent: str) -> str:
        """
        Format tool results into natural response.

        TODO:
        1. Summarize findings
        2. Provide recommendations
        3. Suggest next steps
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to format tool results into a natural language response.
        # If self.llm is available, use it to generate a summary of the findings,
        # provide security recommendations, and suggest next investigation steps.
        # If no LLM, create a formatted string summarizing the tool_results with
        # appropriate context based on the intent category."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to load IR playbook definitions from a directory. Use
        # pathlib.Path to find all .yaml, .yml, and .json files in the directory.
        # Parse each file using yaml.safe_load() or json.load(). Return a dict mapping
        # playbook names to their definitions. Handle file not found and parse errors
        # gracefully."
        #
        # Then review and test the generated code.
        pass

    def suggest_playbook(self, incident: dict) -> str:
        """
        Suggest appropriate playbook for incident.

        TODO:
        1. Analyze incident type
        2. Match to available playbooks
        3. Return recommendation
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to suggest an IR playbook based on incident details.
        # Extract the incident type/category from the incident dict. Match against
        # available playbook names in self.playbooks (e.g., 'malware', 'phishing',
        # 'data_breach'). Return a recommendation string with the suggested playbook
        # name and reasoning."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to execute an IR playbook. Look up the playbook by name
        # in self.playbooks. Iterate through each step, using self.copilot to execute
        # actions. If auto_approve is False, pause for confirmation on destructive
        # actions. Track step results and return an execution summary dict with
        # status, completed steps, and any errors."
        #
        # Then review and test the generated code.
        pass

    def get_next_step(self, playbook_name: str, current_step: int) -> Optional[dict]:
        """
        Get next playbook step with guidance.

        TODO:
        1. Look up playbook
        2. Get step at index
        3. Return step details
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to get the next step from a playbook. Look up the playbook
        # by name in self.playbooks. Access the step at current_step index from the
        # playbook's 'steps' list. Return the step dict with details, or None if the
        # index is out of bounds or playbook not found."
        #
        # Then review and test the generated code.
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
        # TODO: Ask your AI assistant:
        # "Write Python code to generate an incident timeline. Get timeline_events
        # from self.state.state.timeline_events. Sort by timestamp in chronological
        # order. Format as a markdown table with columns for Time, Event Type, and
        # Description. Return the formatted timeline string."
        #
        # Then review and test the generated code.
        pass

    def generate_technical_report(self) -> str:
        """
        Generate technical incident report.

        TODO:
        1. Gather all evidence
        2. Format sections
        3. Include IOCs and actions
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate a technical incident report. Gather data from
        # self.state including current_incident, investigated_iocs, actions_taken, and
        # timeline_events. Format a markdown report with sections: Executive Summary,
        # Timeline, Indicators of Compromise, Actions Taken, and Technical Analysis.
        # Return the complete report string."
        #
        # Then review and test the generated code.
        pass

    def generate_executive_summary(self) -> str:
        """
        Generate executive summary.

        TODO:
        1. Summarize incident
        2. Focus on business impact
        3. Keep non-technical
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate an executive summary. Extract key details
        # from self.state.state.current_incident. If self.llm is available, use it
        # to create a non-technical summary focusing on business impact, affected
        # systems, and remediation status. If no LLM, create a template-based summary.
        # Return the executive summary string."
        #
        # Then review and test the generated code.
        pass

    def generate_lessons_learned(self) -> str:
        """
        Generate lessons learned document.

        TODO:
        1. Analyze what happened
        2. Identify improvements
        3. Create action items
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate a lessons learned document. Analyze the
        # incident data from self.state including timeline, actions taken, and IOCs.
        # If self.llm is available, use it to identify what went well, what could
        # be improved, and generate action items for future prevention. Return
        # a formatted lessons learned document string."
        #
        # Then review and test the generated code.
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

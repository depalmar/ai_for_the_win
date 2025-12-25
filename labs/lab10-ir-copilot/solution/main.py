#!/usr/bin/env python3
"""
Lab 10: Incident Response Copilot Agent - Solution

Complete implementation of an AI copilot for incident response.
"""

import json
import os
import re
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
# Task 1: Copilot Tools - SOLUTION
# =============================================================================


class CopilotTools:
    """Tools available to the IR Copilot."""

    def __init__(self, siem_data: dict = None):
        self.siem_data = siem_data or {"events": [], "alerts": []}
        self.hosts = self._build_host_inventory()
        self.threat_intel = self._load_threat_intel()
        self.blocked_iocs = []
        self.isolated_hosts = []
        self.disabled_accounts = []

    def _build_host_inventory(self) -> dict:
        """Build host inventory from SIEM data."""
        hosts = {}
        for event in self.siem_data.get("events", []):
            hostname = event.get("host")
            if hostname and hostname not in hosts:
                hosts[hostname] = {
                    "hostname": hostname,
                    "os": "Windows 10 Enterprise",
                    "ip": f"192.168.1.{len(hosts) + 100}",
                    "last_seen": event.get("timestamp"),
                    "users": [],
                    "events": [],
                }
            if hostname:
                if event.get("user") not in hosts[hostname]["users"]:
                    hosts[hostname]["users"].append(event.get("user"))
                hosts[hostname]["events"].append(event)
        return hosts

    def _load_threat_intel(self) -> dict:
        """Load threat intelligence database."""
        return {
            "185.143.223.47": {
                "classification": "Malicious",
                "confidence": "High",
                "category": "Command & Control",
                "malware_family": "Cobalt Strike",
                "first_seen": "2024-01-10",
                "reports": 23,
                "tags": ["c2", "apt", "cobalt-strike"],
            },
            "91.234.99.100": {
                "classification": "Malicious",
                "confidence": "Medium",
                "category": "Data Exfiltration",
                "malware_family": "Unknown",
                "first_seen": "2024-01-12",
                "reports": 5,
                "tags": ["exfil", "suspicious"],
            },
        }

    def query_siem(self, query: str, time_range: str = "24h") -> List[dict]:
        """Query SIEM for events."""
        events = self.siem_data.get("events", [])
        query_lower = query.lower()

        # Filter by hostname
        host_match = re.search(r"host[:\s]+(\S+)", query_lower)
        if host_match:
            hostname = host_match.group(1).upper()
            events = [e for e in events if e.get("host", "").upper() == hostname]

        # Filter by user
        user_match = re.search(r"user[:\s]+(\S+)", query_lower)
        if user_match:
            username = user_match.group(1).lower()
            events = [e for e in events if e.get("user", "").lower() == username]

        # Filter by event type
        for event_type in ["process", "network", "authentication", "scheduled_task"]:
            if event_type in query_lower:
                events = [e for e in events if e.get("event_type") == event_type]
                break

        # Simple keyword search
        keywords = ["powershell", "suspicious", "encoded", "c2"]
        for keyword in keywords:
            if keyword in query_lower:
                events = [e for e in events if keyword in str(e).lower()]

        return events

    def get_host_info(self, hostname: str) -> dict:
        """Get information about a host."""
        hostname_upper = hostname.upper()

        if hostname_upper in self.hosts:
            host_info = self.hosts[hostname_upper].copy()
            host_info["isolated"] = hostname_upper in self.isolated_hosts
            return host_info

        return {
            "error": f"Host {hostname} not found in inventory",
            "hostname": hostname,
        }

    def lookup_ioc(self, ioc: str, ioc_type: str = None) -> dict:
        """Look up IOC in threat intelligence."""
        # Auto-detect IOC type
        if ioc_type is None:
            if re.match(r"\d+\.\d+\.\d+\.\d+", ioc):
                ioc_type = "ip"
            elif re.match(r"[a-fA-F0-9]{32,64}", ioc):
                ioc_type = "hash"
            elif re.match(r"https?://", ioc):
                ioc_type = "url"
            else:
                ioc_type = "domain"

        # Check threat intel
        if ioc in self.threat_intel:
            result = self.threat_intel[ioc].copy()
            result["ioc"] = ioc
            result["ioc_type"] = ioc_type
            return result

        # Default response for unknown IOCs
        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "classification": "Unknown",
            "confidence": "N/A",
            "message": "No threat intelligence data available for this IOC",
        }

    def get_alert_details(self, alert_id: str) -> dict:
        """Get full details of an alert."""
        for alert in self.siem_data.get("alerts", []):
            if alert.get("alert_id") == alert_id:
                # Add related events
                alert_host = alert.get("host")
                related_events = [
                    e
                    for e in self.siem_data.get("events", [])
                    if e.get("host") == alert_host
                ]
                return {
                    **alert,
                    "related_events": related_events,
                    "event_count": len(related_events),
                }

        return {"error": f"Alert {alert_id} not found"}

    def isolate_host(self, hostname: str, confirm: bool = False) -> dict:
        """Isolate host from network."""
        hostname_upper = hostname.upper()

        if hostname_upper not in self.hosts:
            return {"success": False, "error": f"Host {hostname} not found"}

        if hostname_upper in self.isolated_hosts:
            return {"success": False, "error": f"Host {hostname} is already isolated"}

        if not confirm:
            return {
                "requires_confirmation": True,
                "action": "isolate_host",
                "target": hostname_upper,
                "message": f"Confirm isolation of {hostname}? This will remove the host from the network.",
            }

        # Execute isolation
        self.isolated_hosts.append(hostname_upper)
        return {
            "success": True,
            "action": "isolate_host",
            "target": hostname_upper,
            "timestamp": datetime.now().isoformat(),
            "message": f"Host {hostname} has been isolated from the network",
        }

    def block_ioc(self, ioc: str, block_type: str = "all") -> dict:
        """Block IOC at perimeter."""
        if ioc in self.blocked_iocs:
            return {"success": False, "error": f"IOC {ioc} is already blocked"}

        self.blocked_iocs.append(ioc)
        return {
            "success": True,
            "action": "block_ioc",
            "ioc": ioc,
            "block_type": block_type,
            "timestamp": datetime.now().isoformat(),
            "message": f"IOC {ioc} has been blocked at {block_type}",
        }

    def disable_account(self, username: str, confirm: bool = False) -> dict:
        """Disable user account."""
        if username in self.disabled_accounts:
            return {
                "success": False,
                "error": f"Account {username} is already disabled",
            }

        if not confirm:
            return {
                "requires_confirmation": True,
                "action": "disable_account",
                "target": username,
                "message": f"Confirm disabling account {username}?",
            }

        self.disabled_accounts.append(username)
        return {
            "success": True,
            "action": "disable_account",
            "target": username,
            "timestamp": datetime.now().isoformat(),
            "message": f"Account {username} has been disabled",
        }


# =============================================================================
# Task 2: Agent State Management - SOLUTION
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
        """Set current incident context."""
        self.state.current_incident = incident
        self.state.context["incident_id"] = incident.get("id", str(uuid.uuid4())[:8])
        self.state.context["start_time"] = datetime.now().isoformat()

        # Initialize timeline with incident creation
        self.add_to_timeline(
            {
                "event": "Incident created",
                "type": "incident",
                "details": incident.get("title", "New incident"),
            }
        )

    def add_message(self, role: str, content: str):
        """Add message to history."""
        self.state.messages.append(
            {"role": role, "content": content, "timestamp": datetime.now().isoformat()}
        )

    def add_ioc(self, ioc: str, result: dict):
        """Record investigated IOC."""
        # Check for duplicates
        for existing in self.state.investigated_iocs:
            if existing.get("ioc") == ioc:
                existing.update(result)
                return

        self.state.investigated_iocs.append(
            {"ioc": ioc, "timestamp": datetime.now().isoformat(), **result}
        )

    def request_confirmation(self, action: dict) -> str:
        """Add action pending user confirmation."""
        action_id = str(uuid.uuid4())[:8]
        self.state.pending_confirmations.append(
            {"id": action_id, "timestamp": datetime.now().isoformat(), **action}
        )
        return action_id

    def confirm_action(self, action_id: str = None) -> Optional[dict]:
        """Confirm and execute pending action."""
        if not self.state.pending_confirmations:
            return None

        # If no ID provided, confirm the most recent
        if action_id is None:
            action = self.state.pending_confirmations.pop()
            return action

        # Find by ID
        for i, action in enumerate(self.state.pending_confirmations):
            if action.get("id") == action_id:
                return self.state.pending_confirmations.pop(i)

        return None

    def has_pending_confirmations(self) -> bool:
        """Check if there are pending confirmations."""
        return len(self.state.pending_confirmations) > 0

    def get_pending_confirmation(self) -> Optional[dict]:
        """Get the current pending confirmation without removing it."""
        if self.state.pending_confirmations:
            return self.state.pending_confirmations[-1]
        return None

    def add_to_timeline(self, event: dict):
        """Add event to incident timeline."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now().isoformat()

        self.state.timeline_events.append(event)

        # Keep sorted by timestamp
        self.state.timeline_events.sort(key=lambda x: x.get("timestamp", ""))

    def record_action(self, action: dict):
        """Record completed action."""
        action["completed_at"] = datetime.now().isoformat()
        self.state.actions_taken.append(action)

        # Also add to timeline
        self.add_to_timeline(
            {
                "event": f"Action: {action.get('action', 'Unknown')}",
                "type": "action",
                "details": action.get("message", str(action)),
            }
        )


# =============================================================================
# Task 3: Build the Copilot Agent - SOLUTION
# =============================================================================


class IRCopilot:
    """Incident Response Copilot Agent."""

    def __init__(self, llm=None, tools: CopilotTools = None):
        self.llm = llm
        self.tools = tools or CopilotTools()
        self.state_manager = CopilotStateManager()
        self.system_prompt = self._create_system_prompt()

    def _create_system_prompt(self) -> str:
        """Create copilot system prompt."""
        return """You are an Incident Response Copilot, an AI assistant helping security analysts investigate and respond to security incidents.

CAPABILITIES:
- Query SIEM for events and alerts
- Look up threat intelligence for IOCs
- Get host information and status
- Isolate hosts (requires confirmation)
- Block IOCs at perimeter
- Disable user accounts (requires confirmation)
- Generate incident documentation

GUIDELINES:
1. Always explain your reasoning clearly
2. Request confirmation for destructive/containment actions
3. Cite evidence and sources for all conclusions
4. Proactively suggest next steps based on findings
5. Map findings to MITRE ATT&CK when relevant
6. Maintain awareness of the incident timeline

RESPONSE FORMAT:
- Start with what you're doing
- Present findings clearly
- Provide assessment/analysis
- Suggest recommended next steps

When investigating:
1. Gather context first (who, what, when, where)
2. Look up relevant IOCs
3. Correlate events across sources
4. Assess severity and scope
5. Recommend containment actions
6. Document findings for timeline"""

    def chat(self, message: str) -> str:
        """Process user message and respond."""
        # Add message to history
        self.state_manager.add_message("user", message)

        # Check for pending confirmations
        if self.state_manager.has_pending_confirmations():
            pending = self.state_manager.get_pending_confirmation()
            if self._is_confirmation(message):
                return self._handle_confirmation(pending)
            elif self._is_cancellation(message):
                self.state_manager.confirm_action()  # Remove without executing
                return "Action cancelled."

        # Determine intent
        intent = self._determine_intent(message)

        # Execute based on intent
        response = self._process_intent(intent, message)

        # Add response to history
        self.state_manager.add_message("assistant", response)

        return response

    def _is_confirmation(self, message: str) -> bool:
        """Check if message is a confirmation."""
        confirms = ["confirm", "yes", "proceed", "do it", "approved", "ok", "okay"]
        return message.lower().strip() in confirms

    def _is_cancellation(self, message: str) -> bool:
        """Check if message is a cancellation."""
        cancels = ["cancel", "no", "abort", "stop", "don't", "negative"]
        return message.lower().strip() in cancels

    def _handle_confirmation(self, pending: dict) -> str:
        """Handle a confirmation response."""
        action = self.state_manager.confirm_action()

        if action.get("action") == "isolate_host":
            result = self.tools.isolate_host(action["target"], confirm=True)
        elif action.get("action") == "disable_account":
            result = self.tools.disable_account(action["target"], confirm=True)
        else:
            return "Unknown action type"

        if result.get("success"):
            self.state_manager.record_action(result)
            return self._format_action_result(result)

        return f"Action failed: {result.get('error', 'Unknown error')}"

    def _determine_intent(self, message: str) -> str:
        """Classify user intent."""
        message_lower = message.lower()

        # Investigation intents
        if any(
            kw in message_lower
            for kw in [
                "what happened",
                "investigate",
                "look into",
                "check",
                "query",
                "search",
                "find",
            ]
        ):
            return "investigate"

        # IOC lookup
        if any(
            kw in message_lower
            for kw in ["look up", "lookup", "check ip", "check hash", "threat intel"]
        ):
            return "lookup_ioc"

        # Containment intents
        if any(kw in message_lower for kw in ["isolate", "quarantine", "contain"]):
            return "contain_host"

        if any(kw in message_lower for kw in ["block", "blacklist"]):
            return "block_ioc"

        if any(
            kw in message_lower
            for kw in ["disable account", "disable user", "lock account"]
        ):
            return "disable_account"

        # Documentation
        if any(
            kw in message_lower for kw in ["timeline", "report", "summary", "document"]
        ):
            return "document"

        # Questions
        if any(
            kw in message_lower
            for kw in ["what should", "recommend", "suggest", "next step"]
        ):
            return "recommend"

        return "investigate"

    def _process_intent(self, intent: str, message: str) -> str:
        """Process user intent and generate response."""
        if intent == "investigate":
            return self._handle_investigation(message)
        elif intent == "lookup_ioc":
            return self._handle_ioc_lookup(message)
        elif intent == "contain_host":
            return self._handle_containment(message)
        elif intent == "block_ioc":
            return self._handle_block_ioc(message)
        elif intent == "disable_account":
            return self._handle_disable_account(message)
        elif intent == "document":
            return self._handle_documentation(message)
        elif intent == "recommend":
            return self._handle_recommendation()
        else:
            return self._handle_investigation(message)

    def _handle_investigation(self, message: str) -> str:
        """Handle investigation requests."""
        # Extract hostname if mentioned
        host_match = re.search(
            r"(WORKSTATION|SERVER|HOST)[-_]?\d+", message, re.IGNORECASE
        )

        if host_match:
            hostname = host_match.group(0).upper()
            host_info = self.tools.get_host_info(hostname)
            events = self.tools.query_siem(f"host: {hostname}")

            # Add to timeline
            self.state_manager.add_to_timeline(
                {
                    "event": f"Investigation started for {hostname}",
                    "type": "investigation",
                }
            )

            response = f"**Investigating {hostname}**\n\n"

            if "error" not in host_info:
                response += f"**Host Information:**\n"
                response += f"- OS: {host_info.get('os')}\n"
                response += f"- IP: {host_info.get('ip')}\n"
                response += f"- Users: {', '.join(host_info.get('users', []))}\n"
                response += (
                    f"- Isolated: {'Yes' if host_info.get('isolated') else 'No'}\n\n"
                )

            response += f"**Found {len(events)} events in the last 24 hours:**\n\n"

            for event in events[:5]:
                timestamp = event.get("timestamp", "")[:19]
                event_type = event.get("event_type", "unknown")
                details = event.get("details", "")
                response += f"- `{timestamp}` [{event_type}] {details}\n"

            # Extract IOCs
            iocs = self._extract_iocs(events)
            if iocs:
                response += f"\n**IOCs Found:**\n"
                for ioc in iocs:
                    response += f"- {ioc}\n"

            # Initial assessment
            response += "\n**Initial Assessment:**\n"
            response += self._generate_assessment(events)

            # Recommendations
            response += "\n**Recommended Next Steps:**\n"
            response += "1. Look up the IP in threat intelligence\n"
            response += "2. Check for lateral movement to other hosts\n"
            response += "3. Consider host isolation if confirmed malicious\n"

            return response

        # Generic query
        events = self.tools.query_siem(message)
        return f"Found {len(events)} matching events. Specify a hostname for detailed analysis."

    def _handle_ioc_lookup(self, message: str) -> str:
        """Handle IOC lookup requests."""
        # Extract IP
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", message)
        if ip_match:
            ioc = ip_match.group(0)
            result = self.tools.lookup_ioc(ioc)
            self.state_manager.add_ioc(ioc, result)

            response = f"**Threat Intelligence for {ioc}:**\n\n"

            if result.get("classification") == "Malicious":
                response += f"**Classification:** {result['classification']} (Confidence: {result['confidence']})\n"
                response += f"**Category:** {result.get('category', 'Unknown')}\n"
                response += f"**Associated Malware:** {result.get('malware_family', 'Unknown')}\n"
                response += f"**First Seen:** {result.get('first_seen', 'Unknown')}\n"
                response += f"**Reports:** {result.get('reports', 0)} abuse reports\n"
                response += f"**Tags:** {', '.join(result.get('tags', []))}\n"

                response += "\n**Recommendation:** This IOC is known malicious. Consider blocking at the perimeter."
            else:
                response += f"No threat intelligence data available for this IOC.\n"
                response += "Consider manual analysis or checking additional sources."

            return response

        return "Please provide an IOC (IP, hash, or domain) to look up."

    def _handle_containment(self, message: str) -> str:
        """Handle host containment requests."""
        host_match = re.search(
            r"(WORKSTATION|SERVER|HOST)[-_]?\d+", message, re.IGNORECASE
        )

        if host_match:
            hostname = host_match.group(0).upper()
            result = self.tools.isolate_host(hostname, confirm=False)

            if result.get("requires_confirmation"):
                self.state_manager.request_confirmation(
                    {"action": "isolate_host", "target": hostname}
                )

                response = f"**Isolation Request for {hostname}**\n\n"
                response += "This will:\n"
                response += "- Remove host from network\n"
                response += "- Preserve current state for forensics\n"
                response += "- Block all outbound connections\n\n"
                response += "**Type 'confirm' to proceed or 'cancel' to abort.**"
                return response

            if result.get("error"):
                return f"Cannot isolate: {result['error']}"

        return "Please specify a hostname to isolate (e.g., WORKSTATION-42)"

    def _handle_block_ioc(self, message: str) -> str:
        """Handle IOC blocking requests."""
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", message)

        if ip_match:
            ioc = ip_match.group(0)
            result = self.tools.block_ioc(ioc)

            if result.get("success"):
                self.state_manager.record_action(result)
                return f"**IOC Blocked**\n\n{ioc} has been blocked at the perimeter."

            return f"Failed to block: {result.get('error')}"

        return "Please specify an IOC to block."

    def _handle_disable_account(self, message: str) -> str:
        """Handle account disable requests."""
        user_match = re.search(r"(?:user|account)\s+(\w+)", message, re.IGNORECASE)

        if user_match:
            username = user_match.group(1)
            result = self.tools.disable_account(username, confirm=False)

            if result.get("requires_confirmation"):
                self.state_manager.request_confirmation(
                    {"action": "disable_account", "target": username}
                )
                return f"Confirm disabling account {username}?\n\n**Type 'confirm' to proceed or 'cancel' to abort.**"

            if result.get("error"):
                return f"Cannot disable: {result['error']}"

        return "Please specify a username to disable."

    def _handle_documentation(self, message: str) -> str:
        """Handle documentation requests."""
        documenter = IncidentDocumenter(self.llm, self.state_manager)

        if "timeline" in message.lower():
            return documenter.generate_timeline()
        elif "executive" in message.lower() or "summary" in message.lower():
            return documenter.generate_executive_summary()
        elif "report" in message.lower():
            return documenter.generate_technical_report()
        else:
            return documenter.generate_timeline()

    def _handle_recommendation(self) -> str:
        """Generate recommendations based on current state."""
        response = "**Recommended Next Steps:**\n\n"

        # Check investigated IOCs
        malicious_iocs = [
            ioc
            for ioc in self.state_manager.state.investigated_iocs
            if ioc.get("classification") == "Malicious"
        ]

        if malicious_iocs:
            unblocked = [
                ioc
                for ioc in malicious_iocs
                if ioc["ioc"] not in self.tools.blocked_iocs
            ]
            if unblocked:
                response += f"1. Block malicious IOCs: {', '.join(i['ioc'] for i in unblocked)}\n"

        # Check for unisolated compromised hosts
        compromised_hosts = list(
            set(
                e.get("host")
                for e in self.state_manager.state.timeline_events
                if e.get("type") == "investigation"
            )
        )
        unisolated = [
            h for h in compromised_hosts if h and h not in self.tools.isolated_hosts
        ]
        if unisolated:
            response += f"2. Consider isolating: {', '.join(unisolated)}\n"

        # General recommendations
        response += "3. Document findings in the timeline\n"
        response += "4. Check for lateral movement to other hosts\n"
        response += "5. Preserve evidence for forensics\n"

        return response

    def _extract_iocs(self, events: List[dict]) -> List[str]:
        """Extract IOCs from events."""
        iocs = set()
        for event in events:
            # Extract IPs
            if "dest_ip" in event:
                iocs.add(f"IP: {event['dest_ip']}")
            # Extract suspicious tasks
            if event.get("event_type") == "scheduled_task":
                iocs.add(f"Task: {event.get('task_name', 'Unknown')}")
        return list(iocs)

    def _generate_assessment(self, events: List[dict]) -> str:
        """Generate initial assessment based on events."""
        has_encoded_ps = any("encoded" in str(e).lower() for e in events)
        has_c2 = any(e.get("dest_ip") for e in events)
        has_persistence = any(e.get("event_type") == "scheduled_task" for e in events)

        assessment = ""
        if has_encoded_ps:
            assessment += "- Encoded PowerShell execution detected (T1059.001)\n"
        if has_c2:
            assessment += "- Outbound connection to external IP (potential C2)\n"
        if has_persistence:
            assessment += "- Scheduled task creation (T1053 - Persistence)\n"

        if has_encoded_ps and has_c2:
            assessment += "\n**Severity: HIGH** - Pattern suggests active compromise with C2 communication."

        return assessment if assessment else "Insufficient data for assessment."

    def _format_action_result(self, result: dict) -> str:
        """Format action result for display."""
        action = result.get("action", "Unknown")
        target = result.get("target", "")
        timestamp = result.get("timestamp", "")[:19]

        response = f"**{action.replace('_', ' ').title()} Completed**\n\n"
        response += f"- Target: {target}\n"
        response += f"- Time: {timestamp}\n"
        response += f"- Status: Success\n"

        if action == "isolate_host":
            response += "\n**Next Steps:**\n"
            response += "1. Block associated IOCs at firewall\n"
            response += "2. Check for lateral movement to other hosts\n"
            response += "3. Collect forensic artifacts\n"
            response += "4. Reset user credentials\n"

        return response


# =============================================================================
# Task 4: Playbook Integration - SOLUTION
# =============================================================================


class PlaybookExecutor:
    """Execute IR playbooks with copilot assistance."""

    def __init__(self, copilot: IRCopilot, playbooks_dir: str = None):
        self.copilot = copilot
        self.playbooks = self._load_default_playbooks()
        if playbooks_dir:
            self.playbooks.update(self._load_playbooks(playbooks_dir))
        self.current_step = {}

    def _load_default_playbooks(self) -> dict:
        """Load default playbooks."""
        return {
            "ransomware": {
                "name": "Ransomware Response",
                "steps": [
                    {
                        "action": "isolate_affected",
                        "description": "Isolate affected systems",
                    },
                    {
                        "action": "identify_variant",
                        "description": "Identify ransomware variant",
                    },
                    {
                        "action": "assess_scope",
                        "description": "Assess scope of infection",
                    },
                    {
                        "action": "preserve_evidence",
                        "description": "Preserve evidence for forensics",
                    },
                    {
                        "action": "notify_stakeholders",
                        "description": "Notify stakeholders",
                    },
                    {
                        "action": "recovery",
                        "description": "Begin recovery from backups",
                    },
                ],
            },
            "malware": {
                "name": "Malware Response",
                "steps": [
                    {
                        "action": "investigate_host",
                        "description": "Investigate affected host",
                    },
                    {
                        "action": "lookup_iocs",
                        "description": "Look up IOCs in threat intel",
                    },
                    {
                        "action": "assess_severity",
                        "description": "Assess severity and scope",
                    },
                    {"action": "contain", "description": "Contain affected systems"},
                    {"action": "block_iocs", "description": "Block IOCs at perimeter"},
                    {"action": "eradicate", "description": "Remove malware"},
                    {"action": "verify", "description": "Verify remediation"},
                    {"action": "document", "description": "Document incident"},
                ],
            },
            "phishing": {
                "name": "Phishing Response",
                "steps": [
                    {
                        "action": "quarantine_email",
                        "description": "Quarantine phishing email",
                    },
                    {
                        "action": "identify_recipients",
                        "description": "Identify all recipients",
                    },
                    {"action": "check_clicks", "description": "Check for link clicks"},
                    {
                        "action": "credential_reset",
                        "description": "Reset credentials if needed",
                    },
                    {"action": "block_sender", "description": "Block sender domain"},
                    {"action": "awareness", "description": "Send awareness reminder"},
                ],
            },
        }

    def _load_playbooks(self, directory: str) -> dict:
        """Load playbook files from directory."""
        playbooks = {}
        path = Path(directory)

        for file in path.glob("*.json"):
            try:
                with open(file) as f:
                    pb = json.load(f)
                    playbooks[file.stem] = pb
            except (json.JSONDecodeError, IOError):
                pass

        return playbooks

    def suggest_playbook(self, incident: dict) -> str:
        """Suggest appropriate playbook for incident."""
        incident_type = incident.get("type", "").lower()
        title = incident.get("title", "").lower()

        suggestions = []

        if "ransom" in incident_type or "ransom" in title:
            suggestions.append(("ransomware", "Ransomware Response", "High match"))
        if "malware" in incident_type or "powershell" in title or "c2" in title:
            suggestions.append(("malware", "Malware Response", "High match"))
        if "phish" in incident_type or "email" in title:
            suggestions.append(("phishing", "Phishing Response", "High match"))

        if not suggestions:
            suggestions.append(("malware", "Malware Response", "Default suggestion"))

        response = "**Suggested Playbooks:**\n\n"
        for pb_id, pb_name, confidence in suggestions:
            steps = len(self.playbooks.get(pb_id, {}).get("steps", []))
            response += f"- **{pb_name}** ({steps} steps) - {confidence}\n"

        return response

    def execute_playbook(
        self, playbook_name: str, incident: dict, auto_approve: bool = False
    ) -> dict:
        """Execute playbook steps."""
        if playbook_name not in self.playbooks:
            return {"error": f"Playbook {playbook_name} not found"}

        playbook = self.playbooks[playbook_name]
        results = []

        for i, step in enumerate(playbook["steps"]):
            result = {
                "step": i + 1,
                "action": step["action"],
                "description": step["description"],
                "status": "pending",
            }
            results.append(result)

        self.current_step[playbook_name] = 0

        return {
            "playbook": playbook_name,
            "total_steps": len(playbook["steps"]),
            "results": results,
        }

    def get_next_step(
        self, playbook_name: str, current_step: int = None
    ) -> Optional[dict]:
        """Get next playbook step with guidance."""
        if playbook_name not in self.playbooks:
            return None

        playbook = self.playbooks[playbook_name]
        step_idx = (
            current_step
            if current_step is not None
            else self.current_step.get(playbook_name, 0)
        )

        if step_idx >= len(playbook["steps"]):
            return {"complete": True, "message": "All playbook steps completed"}

        step = playbook["steps"][step_idx]
        return {
            "step_number": step_idx + 1,
            "total_steps": len(playbook["steps"]),
            "action": step["action"],
            "description": step["description"],
            "guidance": f"Execute: {step['description']}",
        }


# =============================================================================
# Task 5: Documentation Generator - SOLUTION
# =============================================================================


class IncidentDocumenter:
    """Generate incident documentation."""

    def __init__(self, llm=None, state_manager: CopilotStateManager = None):
        self.llm = llm
        self.state = state_manager

    def generate_timeline(self) -> str:
        """Generate chronological timeline."""
        if not self.state or not self.state.state.timeline_events:
            return "No timeline events recorded yet."

        response = "**Incident Timeline**\n\n"
        response += "| Time | Type | Event |\n"
        response += "|------|------|-------|\n"

        for event in self.state.state.timeline_events:
            time = event.get("timestamp", "")[:19]
            event_type = event.get("type", "event")
            description = event.get("event", event.get("details", ""))
            response += f"| {time} | {event_type} | {description} |\n"

        return response

    def generate_technical_report(self) -> str:
        """Generate technical incident report."""
        response = "# Technical Incident Report\n\n"

        # Summary
        response += "## Incident Summary\n\n"
        if self.state and self.state.state.current_incident:
            inc = self.state.state.current_incident
            response += f"- **ID:** {inc.get('id', 'N/A')}\n"
            response += f"- **Title:** {inc.get('title', 'N/A')}\n"
            response += f"- **Severity:** {inc.get('severity', 'N/A')}\n"

        # Timeline
        response += "\n## Timeline\n\n"
        response += self.generate_timeline()

        # IOCs
        response += "\n## Indicators of Compromise\n\n"
        if self.state and self.state.state.investigated_iocs:
            for ioc in self.state.state.investigated_iocs:
                classification = ioc.get("classification", "Unknown")
                response += f"- `{ioc.get('ioc')}` - {classification}\n"
        else:
            response += "No IOCs recorded.\n"

        # Actions
        response += "\n## Containment Actions\n\n"
        if self.state and self.state.state.actions_taken:
            for action in self.state.state.actions_taken:
                response += f"- {action.get('action', 'Unknown')}: {action.get('target', 'N/A')}\n"
        else:
            response += "No actions taken.\n"

        # Recommendations
        response += "\n## Recommendations\n\n"
        response += "1. Monitor for additional indicators of compromise\n"
        response += "2. Review and update detection rules\n"
        response += "3. Conduct user awareness training\n"
        response += "4. Update incident response procedures\n"

        return response

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        response = "# Executive Summary\n\n"

        response += "## What Happened\n\n"
        response += "A security incident was detected involving suspicious activity on an endpoint. "
        response += (
            "The incident response team investigated and took containment actions.\n\n"
        )

        response += "## Business Impact\n\n"
        response += "- Systems affected: "
        if self.state and self.state.state.timeline_events:
            hosts = set(
                e.get("host", "")
                for e in self.state.state.timeline_events
                if e.get("host")
            )
            response += f"{len(hosts)} endpoint(s)\n"
        else:
            response += "Under investigation\n"

        response += "- Data at risk: Under assessment\n"
        response += "- Downtime: Minimal due to quick containment\n\n"

        response += "## Actions Taken\n\n"
        if self.state and self.state.state.actions_taken:
            for action in self.state.state.actions_taken:
                response += f"- {action.get('message', str(action))}\n"
        else:
            response += "- Investigation ongoing\n"

        response += "\n## Recommendations\n\n"
        response += "1. Approve any pending containment actions\n"
        response += "2. Allocate resources for full forensic analysis\n"
        response += "3. Consider engagement of external incident response if needed\n"

        return response

    def generate_lessons_learned(self) -> str:
        """Generate lessons learned document."""
        response = "# Lessons Learned\n\n"

        response += "## What Happened\n\n"
        response += "Summary of the incident and root cause.\n\n"

        response += "## What Went Well\n\n"
        response += "- Quick detection by security tools\n"
        response += "- Effective use of IR copilot for investigation\n"
        response += "- Timely containment actions\n\n"

        response += "## What Could Improve\n\n"
        response += "- Detection time could be reduced\n"
        response += "- Communication protocols need refinement\n"
        response += "- Additional automation opportunities identified\n\n"

        response += "## Action Items\n\n"
        response += "| Item | Owner | Due Date |\n"
        response += "|------|-------|----------|\n"
        response += "| Update detection rules | SOC | 1 week |\n"
        response += "| User awareness training | IT | 2 weeks |\n"
        response += "| Review IR procedures | IR Team | 1 month |\n"

        return response


# =============================================================================
# Main Execution
# =============================================================================


def main():
    """Main execution flow."""
    console.print(
        Panel.fit(
            "[bold]Lab 10: Incident Response Copilot - SOLUTION[/bold]",
            border_style="blue",
        )
    )

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

    # Initialize
    tools = CopilotTools(siem_data=sample_siem_data)

    llm = None
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key and LANGCHAIN_AVAILABLE:
        llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        console.print("[green]LLM initialized[/green]")
    else:
        console.print("[yellow]Running without LLM (demo mode)[/yellow]")

    copilot = IRCopilot(llm=llm, tools=tools)

    # Demo conversation
    console.print("\n[bold]Sample IR Copilot Conversation:[/bold]\n")
    console.print("=" * 60)

    demo_conversation = [
        "We got an alert about suspicious PowerShell on WORKSTATION-42",
        "Look up the IP 185.143.223.47",
        "Isolate the host",
        "confirm",
        "What should I do next?",
        "Generate a timeline",
    ]

    for msg in demo_conversation:
        console.print(f"\n[bold cyan]Analyst:[/bold cyan] {msg}")
        response = copilot.chat(msg)
        console.print(f"\n[bold green]Copilot:[/bold green]")
        console.print(Panel(Markdown(response), border_style="green"))

    # Playbook demo
    console.print("\n" + "=" * 60)
    console.print("\n[bold]Playbook Integration Demo:[/bold]\n")

    executor = PlaybookExecutor(copilot)
    incident = {"type": "malware", "title": "Suspicious PowerShell and C2"}
    suggestion = executor.suggest_playbook(incident)
    console.print(Markdown(suggestion))

    console.print("\n" + "=" * 60)
    console.print("[green]IR Copilot demonstration complete![/green]")


if __name__ == "__main__":
    main()

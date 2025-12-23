# Lab 10: IR Copilot - Solution Walkthrough

## Overview

Build an AI-powered Incident Response Copilot that assists analysts through interactive investigation, playbook execution, and automated documentation.

**Time:** 4-6 hours
**Difficulty:** Advanced

---

## Task 1: Conversation Architecture

### Building the Copilot Core

```python
import anthropic
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable
from enum import Enum
import json

class IncidentStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"

@dataclass
class Incident:
    id: str
    title: str
    description: str
    severity: str
    status: IncidentStatus
    created_at: datetime
    assigned_to: Optional[str] = None

    # Investigation data
    iocs: list[dict] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    actions_taken: list[dict] = field(default_factory=list)

    # Documentation
    notes: list[dict] = field(default_factory=list)

    def add_timeline_event(self, event: str, source: str = "analyst"):
        self.timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'source': source
        })

    def add_action(self, action: str, result: str):
        self.actions_taken.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'result': result
        })

class IRCopilot:
    def __init__(self):
        self.client = anthropic.Anthropic()
        self.conversation_history = []
        self.current_incident: Optional[Incident] = None
        self.tools = {}
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        return """You are an AI-powered Incident Response Copilot assisting security analysts. Your role is to:

1. Guide analysts through incident investigation
2. Help execute IR playbooks step-by-step
3. Analyze evidence and provide insights
4. Document findings automatically
5. Recommend containment and remediation actions

Available capabilities:
- Query SIEM for logs and alerts
- Look up IOCs in threat intelligence
- Check asset inventory
- Execute containment actions (with approval)
- Generate incident reports

Always:
- Be concise and actionable
- Prioritize analyst safety and evidence preservation
- Follow the incident response lifecycle
- Document everything for post-incident review
- Ask clarifying questions when needed

Current time: {timestamp}"""

    def register_tool(self, name: str, func: Callable, description: str):
        """Register a tool the copilot can use."""
        self.tools[name] = {
            'function': func,
            'description': description
        }

    def start_incident(self, incident: Incident):
        """Start working on an incident."""
        self.current_incident = incident
        self.conversation_history = []

        # Add incident context to conversation
        context = f"""New incident assigned:
- ID: {incident.id}
- Title: {incident.title}
- Severity: {incident.severity}
- Description: {incident.description}
- Status: {incident.status.value}

I'm ready to help investigate. What would you like to do first?"""

        self.conversation_history.append({
            "role": "assistant",
            "content": context
        })

        return context

    def chat(self, user_message: str) -> str:
        """Process user message and generate response."""

        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        # Build messages with system prompt
        messages = self.conversation_history.copy()

        # Create tool definitions for Claude
        tools = self._get_tool_definitions()

        # Call Claude
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=self.system_prompt.format(timestamp=datetime.now().isoformat()),
            messages=messages,
            tools=tools if tools else None
        )

        # Process response
        assistant_response = self._process_response(response)

        # Add to history
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_response
        })

        # Document in incident timeline
        if self.current_incident:
            self.current_incident.add_timeline_event(
                f"Analyst: {user_message[:100]}...",
                source="chat"
            )

        return assistant_response

    def _get_tool_definitions(self) -> list[dict]:
        """Convert registered tools to Claude tool format."""
        definitions = []

        for name, tool in self.tools.items():
            definitions.append({
                "name": name,
                "description": tool['description'],
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The query or parameters for the tool"
                        }
                    },
                    "required": ["query"]
                }
            })

        return definitions

    def _process_response(self, response) -> str:
        """Process Claude's response, handling tool calls."""

        result_parts = []

        for block in response.content:
            if block.type == "text":
                result_parts.append(block.text)
            elif block.type == "tool_use":
                # Execute tool
                tool_name = block.name
                tool_input = block.input

                if tool_name in self.tools:
                    tool_result = self.tools[tool_name]['function'](tool_input.get('query', ''))
                    result_parts.append(f"\n[Tool: {tool_name}]\n{tool_result}\n")

                    # Document tool use
                    if self.current_incident:
                        self.current_incident.add_action(
                            f"Executed {tool_name}",
                            str(tool_result)[:200]
                        )

        return "\n".join(result_parts)

# Initialize copilot
copilot = IRCopilot()
```

---

## Task 2: Tool Integration

### Adding Investigation Tools

```python
# SIEM Query Tool
def query_siem(query: str) -> str:
    """Query SIEM for logs matching criteria."""
    # In production, integrate with Splunk/Elastic/etc.

    # Simulated response
    if "failed login" in query.lower():
        return json.dumps({
            "total_hits": 47,
            "results": [
                {
                    "timestamp": "2024-12-23T14:30:00Z",
                    "event_type": "authentication_failure",
                    "username": "jsmith",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "10.0.0.5",
                    "failure_reason": "invalid_password"
                },
                {
                    "timestamp": "2024-12-23T14:30:15Z",
                    "event_type": "authentication_failure",
                    "username": "jsmith",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "10.0.0.5",
                    "failure_reason": "invalid_password"
                }
            ],
            "query_time_ms": 234
        }, indent=2)

    return json.dumps({"total_hits": 0, "results": []})

copilot.register_tool(
    "query_siem",
    query_siem,
    "Search SIEM for security events. Supports SPL-like queries."
)

# Threat Intelligence Lookup
def lookup_ioc(query: str) -> str:
    """Look up IOC in threat intelligence platforms."""

    # Simulated TI lookup
    ioc_data = {
        "192.168.1.105": {
            "type": "ip",
            "reputation": "suspicious",
            "first_seen": "2024-12-20",
            "tags": ["scanning", "brute-force"],
            "related_campaigns": ["Operation Nightfall"]
        },
        "evil-domain.com": {
            "type": "domain",
            "reputation": "malicious",
            "category": "c2",
            "malware_families": ["Cobalt Strike"]
        }
    }

    result = ioc_data.get(query, {"status": "not_found", "query": query})
    return json.dumps(result, indent=2)

copilot.register_tool(
    "lookup_ioc",
    lookup_ioc,
    "Look up indicators of compromise (IPs, domains, hashes) in threat intel."
)

# Asset Inventory Lookup
def lookup_asset(query: str) -> str:
    """Look up asset information from inventory."""

    assets = {
        "192.168.1.105": {
            "hostname": "WS-JSMITH-01",
            "type": "workstation",
            "owner": "John Smith",
            "department": "Finance",
            "os": "Windows 11",
            "last_seen": "2024-12-23T14:00:00Z",
            "criticality": "medium",
            "installed_software": ["Office 365", "Chrome", "Slack"]
        },
        "10.0.0.5": {
            "hostname": "DC-PROD-01",
            "type": "domain_controller",
            "criticality": "critical",
            "os": "Windows Server 2022"
        }
    }

    result = assets.get(query, {"status": "not_found", "query": query})
    return json.dumps(result, indent=2)

copilot.register_tool(
    "lookup_asset",
    lookup_asset,
    "Look up asset details from inventory by IP or hostname."
)

# Containment Action
def execute_containment(query: str) -> str:
    """Execute containment action (requires confirmation)."""

    # Parse action
    actions = {
        "isolate": "Network isolation initiated for specified host",
        "disable_account": "User account disabled in Active Directory",
        "block_ip": "IP address added to firewall blocklist",
        "quarantine": "File quarantined by EDR"
    }

    for action, result in actions.items():
        if action in query.lower():
            return json.dumps({
                "status": "executed",
                "action": action,
                "result": result,
                "timestamp": datetime.now().isoformat(),
                "requires_verification": True
            }, indent=2)

    return json.dumps({
        "status": "unknown_action",
        "available_actions": list(actions.keys())
    })

copilot.register_tool(
    "execute_containment",
    execute_containment,
    "Execute containment action. Available: isolate, disable_account, block_ip, quarantine"
)
```

---

## Task 3: Playbook Engine

### Guided Investigation Playbooks

```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class PlaybookStep:
    id: str
    title: str
    description: str
    tool: Optional[str] = None
    tool_query: Optional[str] = None
    requires_input: bool = False
    input_prompt: Optional[str] = None
    next_step: Optional[str] = None
    decision_steps: Optional[dict] = None  # condition -> next_step

class Playbook:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.steps: dict[str, PlaybookStep] = {}
        self.start_step: Optional[str] = None

    def add_step(self, step: PlaybookStep, is_start: bool = False):
        self.steps[step.id] = step
        if is_start:
            self.start_step = step.id

class PlaybookEngine:
    def __init__(self, copilot: IRCopilot):
        self.copilot = copilot
        self.playbooks: dict[str, Playbook] = {}
        self.current_playbook: Optional[Playbook] = None
        self.current_step: Optional[str] = None
        self.step_results: dict[str, str] = {}

    def register_playbook(self, playbook: Playbook):
        self.playbooks[playbook.name] = playbook

    def start_playbook(self, name: str) -> str:
        """Start executing a playbook."""
        if name not in self.playbooks:
            return f"Playbook '{name}' not found. Available: {list(self.playbooks.keys())}"

        self.current_playbook = self.playbooks[name]
        self.current_step = self.current_playbook.start_step
        self.step_results = {}

        return self._execute_current_step()

    def _execute_current_step(self) -> str:
        """Execute the current playbook step."""
        if not self.current_playbook or not self.current_step:
            return "No active playbook."

        step = self.current_playbook.steps[self.current_step]

        output = [f"\n## Playbook: {self.current_playbook.name}"]
        output.append(f"### Step: {step.title}")
        output.append(f"\n{step.description}")

        # Execute tool if specified
        if step.tool and step.tool in self.copilot.tools:
            query = step.tool_query or ""
            result = self.copilot.tools[step.tool]['function'](query)
            output.append(f"\n**Tool Output ({step.tool}):**\n```\n{result}\n```")
            self.step_results[step.id] = result

        # Request input if needed
        if step.requires_input:
            output.append(f"\n**Action Required:** {step.input_prompt}")
        else:
            # Auto-advance to next step
            if step.next_step:
                output.append(f"\n*Proceeding to next step...*")

        return "\n".join(output)

    def advance(self, user_input: str = None) -> str:
        """Advance to next step, optionally with user input."""
        if not self.current_playbook or not self.current_step:
            return "No active playbook."

        step = self.current_playbook.steps[self.current_step]

        # Store user input if provided
        if user_input:
            self.step_results[f"{step.id}_input"] = user_input

        # Determine next step
        if step.decision_steps and user_input:
            # Decision-based routing
            next_step = step.decision_steps.get(user_input.lower(), step.next_step)
        else:
            next_step = step.next_step

        if not next_step:
            return self._complete_playbook()

        self.current_step = next_step
        return self._execute_current_step()

    def _complete_playbook(self) -> str:
        """Complete the playbook and generate summary."""
        output = [f"\n## Playbook Complete: {self.current_playbook.name}"]
        output.append("\n### Steps Completed:")

        for step_id, step in self.current_playbook.steps.items():
            if step_id in self.step_results:
                output.append(f"- ✓ {step.title}")

        output.append("\n### Key Findings:")
        # Summarize results
        for key, value in self.step_results.items():
            if not key.endswith('_input'):
                output.append(f"- {key}: {value[:100]}...")

        self.current_playbook = None
        self.current_step = None

        return "\n".join(output)

# Create a brute force investigation playbook
def create_brute_force_playbook() -> Playbook:
    playbook = Playbook(
        "brute_force_investigation",
        "Investigate potential brute force attack"
    )

    playbook.add_step(PlaybookStep(
        id="identify_source",
        title="Identify Attack Source",
        description="Query SIEM for authentication failures to identify source IP(s).",
        tool="query_siem",
        tool_query="failed login last 24h",
        next_step="lookup_source"
    ), is_start=True)

    playbook.add_step(PlaybookStep(
        id="lookup_source",
        title="Investigate Source IP",
        description="Check threat intel and asset inventory for source IP.",
        tool="lookup_ioc",
        tool_query="192.168.1.105",
        next_step="assess_impact"
    ))

    playbook.add_step(PlaybookStep(
        id="assess_impact",
        title="Assess Impact",
        description="Determine if any authentication attempts succeeded.",
        requires_input=True,
        input_prompt="Were any login attempts successful? (yes/no)",
        decision_steps={
            "yes": "contain_threat",
            "no": "monitor_source"
        }
    ))

    playbook.add_step(PlaybookStep(
        id="contain_threat",
        title="Contain Threat",
        description="Isolate compromised system and disable account.",
        tool="execute_containment",
        tool_query="isolate host AND disable_account",
        next_step="document"
    ))

    playbook.add_step(PlaybookStep(
        id="monitor_source",
        title="Monitor Source",
        description="Add source to watch list for continued monitoring.",
        next_step="document"
    ))

    playbook.add_step(PlaybookStep(
        id="document",
        title="Document Findings",
        description="Compile investigation findings for incident report.",
        requires_input=True,
        input_prompt="Add any additional notes for the incident report:"
    ))

    return playbook

# Register playbook
playbook_engine = PlaybookEngine(copilot)
playbook_engine.register_playbook(create_brute_force_playbook())
```

---

## Task 4: Automated Documentation

### Generating Incident Reports

```python
class IncidentDocumenter:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def generate_timeline_report(self, incident: Incident) -> str:
        """Generate formatted timeline report."""

        report = [f"# Incident Timeline: {incident.id}"]
        report.append(f"\n**Title:** {incident.title}")
        report.append(f"**Severity:** {incident.severity}")
        report.append(f"**Status:** {incident.status.value}")
        report.append(f"**Created:** {incident.created_at.isoformat()}")

        if incident.timeline:
            report.append("\n## Timeline of Events\n")
            for event in sorted(incident.timeline, key=lambda x: x['timestamp']):
                report.append(f"- **{event['timestamp']}** [{event['source']}]: {event['event']}")

        if incident.actions_taken:
            report.append("\n## Actions Taken\n")
            for action in incident.actions_taken:
                report.append(f"- **{action['timestamp']}**: {action['action']}")
                report.append(f"  - Result: {action['result']}")

        if incident.iocs:
            report.append("\n## Indicators of Compromise\n")
            for ioc in incident.iocs:
                report.append(f"- **{ioc['type']}**: `{ioc['value']}`")

        if incident.affected_systems:
            report.append("\n## Affected Systems\n")
            for system in incident.affected_systems:
                report.append(f"- {system}")

        return "\n".join(report)

    def generate_executive_summary(self, incident: Incident) -> str:
        """Generate AI-powered executive summary."""

        # Compile incident data
        incident_data = {
            'id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'severity': incident.severity,
            'status': incident.status.value,
            'timeline_events': len(incident.timeline),
            'actions_taken': len(incident.actions_taken),
            'iocs_found': len(incident.iocs),
            'affected_systems': len(incident.affected_systems)
        }

        prompt = f"""Generate an executive summary for this security incident:

## Incident Data
{json.dumps(incident_data, indent=2)}

## Timeline (last 10 events)
{json.dumps(incident.timeline[-10:], indent=2)}

## Actions Taken
{json.dumps(incident.actions_taken, indent=2)}

Write a 2-3 paragraph executive summary that:
1. Summarizes what happened
2. Describes the response actions taken
3. Outlines current status and next steps
4. Uses non-technical language for leadership

Keep it concise and factual."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def generate_lessons_learned(self, incident: Incident) -> str:
        """Generate lessons learned document."""

        prompt = f"""Based on this incident, generate a lessons learned document:

## Incident Summary
- Title: {incident.title}
- Description: {incident.description}
- Severity: {incident.severity}

## Timeline
{json.dumps(incident.timeline, indent=2)}

## Actions Taken
{json.dumps(incident.actions_taken, indent=2)}

Generate a lessons learned document with:
1. What went well
2. What could be improved
3. Specific recommendations for:
   - Detection improvements
   - Response process improvements
   - Prevention measures
4. Action items with owners (use placeholder names)

Format as markdown."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Initialize documenter
documenter = IncidentDocumenter()
```

---

## Task 5: Interactive Session

### Complete IR Copilot Session Example

```python
def run_ir_session():
    """Run an interactive IR Copilot session."""

    # Create incident
    incident = Incident(
        id="INC-2024-1223",
        title="Suspected Brute Force Attack on Domain Controller",
        description="Multiple failed authentication attempts detected targeting DC-PROD-01",
        severity="HIGH",
        status=IncidentStatus.NEW,
        created_at=datetime.now()
    )

    # Start copilot
    print(copilot.start_incident(incident))

    # Interactive loop
    while True:
        user_input = input("\nYou: ").strip()

        if user_input.lower() == 'quit':
            break
        elif user_input.lower() == 'playbook':
            print(playbook_engine.start_playbook("brute_force_investigation"))
        elif user_input.lower() == 'next':
            print(playbook_engine.advance())
        elif user_input.lower().startswith('answer:'):
            answer = user_input[7:].strip()
            print(playbook_engine.advance(answer))
        elif user_input.lower() == 'report':
            print(documenter.generate_timeline_report(incident))
        elif user_input.lower() == 'summary':
            print(documenter.generate_executive_summary(incident))
        else:
            response = copilot.chat(user_input)
            print(f"\nCopilot: {response}")

# Example conversation flow
"""
Copilot: New incident assigned:
- ID: INC-2024-1223
- Title: Suspected Brute Force Attack on Domain Controller
- Severity: HIGH
...

You: What do we know about the source IP 192.168.1.105?

Copilot: Let me look up that IP in our threat intel and asset inventory.

[Tool: lookup_ioc]
{
  "type": "ip",
  "reputation": "suspicious",
  "tags": ["scanning", "brute-force"]
}

[Tool: lookup_asset]
{
  "hostname": "WS-JSMITH-01",
  "owner": "John Smith",
  "department": "Finance"
}

Based on the lookups, 192.168.1.105 is associated with workstation WS-JSMITH-01,
owned by John Smith in Finance. The IP has been flagged as suspicious with
brute-force activity tags. This could indicate:
1. John's workstation is compromised
2. Credentials were stolen and used from this system
3. An insider threat scenario

Recommended next steps:
1. Contact John Smith to verify recent activity
2. Check for malware on WS-JSMITH-01
3. Review John's account activity

Would you like me to query the SIEM for more details?

You: yes, check for any successful logins

Copilot: [Tool: query_siem]
...
"""

# Run session
if __name__ == "__main__":
    run_ir_session()
```

---

## Task 6: State Management

### Persisting Conversation and Incident State

```python
import sqlite3
from pathlib import Path

class IRStateManager:
    def __init__(self, db_path: str = "ir_copilot.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                severity TEXT,
                status TEXT,
                created_at TEXT,
                data JSON
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                role TEXT,
                content TEXT,
                timestamp TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)

        conn.commit()
        conn.close()

    def save_incident(self, incident: Incident):
        """Save incident to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO incidents
            (id, title, description, severity, status, created_at, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.id,
            incident.title,
            incident.description,
            incident.severity,
            incident.status.value,
            incident.created_at.isoformat(),
            json.dumps({
                'iocs': incident.iocs,
                'affected_systems': incident.affected_systems,
                'timeline': incident.timeline,
                'actions_taken': incident.actions_taken,
                'notes': incident.notes
            })
        ))

        conn.commit()
        conn.close()

    def load_incident(self, incident_id: str) -> Optional[Incident]:
        """Load incident from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()

        if row:
            data = json.loads(row[6])
            incident = Incident(
                id=row[0],
                title=row[1],
                description=row[2],
                severity=row[3],
                status=IncidentStatus(row[4]),
                created_at=datetime.fromisoformat(row[5]),
                iocs=data['iocs'],
                affected_systems=data['affected_systems'],
                timeline=data['timeline'],
                actions_taken=data['actions_taken'],
                notes=data['notes']
            )
            conn.close()
            return incident

        conn.close()
        return None

    def save_conversation(self, incident_id: str, history: list[dict]):
        """Save conversation history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Clear existing conversation
        cursor.execute("DELETE FROM conversations WHERE incident_id = ?", (incident_id,))

        # Insert new messages
        for msg in history:
            cursor.execute("""
                INSERT INTO conversations (incident_id, role, content, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                incident_id,
                msg['role'],
                msg['content'],
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

    def load_conversation(self, incident_id: str) -> list[dict]:
        """Load conversation history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT role, content FROM conversations
            WHERE incident_id = ? ORDER BY id
        """, (incident_id,))

        history = [{'role': row[0], 'content': row[1]} for row in cursor.fetchall()]
        conn.close()

        return history

# Initialize state manager
state_manager = IRStateManager()
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Context too long | Summarize older conversation turns |
| Tool errors | Add error handling and retries |
| Playbook stuck | Add escape commands, manual override |
| Slow responses | Cache tool results, use streaming |
| Lost state | Implement auto-save on each turn |

---

## Next Steps

- Add voice interface for hands-free operation
- Integrate with SOAR for automated response
- Build team collaboration features
- Add case management integration
- Implement ML-based response suggestions

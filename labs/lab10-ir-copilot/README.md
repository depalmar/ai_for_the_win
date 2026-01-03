# Lab 10: Incident Response Copilot Agent

Build an AI copilot that assists analysts throughout the incident response lifecycle.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Design conversational AI for IR workflows
2. Build multi-tool agent architectures
3. Implement context-aware assistance
4. Create automated playbook execution
5. Generate incident documentation automatically

---

## ⏱️ Estimated Time

120-150 minutes (with AI assistance)

---

## 📋 Prerequisites

- Completed all previous labs (1-9)
- Strong understanding of IR processes
- LLM API access

### Required Libraries

```bash
pip install langchain langchain-anthropic langgraph
pip install streamlit  # For UI
pip install rich
```

---

## 📖 Background

### IR Copilot Capabilities

```
┌─────────────────────────────────────────────────────────────┐
│                    IR COPILOT AGENT                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  INVESTIGATE          CONTAIN            REMEDIATE           │
│  ───────────          ───────            ─────────           │
│  • Query logs         • Isolate host     • Run scripts       │
│  • Analyze alerts     • Block IOCs       • Apply patches     │
│  • Correlate events   • Disable accounts • Reset creds       │
│  • Extract IOCs       • Network segment  • Clean malware     │
│                                                              │
│  DOCUMENT             COMMUNICATE        LEARN               │
│  ────────             ───────────        ─────               │
│  • Timeline           • Status updates   • Store patterns    │
│  • Evidence chain     • Exec summaries   • Update playbooks  │
│  • Lessons learned    • Ticket updates   • Train on cases    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Conversation Patterns

| User Says | Copilot Does |
|-----------|-------------|
| "What happened on SERVER01?" | Queries logs, summarizes events |
| "Is this IP malicious?" | Looks up TI, provides assessment |
| "Isolate this host" | Confirms, executes isolation |
| "What should I do next?" | Suggests playbook steps |
| "Generate timeline" | Creates incident timeline |
| "Write exec summary" | Generates summary for leadership |

---

## 🔬 Lab Tasks

### Task 1: Copilot Tools (25 min)

```python
# Define tools the copilot can use

class CopilotTools:
    """Tools available to the IR Copilot."""
    
    # Investigation Tools
    def query_siem(self, query: str, time_range: str = "24h") -> List[dict]:
        """
        Query SIEM for events.
        
        TODO:
        1. Parse natural language to query syntax
        2. Execute search
        3. Return formatted results
        """
        pass
    
    def get_host_info(self, hostname: str) -> dict:
        """
        Get information about a host.
        
        Returns:
        - OS, IP, last seen
        - Recent events
        - Installed software
        - Running processes
        """
        pass
    
    def lookup_ioc(self, ioc: str, ioc_type: str = None) -> dict:
        """
        Look up IOC in threat intelligence.
        
        Auto-detects type: IP, domain, hash, URL
        """
        pass
    
    def get_alert_details(self, alert_id: str) -> dict:
        """Get full details of an alert."""
        pass
    
    # Containment Tools
    def isolate_host(self, hostname: str, confirm: bool = False) -> dict:
        """
        Isolate host from network.
        
        Requires confirmation for execution.
        """
        pass
    
    def block_ioc(self, ioc: str, block_type: str = "all") -> dict:
        """
        Block IOC at perimeter.
        
        block_type: firewall, proxy, dns, all
        """
        pass
    
    def disable_account(self, username: str, confirm: bool = False) -> dict:
        """Disable user account."""
        pass
    
    # Documentation Tools
    def create_timeline(self, events: List[dict]) -> str:
        """Generate incident timeline."""
        pass
    
    def generate_report(self, incident_id: str, report_type: str) -> str:
        """
        Generate incident report.
        
        report_type: technical, executive, lessons_learned
        """
        pass
    
    def update_ticket(self, ticket_id: str, update: str) -> dict:
        """Update incident ticket."""
        pass
```

### Task 2: Agent State Management (20 min)

```python
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph

class IRCopilotState(TypedDict):
    """State maintained throughout conversation."""
    
    messages: List[dict]              # Conversation history
    current_incident: Optional[dict]   # Active incident
    investigated_iocs: List[str]       # IOCs already checked
    actions_taken: List[dict]          # Containment actions
    pending_confirmations: List[dict]  # Actions awaiting approval
    timeline_events: List[dict]        # Events for timeline
    context: dict                      # Additional context


class CopilotStateManager:
    """Manage copilot state across conversations."""
    
    def __init__(self):
        self.state = IRCopilotState(
            messages=[],
            current_incident=None,
            investigated_iocs=[],
            actions_taken=[],
            pending_confirmations=[],
            timeline_events=[],
            context={}
        )
    
    def set_incident(self, incident: dict):
        """Set current incident context."""
        pass
    
    def add_ioc(self, ioc: str, result: dict):
        """Record investigated IOC."""
        pass
    
    def request_confirmation(self, action: dict):
        """Add action pending user confirmation."""
        pass
    
    def confirm_action(self, action_id: str) -> dict:
        """Confirm and execute pending action."""
        pass
    
    def add_to_timeline(self, event: dict):
        """Add event to incident timeline."""
        pass
```

### Task 3: Build the Copilot Agent (30 min)

```python
class IRCopilot:
    """Incident Response Copilot Agent."""
    
    def __init__(self, llm, tools: CopilotTools):
        self.llm = llm
        self.tools = tools
        self.state_manager = CopilotStateManager()
        self.system_prompt = self._create_system_prompt()
    
    def _create_system_prompt(self) -> str:
        """
        Create copilot system prompt.
        
        TODO:
        1. Define copilot role and capabilities
        2. List available tools
        3. Set safety guidelines
        4. Define response format
        """
        return """You are an Incident Response Copilot...
        
CAPABILITIES:
- Query logs and SIEM
- Look up threat intelligence
- Analyze alerts and events
- Suggest containment actions
- Generate documentation

GUIDELINES:
- Always explain your reasoning
- Request confirmation for destructive actions
- Cite evidence for conclusions
- Suggest next steps proactively

When investigating:
1. Gather context first
2. Look up IOCs
3. Correlate events
4. Assess severity
5. Recommend actions

Available tools: {tools}
"""
    
    def chat(self, message: str) -> str:
        """
        Process user message and respond.
        
        TODO:
        1. Add message to history
        2. Determine intent
        3. Execute relevant tools
        4. Generate response
        5. Suggest next actions
        """
        pass
    
    def _determine_intent(self, message: str) -> str:
        """
        Classify user intent.
        
        Intents:
        - investigate: Gather information
        - contain: Take containment action
        - document: Generate documentation
        - explain: Explain something
        - suggest: Ask for recommendations
        """
        pass
    
    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """Execute a tool and return results."""
        pass
    
    def _require_confirmation(self, action: dict) -> str:
        """
        Check if action needs confirmation.
        
        High-risk actions requiring confirmation:
        - Host isolation
        - Account disabling
        - Firewall changes
        """
        pass
```

### Task 4: Playbook Integration (20 min)

```python
class PlaybookExecutor:
    """Execute IR playbooks with copilot assistance."""
    
    def __init__(self, copilot: IRCopilot, playbooks_dir: str):
        self.copilot = copilot
        self.playbooks = self._load_playbooks(playbooks_dir)
    
    def _load_playbooks(self, directory: str) -> dict:
        """Load playbook definitions."""
        pass
    
    def suggest_playbook(self, incident: dict) -> str:
        """
        Suggest appropriate playbook for incident.
        
        TODO:
        1. Analyze incident type
        2. Match to available playbooks
        3. Return recommendation
        """
        pass
    
    def execute_playbook(
        self,
        playbook_name: str,
        incident: dict,
        auto_approve: bool = False
    ) -> dict:
        """
        Execute playbook steps.
        
        TODO:
        1. Load playbook
        2. For each step:
           - Explain what will happen
           - Execute or request confirmation
           - Record result
        3. Return execution summary
        """
        pass
    
    def get_next_step(self, playbook_name: str, current_step: int) -> dict:
        """Get next playbook step with copilot guidance."""
        pass
```

### Task 5: Documentation Generator (15 min)

```python
class IncidentDocumenter:
    """Generate incident documentation."""
    
    def __init__(self, llm, state_manager: CopilotStateManager):
        self.llm = llm
        self.state = state_manager
    
    def generate_timeline(self) -> str:
        """
        Generate chronological timeline.
        
        Format:
        | Time | Event | Source | Significance |
        |------|-------|--------|--------------|
        """
        pass
    
    def generate_technical_report(self) -> str:
        """
        Generate technical incident report.
        
        Sections:
        - Incident Summary
        - Timeline
        - Technical Analysis
        - IOCs
        - Containment Actions
        - Recommendations
        """
        pass
    
    def generate_executive_summary(self) -> str:
        """
        Generate executive summary.
        
        TODO:
        1. Summarize in non-technical terms
        2. Focus on business impact
        3. Include key decisions needed
        4. Keep to 1 page
        """
        pass
    
    def generate_lessons_learned(self) -> str:
        """
        Generate lessons learned document.
        
        Sections:
        - What happened
        - What went well
        - What could improve
        - Action items
        """
        pass
```

### Task 6: Interactive UI (15 min)

```python
# streamlit_app.py

import streamlit as st

def create_copilot_ui():
    """
    Create Streamlit UI for IR Copilot.
    
    TODO:
    1. Chat interface
    2. Incident context panel
    3. Action confirmation dialogs
    4. Timeline visualization
    5. Report generation buttons
    """
    
    st.title("🛡️ IR Copilot")
    
    # Sidebar - Incident Context
    with st.sidebar:
        st.header("Current Incident")
        # Display incident info
        
        st.header("Actions Taken")
        # List actions
        
        st.header("Quick Actions")
        if st.button("Generate Timeline"):
            pass
        if st.button("Create Report"):
            pass
    
    # Main chat interface
    st.header("Chat with Copilot")
    
    # Message history
    for msg in st.session_state.get("messages", []):
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
    
    # Input
    if prompt := st.chat_input("Ask the copilot..."):
        # Process message
        pass
```

---

## 📁 Files

```
lab10-ir-copilot/
├── README.md
├── starter/
│   ├── main.py
│   ├── tools.py
│   ├── agent.py
│   ├── state.py
│   ├── playbooks.py
│   ├── documenter.py
│   └── streamlit_app.py
├── solution/
│   └── main.py
├── playbooks/
│   ├── ransomware.yaml
│   ├── phishing.yaml
│   ├── data_breach.yaml
│   └── malware.yaml
├── data/
│   ├── sample_incident.json
│   └── mock_siem_data.json
└── tests/
    └── test_copilot.py
```

---

## 💬 Sample Conversation

```
User: We got an alert about suspicious PowerShell on WORKSTATION-42

Copilot: I'll investigate WORKSTATION-42. Let me gather some information.

🔍 Querying SIEM for recent events on WORKSTATION-42...

Found 47 events in the last 24 hours. Here's what I see:

**Timeline Summary:**
- 09:15 - User jsmith logged in
- 09:23 - PowerShell executed encoded command
- 09:24 - Network connection to 185.x.x.x:443
- 09:25 - New scheduled task created

**Initial Assessment:** This looks like a potential compromise. The PowerShell 
execution pattern matches T1059.001 (PowerShell) and the C2 connection suggests 
active attacker access.

**IOCs Found:**
- IP: 185.143.223.47
- Scheduled Task: "WindowsUpdate"

Would you like me to:
1. Look up the IP in threat intelligence?
2. Get more details about the scheduled task?
3. Start containment procedures?

---

User: Look up the IP and then isolate the host

Copilot: 🔍 Looking up 185.143.223.47...

**Threat Intelligence Results:**
- **Classification:** Malicious (High Confidence)
- **Category:** Command & Control
- **Associated Malware:** Cobalt Strike
- **First Seen:** 2024-01-10
- **Reports:** 23 abuse reports

This IP is associated with known Cobalt Strike infrastructure.

⚠️ **Isolation Request**
You've requested to isolate WORKSTATION-42. This will:
- Remove host from network
- Preserve current state for forensics
- Block all outbound connections

**Type 'confirm' to proceed or 'cancel' to abort.**

---

User: confirm

Copilot: ✅ **Host Isolated**

WORKSTATION-42 has been isolated from the network.

**Actions Taken:**
1. Network isolation enabled via EDR
2. Host quarantined at 10:45 UTC
3. Incident ticket INC-2024-0142 created

**Next Recommended Steps:**
1. Block IOC 185.143.223.47 at firewall
2. Check for lateral movement to other hosts
3. Collect forensic artifacts from WORKSTATION-42
4. Reset credentials for user jsmith

Shall I proceed with any of these?
```

---

## ✅ Success Criteria

- [ ] Copilot understands IR context
- [ ] Tools execute correctly
- [ ] Confirmation required for dangerous actions
- [ ] Conversation maintains context
- [ ] Documentation generates correctly
- [ ] Playbooks execute step-by-step
- [ ] UI is functional and intuitive

---

## 🚀 Bonus Challenges

1. **Voice Interface**: Add speech-to-text for hands-free use
2. **Team Collaboration**: Multiple analysts on same incident
3. **Learning**: Improve from analyst feedback
4. **Integration**: Connect to real SIEM/EDR/SOAR
5. **Mobile**: Create mobile-friendly interface

---

## 🎓 Capstone Project

**Build a complete IR Copilot** that:

1. Handles multiple concurrent incidents
2. Integrates with your lab SIEM
3. Executes real playbooks
4. Generates compliant documentation
5. Learns from past incidents

**Deliverables:**
- Working copilot application
- 3 custom playbooks
- Integration documentation
- Demo video

---

## 📚 Resources

- [LangGraph](https://python.langchain.com/docs/langgraph)
- [Streamlit](https://streamlit.io/)
- [NIST IR Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS IR Process](https://www.sans.org/white-papers/incident-handlers-handbook/)

---

> **Stuck?** See the [Lab 10 Walkthrough](../../docs/walkthroughs/lab10-ir-copilot-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 11 - AI-Powered Ransomware Detection](../lab11-ransomware-detection/)

#!/usr/bin/env python3
"""Tests for Lab 10: Incident Response Copilot Agent."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab10-ir-copilot" / "solution")
sys.path.insert(0, lab_path)

from main import (
    CopilotStateManager,
    CopilotTools,
    IncidentDocumenter,
    IRCopilot,
    IRCopilotState,
    PlaybookExecutor,
)


@pytest.fixture
def sample_siem_data():
    """Create sample SIEM data."""
    return {
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
                "command_line": "powershell -enc SGVsbG8=",
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
        ],
        "alerts": [
            {
                "alert_id": "ALT-2024-0042",
                "timestamp": "2024-01-15T09:24:30Z",
                "host": "WORKSTATION-42",
                "severity": "HIGH",
                "title": "Suspicious PowerShell Activity",
            }
        ],
    }


@pytest.fixture
def copilot_tools(sample_siem_data):
    """Create CopilotTools instance."""
    return CopilotTools(siem_data=sample_siem_data)


@pytest.fixture
def state_manager():
    """Create CopilotStateManager instance."""
    return CopilotStateManager()


@pytest.fixture
def copilot(copilot_tools):
    """Create IRCopilot instance."""
    return IRCopilot(llm=None, tools=copilot_tools)


class TestCopilotTools:
    """Tests for CopilotTools."""

    def test_query_siem_by_host(self, copilot_tools):
        """Test SIEM query by hostname."""
        events = copilot_tools.query_siem("host: WORKSTATION-42")

        assert events is not None
        assert len(events) == 3
        assert all(e["host"] == "WORKSTATION-42" for e in events)

    def test_query_siem_by_event_type(self, copilot_tools):
        """Test SIEM query by event type."""
        events = copilot_tools.query_siem("process events")

        assert events is not None
        assert all(e["event_type"] == "process" for e in events)

    def test_get_host_info(self, copilot_tools):
        """Test host information retrieval."""
        host_info = copilot_tools.get_host_info("WORKSTATION-42")

        assert host_info is not None
        assert "hostname" in host_info
        assert host_info["hostname"] == "WORKSTATION-42"
        assert "users" in host_info

    def test_get_host_info_not_found(self, copilot_tools):
        """Test host info for non-existent host."""
        host_info = copilot_tools.get_host_info("NONEXISTENT-HOST")

        assert host_info is not None
        assert "error" in host_info

    def test_lookup_malicious_ioc(self, copilot_tools):
        """Test IOC lookup for known malicious IP."""
        result = copilot_tools.lookup_ioc("185.143.223.47")

        assert result is not None
        assert result["classification"] == "Malicious"
        assert "Cobalt Strike" in result.get("malware_family", "")

    def test_lookup_unknown_ioc(self, copilot_tools):
        """Test IOC lookup for unknown IP."""
        result = copilot_tools.lookup_ioc("8.8.8.8")

        assert result is not None
        assert result["classification"] == "Unknown"

    def test_isolate_host_requires_confirmation(self, copilot_tools):
        """Test host isolation requires confirmation."""
        result = copilot_tools.isolate_host("WORKSTATION-42", confirm=False)

        assert result is not None
        assert result.get("requires_confirmation") is True

    def test_isolate_host_with_confirmation(self, copilot_tools):
        """Test host isolation with confirmation."""
        result = copilot_tools.isolate_host("WORKSTATION-42", confirm=True)

        assert result is not None
        assert result.get("success") is True
        assert "WORKSTATION-42" in copilot_tools.isolated_hosts

    def test_block_ioc(self, copilot_tools):
        """Test IOC blocking."""
        result = copilot_tools.block_ioc("185.143.223.47")

        assert result is not None
        assert result.get("success") is True
        assert "185.143.223.47" in copilot_tools.blocked_iocs


class TestCopilotStateManager:
    """Tests for CopilotStateManager."""

    def test_initial_state(self, state_manager):
        """Test initial state."""
        assert state_manager.state is not None
        assert state_manager.state.messages == []
        assert state_manager.state.current_incident is None

    def test_set_incident(self, state_manager):
        """Test setting current incident."""
        incident = {"id": "INC-001", "title": "Test Incident"}
        state_manager.set_incident(incident)

        assert state_manager.state.current_incident == incident
        assert "incident_id" in state_manager.state.context

    def test_add_message(self, state_manager):
        """Test adding messages."""
        state_manager.add_message("user", "Hello")
        state_manager.add_message("assistant", "Hi there")

        assert len(state_manager.state.messages) == 2
        assert state_manager.state.messages[0]["role"] == "user"
        assert state_manager.state.messages[1]["role"] == "assistant"

    def test_add_ioc(self, state_manager):
        """Test adding investigated IOC."""
        state_manager.add_ioc("192.168.1.1", {"classification": "Benign"})

        assert len(state_manager.state.investigated_iocs) == 1
        assert state_manager.state.investigated_iocs[0]["ioc"] == "192.168.1.1"

    def test_request_confirmation(self, state_manager):
        """Test requesting confirmation."""
        action = {"action": "isolate_host", "target": "HOST-01"}
        action_id = state_manager.request_confirmation(action)

        assert action_id is not None
        assert len(state_manager.state.pending_confirmations) == 1

    def test_confirm_action(self, state_manager):
        """Test confirming action."""
        action = {"action": "isolate_host", "target": "HOST-01"}
        state_manager.request_confirmation(action)

        confirmed = state_manager.confirm_action()

        assert confirmed is not None
        assert confirmed["action"] == "isolate_host"
        assert len(state_manager.state.pending_confirmations) == 0

    def test_add_to_timeline(self, state_manager):
        """Test adding timeline events."""
        event = {"event": "Investigation started", "type": "investigation"}
        state_manager.add_to_timeline(event)

        assert len(state_manager.state.timeline_events) == 1
        assert "timestamp" in state_manager.state.timeline_events[0]


class TestIRCopilot:
    """Tests for IRCopilot."""

    def test_copilot_initialization(self, copilot):
        """Test copilot initialization."""
        assert copilot is not None
        assert copilot.tools is not None
        assert copilot.state_manager is not None

    def test_system_prompt_created(self, copilot):
        """Test system prompt is created."""
        assert copilot.system_prompt is not None
        assert len(copilot.system_prompt) > 0

    def test_chat_investigation(self, copilot):
        """Test investigation chat."""
        response = copilot.chat("What happened on WORKSTATION-42?")

        assert response is not None
        assert len(response) > 0
        assert "WORKSTATION-42" in response

    def test_chat_ioc_lookup(self, copilot):
        """Test IOC lookup chat."""
        response = copilot.chat("Look up IP 185.143.223.47")

        assert response is not None
        assert "185.143.223.47" in response
        assert "Malicious" in response or "malicious" in response.lower()

    def test_chat_containment_request(self, copilot):
        """Test containment request requires confirmation."""
        response = copilot.chat("Isolate WORKSTATION-42")

        assert response is not None
        assert "confirm" in response.lower()

    def test_chat_confirmation_flow(self, copilot):
        """Test confirmation flow."""
        # Request isolation
        copilot.chat("Isolate WORKSTATION-42")

        # Confirm
        response = copilot.chat("confirm")

        assert response is not None
        assert "isolated" in response.lower() or "success" in response.lower()


class TestPlaybookExecutor:
    """Tests for PlaybookExecutor."""

    def test_executor_initialization(self, copilot):
        """Test executor initialization."""
        executor = PlaybookExecutor(copilot)

        assert executor is not None
        assert executor.playbooks is not None

    def test_suggest_playbook(self, copilot):
        """Test playbook suggestion."""
        executor = PlaybookExecutor(copilot)
        incident = {"type": "malware", "title": "Suspicious PowerShell"}

        suggestion = executor.suggest_playbook(incident)

        assert suggestion is not None
        assert "Malware" in suggestion

    def test_get_playbook_step(self, copilot):
        """Test getting playbook step."""
        executor = PlaybookExecutor(copilot)
        step = executor.get_next_step("malware", 0)

        assert step is not None
        assert "step_number" in step or "action" in step


class TestIncidentDocumenter:
    """Tests for IncidentDocumenter."""

    def test_generate_timeline(self, state_manager):
        """Test timeline generation."""
        state_manager.add_to_timeline({"event": "Alert received", "type": "alert"})
        state_manager.add_to_timeline({"event": "Investigation started", "type": "investigation"})

        documenter = IncidentDocumenter(llm=None, state_manager=state_manager)
        timeline = documenter.generate_timeline()

        assert timeline is not None
        assert "Timeline" in timeline
        assert "Alert received" in timeline

    def test_generate_technical_report(self, state_manager):
        """Test technical report generation."""
        state_manager.set_incident({"id": "INC-001", "title": "Test", "severity": "HIGH"})

        documenter = IncidentDocumenter(llm=None, state_manager=state_manager)
        report = documenter.generate_technical_report()

        assert report is not None
        assert "Technical" in report or "Report" in report

    def test_generate_executive_summary(self, state_manager):
        """Test executive summary generation."""
        documenter = IncidentDocumenter(llm=None, state_manager=state_manager)
        summary = documenter.generate_executive_summary()

        assert summary is not None
        assert "Executive" in summary or "Summary" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

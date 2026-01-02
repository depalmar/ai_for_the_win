#!/usr/bin/env python3
"""
Workflow Orchestration Examples for AI Security Tools

This module demonstrates workflow orchestration patterns using LangGraph
for building multi-stage security analysis pipelines.

=============================================================================
OVERVIEW
=============================================================================

Workflow orchestration allows you to:
1. Chain multiple AI/ML stages together
2. Implement conditional logic and branching
3. Maintain state across processing stages
4. Build robust, production-ready pipelines

This example implements a simplified threat detection workflow that:
- Ingests security events
- Filters using ML (Isolation Forest)
- Enriches with LLM analysis
- Correlates related events
- Generates final verdicts

=============================================================================
KEY CONCEPTS
=============================================================================

1. StateGraph: Defines the workflow as a directed graph
2. Nodes: Individual processing stages (functions)
3. Edges: Connections between stages (can be conditional)
4. State: Typed dictionary passed between nodes
5. Checkpoints: For persistence and resumability

=============================================================================
"""

import json
import operator
import os
from datetime import datetime
from typing import Annotated, Dict, List, Optional, TypedDict

# Check for LangGraph availability
try:
    from langgraph.graph import END, StateGraph

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    print("LangGraph not available. Install with: pip install langgraph")

from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# STATE DEFINITION
# =============================================================================


class ThreatDetectionState(TypedDict):
    """
    State object passed through the workflow.

    Each node can read and modify this state.
    Uses TypedDict for type safety and IDE support.

    Key Design Principles:
    - Keep state minimal but complete
    - Use clear, descriptive field names
    - Include metadata for debugging
    """

    # Input events to process
    events: List[dict]

    # Filtered events (after ML stage)
    filtered_events: Annotated[List[dict], operator.add]

    # Enriched events (after LLM stage)
    enriched_events: List[dict]

    # Correlation results
    correlations: List[dict]

    # Final verdict
    verdict: Optional[dict]

    # Processing metadata
    metadata: dict


# =============================================================================
# WORKFLOW NODES
# =============================================================================


def ingest_node(state: ThreatDetectionState) -> dict:
    """
    Node 1: Event Ingestion

    Normalizes raw events into a standard format.
    This is typically the entry point of the workflow.

    Args:
        state: Current workflow state

    Returns:
        Dict with state updates (only modified fields)
    """
    events = state.get("events", [])
    normalized = []

    for i, event in enumerate(events):
        normalized.append(
            {
                "id": f"evt-{i:04d}",
                "timestamp": event.get("timestamp", datetime.now().isoformat()),
                "event_type": event.get("event_type", "unknown"),
                "host": event.get("host", "unknown"),
                "user": event.get("user", "unknown"),
                "process": event.get("process_name", ""),
                "command": event.get("command_line", ""),
                "network": {
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                },
                "raw": event,
            }
        )

    return {
        "events": normalized,
        "metadata": {
            **state.get("metadata", {}),
            "ingested_count": len(normalized),
            "ingested_at": datetime.now().isoformat(),
        },
    }


def ml_filter_node(state: ThreatDetectionState) -> dict:
    """
    Node 2: ML-Based Filtering

    Uses heuristics (or trained ML model) to score events.
    Only high-scoring events proceed to next stage.

    In production, this would use:
    - Isolation Forest for anomaly detection
    - Pre-trained classifiers
    - Feature engineering pipelines

    Args:
        state: Current workflow state

    Returns:
        Dict with filtered events
    """
    events = state.get("events", [])
    filtered = []

    for event in events:
        # Calculate anomaly score using heuristics
        score = 0.0

        command = event.get("command", "").lower()

        # Suspicious command patterns
        if "-enc" in command or "encoded" in command:
            score += 0.3
        if "powershell" in command and "hidden" in command:
            score += 0.3
        if "http://" in command or "https://" in command:
            score += 0.2
        if any(s in command for s in ["wget", "curl", "invoke-webrequest"]):
            score += 0.2

        # Network indicators
        if event.get("network", {}).get("dest_ip"):
            score += 0.1

        # Suspicious processes
        process = event.get("process", "").lower()
        if process in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]:
            score += 0.1

        # Add score to event
        event["anomaly_score"] = min(1.0, score)

        # Filter threshold
        if score >= 0.3:
            filtered.append(event)

    return {
        "filtered_events": filtered,
        "metadata": {
            **state.get("metadata", {}),
            "filtered_count": len(filtered),
            "filtered_at": datetime.now().isoformat(),
        },
    }


def enrichment_node(state: ThreatDetectionState) -> dict:
    """
    Node 3: LLM Enrichment

    Enriches events with contextual analysis.
    In production, this would call an LLM for:
    - Threat classification
    - MITRE ATT&CK mapping
    - IOC extraction

    Args:
        state: Current workflow state

    Returns:
        Dict with enriched events
    """
    filtered = state.get("filtered_events", [])
    enriched = []

    # MITRE ATT&CK mappings (simplified)
    mitre_mappings = {
        "powershell": ["T1059.001"],
        "cmd.exe": ["T1059.003"],
        "encoded": ["T1027"],
        "schtasks": ["T1053.005"],
        "reg.exe": ["T1112"],
        "whoami": ["T1033"],
        "net.exe": ["T1087"],
    }

    for event in filtered:
        command = event.get("command", "").lower()
        process = event.get("process", "").lower()

        # Map to MITRE techniques
        techniques = []
        for keyword, techs in mitre_mappings.items():
            if keyword in command or keyword in process:
                techniques.extend(techs)

        # Add enrichment
        event["mitre_techniques"] = list(set(techniques))
        event["threat_level"] = (
            "HIGH"
            if event["anomaly_score"] > 0.7
            else "MEDIUM" if event["anomaly_score"] > 0.4 else "LOW"
        )
        event["analysis"] = f"Detected {len(techniques)} MITRE techniques"

        enriched.append(event)

    return {
        "enriched_events": enriched,
        "metadata": {
            **state.get("metadata", {}),
            "enriched_count": len(enriched),
            "enriched_at": datetime.now().isoformat(),
        },
    }


def correlation_node(state: ThreatDetectionState) -> dict:
    """
    Node 4: Event Correlation

    Finds relationships between events to detect attack chains.
    Correlates by:
    - Host
    - User
    - Time window
    - MITRE technique progression

    Args:
        state: Current workflow state

    Returns:
        Dict with correlation results
    """
    events = state.get("enriched_events", [])
    correlations = []

    # Group by host
    by_host = {}
    for event in events:
        host = event.get("host", "unknown")
        if host not in by_host:
            by_host[host] = []
        by_host[host].append(event)

    # Find attack chains
    for host, host_events in by_host.items():
        if len(host_events) > 1:
            # Collect all techniques
            all_techniques = []
            for e in host_events:
                all_techniques.extend(e.get("mitre_techniques", []))

            correlations.append(
                {
                    "host": host,
                    "event_count": len(host_events),
                    "techniques": list(set(all_techniques)),
                    "is_attack_chain": len(set(all_techniques)) > 1,
                    "events": [e["id"] for e in host_events],
                }
            )

    return {
        "correlations": correlations,
        "metadata": {
            **state.get("metadata", {}),
            "correlation_count": len(correlations),
            "correlated_at": datetime.now().isoformat(),
        },
    }


def verdict_node(state: ThreatDetectionState) -> dict:
    """
    Node 5: Final Verdict

    Generates the final threat assessment based on all analysis.
    Produces actionable output for SOC analysts.

    Args:
        state: Current workflow state

    Returns:
        Dict with final verdict
    """
    correlations = state.get("correlations", [])
    enriched = state.get("enriched_events", [])

    # Determine overall verdict
    has_attack_chain = any(c.get("is_attack_chain") for c in correlations)
    max_score = max((e.get("anomaly_score", 0) for e in enriched), default=0)

    if has_attack_chain and max_score > 0.6:
        verdict_type = "MALICIOUS"
        confidence = min(0.95, max_score + 0.2)
    elif max_score > 0.5:
        verdict_type = "SUSPICIOUS"
        confidence = max_score
    else:
        verdict_type = "BENIGN"
        confidence = 1.0 - max_score

    verdict = {
        "verdict": verdict_type,
        "confidence": confidence,
        "attack_chain_detected": has_attack_chain,
        "total_events": len(enriched),
        "total_correlations": len(correlations),
        "recommended_actions": [],
    }

    # Add recommended actions
    if verdict_type == "MALICIOUS":
        verdict["recommended_actions"] = [
            "Isolate affected hosts immediately",
            "Collect forensic artifacts",
            "Reset compromised credentials",
            "Block identified IOCs at perimeter",
        ]
    elif verdict_type == "SUSPICIOUS":
        verdict["recommended_actions"] = [
            "Investigate further",
            "Review user activity logs",
            "Check for additional indicators",
        ]

    return {
        "verdict": verdict,
        "metadata": {
            **state.get("metadata", {}),
            "verdict_at": datetime.now().isoformat(),
            "workflow_complete": True,
        },
    }


# =============================================================================
# CONDITIONAL ROUTING
# =============================================================================


def should_continue(state: ThreatDetectionState) -> str:
    """
    Conditional edge function.

    Determines which node to execute next based on current state.
    This enables branching logic in the workflow.

    Args:
        state: Current workflow state

    Returns:
        Name of next node to execute
    """
    filtered = state.get("filtered_events", [])

    if not filtered:
        # No suspicious events, skip to verdict
        return "verdict"
    else:
        # Continue to enrichment
        return "enrich"


# =============================================================================
# WORKFLOW BUILDER
# =============================================================================


def build_detection_workflow():
    """
    Build the complete threat detection workflow.

    This function:
    1. Creates a StateGraph with our state type
    2. Adds nodes for each processing stage
    3. Defines edges (including conditional ones)
    4. Compiles into an executable workflow

    Returns:
        Compiled workflow ready for execution
    """
    if not LANGGRAPH_AVAILABLE:
        raise ImportError("LangGraph is required. Install with: pip install langgraph")

    # Create workflow with state type
    workflow = StateGraph(ThreatDetectionState)

    # Add nodes
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("ml_filter", ml_filter_node)
    workflow.add_node("enrich", enrichment_node)
    workflow.add_node("correlate", correlation_node)
    workflow.add_node("verdict", verdict_node)

    # Define edges (linear flow for simplicity)
    workflow.set_entry_point("ingest")
    workflow.add_edge("ingest", "ml_filter")

    # Conditional routing after ML filter
    workflow.add_conditional_edges(
        "ml_filter", should_continue, {"enrich": "enrich", "verdict": "verdict"}
    )

    workflow.add_edge("enrich", "correlate")
    workflow.add_edge("correlate", "verdict")
    workflow.add_edge("verdict", END)

    # Compile
    return workflow.compile()


# =============================================================================
# SIMPLE PIPELINE (NON-LANGGRAPH)
# =============================================================================


class SimplePipeline:
    """
    Simple pipeline implementation without LangGraph.

    Use this when LangGraph isn't available or for simpler use cases.
    Demonstrates the same concepts with plain Python.
    """

    def __init__(self):
        self.stages = [
            ("ingest", ingest_node),
            ("ml_filter", ml_filter_node),
            ("enrich", enrichment_node),
            ("correlate", correlation_node),
            ("verdict", verdict_node),
        ]

    def run(self, initial_state: dict) -> dict:
        """
        Run events through all pipeline stages.

        Args:
            initial_state: Initial state with events

        Returns:
            Final state after all stages
        """
        state = {
            "events": initial_state.get("events", []),
            "filtered_events": [],
            "enriched_events": [],
            "correlations": [],
            "verdict": None,
            "metadata": {"started_at": datetime.now().isoformat()},
        }

        for stage_name, stage_fn in self.stages:
            print(f"Running stage: {stage_name}")
            updates = stage_fn(state)
            state.update(updates)

            # Check for early exit
            if stage_name == "ml_filter" and not state.get("filtered_events"):
                print("No suspicious events, skipping to verdict")
                updates = verdict_node(state)
                state.update(updates)
                break

        return state


# =============================================================================
# DEMO
# =============================================================================


def run_demo():
    """
    Demonstrate the workflow with sample attack events.
    """
    print("=" * 70)
    print("WORKFLOW ORCHESTRATION DEMO")
    print("=" * 70)

    # Sample attack scenario
    events = [
        {
            "timestamp": "2024-01-15T03:22:10Z",
            "host": "WORKSTATION01",
            "event_type": "process",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SGVsbG8= -nop -w hidden",
            "user": "jsmith",
        },
        {
            "timestamp": "2024-01-15T03:22:15Z",
            "host": "WORKSTATION01",
            "event_type": "network",
            "process_name": "powershell.exe",
            "dest_ip": "185.143.223.47",
            "dest_port": 443,
            "user": "jsmith",
        },
        {
            "timestamp": "2024-01-15T03:22:20Z",
            "host": "WORKSTATION01",
            "event_type": "process",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami && hostname",
            "user": "jsmith",
        },
        {
            "timestamp": "2024-01-15T03:23:00Z",
            "host": "WORKSTATION01",
            "event_type": "process",
            "process_name": "schtasks.exe",
            "command_line": "schtasks /create /tn Update /tr malware.exe /sc daily",
            "user": "jsmith",
        },
    ]

    initial_state = {
        "events": events,
        "filtered_events": [],
        "enriched_events": [],
        "correlations": [],
        "verdict": None,
        "metadata": {},
    }

    # Run with LangGraph if available
    if LANGGRAPH_AVAILABLE:
        print("\nUsing LangGraph workflow...")
        workflow = build_detection_workflow()
        result = workflow.invoke(initial_state)
    else:
        print("\nUsing simple pipeline (LangGraph not available)...")
        pipeline = SimplePipeline()
        result = pipeline.run(initial_state)

    # Display results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(f"\nEvents processed: {result['metadata'].get('ingested_count', 0)}")
    print(f"Events filtered: {result['metadata'].get('filtered_count', 0)}")
    print(f"Correlations found: {result['metadata'].get('correlation_count', 0)}")

    verdict = result.get("verdict", {})
    print(f"\nFinal Verdict: {verdict.get('verdict', 'N/A')}")
    print(f"Confidence: {verdict.get('confidence', 0):.1%}")
    print(f"Attack Chain Detected: {verdict.get('attack_chain_detected', False)}")

    if verdict.get("recommended_actions"):
        print("\nRecommended Actions:")
        for action in verdict["recommended_actions"]:
            print(f"  - {action}")

    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()

#!/usr/bin/env python3
"""
Lab 09: Multi-Stage Threat Detection Pipeline - Solution

Complete implementation of multi-stage detection pipeline.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

load_dotenv()

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from rich.console import Console
from rich.table import Table

console = Console()


# =============================================================================
# MITRE ATT&CK Mapping
# =============================================================================

MITRE_MAPPINGS = {
    "powershell.exe": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "reg.exe": ["T1112"],
    "schtasks.exe": ["T1053.005"],
    "net.exe": ["T1087"],
    "whoami": ["T1033"],
    "encoded_command": ["T1027"],
}


# =============================================================================
# Task 1: Data Ingestion Layer - SOLUTION
# =============================================================================


class EventIngestor:
    """Ingest and normalize security events."""

    def __init__(self):
        self.buffer = []

    def ingest_event(self, raw_event: dict, source: str) -> dict:
        """Normalize a raw event into standard schema."""
        normalized = self.create_normalized_event(raw_event, source)
        self.buffer.append(normalized)
        return normalized

    def create_normalized_event(self, raw: dict, source: str) -> dict:
        """Create normalized event structure."""
        event_id = str(uuid.uuid4())

        # Parse timestamp
        ts = raw.get("timestamp", datetime.now().isoformat())
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                ts = datetime.now()

        normalized = {
            "id": event_id,
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else ts,
            "source": source,
            "event_type": raw.get("event_type", "unknown"),
            "host": raw.get("host", "unknown"),
            "user": raw.get("user", "unknown"),
            "details": {
                "process_name": raw.get("process_name"),
                "command_line": raw.get("command_line"),
                "parent_process": raw.get("parent_process"),
                "dest_ip": raw.get("dest_ip"),
                "dest_port": raw.get("dest_port"),
            },
            "raw": raw,
        }

        return normalized


# =============================================================================
# Task 2: ML Filtering Stage - SOLUTION
# =============================================================================


class MLFilterStage:
    """Stage 1: ML-based anomaly filtering."""

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.threshold = 0.5
        self.is_trained = False

    def extract_features(self, event: dict) -> np.ndarray:
        """Extract ML features from event."""
        details = event.get("details", {})

        features = []

        # Time features
        try:
            ts = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
            features.append(ts.hour)
            features.append(1 if ts.weekday() >= 5 else 0)
        except:
            features.extend([12, 0])

        # Process features
        cmd = details.get("command_line", "") or ""
        features.append(len(cmd))
        features.append(1 if "-enc" in cmd.lower() or "-encoded" in cmd.lower() else 0)
        features.append(1 if "http" in cmd.lower() else 0)

        # Network features
        features.append(1 if details.get("dest_ip") else 0)
        port = details.get("dest_port", 0) or 0
        features.append(1 if port == 443 or port == 80 else 0)

        return np.array(features).reshape(1, -1)

    def train(self, events: List[dict]):
        """Train the anomaly detection model."""
        if not events:
            return

        X = np.vstack([self.extract_features(e) for e in events])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

    def score_event(self, event: dict) -> float:
        """Score event anomaly level (0-1)."""
        features = self.extract_features(event)

        if self.is_trained:
            features_scaled = self.scaler.transform(features)
            score = self.model.decision_function(features_scaled)[0]
            # Convert to 0-1 (lower decision function = more anomalous)
            normalized = 1 - (score + 0.5)
            return max(0, min(1, normalized))
        else:
            # Heuristic scoring when not trained
            details = event.get("details", {})
            score = 0.0
            cmd = details.get("command_line", "") or ""
            if "-enc" in cmd.lower():
                score += 0.4
            if "http" in cmd.lower():
                score += 0.2
            if details.get("dest_ip"):
                score += 0.2
            return min(1.0, score)

    def filter_events(self, events: List[dict]) -> List[dict]:
        """Filter events above threshold."""
        filtered = []
        for event in events:
            score = self.score_event(event)
            if score >= self.threshold:
                event["anomaly_score"] = score
                filtered.append(event)
        return filtered


# =============================================================================
# Task 3: LLM Enrichment Stage - SOLUTION
# =============================================================================


class LLMEnrichmentStage:
    """Stage 2: LLM-based context enrichment."""

    def __init__(self, llm=None):
        if llm:
            self.llm = llm
        elif LANGCHAIN_AVAILABLE and os.getenv("ANTHROPIC_API_KEY"):
            self.llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        else:
            self.llm = None
        self.cache = {}

    def enrich_event(self, event: dict) -> dict:
        """Enrich event with analysis."""
        event = event.copy()

        # Map to MITRE
        mitre_techniques = self._map_to_mitre(event)
        event["mitre_mapping"] = mitre_techniques

        # Add threat assessment
        event["threat_assessment"] = self._assess_threat(event)

        # LLM enrichment if available
        if self.llm:
            event["llm_analysis"] = self._llm_analyze(event)

        return event

    def _map_to_mitre(self, event: dict) -> List[str]:
        """Map event to MITRE ATT&CK techniques."""
        techniques = []
        details = event.get("details", {})

        process = (details.get("process_name") or "").lower()
        cmd = (details.get("command_line") or "").lower()

        for keyword, techs in MITRE_MAPPINGS.items():
            if keyword in process or keyword in cmd:
                techniques.extend(techs)

        return list(set(techniques))

    def _assess_threat(self, event: dict) -> dict:
        """Assess threat level."""
        score = event.get("anomaly_score", 0.5)
        mitre = event.get("mitre_mapping", [])

        if score > 0.8 and len(mitre) > 1:
            severity = "HIGH"
        elif score > 0.6:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "severity": severity,
            "confidence": score,
            "techniques_count": len(mitre),
        }

    def _llm_analyze(self, event: dict) -> str:
        """Get LLM analysis."""
        cache_key = hashlib.md5(
            json.dumps(event["details"], sort_keys=True).encode(), usedforsecurity=False
        ).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]

        prompt = f"""Briefly analyze this security event (2-3 sentences):
Process: {event['details'].get('process_name')}
Command: {event['details'].get('command_line', '')[:100]}
Network: {event['details'].get('dest_ip')}:{event['details'].get('dest_port')}

Is this suspicious? What might it indicate?"""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            analysis = response.content
            self.cache[cache_key] = analysis
            return analysis
        except:
            return "Analysis unavailable"


# =============================================================================
# Task 4: Correlation Stage - SOLUTION
# =============================================================================


class CorrelationStage:
    """Stage 3: Event correlation and chain detection."""

    def __init__(self, time_window: int = 300):
        self.time_window = time_window
        self.event_buffer = []

    def add_event(self, event: dict):
        """Add event to correlation buffer."""
        self.event_buffer.append(event)
        # Keep buffer manageable
        if len(self.event_buffer) > 1000:
            self.event_buffer = self.event_buffer[-500:]

    def find_related_events(self, event: dict) -> List[dict]:
        """Find events related to this one."""
        related = []
        try:
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except:
            event_time = datetime.now()

        for other in self.event_buffer:
            if other["id"] == event["id"]:
                continue

            try:
                other_time = datetime.fromisoformat(other["timestamp"].replace("Z", "+00:00"))
            except:
                continue

            # Check time window
            time_diff = abs((event_time - other_time).total_seconds())
            if time_diff > self.time_window:
                continue

            # Check correlation (same host or user)
            if event["host"] == other["host"] or event["user"] == other["user"]:
                related.append(other)

        return related

    def detect_attack_chain(self, events: List[dict]) -> dict:
        """Detect attack chain patterns."""
        if not events:
            return {"detected": False}

        # Sort by time
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

        # Collect all MITRE techniques
        all_techniques = []
        for e in sorted_events:
            all_techniques.extend(e.get("mitre_mapping", []))

        # Define attack patterns
        patterns = {
            "initial_access_execution": [["T1059.001", "T1059.003"]],
            "execution_persistence": [["T1059.001", "T1053.005"]],
            "discovery_lateral": [["T1033", "T1087"]],
        }

        detected_patterns = []
        for pattern_name, technique_sets in patterns.items():
            for tech_set in technique_sets:
                if all(t in all_techniques for t in tech_set):
                    detected_patterns.append(pattern_name)

        return {
            "detected": len(detected_patterns) > 0,
            "patterns": detected_patterns,
            "techniques": list(set(all_techniques)),
            "events": sorted_events,
            "event_count": len(events),
        }


# =============================================================================
# Task 5: Verdict & Response Stage - SOLUTION
# =============================================================================


class VerdictStage:
    """Stage 4: Final verdict and response generation."""

    def __init__(self, llm=None):
        self.llm = llm

    def generate_verdict(self, events: List[dict], chain_analysis: dict = None) -> dict:
        """Generate final verdict."""
        if not events:
            return {"verdict": "benign", "confidence": 0.0}

        # Default empty chain analysis if not provided
        if chain_analysis is None:
            chain_analysis = {}

        # Calculate overall confidence
        scores = [e.get("anomaly_score", 0) for e in events]
        avg_score = sum(scores) / len(scores) if scores else 0

        # Determine verdict
        if chain_analysis.get("detected") and avg_score > 0.6:
            verdict = "malicious"
            confidence = min(0.95, avg_score + 0.2)
        elif avg_score > 0.7:
            verdict = "suspicious"
            confidence = avg_score
        else:
            verdict = "benign"
            confidence = 1 - avg_score

        return {
            "verdict": verdict,
            "confidence": confidence,
            "attack_patterns": chain_analysis.get("patterns", []),
            "techniques": chain_analysis.get("techniques", []),
            "event_count": len(events),
        }

    def create_alert(self, events: List[dict], verdict: dict) -> dict:
        """Create final alert for SOC."""
        # Determine severity and actions based on verdict
        if verdict["verdict"] == "malicious":
            severity = "HIGH"
            title = f"Potential MALICIOUS activity detected"
            actions = [
                "Isolate affected hosts",
                "Reset user credentials",
                "Collect forensic artifacts",
                "Block identified IOCs",
            ]
        elif verdict["verdict"] == "suspicious":
            severity = "MEDIUM"
            title = f"Potential SUSPICIOUS activity detected"
            actions = [
                "Investigate affected hosts",
                "Review user activity",
                "Monitor for additional indicators",
            ]
        else:  # benign
            severity = "INFO"
            title = f"Activity detected - benign classification"
            actions = ["No action required", "Events logged for baseline"]

        alert = {
            "alert_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
            "title": title,
            "severity": severity,
            "confidence": verdict["confidence"],
            "verdict": verdict["verdict"],
            "summary": f"Detected {len(events)} related events with attack patterns: {verdict['attack_patterns']}",
            "mitre_techniques": verdict["techniques"],
            "affected_hosts": list(set(e["host"] for e in events)),
            "affected_users": list(set(e["user"] for e in events)),
            "timeline": [{"time": e["timestamp"], "event": e["event_type"]} for e in events],
            "recommended_actions": actions,
        }

        return alert


# =============================================================================
# Task 6: Sigma Rule Generator - SOLUTION
# =============================================================================


class SigmaRuleGenerator:
    """Generate Sigma detection rules from detected patterns."""

    def __init__(self):
        self.rule_counter = 0

    def generate_rule_from_event(self, event: dict) -> str:
        """Generate a Sigma rule from a detected event."""
        self.rule_counter += 1
        rule_id = str(uuid.uuid4())
        details = event.get("details", {})
        mitre = event.get("mitre_mapping", [])

        # Determine rule focus based on event details
        process_name = details.get("process_name", "")
        command_line = details.get("command_line", "")
        dest_ip = details.get("dest_ip", "")

        # Build detection based on available data
        detection_items = []
        if process_name:
            detection_items.append(f"        Image|endswith: '\\\\{process_name}'")
        if command_line:
            # Extract key patterns from command line
            patterns = self._extract_patterns(command_line)
            if patterns:
                detection_items.append("        CommandLine|contains:")
                for p in patterns[:3]:  # Limit to top 3 patterns
                    detection_items.append(f"            - '{p}'")

        detection_yaml = "\n".join(detection_items) if detection_items else "        # TODO: Add detection logic"

        # Build tags
        tags_yaml = "\n".join([f"    - attack.{t.lower()}" for t in mitre]) if mitre else "    - attack.execution"

        rule = f"""title: Auto-Generated Detection - {process_name or 'Suspicious Activity'}
id: {rule_id}
status: experimental
description: |
    Automatically generated rule from pipeline detection.
    Event type: {event.get('event_type', 'unknown')}
    Host: {event.get('host', 'unknown')}
references:
    - https://attack.mitre.org/
author: AI for the Win Pipeline
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: process_creation
    product: windows

detection:
    selection:
{detection_yaml}
    condition: selection

falsepositives:
    - Legitimate administrative activity
    - Requires tuning for environment

level: {self._determine_level(event)}

tags:
{tags_yaml}
"""
        return rule

    def generate_rule_from_alert(self, alert: dict) -> str:
        """Generate a comprehensive Sigma rule from an alert with correlated events."""
        rule_id = str(uuid.uuid4())
        techniques = alert.get("mitre_techniques", [])
        hosts = alert.get("affected_hosts", [])

        # Build tags
        tags = []
        for tech in techniques:
            tags.append(f"    - attack.{tech.lower()}")
        tags_yaml = "\n".join(tags) if tags else "    - attack.execution"

        # Determine level based on severity
        level_map = {"HIGH": "critical", "MEDIUM": "high", "INFO": "medium"}
        level = level_map.get(alert.get("severity", "MEDIUM"), "high")

        rule = f"""title: {alert.get('title', 'Pipeline Detection')}
id: {rule_id}
status: experimental
description: |
    Alert generated by detection pipeline.
    Confidence: {alert.get('confidence', 0):.1%}
    Summary: {alert.get('summary', 'N/A')}
references:
    - https://attack.mitre.org/
author: AI for the Win Pipeline
date: {datetime.now().strftime('%Y/%m/%d')}

logsource:
    category: process_creation
    product: windows

detection:
    selection_host:
        ComputerName:
{chr(10).join([f"            - '{h}'" for h in hosts])}

    selection_user:
        User:
{chr(10).join([f"            - '{u}'" for u in alert.get('affected_users', [])])}

    # Note: Refine with specific process/command patterns
    condition: selection_host and selection_user

falsepositives:
    - Legitimate user activity
    - Review and tune for your environment

level: {level}

tags:
{tags_yaml}
"""
        return rule

    def _extract_patterns(self, command_line: str) -> list:
        """Extract meaningful patterns from command line."""
        patterns = []
        # Look for encoded commands
        if "-enc" in command_line.lower():
            patterns.append("-enc")
        if "-nop" in command_line.lower():
            patterns.append("-nop")
        if "hidden" in command_line.lower():
            patterns.append("hidden")
        # Look for suspicious commands
        for cmd in ["whoami", "net ", "schtasks", "reg ", "http"]:
            if cmd in command_line.lower():
                patterns.append(cmd.strip())
        return patterns

    def _determine_level(self, event: dict) -> str:
        """Determine severity level from event data."""
        score = event.get("anomaly_score", 0.5)
        mitre = event.get("mitre_mapping", [])

        if score > 0.8 or len(mitre) > 2:
            return "critical"
        elif score > 0.6:
            return "high"
        elif score > 0.4:
            return "medium"
        return "low"


# =============================================================================
# Task 7: Pipeline Orchestrator - SOLUTION
# =============================================================================


class DetectionPipeline:
    """Orchestrate the complete pipeline."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.ingestor = EventIngestor()
        self.ml_filter = MLFilterStage()
        self.enricher = LLMEnrichmentStage()
        self.correlator = CorrelationStage()
        self.verdict_stage = VerdictStage()
        self.sigma_generator = SigmaRuleGenerator()
        self.alerts = []
        self.sigma_rules = []  # Store generated Sigma rules

    def process_event(self, raw_event: dict, source: str) -> Optional[dict]:
        """Process single event through pipeline."""
        # Stage 1: Normalize
        event = self.ingestor.ingest_event(raw_event, source)

        # Stage 2: ML Filter
        score = self.ml_filter.score_event(event)
        event["anomaly_score"] = score

        if score < self.ml_filter.threshold:
            return None  # Below threshold

        # Stage 3: Enrich
        event = self.enricher.enrich_event(event)

        # Stage 4: Correlate
        self.correlator.add_event(event)
        related = self.correlator.find_related_events(event)
        all_events = [event] + related

        chain_analysis = self.correlator.detect_attack_chain(all_events)

        # Stage 5: Verdict
        verdict = self.verdict_stage.generate_verdict(all_events, chain_analysis)

        if verdict["verdict"] != "benign":
            alert = self.verdict_stage.create_alert(all_events, verdict)
            if alert:
                self.alerts.append(alert)
                # Generate Sigma rule from alert
                sigma_rule = self.sigma_generator.generate_rule_from_alert(alert)
                self.sigma_rules.append(sigma_rule)
                alert["sigma_rule"] = sigma_rule
                return alert

        return None

    def process_batch(self, events: List[dict]) -> List[dict]:
        """Process batch of events."""
        alerts = []
        for event in events:
            result = self.process_event(event, "batch")
            if result:
                alerts.append(result)
        return alerts


# =============================================================================
# Main - SOLUTION
# =============================================================================


def main():
    """Main execution."""
    console.print("[bold]Lab 09: Threat Detection Pipeline - SOLUTION[/bold]")

    # Attack scenario events
    attack_events = [
        {
            "timestamp": "2024-01-15T03:22:10Z",
            "host": "WORKSTATION01",
            "event_type": "process",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SGVsbG8gV29ybGQ= -nop -w hidden",
            "parent_process": "outlook.exe",
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
            "parent_process": "powershell.exe",
            "user": "jsmith",
        },
        {
            "timestamp": "2024-01-15T03:23:00Z",
            "host": "WORKSTATION01",
            "event_type": "process",
            "process_name": "schtasks.exe",
            "command_line": "schtasks /create /tn Update /tr malware.exe /sc daily",
            "parent_process": "powershell.exe",
            "user": "jsmith",
        },
    ]

    console.print(f"\n[yellow]Processing {len(attack_events)} events through pipeline...[/yellow]")

    pipeline = DetectionPipeline()

    for i, event in enumerate(attack_events, 1):
        console.print(f"\n[dim]Processing event {i}/{len(attack_events)}...[/dim]")
        console.print(f"  Process: {event.get('process_name')}")
        console.print(f"  Command: {event.get('command_line', '')[:50]}...")

        result = pipeline.process_event(event, "sysmon")

        if result:
            console.print(f"[bold red]ALERT GENERATED![/bold red]")
            console.print(f"  Severity: {result['severity']}")
            console.print(f"  Confidence: {result['confidence']:.2f}")
            console.print(f"  Techniques: {result['mitre_techniques']}")

    # Summary
    console.print("\n" + "=" * 60)
    console.print("[bold]Pipeline Summary[/bold]")
    console.print(f"Events processed: {len(attack_events)}")
    console.print(f"Alerts generated: {len(pipeline.alerts)}")

    if pipeline.alerts:
        console.print("\n[bold]Alert Details:[/bold]")
        for alert in pipeline.alerts:
            table = Table(title=alert["title"])
            table.add_column("Field", style="cyan")
            table.add_column("Value")

            table.add_row("Alert ID", alert["alert_id"][:8])
            table.add_row("Severity", alert["severity"])
            table.add_row("Confidence", f"{alert['confidence']:.1%}")
            table.add_row("Hosts", ", ".join(alert["affected_hosts"]))
            table.add_row("Techniques", ", ".join(alert["mitre_techniques"]))

            console.print(table)

    # Display generated Sigma rules
    if pipeline.sigma_rules:
        console.print("\n[bold yellow]📋 Generated Sigma Rules:[/bold yellow]")
        console.print("-" * 60)
        for i, rule in enumerate(pipeline.sigma_rules, 1):
            console.print(f"\n[cyan]Rule {i}:[/cyan]")
            # Show first 30 lines of rule
            lines = rule.strip().split("\n")[:30]
            for line in lines:
                console.print(f"  {line}")
            if len(rule.split("\n")) > 30:
                console.print("  ...")
        console.print("\n💾 Sigma rules can be exported and used with any SIEM!")


if __name__ == "__main__":
    main()

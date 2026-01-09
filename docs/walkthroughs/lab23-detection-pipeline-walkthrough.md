# Lab 09: Detection Pipeline - Solution Walkthrough

## Overview

Build a multi-stage detection pipeline that combines rule-based filtering, ML triage, and LLM enrichment for efficient alert processing.

**Time:** 3-4 hours
**Difficulty:** Advanced

---

## Task 1: Pipeline Architecture

### Designing the Multi-Stage Pipeline

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum
import json

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class Alert:
    id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: AlertSeverity
    raw_data: dict
    metadata: dict = field(default_factory=dict)

    # Pipeline processing results
    stage_results: dict = field(default_factory=dict)
    ml_score: Optional[float] = None
    llm_analysis: Optional[str] = None
    final_priority: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'severity': self.severity.name,
            'ml_score': self.ml_score,
            'final_priority': self.final_priority,
            'raw_data': self.raw_data
        }

class PipelineStage(ABC):
    """Base class for pipeline stages."""

    @abstractmethod
    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Process alerts and return filtered/enriched results."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

class DetectionPipeline:
    def __init__(self):
        self.stages: list[PipelineStage] = []
        self.metrics = {
            'total_input': 0,
            'stage_outputs': {},
            'processing_time_ms': {}
        }

    def add_stage(self, stage: PipelineStage):
        self.stages.append(stage)

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Run alerts through all pipeline stages."""
        import time

        self.metrics['total_input'] = len(alerts)
        current_alerts = alerts

        for stage in self.stages:
            start = time.time()
            current_alerts = stage.process(current_alerts)
            elapsed = (time.time() - start) * 1000

            self.metrics['stage_outputs'][stage.name] = len(current_alerts)
            self.metrics['processing_time_ms'][stage.name] = elapsed

            print(f"Stage '{stage.name}': {len(current_alerts)} alerts ({elapsed:.1f}ms)")

        return current_alerts

    def get_metrics(self) -> dict:
        return self.metrics
```

---

## Task 2: Rule-Based Pre-Filter

### Implementing Fast Filtering Rules

```python
import re
from typing import Callable

class RuleBasedFilter(PipelineStage):
    """Stage 1: Fast rule-based filtering to reduce volume."""

    def __init__(self):
        self.rules: list[Callable[[Alert], bool]] = []
        self.suppression_rules: list[Callable[[Alert], bool]] = []

    @property
    def name(self) -> str:
        return "rule_filter"

    def add_pass_rule(self, rule: Callable[[Alert], bool], description: str = ""):
        """Add rule that must pass for alert to continue."""
        self.rules.append(rule)

    def add_suppression_rule(self, rule: Callable[[Alert], bool], description: str = ""):
        """Add rule that suppresses matching alerts."""
        self.suppression_rules.append(rule)

    def process(self, alerts: list[Alert]) -> list[Alert]:
        filtered = []

        for alert in alerts:
            # Check suppression rules first
            suppressed = any(rule(alert) for rule in self.suppression_rules)
            if suppressed:
                alert.stage_results['rule_filter'] = 'suppressed'
                continue

            # Check pass rules (all must pass)
            if self.rules:
                passed = all(rule(alert) for rule in self.rules)
            else:
                passed = True

            if passed:
                alert.stage_results['rule_filter'] = 'passed'
                filtered.append(alert)
            else:
                alert.stage_results['rule_filter'] = 'filtered'

        return filtered

# Configure rule-based filter
rule_filter = RuleBasedFilter()

# Suppress known false positives
rule_filter.add_suppression_rule(
    lambda a: a.source == "vulnerability_scanner" and "scheduled_scan" in a.raw_data.get('tags', []),
    "Suppress scheduled vulnerability scans"
)

rule_filter.add_suppression_rule(
    lambda a: a.event_type == "failed_login" and a.raw_data.get('username', '').startswith('svc_'),
    "Suppress service account login noise"
)

# Only pass alerts from critical sources during quiet hours
rule_filter.add_pass_rule(
    lambda a: a.severity.value >= AlertSeverity.LOW.value,
    "Filter INFO-level alerts"
)

# Suppress test/dev environment noise
rule_filter.add_suppression_rule(
    lambda a: any(env in a.raw_data.get('hostname', '').lower()
                  for env in ['test', 'dev', 'staging']),
    "Suppress non-production alerts"
)
```

---

## Task 3: ML Triage Stage

### Training and Applying ML Models

```python
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class MLTriageStage(PipelineStage):
    """Stage 2: ML-based alert scoring and triage."""

    def __init__(self, model_path: str = None):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.feature_names = []

        if model_path:
            self.load_model(model_path)

    @property
    def name(self) -> str:
        return "ml_triage"

    def extract_features(self, alert: Alert) -> np.ndarray:
        """Extract ML features from alert."""
        features = {
            # Temporal features
            'hour_of_day': alert.timestamp.hour,
            'day_of_week': alert.timestamp.weekday(),
            'is_weekend': 1 if alert.timestamp.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= alert.timestamp.hour <= 17 else 0,

            # Severity encoding
            'severity_value': alert.severity.value,

            # Source encoding (simplified)
            'source_edr': 1 if 'edr' in alert.source.lower() else 0,
            'source_firewall': 1 if 'firewall' in alert.source.lower() else 0,
            'source_ids': 1 if 'ids' in alert.source.lower() else 0,
            'source_siem': 1 if 'siem' in alert.source.lower() else 0,

            # Event type features
            'is_auth_event': 1 if 'auth' in alert.event_type.lower() else 0,
            'is_network_event': 1 if 'network' in alert.event_type.lower() else 0,
            'is_malware_event': 1 if 'malware' in alert.event_type.lower() else 0,

            # Raw data features
            'has_ip': 1 if alert.raw_data.get('src_ip') else 0,
            'has_user': 1 if alert.raw_data.get('username') else 0,
            'event_count': alert.raw_data.get('event_count', 1),
            'bytes_transferred': alert.raw_data.get('bytes', 0),
        }

        self.feature_names = list(features.keys())
        return np.array(list(features.values())).reshape(1, -1)

    def train(self, labeled_alerts: list[tuple[Alert, int]]):
        """Train classifier on labeled alerts (alert, is_true_positive)."""
        X = []
        y = []

        for alert, label in labeled_alerts:
            features = self.extract_features(alert)
            X.append(features.flatten())
            y.append(label)

        X = np.array(X)
        y = np.array(y)

        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)

        # Train classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            class_weight='balanced',
            random_state=42
        )
        self.classifier.fit(X_scaled, y)

        # Train anomaly detector for unknown patterns
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.anomaly_detector.fit(X_scaled)

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Score and filter alerts using ML."""
        if not self.classifier:
            # No model trained, pass all alerts
            return alerts

        scored_alerts = []

        for alert in alerts:
            features = self.extract_features(alert)
            features_scaled = self.scaler.transform(features)

            # Get probability of true positive
            proba = self.classifier.predict_proba(features_scaled)[0]
            tp_score = proba[1] if len(proba) > 1 else proba[0]

            # Check for anomalies
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = anomaly_score < 0

            # Combine scores
            alert.ml_score = tp_score
            alert.stage_results['ml_triage'] = {
                'tp_probability': float(tp_score),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': is_anomaly
            }

            # Filter low-confidence alerts (keep anomalies regardless)
            if tp_score >= 0.3 or is_anomaly:
                scored_alerts.append(alert)

        # Sort by score
        scored_alerts.sort(key=lambda a: a.ml_score or 0, reverse=True)

        return scored_alerts

    def save_model(self, path: str):
        joblib.dump({
            'classifier': self.classifier,
            'anomaly_detector': self.anomaly_detector,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, path)

    def load_model(self, path: str):
        data = joblib.load(path)
        self.classifier = data['classifier']
        self.anomaly_detector = data['anomaly_detector']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']

# Initialize ML stage
ml_stage = MLTriageStage("models/alert_triage.joblib")
```

---

## Task 4: LLM Enrichment Stage

### AI-Powered Alert Analysis

```python
import anthropic
from concurrent.futures import ThreadPoolExecutor, as_completed

class LLMEnrichmentStage(PipelineStage):
    """Stage 3: LLM-powered alert enrichment and analysis."""

    def __init__(self, max_alerts: int = 50, parallel: int = 5):
        self.client = anthropic.Anthropic()
        self.max_alerts = max_alerts  # Limit LLM calls
        self.parallel = parallel

    @property
    def name(self) -> str:
        return "llm_enrichment"

    def _analyze_alert(self, alert: Alert) -> Alert:
        """Analyze single alert with LLM."""

        prompt = f"""You are a SOC analyst triaging security alerts. Analyze this alert and provide a brief assessment.

## Alert Details
- ID: {alert.id}
- Timestamp: {alert.timestamp.isoformat()}
- Source: {alert.source}
- Event Type: {alert.event_type}
- Severity: {alert.severity.name}
- ML Score: {alert.ml_score:.2f if alert.ml_score else 'N/A'}

## Raw Event Data
```json
{json.dumps(alert.raw_data, indent=2, default=str)}
```

Provide a JSON response with:
1. "summary": One-sentence description of what happened
2. "threat_assessment": "confirmed_threat", "likely_threat", "suspicious", "likely_benign", or "benign"
3. "confidence": 0.0-1.0
4. "iocs": List of indicators of compromise found
5. "mitre_techniques": Relevant MITRE ATT&CK technique IDs
6. "recommended_actions": List of 1-3 immediate actions
7. "priority": 1-5 (1 highest)

Return ONLY valid JSON."""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            analysis = json.loads(response.content[0].text)
            alert.llm_analysis = analysis.get('summary', '')
            alert.final_priority = analysis.get('priority', 3)
            alert.stage_results['llm_enrichment'] = analysis

        except Exception as e:
            alert.stage_results['llm_enrichment'] = {'error': str(e)}
            alert.final_priority = 3  # Default priority

        return alert

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Enrich top alerts with LLM analysis."""

        # Limit to top N alerts by ML score
        alerts_to_process = alerts[:self.max_alerts]
        remaining = alerts[self.max_alerts:]

        # Process in parallel
        enriched = []
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = {executor.submit(self._analyze_alert, a): a
                      for a in alerts_to_process}

            for future in as_completed(futures):
                try:
                    enriched.append(future.result())
                except Exception as e:
                    alert = futures[future]
                    alert.stage_results['llm_enrichment'] = {'error': str(e)}
                    enriched.append(alert)

        # Add remaining alerts without LLM analysis
        for alert in remaining:
            alert.stage_results['llm_enrichment'] = {'skipped': 'over_limit'}
            alert.final_priority = 4  # Lower priority for non-analyzed
            enriched.append(alert)

        # Sort by final priority
        enriched.sort(key=lambda a: (a.final_priority or 5, -(a.ml_score or 0)))

        return enriched

# Initialize LLM stage
llm_stage = LLMEnrichmentStage(max_alerts=50, parallel=5)
```

---

## Task 5: Alert Correlation

### Grouping Related Alerts

```python
from collections import defaultdict
from datetime import timedelta

class AlertCorrelator(PipelineStage):
    """Stage 4: Correlate and group related alerts."""

    def __init__(self, time_window: timedelta = timedelta(minutes=5)):
        self.time_window = time_window

    @property
    def name(self) -> str:
        return "correlation"

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Correlate alerts by common attributes."""

        # Group by potential correlation keys
        correlation_groups = defaultdict(list)

        for alert in alerts:
            # Extract correlation keys
            keys = self._get_correlation_keys(alert)
            for key in keys:
                correlation_groups[key].append(alert)

        # Identify correlated incidents
        processed_ids = set()
        correlated_alerts = []

        for key, group in correlation_groups.items():
            if len(group) > 1:
                # Check time proximity
                group.sort(key=lambda a: a.timestamp)

                incident_alerts = []
                for i, alert in enumerate(group):
                    if alert.id in processed_ids:
                        continue

                    # Find alerts within time window
                    related = [alert]
                    for other in group[i+1:]:
                        if other.id in processed_ids:
                            continue
                        if other.timestamp - alert.timestamp <= self.time_window:
                            related.append(other)
                            processed_ids.add(other.id)

                    if len(related) > 1:
                        # Create incident from correlated alerts
                        incident = self._merge_alerts(related, key)
                        correlated_alerts.append(incident)
                        processed_ids.add(alert.id)
                    elif alert.id not in processed_ids:
                        correlated_alerts.append(alert)
                        processed_ids.add(alert.id)

        # Add uncorrelated alerts
        for alert in alerts:
            if alert.id not in processed_ids:
                correlated_alerts.append(alert)

        return correlated_alerts

    def _get_correlation_keys(self, alert: Alert) -> list[str]:
        """Extract keys for correlation."""
        keys = []

        raw = alert.raw_data

        # Correlate by source IP
        if raw.get('src_ip'):
            keys.append(f"src_ip:{raw['src_ip']}")

        # Correlate by destination IP
        if raw.get('dst_ip'):
            keys.append(f"dst_ip:{raw['dst_ip']}")

        # Correlate by user
        if raw.get('username'):
            keys.append(f"user:{raw['username']}")

        # Correlate by hostname
        if raw.get('hostname'):
            keys.append(f"host:{raw['hostname']}")

        # Correlate by process
        if raw.get('process_name'):
            keys.append(f"proc:{raw['process_name']}")

        return keys

    def _merge_alerts(self, alerts: list[Alert], correlation_key: str) -> Alert:
        """Merge correlated alerts into incident."""

        # Use highest severity alert as base
        alerts.sort(key=lambda a: a.severity.value, reverse=True)
        primary = alerts[0]

        # Create merged alert
        merged = Alert(
            id=f"incident_{primary.id}",
            timestamp=min(a.timestamp for a in alerts),
            source="correlation_engine",
            event_type="correlated_incident",
            severity=primary.severity,
            raw_data={
                'correlation_key': correlation_key,
                'alert_count': len(alerts),
                'alert_ids': [a.id for a in alerts],
                'sources': list(set(a.source for a in alerts)),
                'event_types': list(set(a.event_type for a in alerts)),
                'time_span_seconds': (max(a.timestamp for a in alerts) -
                                     min(a.timestamp for a in alerts)).total_seconds()
            },
            metadata={'correlated_alerts': [a.to_dict() for a in alerts]}
        )

        # Inherit best ML score
        merged.ml_score = max((a.ml_score or 0) for a in alerts)

        # Inherit highest priority
        priorities = [a.final_priority for a in alerts if a.final_priority]
        merged.final_priority = min(priorities) if priorities else 3

        merged.stage_results['correlation'] = {
            'merged_count': len(alerts),
            'correlation_key': correlation_key
        }

        return merged

# Initialize correlator
correlator = AlertCorrelator(time_window=timedelta(minutes=10))
```

---

## Task 6: Complete Pipeline Assembly

### Putting It All Together

```python
def build_detection_pipeline() -> DetectionPipeline:
    """Build the complete detection pipeline."""

    pipeline = DetectionPipeline()

    # Stage 1: Rule-based filtering
    rule_filter = RuleBasedFilter()
    rule_filter.add_suppression_rule(
        lambda a: "scheduled" in a.raw_data.get('tags', []),
        "Suppress scheduled tasks"
    )
    rule_filter.add_suppression_rule(
        lambda a: a.severity == AlertSeverity.INFO,
        "Suppress INFO alerts"
    )
    pipeline.add_stage(rule_filter)

    # Stage 2: ML triage
    ml_stage = MLTriageStage("models/alert_triage.joblib")
    pipeline.add_stage(ml_stage)

    # Stage 3: LLM enrichment (top 50 alerts only)
    llm_stage = LLMEnrichmentStage(max_alerts=50, parallel=5)
    pipeline.add_stage(llm_stage)

    # Stage 4: Correlation
    correlator = AlertCorrelator(time_window=timedelta(minutes=10))
    pipeline.add_stage(correlator)

    return pipeline

# Run pipeline
pipeline = build_detection_pipeline()

# Simulate incoming alerts
test_alerts = load_alerts_from_siem("alerts.json")  # Your data source
print(f"\nProcessing {len(test_alerts)} alerts...")

# Process
results = pipeline.process(test_alerts)

# Display results
print(f"\n{'='*60}")
print("Pipeline Results")
print(f"{'='*60}")
print(f"Input: {pipeline.metrics['total_input']} alerts")
for stage, count in pipeline.metrics['stage_outputs'].items():
    time_ms = pipeline.metrics['processing_time_ms'][stage]
    print(f"  {stage}: {count} alerts ({time_ms:.1f}ms)")

print(f"\nTop 10 Prioritized Alerts:")
for alert in results[:10]:
    print(f"  P{alert.final_priority} | {alert.ml_score:.2f} | {alert.event_type} | {alert.llm_analysis or 'No analysis'}")
```

---

## Expected Output

```
Processing 10000 alerts...
Stage 'rule_filter': 3500 alerts (45.2ms)
Stage 'ml_triage': 850 alerts (234.5ms)
Stage 'llm_enrichment': 850 alerts (15234.1ms)
Stage 'correlation': 320 alerts (89.3ms)

============================================================
Pipeline Results
============================================================
Input: 10000 alerts
  rule_filter: 3500 alerts (45.2ms)
  ml_triage: 850 alerts (234.5ms)
  llm_enrichment: 850 alerts (15234.1ms)
  correlation: 320 alerts (89.3ms)

Top 10 Prioritized Alerts:
  P1 | 0.95 | correlated_incident | Multiple failed logins followed by successful auth from unusual location
  P1 | 0.92 | malware_detected | Cobalt Strike beacon identified communicating with known C2
  P1 | 0.89 | privilege_escalation | Service account created with domain admin privileges
  P2 | 0.85 | data_exfiltration | Large data transfer to external IP during off-hours
  P2 | 0.82 | lateral_movement | RDP connection from compromised workstation to domain controller
  ...
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Too many alerts | Tighten rule filters, increase ML threshold |
| Slow LLM stage | Reduce max_alerts, increase parallelism |
| Poor ML accuracy | Retrain with recent labeled data |
| Over-correlation | Reduce time window, add correlation key specificity |
| Missing context | Add more data sources to raw_data |

---

## Next Steps

- Add feedback loop for ML model improvement
- Implement real-time streaming with Kafka
- Build analyst feedback interface
- Add automated response actions
- Create pipeline performance dashboards

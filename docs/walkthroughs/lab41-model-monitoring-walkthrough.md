# Lab 41: ML Model Security Monitoring Walkthrough

Step-by-step guide to building production monitoring for ML model security.

## Overview

This walkthrough guides you through:
1. Detecting data and concept drift in production
2. Identifying adversarial inputs in real-time
3. Monitoring for model extraction attacks
4. Building alerting systems for ML security events

**Difficulty:** Intermediate
**Time:** 90-120 minutes
**Prerequisites:** Lab 38, Lab 40

---

## Why Monitor ML Models?

| Threat | Detection Challenge | Impact |
|--------|-------------------|--------|
| Data Drift | Input distribution changes | Degraded accuracy |
| Adversarial Inputs | Subtle perturbations | Incorrect predictions |
| Model Extraction | Query patterns analysis | IP theft |
| Prompt Injection | Real-time input analysis | Unauthorized actions |

---

## Exercise 1: Data Drift Detection

### Statistical Drift Detection

```python
import numpy as np
import pandas as pd
from scipy import stats
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

@dataclass
class DriftResult:
    feature: str
    drift_detected: bool
    p_value: float
    drift_score: float
    method: str
    timestamp: datetime

class DataDriftDetector:
    """Detect data drift in production ML inputs."""

    def __init__(self, reference_data: pd.DataFrame, threshold: float = 0.05):
        self.reference = reference_data
        self.threshold = threshold
        self.reference_stats = self._compute_statistics(reference_data)

    def _compute_statistics(self, data: pd.DataFrame) -> Dict:
        """Compute reference statistics for each feature."""
        stats_dict = {}
        for col in data.columns:
            if data[col].dtype in ['float64', 'int64']:
                stats_dict[col] = {
                    'mean': data[col].mean(),
                    'std': data[col].std(),
                    'min': data[col].min(),
                    'max': data[col].max(),
                }
        return stats_dict

    def detect_drift(self, production_data: pd.DataFrame) -> List[DriftResult]:
        """Detect drift between reference and production data."""
        results = []

        for col in production_data.columns:
            if col not in self.reference.columns:
                continue

            if production_data[col].dtype in ['float64', 'int64']:
                result = self._ks_test(col, production_data[col])
            else:
                result = self._chi_square_test(col, production_data[col])

            results.append(result)

        return results

    def _ks_test(self, feature: str, production_values: pd.Series) -> DriftResult:
        """Kolmogorov-Smirnov test for numerical features."""
        reference_values = self.reference[feature].dropna()
        production_values = production_values.dropna()

        statistic, p_value = stats.ks_2samp(reference_values, production_values)

        return DriftResult(
            feature=feature,
            drift_detected=p_value < self.threshold,
            p_value=p_value,
            drift_score=statistic,
            method='ks_test',
            timestamp=datetime.now()
        )
```

### Real-time Monitoring

```python
from collections import deque
import threading
import time

class RealTimeDriftMonitor:
    """Real-time drift monitoring with streaming data."""

    def __init__(self, reference_data: pd.DataFrame, alert_callback=None):
        self.drift_detector = DataDriftDetector(reference_data)
        self.buffer = deque(maxlen=1000)
        self.alert_callback = alert_callback
        self.drift_alerts = []

    def add_sample(self, sample: Dict):
        """Add a new sample to the monitoring buffer."""
        sample['_timestamp'] = datetime.now()
        self.buffer.append(sample)

        if len(self.buffer) >= 100:
            self._analyze_buffer()

    def _analyze_buffer(self):
        """Analyze current buffer for drift."""
        df = pd.DataFrame(list(self.buffer))
        feature_cols = [c for c in df.columns if not c.startswith('_')]

        drift_results = self.drift_detector.detect_drift(df[feature_cols])
        drifted_features = [r for r in drift_results if r.drift_detected]

        if drifted_features:
            alert = {
                'timestamp': datetime.now(),
                'features': [f.feature for f in drifted_features],
                'severity': self._calculate_severity(drifted_features),
            }
            self.drift_alerts.append(alert)

            if self.alert_callback:
                self.alert_callback(alert)

    def _calculate_severity(self, drift_results: List[DriftResult]) -> str:
        """Calculate alert severity based on drift magnitude."""
        max_score = max(r.drift_score for r in drift_results)

        if max_score > 0.5:
            return 'CRITICAL'
        elif max_score > 0.3:
            return 'HIGH'
        elif max_score > 0.1:
            return 'MEDIUM'
        return 'LOW'
```

---

## Exercise 2: Adversarial Input Detection

### Anomaly Detection for Inputs

```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AdversarialInputDetector:
    """Detect potentially adversarial inputs to ML models."""

    def __init__(self, training_data: np.ndarray):
        self.scaler = StandardScaler()
        self.training_data_scaled = self.scaler.fit_transform(training_data)

        self.iso_forest = IsolationForest(
            contamination=0.01,
            random_state=42,
            n_estimators=100
        )
        self.iso_forest.fit(self.training_data_scaled)

        self.feature_stats = self._compute_feature_stats(training_data)

    def _compute_feature_stats(self, data: np.ndarray) -> Dict:
        """Compute feature statistics for anomaly checks."""
        return {
            'mean': np.mean(data, axis=0),
            'std': np.std(data, axis=0),
            'min': np.min(data, axis=0),
            'max': np.max(data, axis=0)
        }

    def detect_adversarial(self, inputs: np.ndarray) -> Dict:
        """Detect potentially adversarial inputs."""
        results = {
            'inputs_analyzed': len(inputs),
            'anomalies_detected': 0,
            'anomaly_indices': [],
            'details': []
        }

        inputs_scaled = self.scaler.transform(inputs)
        predictions = self.iso_forest.predict(inputs_scaled)
        scores = self.iso_forest.decision_function(inputs_scaled)

        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            is_anomaly = pred == -1
            input_vec = inputs[idx]
            anomaly_reasons = []

            # Check for out-of-distribution values
            for feat_idx in range(len(input_vec)):
                feat_val = input_vec[feat_idx]
                if feat_val < self.feature_stats['min'][feat_idx]:
                    anomaly_reasons.append(f'Feature {feat_idx} below min')
                if feat_val > self.feature_stats['max'][feat_idx]:
                    anomaly_reasons.append(f'Feature {feat_idx} above max')

            if is_anomaly or anomaly_reasons:
                results['anomalies_detected'] += 1
                results['anomaly_indices'].append(idx)
                results['details'].append({
                    'index': idx,
                    'score': score,
                    'reasons': anomaly_reasons
                })

        return results
```

### LLM Input Monitoring

```python
class LLMInputMonitor:
    """Monitor LLM inputs for adversarial patterns."""

    INJECTION_PATTERNS = [
        r'ignore.*(?:previous|above).*instruction',
        r'disregard.*(?:system|prompt)',
        r'you are now',
        r'new instruction',
    ]

    JAILBREAK_PATTERNS = [
        r'DAN', r'developer mode', r'no restrictions',
        r'hypothetically', r'roleplay as',
    ]

    def analyze_input(self, user_input: str, user_id: str = None) -> Dict:
        """Analyze LLM input for adversarial patterns."""
        analysis = {
            'timestamp': datetime.now(),
            'user_id': user_id,
            'input_length': len(user_input),
            'injection_detected': False,
            'jailbreak_detected': False,
            'suspicious_patterns': [],
            'risk_score': 0
        }

        # Check for injection patterns
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                analysis['injection_detected'] = True
                analysis['suspicious_patterns'].append({'type': 'injection', 'pattern': pattern})
                analysis['risk_score'] += 30

        # Check for jailbreak patterns
        for pattern in self.JAILBREAK_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                analysis['jailbreak_detected'] = True
                analysis['suspicious_patterns'].append({'type': 'jailbreak', 'pattern': pattern})
                analysis['risk_score'] += 20

        return analysis
```

---

## Exercise 3: Model Extraction Detection

### Query Pattern Analysis

```python
class ModelExtractionDetector:
    """Detect model extraction attacks through query analysis."""

    def __init__(self):
        self.query_history = []
        self.user_profiles = {}

    def log_query(self, user_id: str, query: np.ndarray, response):
        """Log a query for extraction detection."""
        entry = {
            'user_id': user_id,
            'query': query,
            'response': response,
            'timestamp': datetime.now()
        }

        self.query_history.append(entry)
        self._update_user_profile(user_id, entry)

    def _update_user_profile(self, user_id: str, entry: Dict):
        """Update user profile with query statistics."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'query_count': 0,
                'queries': [],
                'first_seen': entry['timestamp']
            }

        profile = self.user_profiles[user_id]
        profile['query_count'] += 1
        profile['queries'].append(entry)
        profile['last_seen'] = entry['timestamp']

    def detect_extraction_attempt(self, user_id: str) -> Dict:
        """Analyze user behavior for extraction patterns."""
        if user_id not in self.user_profiles:
            return {'suspicious': False, 'reason': 'New user'}

        profile = self.user_profiles[user_id]
        queries = profile['queries']
        indicators = []

        # Check query volume
        if profile['query_count'] > 10000:
            indicators.append({
                'type': 'high_volume',
                'value': profile['query_count']
            })

        # Check query rate
        if len(queries) >= 2:
            time_span = (queries[-1]['timestamp'] - queries[0]['timestamp']).total_seconds()
            rate = len(queries) / (time_span / 3600) if time_span > 0 else float('inf')

            if rate > 1000:
                indicators.append({'type': 'high_rate', 'value': rate})

        # Check for systematic patterns
        if len(queries) >= 100:
            systematic_score = self._detect_systematic_queries(queries)
            if systematic_score > 0.7:
                indicators.append({'type': 'systematic_pattern', 'score': systematic_score})

        return {
            'user_id': user_id,
            'suspicious': len(indicators) > 0,
            'risk_level': 'HIGH' if len(indicators) >= 2 else 'MEDIUM',
            'indicators': indicators
        }
```

---

## Exercise 4: Security Alert System

### Centralized Alerting

```python
import uuid

class MLSecurityAlertSystem:
    """Centralized alert system for ML security events."""

    def __init__(self):
        self.alerts = []
        self.alert_handlers = []
        self.alert_thresholds = {
            'drift': {'warning': 0.1, 'critical': 0.3},
            'adversarial': {'warning': 0.5, 'critical': 0.8},
            'extraction': {'warning': 100, 'critical': 1000}
        }

    def register_handler(self, handler_func):
        """Register an alert handler."""
        self.alert_handlers.append(handler_func)

    def generate_alert(self, alert_type: str, severity: str, details: Dict, source: str = None):
        """Generate and dispatch security alert."""
        alert = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'source': source,
            'details': details
        }

        self.alerts.append(alert)

        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")

        return alert

    def integrate_siem(self, siem_config: Dict):
        """Set up SIEM integration."""
        def siem_handler(alert):
            siem_event = {
                'event_type': 'ml_security_alert',
                'timestamp': alert['timestamp'],
                'severity': alert['severity'],
                'category': alert['type'],
                'description': self._format_description(alert),
            }
            # Send to SIEM
            self._send_to_siem(siem_event, siem_config)

        self.register_handler(siem_handler)
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           ML SECURITY MONITORING REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Period: Last 24 hours
Model: fraud_detection_v2

━━━━━ DRIFT DETECTION ━━━━━
🔴 CRITICAL: Feature 'transaction_amount' drift detected
   KS Statistic: 0.45 (threshold: 0.05)
   Production mean: $523.45 vs Reference: $245.12

━━━━━ ADVERSARIAL INPUTS ━━━━━
Anomalies Detected: 47 of 10,234 inputs (0.46%)
🟠 HIGH: 12 inputs with extreme feature values

━━━━━ EXTRACTION ATTEMPTS ━━━━━
🔴 CRITICAL: User api_user_847
   Query volume: 15,234 in 2 hours
   Pattern: Systematic boundary probing detected

━━━━━ RECOMMENDATIONS ━━━━━
1. Investigate drift in transaction_amount
2. Review anomalous inputs for attack patterns
3. Rate-limit api_user_847 immediately
```

---

## Resources

- [Evidently AI - ML Monitoring](https://www.evidentlyai.com/)
- [Alibi Detect](https://docs.seldon.io/projects/alibi-detect/)
- [WhyLabs - ML Observability](https://whylabs.ai/)

---

*Next: Lab 43 - RAG Security Walkthrough*

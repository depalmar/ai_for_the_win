# Lab 41: ML Model Security Monitoring

## Overview

Build production monitoring systems for ML models to detect drift, adversarial attacks, data poisoning, and anomalous model behavior in real-time.

**Difficulty**: Intermediate
**Duration**: 90-120 minutes
**Prerequisites**: Lab 38 (ML Security Intro), Lab 40 (LLM Security Testing), basic MLOps knowledge

## Learning Objectives

By the end of this lab, you will be able to:
1. Design model monitoring architectures for security
2. Detect data and concept drift in production
3. Identify adversarial inputs in real-time
4. Monitor for model extraction attacks
5. Build alerting systems for ML security events

## Background

### Why Monitor ML Models?

ML models face unique security challenges in production:

| Threat | Detection Challenge | Impact |
|--------|-------------------|--------|
| Data Drift | Input distribution changes | Degraded accuracy, unexpected behavior |
| Adversarial Inputs | Subtle perturbations | Incorrect predictions |
| Model Extraction | Query patterns analysis | Intellectual property theft |
| Data Poisoning | Training data integrity | Backdoor activation |
| Prompt Injection | Real-time input analysis | Unauthorized actions |

### Monitoring Architecture

```
Production Traffic          Analysis Pipeline         Alert System
┌─────────────────┐        ┌───────────────┐        ┌─────────────────┐
│   API Gateway   │───────▶│  Feature      │───────▶│  Anomaly        │
│                 │        │  Extraction   │        │  Detection      │
│   Model API     │        ├───────────────┤        ├─────────────────┤
│                 │───────▶│  Drift        │───────▶│  Alert          │
│   Predictions   │        │  Detection    │        │  Generation     │
│                 │        ├───────────────┤        ├─────────────────┤
│   Feedback      │───────▶│  Adversarial  │───────▶│  SIEM           │
│                 │        │  Detection    │        │  Integration    │
└─────────────────┘        └───────────────┘        └─────────────────┘
```

## Part 1: Data Drift Detection

### Exercise 1.1: Statistical Drift Detection

```python
import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

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
                    'percentiles': data[col].quantile([0.25, 0.5, 0.75]).to_dict()
                }
            else:
                stats_dict[col] = {
                    'value_counts': data[col].value_counts(normalize=True).to_dict()
                }

        return stats_dict

    def detect_drift(self, production_data: pd.DataFrame) -> List[DriftResult]:
        """Detect drift between reference and production data."""

        results = []

        for col in production_data.columns:
            if col not in self.reference.columns:
                continue

            if production_data[col].dtype in ['float64', 'int64']:
                # Numerical features: KS test
                result = self._ks_test(col, production_data[col])
            else:
                # Categorical features: Chi-square test
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

    def _chi_square_test(self, feature: str, production_values: pd.Series) -> DriftResult:
        """Chi-square test for categorical features."""

        ref_counts = self.reference[feature].value_counts()
        prod_counts = production_values.value_counts()

        # Align categories
        all_categories = set(ref_counts.index) | set(prod_counts.index)

        ref_aligned = [ref_counts.get(cat, 0) for cat in all_categories]
        prod_aligned = [prod_counts.get(cat, 0) for cat in all_categories]

        # Normalize to same total
        total = sum(prod_aligned)
        ref_expected = [r * total / sum(ref_aligned) for r in ref_aligned]

        statistic, p_value = stats.chisquare(prod_aligned, ref_expected)

        return DriftResult(
            feature=feature,
            drift_detected=p_value < self.threshold,
            p_value=p_value,
            drift_score=statistic,
            method='chi_square',
            timestamp=datetime.now()
        )
```

### Exercise 1.2: Concept Drift Detection

```python
class ConceptDriftDetector:
    """Detect concept drift - changes in relationship between features and target."""

    def __init__(self, model, window_size: int = 1000):
        self.model = model
        self.window_size = window_size
        self.performance_history = []

    def monitor_performance(self, X: np.ndarray, y_true: np.ndarray) -> Dict:
        """Monitor model performance over time."""

        y_pred = self.model.predict(X)

        # Calculate metrics
        metrics = {
            'timestamp': datetime.now(),
            'accuracy': (y_pred == y_true).mean(),
            'samples': len(y_true)
        }

        self.performance_history.append(metrics)

        # Check for concept drift using Page-Hinkley test
        drift_detected = self._page_hinkley_test()

        return {
            'current_metrics': metrics,
            'drift_detected': drift_detected,
            'history_length': len(self.performance_history)
        }

    def _page_hinkley_test(self, delta: float = 0.005, threshold: float = 50) -> bool:
        """Page-Hinkley test for concept drift detection."""

        if len(self.performance_history) < self.window_size:
            return False

        # Use accuracy as the monitored metric
        values = [h['accuracy'] for h in self.performance_history[-self.window_size:]]

        mean = np.mean(values)
        cumsum = 0
        min_cumsum = 0

        for v in values:
            cumsum += v - mean - delta
            min_cumsum = min(min_cumsum, cumsum)

            if cumsum - min_cumsum > threshold:
                return True

        return False

    def get_drift_report(self) -> Dict:
        """Generate drift report from history."""

        if not self.performance_history:
            return {'status': 'no_data'}

        recent = self.performance_history[-100:]
        older = self.performance_history[-500:-100] if len(self.performance_history) > 500 else []

        report = {
            'current_accuracy': recent[-1]['accuracy'] if recent else None,
            'recent_avg_accuracy': np.mean([r['accuracy'] for r in recent]),
            'total_samples': sum(h['samples'] for h in self.performance_history)
        }

        if older:
            report['older_avg_accuracy'] = np.mean([r['accuracy'] for r in older])
            report['accuracy_change'] = report['recent_avg_accuracy'] - report['older_avg_accuracy']

        return report
```

### Exercise 1.3: Real-time Drift Monitoring

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
        self.monitoring = False
        self.drift_alerts = []

    def add_sample(self, sample: Dict):
        """Add a new sample to the monitoring buffer."""

        sample['_timestamp'] = datetime.now()
        self.buffer.append(sample)

        # Check if buffer is ready for analysis
        if len(self.buffer) >= 100:
            self._analyze_buffer()

    def _analyze_buffer(self):
        """Analyze current buffer for drift."""

        # Convert buffer to DataFrame
        df = pd.DataFrame(list(self.buffer))

        # Exclude metadata columns
        feature_cols = [c for c in df.columns if not c.startswith('_')]
        feature_df = df[feature_cols]

        # Detect drift
        drift_results = self.drift_detector.detect_drift(feature_df)

        # Check for significant drift
        drifted_features = [r for r in drift_results if r.drift_detected]

        if drifted_features:
            alert = {
                'timestamp': datetime.now(),
                'features': [f.feature for f in drifted_features],
                'severity': self._calculate_severity(drifted_features),
                'details': [vars(f) for f in drifted_features]
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
        else:
            return 'LOW'

    def start_monitoring(self, check_interval: int = 60):
        """Start background monitoring thread."""

        self.monitoring = True

        def monitor_loop():
            while self.monitoring:
                if len(self.buffer) >= 100:
                    self._analyze_buffer()
                time.sleep(check_interval)

        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()

    def stop_monitoring(self):
        """Stop monitoring."""
        self.monitoring = False
```

## Part 2: Adversarial Input Detection

### Exercise 2.1: Input Anomaly Detection

```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AdversarialInputDetector:
    """Detect potentially adversarial inputs to ML models."""

    def __init__(self, training_data: np.ndarray):
        self.scaler = StandardScaler()
        self.training_data_scaled = self.scaler.fit_transform(training_data)

        # Train anomaly detector on clean training data
        self.iso_forest = IsolationForest(
            contamination=0.01,
            random_state=42,
            n_estimators=100
        )
        self.iso_forest.fit(self.training_data_scaled)

        # Store statistics for additional checks
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
            'anomaly_scores': [],
            'details': []
        }

        # Scale inputs
        inputs_scaled = self.scaler.transform(inputs)

        # Isolation Forest anomaly detection
        predictions = self.iso_forest.predict(inputs_scaled)
        scores = self.iso_forest.decision_function(inputs_scaled)

        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            is_anomaly = pred == -1

            # Additional checks
            input_vec = inputs[idx]
            anomaly_reasons = []

            # Check for out-of-distribution values
            for feat_idx in range(len(input_vec)):
                feat_val = input_vec[feat_idx]
                feat_min = self.feature_stats['min'][feat_idx]
                feat_max = self.feature_stats['max'][feat_idx]
                feat_mean = self.feature_stats['mean'][feat_idx]
                feat_std = self.feature_stats['std'][feat_idx]

                if feat_val < feat_min or feat_val > feat_max:
                    anomaly_reasons.append(f'Feature {feat_idx} out of range')

                # Check for extreme z-score
                if feat_std > 0:
                    z_score = abs(feat_val - feat_mean) / feat_std
                    if z_score > 4:
                        anomaly_reasons.append(f'Feature {feat_idx} extreme z-score: {z_score:.2f}')

            if is_anomaly or anomaly_reasons:
                results['anomalies_detected'] += 1
                results['anomaly_indices'].append(idx)
                results['anomaly_scores'].append(score)
                results['details'].append({
                    'index': idx,
                    'isolation_forest_score': score,
                    'reasons': anomaly_reasons
                })

        return results
```

### Exercise 2.2: Gradient-Based Attack Detection

```python
class GradientAttackDetector:
    """Detect gradient-based adversarial attacks."""

    def __init__(self, model, epsilon_threshold: float = 0.1):
        self.model = model
        self.epsilon_threshold = epsilon_threshold
        self.input_history = []

    def detect_perturbation_attack(
        self,
        current_input: np.ndarray,
        previous_input: np.ndarray,
        current_prediction: int,
        previous_prediction: int
    ) -> Dict:
        """Detect if input change resembles adversarial perturbation."""

        # Calculate perturbation
        perturbation = current_input - previous_input
        perturbation_norm = np.linalg.norm(perturbation)

        # Check if small perturbation caused prediction change
        is_suspicious = (
            perturbation_norm < self.epsilon_threshold and
            current_prediction != previous_prediction
        )

        result = {
            'perturbation_norm': perturbation_norm,
            'prediction_changed': current_prediction != previous_prediction,
            'is_suspicious': is_suspicious,
            'perturbation_pattern': self._analyze_perturbation(perturbation)
        }

        return result

    def _analyze_perturbation(self, perturbation: np.ndarray) -> Dict:
        """Analyze perturbation pattern for adversarial signatures."""

        return {
            'l2_norm': np.linalg.norm(perturbation),
            'l_inf_norm': np.max(np.abs(perturbation)),
            'sparsity': np.sum(perturbation != 0) / len(perturbation),
            'mean_perturbation': np.mean(np.abs(perturbation)),
            'max_perturbed_feature': int(np.argmax(np.abs(perturbation)))
        }

    def track_input_sequence(self, user_id: str, input_vec: np.ndarray, prediction: int):
        """Track input sequences for detecting iterative attacks."""

        self.input_history.append({
            'user_id': user_id,
            'input': input_vec,
            'prediction': prediction,
            'timestamp': datetime.now()
        })

        # Analyze recent history for this user
        user_history = [h for h in self.input_history if h['user_id'] == user_id]

        if len(user_history) >= 2:
            # Check for iterative refinement pattern
            recent = user_history[-10:]

            perturbations = []
            for i in range(1, len(recent)):
                pert = recent[i]['input'] - recent[i-1]['input']
                perturbations.append(np.linalg.norm(pert))

            # Suspicious if many small perturbations
            if len(perturbations) > 5 and np.mean(perturbations) < 0.05:
                return {
                    'alert': True,
                    'reason': 'Iterative small perturbations detected',
                    'user_id': user_id,
                    'perturbation_count': len(perturbations),
                    'mean_perturbation': np.mean(perturbations)
                }

        return {'alert': False}
```

### Exercise 2.3: LLM Input Monitoring

```python
class LLMInputMonitor:
    """Monitor LLM inputs for adversarial patterns."""

    INJECTION_PATTERNS = [
        r'ignore.*(?:previous|above).*instruction',
        r'disregard.*(?:system|prompt)',
        r'you are now',
        r'new instruction',
        r'\[(?:system|admin|debug)\]',
        r'```.*(?:system|instruction)',
    ]

    JAILBREAK_PATTERNS = [
        r'DAN',
        r'developer mode',
        r'no restrictions',
        r'hypothetically',
        r'roleplay as',
        r'pretend you',
    ]

    def __init__(self):
        self.input_history = []
        self.alerts = []

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
                analysis['suspicious_patterns'].append({
                    'type': 'injection',
                    'pattern': pattern
                })
                analysis['risk_score'] += 30

        # Check for jailbreak patterns
        for pattern in self.JAILBREAK_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                analysis['jailbreak_detected'] = True
                analysis['suspicious_patterns'].append({
                    'type': 'jailbreak',
                    'pattern': pattern
                })
                analysis['risk_score'] += 20

        # Check for encoding tricks
        encoding_tricks = self._detect_encoding_tricks(user_input)
        if encoding_tricks:
            analysis['suspicious_patterns'].extend(encoding_tricks)
            analysis['risk_score'] += 15 * len(encoding_tricks)

        # Check for unusual character patterns
        char_analysis = self._analyze_characters(user_input)
        if char_analysis['suspicious']:
            analysis['suspicious_patterns'].append(char_analysis)
            analysis['risk_score'] += 10

        # Store in history
        self.input_history.append(analysis)

        # Generate alert if high risk
        if analysis['risk_score'] >= 30:
            alert = {
                'severity': 'HIGH' if analysis['risk_score'] >= 50 else 'MEDIUM',
                'analysis': analysis
            }
            self.alerts.append(alert)

        return analysis

    def _detect_encoding_tricks(self, text: str) -> List[Dict]:
        """Detect encoding-based attacks."""

        tricks = []

        # Base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        if re.search(base64_pattern, text):
            tricks.append({'type': 'encoding', 'subtype': 'base64'})

        # Zero-width characters
        if re.search(r'[\u200b\u200c\u200d\ufeff]', text):
            tricks.append({'type': 'encoding', 'subtype': 'zero_width'})

        # Unicode direction overrides
        if re.search(r'[\u202a-\u202e]', text):
            tricks.append({'type': 'encoding', 'subtype': 'direction_override'})

        return tricks

    def _analyze_characters(self, text: str) -> Dict:
        """Analyze character distribution for anomalies."""

        analysis = {
            'type': 'character_analysis',
            'suspicious': False,
            'details': {}
        }

        # Check for unusual Unicode ranges
        unusual_chars = sum(1 for c in text if ord(c) > 127)
        unusual_ratio = unusual_chars / len(text) if text else 0

        if unusual_ratio > 0.3:
            analysis['suspicious'] = True
            analysis['details']['unusual_char_ratio'] = unusual_ratio

        # Check for control characters
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\n\t\r')
        if control_chars > 0:
            analysis['suspicious'] = True
            analysis['details']['control_chars'] = control_chars

        return analysis
```

## Part 3: Model Extraction Detection

### Exercise 3.1: Query Pattern Analysis

```python
class ModelExtractionDetector:
    """Detect model extraction attacks through query analysis."""

    def __init__(self, model_type: str = 'classifier'):
        self.model_type = model_type
        self.query_history = []
        self.user_profiles = {}

    def log_query(self, user_id: str, query: np.ndarray, response: Any):
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
                'first_seen': entry['timestamp'],
                'feature_coverage': set()
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
                'value': profile['query_count'],
                'threshold': 10000
            })

        # Check query rate
        if len(queries) >= 2:
            time_span = (queries[-1]['timestamp'] - queries[0]['timestamp']).total_seconds()
            rate = len(queries) / (time_span / 3600) if time_span > 0 else float('inf')

            if rate > 1000:  # More than 1000 queries per hour
                indicators.append({
                    'type': 'high_rate',
                    'value': rate,
                    'threshold': 1000
                })

        # Check for systematic querying patterns
        systematic_score = self._detect_systematic_queries(queries)
        if systematic_score > 0.7:
            indicators.append({
                'type': 'systematic_pattern',
                'score': systematic_score
            })

        # Check for decision boundary probing
        boundary_probing = self._detect_boundary_probing(queries)
        if boundary_probing['detected']:
            indicators.append({
                'type': 'boundary_probing',
                **boundary_probing
            })

        return {
            'user_id': user_id,
            'suspicious': len(indicators) > 0,
            'risk_level': self._calculate_risk_level(indicators),
            'indicators': indicators
        }

    def _detect_systematic_queries(self, queries: List[Dict]) -> float:
        """Detect systematic query patterns indicative of extraction."""

        if len(queries) < 100:
            return 0.0

        # Convert queries to numpy array
        query_vectors = np.array([q['query'] for q in queries[-1000:]])

        # Check for grid-like patterns
        variance_per_feature = np.var(query_vectors, axis=0)
        uniform_features = np.sum(variance_per_feature < 0.01)

        # Check for sequential patterns
        diffs = np.diff(query_vectors, axis=0)
        uniform_diffs = np.sum(np.var(diffs, axis=0) < 0.001)

        systematic_score = (uniform_features + uniform_diffs) / (2 * query_vectors.shape[1])

        return systematic_score

    def _detect_boundary_probing(self, queries: List[Dict]) -> Dict:
        """Detect decision boundary probing."""

        if len(queries) < 50:
            return {'detected': False}

        # Group queries by response
        response_groups = {}
        for q in queries[-500:]:
            resp = str(q['response'])
            if resp not in response_groups:
                response_groups[resp] = []
            response_groups[resp].append(q['query'])

        # Check for queries near decision boundaries
        if len(response_groups) >= 2:
            # Find pairs of queries with different responses that are close together
            boundary_pairs = 0

            for resp1, queries1 in response_groups.items():
                for resp2, queries2 in response_groups.items():
                    if resp1 >= resp2:
                        continue

                    for q1 in queries1[:100]:
                        for q2 in queries2[:100]:
                            dist = np.linalg.norm(np.array(q1) - np.array(q2))
                            if dist < 0.1:
                                boundary_pairs += 1

            if boundary_pairs > 50:
                return {
                    'detected': True,
                    'boundary_pairs': boundary_pairs
                }

        return {'detected': False}

    def _calculate_risk_level(self, indicators: List[Dict]) -> str:
        """Calculate overall risk level."""

        if not indicators:
            return 'LOW'

        indicator_types = [i['type'] for i in indicators]

        if 'boundary_probing' in indicator_types and 'systematic_pattern' in indicator_types:
            return 'CRITICAL'
        elif 'boundary_probing' in indicator_types or len(indicators) >= 3:
            return 'HIGH'
        elif len(indicators) >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
```

### Exercise 3.2: Response Watermarking

```python
class ModelWatermarking:
    """Watermark model responses to detect theft."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.watermark_patterns = self._generate_patterns()

    def _generate_patterns(self) -> Dict:
        """Generate watermark patterns from secret key."""

        import hashlib

        # Create deterministic random generator from key
        seed = int(hashlib.sha256(self.secret_key.encode()).hexdigest()[:8], 16)
        np.random.seed(seed)

        return {
            'confidence_adjustment': np.random.uniform(-0.001, 0.001, 1000),
            'response_delay_pattern': np.random.uniform(0, 0.01, 100)
        }

    def watermark_response(self, response: Dict, query_hash: str) -> Dict:
        """Add subtle watermark to model response."""

        watermarked = response.copy()

        # Add confidence watermark
        if 'confidence' in watermarked:
            idx = hash(query_hash) % len(self.watermark_patterns['confidence_adjustment'])
            adjustment = self.watermark_patterns['confidence_adjustment'][idx]
            watermarked['confidence'] += adjustment

        # Add response time watermark
        delay_idx = hash(query_hash) % len(self.watermark_patterns['response_delay_pattern'])
        watermarked['_watermark_delay'] = self.watermark_patterns['response_delay_pattern'][delay_idx]

        return watermarked

    def verify_watermark(self, responses: List[Dict], queries: List[str]) -> Dict:
        """Verify if responses contain our watermark."""

        if len(responses) < 100:
            return {'verified': False, 'reason': 'Insufficient samples'}

        # Extract potential watermark signals
        confidence_deltas = []
        for resp, query in zip(responses, queries):
            if 'confidence' not in resp:
                continue

            idx = hash(query) % len(self.watermark_patterns['confidence_adjustment'])
            expected = self.watermark_patterns['confidence_adjustment'][idx]

            # Compare with response (would need original confidence)
            # This is a simplified check
            confidence_deltas.append(resp['confidence'])

        # Statistical test for watermark presence
        correlation = np.corrcoef(
            confidence_deltas[:len(self.watermark_patterns['confidence_adjustment'])],
            self.watermark_patterns['confidence_adjustment'][:len(confidence_deltas)]
        )[0, 1]

        return {
            'verified': correlation > 0.8,
            'correlation': correlation,
            'samples_analyzed': len(responses)
        }
```

## Part 4: Alerting and Integration

### Exercise 4.1: Security Alert System

```python
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

    def generate_alert(
        self,
        alert_type: str,
        severity: str,
        details: Dict,
        source: str = None
    ):
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

        # Dispatch to handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")

        return alert

    def integrate_siem(self, siem_config: Dict):
        """Set up SIEM integration."""

        def siem_handler(alert):
            # Format for SIEM ingestion
            siem_event = {
                'event_type': 'ml_security_alert',
                'timestamp': alert['timestamp'],
                'severity': alert['severity'],
                'category': alert['type'],
                'description': self._format_description(alert),
                'raw_data': alert
            }

            # Send to SIEM (implementation depends on SIEM type)
            self._send_to_siem(siem_event, siem_config)

        self.register_handler(siem_handler)

    def _format_description(self, alert: Dict) -> str:
        """Format alert for human readability."""

        descriptions = {
            'drift': f"Data drift detected in features: {alert['details'].get('features', 'unknown')}",
            'adversarial': f"Potential adversarial input detected from user {alert['details'].get('user_id', 'unknown')}",
            'extraction': f"Model extraction attempt suspected from {alert['details'].get('user_id', 'unknown')}"
        }

        return descriptions.get(alert['type'], f"ML security event: {alert['type']}")

    def _send_to_siem(self, event: Dict, config: Dict):
        """Send event to SIEM."""
        # Implementation depends on SIEM type (Elasticsearch, OpenSearch, etc.)
        pass
```

## Exercises

### Exercise 1: Drift Detection Setup
1. Implement drift detection for a sample dataset
2. Configure thresholds for different features
3. Set up alerting for drift events

### Exercise 2: Adversarial Monitoring
1. Deploy adversarial input detection
2. Test with various attack patterns
3. Tune detection sensitivity

### Exercise 3: Extraction Detection
1. Implement query pattern analysis
2. Configure user profiling
3. Test with simulated extraction attacks

### Exercise 4: Integration
1. Set up centralized alerting
2. Create SIEM integration
3. Build monitoring dashboard

## Challenge Questions

1. How do you balance detection sensitivity with false positive rates?
2. What are the limitations of statistical drift detection?
3. Design a system to detect coordinated extraction attacks from multiple accounts.
4. How would you detect model extraction through a proxy/VPN?

## Resources

- [Evidently AI - ML Monitoring](https://www.evidentlyai.com/)
- [Alibi Detect](https://docs.seldon.io/projects/alibi-detect/)
- [WhyLabs - ML Observability](https://whylabs.ai/)
- [MLflow Model Registry](https://mlflow.org/docs/latest/model-registry.html)

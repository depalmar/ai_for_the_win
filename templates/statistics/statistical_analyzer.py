#!/usr/bin/env python3
"""
Statistical Analysis Utilities for Security ML

Provides statistical analysis for:
- Detection metrics (precision, recall, F1, ROC)
- Anomaly scoring and calibration
- Clustering validation
- Confidence intervals
- Hypothesis testing
- Distribution analysis
"""

import math
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Any
from collections import Counter
import json


@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification."""
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return self.true_positives + self.true_negatives + self.false_positives + self.false_negatives

    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom > 0 else 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives
        }


@dataclass
class ConfidenceInterval:
    """Confidence interval for a statistic."""
    point_estimate: float
    lower_bound: float
    upper_bound: float
    confidence_level: float = 0.95

    @property
    def margin_of_error(self) -> float:
        return (self.upper_bound - self.lower_bound) / 2


@dataclass
class ClusterMetrics:
    """Metrics for clustering evaluation."""
    silhouette_score: float
    davies_bouldin_index: float
    calinski_harabasz_index: float
    num_clusters: int
    cluster_sizes: List[int]


class StatisticalAnalyzer:
    """Statistical analysis for security ML models."""

    # Z-scores for common confidence levels
    Z_SCORES = {
        0.90: 1.645,
        0.95: 1.96,
        0.99: 2.576
    }

    # ==========================================================================
    # Basic Statistics
    # ==========================================================================

    @staticmethod
    def mean(values: List[float]) -> float:
        """Calculate mean of values."""
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def variance(values: List[float], sample: bool = True) -> float:
        """Calculate variance of values."""
        if len(values) < 2:
            return 0.0
        m = StatisticalAnalyzer.mean(values)
        ss = sum((x - m) ** 2 for x in values)
        return ss / (len(values) - 1) if sample else ss / len(values)

    @staticmethod
    def std_dev(values: List[float], sample: bool = True) -> float:
        """Calculate standard deviation."""
        return math.sqrt(StatisticalAnalyzer.variance(values, sample))

    @staticmethod
    def median(values: List[float]) -> float:
        """Calculate median of values."""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        mid = n // 2
        if n % 2 == 0:
            return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
        return sorted_vals[mid]

    @staticmethod
    def percentile(values: List[float], p: float) -> float:
        """Calculate p-th percentile."""
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * (p / 100)
        f = int(k)
        c = f + 1 if f + 1 < len(sorted_vals) else f
        return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])

    @staticmethod
    def iqr(values: List[float]) -> float:
        """Calculate interquartile range."""
        return StatisticalAnalyzer.percentile(values, 75) - StatisticalAnalyzer.percentile(values, 25)

    # ==========================================================================
    # Entropy and Information Theory
    # ==========================================================================

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def normalized_entropy(data: bytes) -> float:
        """Calculate normalized entropy (0-1 scale)."""
        entropy = StatisticalAnalyzer.shannon_entropy(data)
        # Max entropy for bytes is 8 bits
        return entropy / 8.0

    # ==========================================================================
    # Detection Metrics
    # ==========================================================================

    @staticmethod
    def calculate_confusion_matrix(
        y_true: List[int],
        y_pred: List[int]
    ) -> ConfusionMatrix:
        """Calculate confusion matrix from predictions."""
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

        return ConfusionMatrix(
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn
        )

    @staticmethod
    def calculate_roc_points(
        y_true: List[int],
        y_scores: List[float],
        num_thresholds: int = 100
    ) -> List[Tuple[float, float]]:
        """Calculate ROC curve points (FPR, TPR)."""
        min_score = min(y_scores)
        max_score = max(y_scores)
        thresholds = [
            min_score + (max_score - min_score) * i / num_thresholds
            for i in range(num_thresholds + 1)
        ]

        points = []
        for threshold in thresholds:
            y_pred = [1 if s >= threshold else 0 for s in y_scores]
            cm = StatisticalAnalyzer.calculate_confusion_matrix(y_true, y_pred)
            points.append((cm.false_positive_rate, cm.recall))

        return sorted(points)

    @staticmethod
    def calculate_auc(points: List[Tuple[float, float]]) -> float:
        """Calculate area under curve using trapezoidal rule."""
        if len(points) < 2:
            return 0.0

        auc = 0.0
        for i in range(1, len(points)):
            x1, y1 = points[i - 1]
            x2, y2 = points[i]
            auc += (x2 - x1) * (y1 + y2) / 2

        return auc

    # ==========================================================================
    # Confidence Intervals
    # ==========================================================================

    @staticmethod
    def proportion_confidence_interval(
        successes: int,
        total: int,
        confidence: float = 0.95
    ) -> ConfidenceInterval:
        """Calculate confidence interval for a proportion."""
        if total == 0:
            return ConfidenceInterval(0.0, 0.0, 0.0, confidence)

        p = successes / total
        z = StatisticalAnalyzer.Z_SCORES.get(confidence, 1.96)
        se = math.sqrt(p * (1 - p) / total)
        margin = z * se

        return ConfidenceInterval(
            point_estimate=p,
            lower_bound=max(0, p - margin),
            upper_bound=min(1, p + margin),
            confidence_level=confidence
        )

    @staticmethod
    def mean_confidence_interval(
        values: List[float],
        confidence: float = 0.95
    ) -> ConfidenceInterval:
        """Calculate confidence interval for the mean."""
        if len(values) < 2:
            m = values[0] if values else 0.0
            return ConfidenceInterval(m, m, m, confidence)

        m = StatisticalAnalyzer.mean(values)
        se = StatisticalAnalyzer.std_dev(values) / math.sqrt(len(values))
        z = StatisticalAnalyzer.Z_SCORES.get(confidence, 1.96)
        margin = z * se

        return ConfidenceInterval(
            point_estimate=m,
            lower_bound=m - margin,
            upper_bound=m + margin,
            confidence_level=confidence
        )

    # ==========================================================================
    # Anomaly Detection Statistics
    # ==========================================================================

    @staticmethod
    def z_score(value: float, mean: float, std: float) -> float:
        """Calculate z-score for a value."""
        if std == 0:
            return 0.0
        return (value - mean) / std

    @staticmethod
    def modified_z_score(value: float, median: float, mad: float) -> float:
        """Calculate modified z-score using MAD."""
        if mad == 0:
            return 0.0
        return 0.6745 * (value - median) / mad

    @staticmethod
    def median_absolute_deviation(values: List[float]) -> float:
        """Calculate Median Absolute Deviation."""
        med = StatisticalAnalyzer.median(values)
        deviations = [abs(x - med) for x in values]
        return StatisticalAnalyzer.median(deviations)

    @staticmethod
    def identify_outliers_iqr(
        values: List[float],
        multiplier: float = 1.5
    ) -> List[Tuple[int, float]]:
        """Identify outliers using IQR method."""
        q1 = StatisticalAnalyzer.percentile(values, 25)
        q3 = StatisticalAnalyzer.percentile(values, 75)
        iqr = q3 - q1

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        outliers = [
            (i, v) for i, v in enumerate(values)
            if v < lower_bound or v > upper_bound
        ]
        return outliers

    @staticmethod
    def identify_outliers_zscore(
        values: List[float],
        threshold: float = 3.0
    ) -> List[Tuple[int, float]]:
        """Identify outliers using z-score method."""
        mean = StatisticalAnalyzer.mean(values)
        std = StatisticalAnalyzer.std_dev(values)

        outliers = [
            (i, v) for i, v in enumerate(values)
            if abs(StatisticalAnalyzer.z_score(v, mean, std)) > threshold
        ]
        return outliers

    # ==========================================================================
    # Clustering Statistics
    # ==========================================================================

    @staticmethod
    def silhouette_coefficient(
        point: List[float],
        cluster: List[List[float]],
        other_clusters: List[List[List[float]]]
    ) -> float:
        """Calculate silhouette coefficient for a single point."""
        def euclidean_distance(p1: List[float], p2: List[float]) -> float:
            return math.sqrt(sum((a - b) ** 2 for a, b in zip(p1, p2)))

        # Calculate a(i) - average distance to points in same cluster
        if len(cluster) <= 1:
            a = 0
        else:
            distances = [euclidean_distance(point, p) for p in cluster if p != point]
            a = sum(distances) / len(distances) if distances else 0

        # Calculate b(i) - minimum average distance to points in other clusters
        b_values = []
        for other in other_clusters:
            if other:
                distances = [euclidean_distance(point, p) for p in other]
                b_values.append(sum(distances) / len(distances))

        b = min(b_values) if b_values else 0

        # Calculate silhouette
        if max(a, b) == 0:
            return 0
        return (b - a) / max(a, b)

    # ==========================================================================
    # Statistical Tests
    # ==========================================================================

    @staticmethod
    def chi_squared_test(
        observed: List[int],
        expected: List[float]
    ) -> Tuple[float, float]:
        """
        Perform chi-squared test.
        Returns (chi_squared_statistic, p_value_approximation).
        """
        if len(observed) != len(expected):
            raise ValueError("Observed and expected must have same length")

        chi_sq = sum(
            (o - e) ** 2 / e
            for o, e in zip(observed, expected)
            if e > 0
        )

        # Degrees of freedom
        df = len(observed) - 1

        # Approximate p-value (simplified)
        # For accurate p-values, use scipy.stats.chi2.sf
        p_value = math.exp(-chi_sq / 2) if chi_sq < 20 else 0.0

        return chi_sq, p_value

    @staticmethod
    def two_sample_t_test(
        sample1: List[float],
        sample2: List[float]
    ) -> Tuple[float, str]:
        """
        Perform two-sample t-test.
        Returns (t_statistic, significance_interpretation).
        """
        n1, n2 = len(sample1), len(sample2)
        if n1 < 2 or n2 < 2:
            return 0.0, "Insufficient data"

        mean1 = StatisticalAnalyzer.mean(sample1)
        mean2 = StatisticalAnalyzer.mean(sample2)
        var1 = StatisticalAnalyzer.variance(sample1)
        var2 = StatisticalAnalyzer.variance(sample2)

        # Pooled standard error
        se = math.sqrt(var1 / n1 + var2 / n2)
        if se == 0:
            return 0.0, "No variance"

        t_stat = (mean1 - mean2) / se

        # Interpretation
        if abs(t_stat) > 2.576:
            interpretation = "Highly significant (p < 0.01)"
        elif abs(t_stat) > 1.96:
            interpretation = "Significant (p < 0.05)"
        elif abs(t_stat) > 1.645:
            interpretation = "Marginally significant (p < 0.10)"
        else:
            interpretation = "Not significant"

        return t_stat, interpretation

    # ==========================================================================
    # Detection Performance Analysis
    # ==========================================================================

    @staticmethod
    def detection_performance_summary(
        y_true: List[int],
        y_pred: List[int],
        y_scores: Optional[List[float]] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive detection performance summary."""
        cm = StatisticalAnalyzer.calculate_confusion_matrix(y_true, y_pred)

        summary = {
            "confusion_matrix": cm.to_dict(),
            "total_samples": cm.total,
            "positive_rate": sum(y_true) / len(y_true) if y_true else 0,
        }

        # Calculate precision CI
        precision_ci = StatisticalAnalyzer.proportion_confidence_interval(
            cm.true_positives,
            cm.true_positives + cm.false_positives
        )
        summary["precision_95ci"] = {
            "point": precision_ci.point_estimate,
            "lower": precision_ci.lower_bound,
            "upper": precision_ci.upper_bound
        }

        # Calculate recall CI
        recall_ci = StatisticalAnalyzer.proportion_confidence_interval(
            cm.true_positives,
            cm.true_positives + cm.false_negatives
        )
        summary["recall_95ci"] = {
            "point": recall_ci.point_estimate,
            "lower": recall_ci.lower_bound,
            "upper": recall_ci.upper_bound
        }

        # ROC AUC if scores provided
        if y_scores:
            roc_points = StatisticalAnalyzer.calculate_roc_points(y_true, y_scores)
            summary["roc_auc"] = StatisticalAnalyzer.calculate_auc(roc_points)

        return summary


class SecurityMetrics:
    """Security-specific metrics and analysis."""

    @staticmethod
    def alert_fatigue_score(
        total_alerts: int,
        true_positives: int,
        time_to_triage_minutes: List[float]
    ) -> Dict[str, float]:
        """Calculate alert fatigue metrics."""
        precision = true_positives / total_alerts if total_alerts > 0 else 0

        avg_triage_time = StatisticalAnalyzer.mean(time_to_triage_minutes)
        median_triage_time = StatisticalAnalyzer.median(time_to_triage_minutes)

        # Alert fatigue score (higher = worse)
        # Based on false positive rate and triage time
        fp_rate = 1 - precision
        fatigue_score = fp_rate * (1 + avg_triage_time / 60)  # Normalize by hours

        return {
            "precision": precision,
            "false_positive_rate": fp_rate,
            "avg_triage_time_min": avg_triage_time,
            "median_triage_time_min": median_triage_time,
            "alert_fatigue_score": fatigue_score,
            "interpretation": (
                "Critical" if fatigue_score > 0.7 else
                "High" if fatigue_score > 0.5 else
                "Medium" if fatigue_score > 0.3 else
                "Low"
            )
        }

    @staticmethod
    def detection_coverage(
        techniques_detected: List[str],
        total_techniques: List[str]
    ) -> Dict[str, Any]:
        """Calculate MITRE ATT&CK detection coverage."""
        detected_set = set(techniques_detected)
        total_set = set(total_techniques)

        covered = detected_set.intersection(total_set)
        missing = total_set - detected_set

        coverage_pct = len(covered) / len(total_set) * 100 if total_set else 0

        return {
            "total_techniques": len(total_set),
            "techniques_covered": len(covered),
            "techniques_missing": len(missing),
            "coverage_percentage": coverage_pct,
            "missing_techniques": list(missing),
            "rating": (
                "Excellent" if coverage_pct >= 80 else
                "Good" if coverage_pct >= 60 else
                "Fair" if coverage_pct >= 40 else
                "Poor"
            )
        }

    @staticmethod
    def ransomware_impact_score(
        encrypted_files: int,
        total_files: int,
        critical_systems_affected: int,
        total_systems: int,
        data_exfiltrated_gb: float,
        recovery_time_hours: float
    ) -> Dict[str, Any]:
        """Calculate ransomware incident impact score."""
        # File impact (0-25 points)
        file_impact = (encrypted_files / total_files * 25) if total_files > 0 else 0

        # System impact (0-25 points)
        system_impact = (critical_systems_affected / total_systems * 25) if total_systems > 0 else 0

        # Data impact (0-25 points)
        data_impact = min(25, data_exfiltrated_gb * 2.5)

        # Recovery impact (0-25 points)
        recovery_impact = min(25, recovery_time_hours / 4)

        total_score = file_impact + system_impact + data_impact + recovery_impact

        return {
            "file_impact_score": file_impact,
            "system_impact_score": system_impact,
            "data_impact_score": data_impact,
            "recovery_impact_score": recovery_impact,
            "total_impact_score": total_score,
            "severity": (
                "Critical" if total_score >= 75 else
                "High" if total_score >= 50 else
                "Medium" if total_score >= 25 else
                "Low"
            ),
            "metrics": {
                "files_encrypted_pct": encrypted_files / total_files * 100 if total_files else 0,
                "systems_affected_pct": critical_systems_affected / total_systems * 100 if total_systems else 0,
                "data_exfiltrated_gb": data_exfiltrated_gb,
                "recovery_time_hours": recovery_time_hours
            }
        }


def main():
    """Demo the statistical analyzer."""
    print("=" * 60)
    print("Statistical Analysis Demo")
    print("=" * 60)

    # Sample detection data
    y_true = [1, 1, 1, 1, 0, 0, 0, 0, 1, 0]
    y_pred = [1, 1, 0, 1, 0, 1, 0, 0, 1, 0]
    y_scores = [0.9, 0.8, 0.4, 0.7, 0.2, 0.6, 0.3, 0.1, 0.85, 0.15]

    # Calculate metrics
    analyzer = StatisticalAnalyzer()

    print("\n[1] Detection Performance:")
    summary = analyzer.detection_performance_summary(y_true, y_pred, y_scores)
    print(f"  Accuracy: {summary['confusion_matrix']['accuracy']:.2%}")
    print(f"  Precision: {summary['confusion_matrix']['precision']:.2%}")
    print(f"  Recall: {summary['confusion_matrix']['recall']:.2%}")
    print(f"  F1 Score: {summary['confusion_matrix']['f1_score']:.2%}")
    print(f"  ROC AUC: {summary.get('roc_auc', 'N/A'):.3f}")

    print("\n[2] Confidence Intervals (95%):")
    print(f"  Precision: [{summary['precision_95ci']['lower']:.2%}, {summary['precision_95ci']['upper']:.2%}]")
    print(f"  Recall: [{summary['recall_95ci']['lower']:.2%}, {summary['recall_95ci']['upper']:.2%}]")

    # Anomaly scores
    print("\n[3] Anomaly Detection:")
    scores = [10, 12, 11, 13, 9, 100, 11, 12, 10, 150]
    outliers = analyzer.identify_outliers_iqr(scores)
    print(f"  Outliers (IQR method): {outliers}")

    # Security metrics
    print("\n[4] Alert Fatigue Analysis:")
    fatigue = SecurityMetrics.alert_fatigue_score(
        total_alerts=1000,
        true_positives=300,
        time_to_triage_minutes=[5, 10, 3, 15, 8, 20, 4, 6, 12, 7]
    )
    print(f"  False Positive Rate: {fatigue['false_positive_rate']:.2%}")
    print(f"  Avg Triage Time: {fatigue['avg_triage_time_min']:.1f} min")
    print(f"  Fatigue Score: {fatigue['alert_fatigue_score']:.2f}")
    print(f"  Interpretation: {fatigue['interpretation']}")

    # Ransomware impact
    print("\n[5] Ransomware Impact Score:")
    impact = SecurityMetrics.ransomware_impact_score(
        encrypted_files=5000,
        total_files=10000,
        critical_systems_affected=3,
        total_systems=20,
        data_exfiltrated_gb=50,
        recovery_time_hours=72
    )
    print(f"  Total Impact Score: {impact['total_impact_score']:.1f}/100")
    print(f"  Severity: {impact['severity']}")


if __name__ == "__main__":
    main()

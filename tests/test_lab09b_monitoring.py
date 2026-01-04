"""Tests for Lab 09b: Monitoring AI Systems."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab09b-monitoring-ai-systems" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        AIMetrics,
        MetricsCollector,
        PerformanceMonitor,
        create_dashboard_data,
    )


def test_ai_metrics_dataclass():
    """Test AIMetrics dataclass structure."""
    from main import AIMetrics

    metrics = AIMetrics(
        timestamp="2024-01-15T10:30:00Z",
        model_name="claude-3-5-sonnet",
        latency_ms=150.5,
        tokens_used=500,
        cost_usd=0.015,
        success=True,
    )

    assert metrics.latency_ms == 150.5
    assert metrics.success is True


def test_metrics_collector_record():
    """Test recording metrics."""
    from main import MetricsCollector

    collector = MetricsCollector()
    collector.record(
        model_name="test-model",
        latency_ms=100.0,
        tokens_used=200,
        cost_usd=0.01,
        success=True,
    )

    assert len(collector.metrics) == 1
    assert collector.metrics[0].model_name == "test-model"


def test_metrics_collector_summary():
    """Test metrics summary calculation."""
    from main import MetricsCollector

    collector = MetricsCollector()

    # Record multiple metrics
    for i in range(5):
        collector.record(
            model_name="test-model",
            latency_ms=100.0 + i * 10,
            tokens_used=200,
            cost_usd=0.01,
            success=i < 4,  # 4 successes, 1 failure
        )

    summary = collector.get_summary()

    assert "total_calls" in summary
    assert summary["total_calls"] == 5
    assert "success_rate" in summary
    assert summary["success_rate"] == 0.8  # 4/5
    assert "avg_latency_ms" in summary


def test_performance_monitor_threshold():
    """Test performance threshold monitoring."""
    from main import PerformanceMonitor

    monitor = PerformanceMonitor(
        latency_threshold_ms=200.0,
        error_rate_threshold=0.1,
    )

    # Test latency alert
    alerts = monitor.check_latency(250.0)
    assert len(alerts) > 0  # Should generate alert

    # Test acceptable latency
    alerts = monitor.check_latency(150.0)
    assert len(alerts) == 0  # No alert


def test_dashboard_data_generation():
    """Test dashboard data generation."""
    from main import MetricsCollector, create_dashboard_data

    collector = MetricsCollector()
    collector.record(
        model_name="test-model",
        latency_ms=100.0,
        tokens_used=200,
        cost_usd=0.01,
        success=True,
    )

    dashboard = create_dashboard_data(collector)

    assert "summary" in dashboard
    assert "recent_metrics" in dashboard
    assert "alerts" in dashboard

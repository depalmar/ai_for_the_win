#!/usr/bin/env python3
"""Tests for Lab 09: Multi-Stage Threat Detection Pipeline."""

import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab23-detection-pipeline" / "solution")
sys.path.insert(0, lab_path)

from main import CorrelationStage, DetectionPipeline, EventIngestor, MLFilterStage, VerdictStage


@pytest.fixture
def sample_sysmon_event():
    """Create sample Sysmon event."""
    return {
        "timestamp": "2024-01-15T03:22:10Z",
        "host": "WORKSTATION01",
        "event_type": "process",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc SGVsbG8gV29ybGQ=",
        "parent_process": "cmd.exe",
        "user": "jsmith",
    }


@pytest.fixture
def sample_network_event():
    """Create sample network event."""
    return {
        "timestamp": "2024-01-15T03:22:15Z",
        "host": "WORKSTATION01",
        "event_type": "network",
        "process_name": "powershell.exe",
        "dest_ip": "185.143.223.47",
        "dest_port": 443,
        "user": "jsmith",
    }


@pytest.fixture
def sample_events(sample_sysmon_event, sample_network_event):
    """Create list of sample events."""
    return [sample_sysmon_event, sample_network_event]


class TestEventIngestor:
    """Tests for event ingestion."""

    def test_ingest_sysmon_event(self, sample_sysmon_event):
        """Test Sysmon event ingestion."""
        ingestor = EventIngestor()
        normalized = ingestor.ingest_event(sample_sysmon_event, "sysmon")

        assert normalized is not None
        assert "id" in normalized
        assert "timestamp" in normalized
        assert "source" in normalized
        assert normalized["source"] == "sysmon"

    def test_ingest_windows_event(self):
        """Test Windows event ingestion."""
        windows_event = {
            "EventTime": "2024-01-15T10:00:00Z",
            "Computer": "SERVER01",
            "EventID": 4624,
            "TargetUserName": "admin",
        }

        ingestor = EventIngestor()
        normalized = ingestor.ingest_event(windows_event, "windows")

        assert normalized is not None
        assert "host" in normalized

    def test_normalized_event_schema(self, sample_sysmon_event):
        """Test that normalized events follow schema."""
        ingestor = EventIngestor()
        normalized = ingestor.ingest_event(sample_sysmon_event, "sysmon")

        required_fields = ["id", "timestamp", "source", "event_type", "host"]
        for field in required_fields:
            assert field in normalized


class TestMLFilterStage:
    """Tests for ML filtering stage."""

    def test_extract_features(self, sample_sysmon_event):
        """Test feature extraction."""
        ingestor = EventIngestor()
        normalized = ingestor.ingest_event(sample_sysmon_event, "sysmon")

        ml_filter = MLFilterStage()
        features = ml_filter.extract_features(normalized)

        assert features is not None
        assert isinstance(features, np.ndarray)
        assert len(features) > 0

    def test_train_model(self, sample_events):
        """Test model training."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        # Add more events for training
        for _ in range(50):
            normalized_events.append(normalized_events[0].copy())

        ml_filter = MLFilterStage()
        ml_filter.train(normalized_events)

        assert ml_filter.model is not None

    def test_score_event(self, sample_events):
        """Test event scoring."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        # Train with synthetic data
        training_events = normalized_events * 50
        ml_filter = MLFilterStage()
        ml_filter.train(training_events)

        score = ml_filter.score_event(normalized_events[0])

        assert score is not None
        assert 0 <= score <= 1

    def test_filter_events(self, sample_events):
        """Test event filtering."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        training_events = normalized_events * 50
        ml_filter = MLFilterStage()
        ml_filter.train(training_events)

        filtered = ml_filter.filter_events(normalized_events)

        assert isinstance(filtered, list)


class TestCorrelationStage:
    """Tests for event correlation."""

    def test_add_event(self, sample_sysmon_event):
        """Test adding events to buffer."""
        ingestor = EventIngestor()
        normalized = ingestor.ingest_event(sample_sysmon_event, "sysmon")

        correlator = CorrelationStage()
        correlator.add_event(normalized)

        assert len(correlator.event_buffer) == 1

    def test_find_related_events(self, sample_events):
        """Test finding related events."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        correlator = CorrelationStage()
        for event in normalized_events:
            correlator.add_event(event)

        related = correlator.find_related_events(normalized_events[0])

        assert isinstance(related, list)
        # Events from same host should be related
        assert len(related) >= 1

    def test_detect_attack_chain(self, sample_events):
        """Test attack chain detection."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        correlator = CorrelationStage()
        chain = correlator.detect_attack_chain(normalized_events)

        assert chain is not None
        assert "events" in chain or "tactics" in chain


class TestVerdictStage:
    """Tests for verdict generation."""

    def test_generate_verdict(self, sample_events):
        """Test verdict generation."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        verdict_stage = VerdictStage()
        verdict = verdict_stage.generate_verdict(normalized_events)

        assert verdict is not None
        assert "verdict" in verdict or "confidence" in verdict

    def test_create_alert(self, sample_events):
        """Test alert creation."""
        ingestor = EventIngestor()
        normalized_events = [ingestor.ingest_event(e, "sysmon") for e in sample_events]

        verdict_stage = VerdictStage()
        verdict = verdict_stage.generate_verdict(normalized_events)
        alert = verdict_stage.create_alert(normalized_events, verdict)

        assert alert is not None
        assert "severity" in alert or "title" in alert


class TestDetectionPipeline:
    """Tests for full detection pipeline."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = DetectionPipeline()

        assert pipeline is not None
        assert pipeline.ingestor is not None
        assert pipeline.ml_filter is not None
        assert pipeline.correlator is not None

    def test_process_single_event(self, sample_sysmon_event):
        """Test processing single event."""
        pipeline = DetectionPipeline()
        result = pipeline.process_event(sample_sysmon_event, "sysmon")

        # Result can be None for benign events
        # Just verify no exceptions
        assert True

    def test_process_batch(self, sample_events):
        """Test batch processing."""
        pipeline = DetectionPipeline()
        results = pipeline.process_batch(sample_events)

        assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

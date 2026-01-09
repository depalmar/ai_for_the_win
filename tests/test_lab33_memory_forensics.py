#!/usr/bin/env python3
"""Tests for Lab 13: AI-Powered Memory Forensics."""

import json
import math
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import numpy as np
import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab33-memory-forensics-ai" / "solution")
sys.path.insert(0, lab_path)

from main import (
    DLLInfo,
    InjectionIndicator,
    MemoryAnalyzer,
    MemoryTriagePipeline,
    NetworkConnection,
    ProcessAnomalyDetector,
    ProcessInfo,
    TriageReport,
    analyze_suspicious_process,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_memory_data():
    """Create sample memory dump data."""
    return {
        "processes": [
            {
                "pid": 4,
                "ppid": 0,
                "name": "System",
                "path": "",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:00",
                "threads": 150,
                "handles": 2000,
                "memory_regions": [],
            },
            {
                "pid": 632,
                "ppid": 4,
                "name": "smss.exe",
                "path": "C:\\Windows\\System32\\smss.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:01",
                "threads": 2,
                "handles": 50,
                "memory_regions": [],
            },
            {
                "pid": 780,
                "ppid": 632,
                "name": "csrss.exe",
                "path": "C:\\Windows\\System32\\csrss.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:02",
                "threads": 12,
                "handles": 500,
                "memory_regions": [],
            },
            {
                "pid": 1234,
                "ppid": 780,
                "name": "services.exe",
                "path": "C:\\Windows\\System32\\services.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:03",
                "threads": 5,
                "handles": 300,
                "memory_regions": [],
            },
            {
                "pid": 2048,
                "ppid": 1234,
                "name": "svchost.exe",
                "path": "C:\\Windows\\System32\\svchost.exe",
                "cmdline": "-k netsvcs",
                "create_time": "2024-01-15T08:00:10",
                "threads": 20,
                "handles": 800,
                "memory_regions": [],
            },
        ],
        "connections": [
            {
                "local_ip": "192.168.1.100",
                "local_port": 49152,
                "remote_ip": "185.234.72.19",
                "remote_port": 443,
                "state": "ESTABLISHED",
                "pid": 2048,
                "protocol": "TCP",
            },
        ],
        "malfind": [],
        "dlls": [
            {
                "pid": 2048,
                "name": "ntdll.dll",
                "path": "C:\\Windows\\System32\\ntdll.dll",
                "base_address": "0x77000000",
                "size": 1900544,
            },
        ],
    }


@pytest.fixture
def malicious_memory_data():
    """Create memory data with malicious processes."""
    return {
        "processes": [
            {
                "pid": 4,
                "ppid": 0,
                "name": "System",
                "path": "",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:00",
                "threads": 150,
                "handles": 2000,
                "memory_regions": [],
            },
            {
                "pid": 632,
                "ppid": 4,
                "name": "smss.exe",
                "path": "C:\\Windows\\System32\\smss.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:00:01",
                "threads": 2,
                "handles": 50,
                "memory_regions": [],
            },
            {
                "pid": 3456,
                "ppid": 5678,
                "name": "outlook.exe",
                "path": "C:\\Program Files\\Microsoft Office\\Office16\\outlook.exe",
                "cmdline": "",
                "create_time": "2024-01-15T09:00:00",
                "threads": 30,
                "handles": 400,
                "memory_regions": [],
            },
            {
                "pid": 5678,
                "ppid": 1234,
                "name": "explorer.exe",
                "path": "C:\\Windows\\explorer.exe",
                "cmdline": "",
                "create_time": "2024-01-15T08:01:00",
                "threads": 40,
                "handles": 1500,
                "memory_regions": [],
            },
            {
                "pid": 4567,
                "ppid": 3456,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQ=",
                "create_time": "2024-01-15T09:05:00",
                "threads": 8,
                "handles": 200,
                "memory_regions": [
                    {"address": "0x7FFE0000", "protection": "RWX", "type": "PRIVATE", "size": 4096},
                ],
            },
            {
                "pid": 9999,
                "ppid": 1,
                "name": "svchost.exe",
                "path": "C:\\Users\\Public\\svchost.exe",
                "cmdline": "-k malware",
                "create_time": "2024-01-15T09:10:00",
                "threads": 3,
                "handles": 100,
                "memory_regions": [
                    {
                        "address": "0x10000000",
                        "protection": "RWX",
                        "type": "PRIVATE",
                        "size": 65536,
                    },
                ],
            },
        ],
        "connections": [
            {
                "local_ip": "192.168.1.100",
                "local_port": 49152,
                "remote_ip": "185.234.72.19",
                "remote_port": 443,
                "state": "ESTABLISHED",
                "pid": 4567,
                "protocol": "TCP",
            },
            {
                "local_ip": "192.168.1.100",
                "local_port": 49154,
                "remote_ip": "91.234.56.78",
                "remote_port": 8080,
                "state": "ESTABLISHED",
                "pid": 9999,
                "protocol": "TCP",
            },
        ],
        "malfind": [
            {
                "pid": 4567,
                "process_name": "powershell.exe",
                "type": "MZ_HEADER_IN_PRIVATE_MEMORY",
                "description": "PE header found in private memory region",
                "address": "0x7FFE0000",
                "confidence": 0.85,
            },
            {
                "pid": 9999,
                "process_name": "svchost.exe",
                "type": "EXECUTABLE_MEMORY",
                "description": "Executable code in non-image memory",
                "address": "0x10000000",
                "confidence": 0.9,
            },
        ],
        "dlls": [
            {
                "pid": 4567,
                "name": "ntdll.dll",
                "path": "C:\\Windows\\System32\\ntdll.dll",
                "base_address": "0x77000000",
                "size": 1900544,
            },
            {
                "pid": 4567,
                "name": "kernel32.dll",
                "path": "C:\\Windows\\System32\\kernel32.dll",
                "base_address": "0x75000000",
                "size": 1200128,
            },
        ],
    }


@pytest.fixture
def sample_process_info():
    """Create sample ProcessInfo object."""
    return ProcessInfo(
        pid=1234,
        ppid=1000,
        name="test.exe",
        path="C:\\Windows\\System32\\test.exe",
        cmdline="test.exe -arg1 -arg2",
        create_time="2024-01-15T08:00:00",
        threads=10,
        handles=100,
        memory_regions=[],
    )


@pytest.fixture
def suspicious_process_info():
    """Create suspicious ProcessInfo object with encoded command."""
    return ProcessInfo(
        pid=4567,
        ppid=3456,
        name="powershell.exe",
        path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline="powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQ=",
        create_time="2024-01-15T09:05:00",
        threads=8,
        handles=200,
        memory_regions=[
            {"address": "0x7FFE0000", "protection": "RWX", "type": "PRIVATE", "size": 4096},
        ],
    )


@pytest.fixture
def fake_svchost_process():
    """Create a fake svchost process outside system directory."""
    return ProcessInfo(
        pid=9999,
        ppid=1,
        name="svchost.exe",
        path="C:\\Users\\Public\\svchost.exe",
        cmdline="-k malware",
        create_time="2024-01-15T09:10:00",
        threads=3,
        handles=100,
        memory_regions=[
            {"address": "0x10000000", "protection": "RWX", "type": "PRIVATE", "size": 65536},
        ],
    )


@pytest.fixture
def sample_network_connection():
    """Create sample NetworkConnection object."""
    return NetworkConnection(
        local_ip="192.168.1.100",
        local_port=49152,
        remote_ip="185.234.72.19",
        remote_port=443,
        state="ESTABLISHED",
        pid=4567,
        protocol="TCP",
    )


@pytest.fixture
def sample_dll_info():
    """Create sample DLLInfo object."""
    return DLLInfo(
        name="ntdll.dll",
        path="C:\\Windows\\System32\\ntdll.dll",
        base_address="0x77000000",
        size=1900544,
        pid=4567,
    )


@pytest.fixture
def sample_injection_indicator():
    """Create sample InjectionIndicator object."""
    return InjectionIndicator(
        pid=4567,
        process_name="powershell.exe",
        indicator_type="MZ_HEADER_IN_PRIVATE_MEMORY",
        description="PE header found in private memory region",
        memory_address="0x7FFE0000",
        confidence=0.85,
    )


@pytest.fixture
def memory_analyzer(sample_memory_data):
    """Create MemoryAnalyzer with sample data."""
    return MemoryAnalyzer(memory_data=sample_memory_data)


@pytest.fixture
def malicious_memory_analyzer(malicious_memory_data):
    """Create MemoryAnalyzer with malicious data."""
    return MemoryAnalyzer(memory_data=malicious_memory_data)


@pytest.fixture
def process_anomaly_detector():
    """Create ProcessAnomalyDetector instance."""
    return ProcessAnomalyDetector()


@pytest.fixture
def baseline_data(tmp_path):
    """Create a baseline file for testing."""
    baseline = {
        "svchost.exe": {
            "expected_paths": [
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\SysWOW64\\svchost.exe",
            ],
            "expected_parents": ["services.exe"],
            "typical_threads": [5, 50],
        },
        "powershell.exe": {
            "expected_paths": [
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
            ],
            "expected_parents": ["explorer.exe", "cmd.exe"],
            "typical_threads": [5, 20],
        },
    }
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline))
    return str(baseline_file)


# =============================================================================
# DataClass Tests
# =============================================================================


class TestProcessInfo:
    """Tests for ProcessInfo dataclass."""

    def test_process_info_creation(self, sample_process_info):
        """Test ProcessInfo creation."""
        assert sample_process_info.pid == 1234
        assert sample_process_info.ppid == 1000
        assert sample_process_info.name == "test.exe"
        assert sample_process_info.path == "C:\\Windows\\System32\\test.exe"

    def test_process_info_defaults(self):
        """Test ProcessInfo default values."""
        proc = ProcessInfo(
            pid=1,
            ppid=0,
            name="test",
            path="",
            cmdline="",
            create_time="",
        )
        assert proc.threads == 0
        assert proc.handles == 0
        assert proc.memory_regions == []

    def test_process_info_to_dict(self, sample_process_info):
        """Test ProcessInfo conversion to dict."""
        proc_dict = asdict(sample_process_info)
        assert isinstance(proc_dict, dict)
        assert proc_dict["pid"] == 1234
        assert proc_dict["name"] == "test.exe"


class TestNetworkConnection:
    """Tests for NetworkConnection dataclass."""

    def test_network_connection_creation(self, sample_network_connection):
        """Test NetworkConnection creation."""
        assert sample_network_connection.local_ip == "192.168.1.100"
        assert sample_network_connection.remote_ip == "185.234.72.19"
        assert sample_network_connection.state == "ESTABLISHED"

    def test_network_connection_defaults(self):
        """Test NetworkConnection default protocol."""
        conn = NetworkConnection(
            local_ip="127.0.0.1",
            local_port=80,
            remote_ip="0.0.0.0",
            remote_port=0,
            state="LISTENING",
            pid=1234,
        )
        assert conn.protocol == "TCP"


class TestDLLInfo:
    """Tests for DLLInfo dataclass."""

    def test_dll_info_creation(self, sample_dll_info):
        """Test DLLInfo creation."""
        assert sample_dll_info.name == "ntdll.dll"
        assert sample_dll_info.size == 1900544
        assert sample_dll_info.pid == 4567


class TestInjectionIndicator:
    """Tests for InjectionIndicator dataclass."""

    def test_injection_indicator_creation(self, sample_injection_indicator):
        """Test InjectionIndicator creation."""
        assert sample_injection_indicator.pid == 4567
        assert sample_injection_indicator.indicator_type == "MZ_HEADER_IN_PRIVATE_MEMORY"
        assert sample_injection_indicator.confidence == 0.85


class TestTriageReport:
    """Tests for TriageReport dataclass."""

    def test_triage_report_creation(self):
        """Test TriageReport creation."""
        report = TriageReport(
            timestamp="2024-01-15T10:00:00",
            findings=[{"process_name": "malware.exe", "anomaly_score": 0.9}],
            iocs={"ips": ["185.234.72.19"]},
            summary="Found 1 suspicious process",
            risk_level="high",
        )
        assert report.risk_level == "high"
        assert len(report.findings) == 1


# =============================================================================
# MemoryAnalyzer Tests
# =============================================================================


class TestMemoryAnalyzer:
    """Tests for MemoryAnalyzer class."""

    def test_analyzer_initialization_empty(self):
        """Test MemoryAnalyzer initialization with no data."""
        analyzer = MemoryAnalyzer()
        assert analyzer.memory_data == {}

    def test_analyzer_initialization_with_data(self, sample_memory_data):
        """Test MemoryAnalyzer initialization with data."""
        analyzer = MemoryAnalyzer(memory_data=sample_memory_data)
        assert analyzer.memory_data == sample_memory_data

    def test_load_from_file(self, tmp_path, sample_memory_data):
        """Test loading memory data from file."""
        data_file = tmp_path / "memory.json"
        data_file.write_text(json.dumps(sample_memory_data))

        analyzer = MemoryAnalyzer()
        analyzer.load_from_file(str(data_file))

        assert analyzer.memory_data == sample_memory_data

    def test_extract_processes(self, memory_analyzer):
        """Test process extraction from memory data."""
        processes = memory_analyzer.extract_processes()

        assert len(processes) == 5
        assert all(isinstance(p, ProcessInfo) for p in processes)
        assert processes[0].name == "System"
        assert processes[0].pid == 4

    def test_extract_processes_empty(self):
        """Test process extraction with empty data."""
        analyzer = MemoryAnalyzer()
        processes = analyzer.extract_processes()
        assert processes == []

    def test_extract_network_connections(self, memory_analyzer):
        """Test network connection extraction."""
        connections = memory_analyzer.extract_network_connections()

        assert len(connections) == 1
        assert all(isinstance(c, NetworkConnection) for c in connections)
        assert connections[0].remote_ip == "185.234.72.19"

    def test_extract_network_connections_empty(self):
        """Test network connection extraction with empty data."""
        analyzer = MemoryAnalyzer()
        connections = analyzer.extract_network_connections()
        assert connections == []

    def test_extract_loaded_dlls(self, memory_analyzer):
        """Test DLL extraction for a specific process."""
        dlls = memory_analyzer.extract_loaded_dlls(pid=2048)

        assert len(dlls) == 1
        assert all(isinstance(d, DLLInfo) for d in dlls)
        assert dlls[0].name == "ntdll.dll"

    def test_extract_loaded_dlls_no_match(self, memory_analyzer):
        """Test DLL extraction for non-existent PID."""
        dlls = memory_analyzer.extract_loaded_dlls(pid=9999)
        assert dlls == []

    def test_detect_injected_code(self, malicious_memory_analyzer):
        """Test injection detection."""
        indicators = malicious_memory_analyzer.detect_injected_code()

        assert len(indicators) == 2
        assert all(isinstance(i, InjectionIndicator) for i in indicators)

    def test_detect_injected_code_clean(self, memory_analyzer):
        """Test injection detection with clean data."""
        indicators = memory_analyzer.detect_injected_code()
        assert indicators == []

    def test_extract_multiple_dlls_for_process(self, malicious_memory_analyzer):
        """Test extracting multiple DLLs for a single process."""
        dlls = malicious_memory_analyzer.extract_loaded_dlls(pid=4567)

        assert len(dlls) == 2
        dll_names = [d.name for d in dlls]
        assert "ntdll.dll" in dll_names
        assert "kernel32.dll" in dll_names


# =============================================================================
# ProcessAnomalyDetector Tests
# =============================================================================


class TestProcessAnomalyDetector:
    """Tests for ProcessAnomalyDetector class."""

    def test_detector_initialization(self, process_anomaly_detector):
        """Test detector initialization."""
        assert process_anomaly_detector is not None
        assert process_anomaly_detector.baseline == {}

    def test_detector_initialization_with_baseline(self, baseline_data):
        """Test detector initialization with baseline file."""
        detector = ProcessAnomalyDetector(baseline_path=baseline_data)
        assert "svchost.exe" in detector.baseline

    def test_detector_initialization_nonexistent_baseline(self):
        """Test detector with non-existent baseline file."""
        detector = ProcessAnomalyDetector(baseline_path="/nonexistent/path.json")
        assert detector.baseline == {}

    def test_calculate_entropy_empty(self, process_anomaly_detector):
        """Test entropy calculation with empty string."""
        entropy = process_anomaly_detector.calculate_entropy("")
        assert entropy == 0.0

    def test_calculate_entropy_uniform(self, process_anomaly_detector):
        """Test entropy calculation with uniform data."""
        entropy = process_anomaly_detector.calculate_entropy("AAAAAAAAAA")
        assert entropy == 0.0

    def test_calculate_entropy_varied(self, process_anomaly_detector):
        """Test entropy calculation with varied data."""
        entropy = process_anomaly_detector.calculate_entropy("abcdefghij")
        # Each character appears once, so entropy should be log2(10)
        expected = math.log2(10)
        assert abs(entropy - expected) < 0.01

    def test_calculate_entropy_base64_command(self, process_anomaly_detector):
        """Test entropy of base64 encoded content."""
        # Base64 content typically has high entropy
        base64_str = "SGVsbG8gV29ybGQgLSBNYWxpY2lvdXMgUGF5bG9hZA=="
        entropy = process_anomaly_detector.calculate_entropy(base64_str)
        assert entropy > 4.0

    def test_extract_features(self, process_anomaly_detector, sample_process_info):
        """Test feature extraction from process."""
        features = process_anomaly_detector.extract_features(sample_process_info)

        assert isinstance(features, np.ndarray)
        assert len(features) == 7  # 7 features extracted

    def test_extract_features_suspicious(self, process_anomaly_detector, suspicious_process_info):
        """Test feature extraction from suspicious process."""
        features = process_anomaly_detector.extract_features(suspicious_process_info)

        # Feature 4: has_encoded should be 1.0
        assert features[4] == 1.0
        # Feature 5: has_suspicious should be 1.0 (due to -nop and -w hidden)
        assert features[5] == 1.0

    def test_extract_features_system_path(self, process_anomaly_detector):
        """Test feature extraction for process in system path."""
        proc = ProcessInfo(
            pid=1,
            ppid=0,
            name="svchost.exe",
            path="C:\\Windows\\System32\\svchost.exe",
            cmdline="-k netsvcs",
            create_time="",
        )
        features = process_anomaly_detector.extract_features(proc)
        # Feature 2: is_system should be 1.0
        assert features[2] == 1.0

    def test_check_parent_child_anomaly_suspicious_spawn(self, process_anomaly_detector):
        """Test detection of suspicious parent-child relationship."""
        processes = [
            ProcessInfo(
                pid=1000,
                ppid=0,
                name="outlook.exe",
                path="",
                cmdline="",
                create_time="",
            ),
            ProcessInfo(
                pid=2000,
                ppid=1000,
                name="powershell.exe",
                path="",
                cmdline="",
                create_time="",
            ),
        ]
        child_process = processes[1]
        anomalies = process_anomaly_detector.check_parent_child_anomaly(child_process, processes)

        assert len(anomalies) >= 1
        assert "Suspicious spawn" in anomalies[0]

    def test_check_parent_child_anomaly_invalid_parent(self, process_anomaly_detector):
        """Test detection of invalid parent for system process."""
        processes = [
            ProcessInfo(
                pid=1000,
                ppid=0,
                name="explorer.exe",
                path="",
                cmdline="",
                create_time="",
            ),
            ProcessInfo(
                pid=2000,
                ppid=1000,
                name="svchost.exe",
                path="",
                cmdline="",
                create_time="",
            ),
        ]
        child_process = processes[1]
        anomalies = process_anomaly_detector.check_parent_child_anomaly(child_process, processes)

        assert len(anomalies) >= 1
        assert "Invalid parent" in anomalies[0]

    def test_check_parent_child_anomaly_no_parent(self, process_anomaly_detector):
        """Test with process that has no parent."""
        processes = [
            ProcessInfo(
                pid=1000,
                ppid=9999,  # Non-existent parent
                name="test.exe",
                path="",
                cmdline="",
                create_time="",
            ),
        ]
        anomalies = process_anomaly_detector.check_parent_child_anomaly(processes[0], processes)
        assert anomalies == []

    def test_score_process_normal(self, process_anomaly_detector, sample_process_info):
        """Test scoring a normal process."""
        result = process_anomaly_detector.score_process(sample_process_info, [sample_process_info])

        assert "anomaly_score" in result
        assert "risk_factors" in result
        assert "features" in result
        assert result["anomaly_score"] < 0.5

    def test_score_process_suspicious(
        self, process_anomaly_detector, suspicious_process_info, malicious_memory_data
    ):
        """Test scoring a suspicious process."""
        # Extract processes to use for parent-child checking
        processes = [
            ProcessInfo(
                pid=3456,
                ppid=0,
                name="outlook.exe",
                path="",
                cmdline="",
                create_time="",
            ),
            suspicious_process_info,
        ]

        result = process_anomaly_detector.score_process(suspicious_process_info, processes)

        assert result["anomaly_score"] > 0.5
        assert len(result["risk_factors"]) > 0

    def test_score_process_fake_svchost(self, process_anomaly_detector, fake_svchost_process):
        """Test scoring a fake svchost outside system directory."""
        result = process_anomaly_detector.score_process(
            fake_svchost_process, [fake_svchost_process]
        )

        # Should have high score due to svchost outside system path
        assert result["anomaly_score"] >= 0.4
        assert any("outside system directory" in rf for rf in result["risk_factors"])

    def test_detect_process_hollowing_positive(
        self, process_anomaly_detector, suspicious_process_info
    ):
        """Test process hollowing detection with RWX memory."""
        result = process_anomaly_detector.detect_process_hollowing(suspicious_process_info)

        assert result["is_hollowed"] is True
        assert result["confidence"] > 0
        assert len(result["indicators"]) > 0

    def test_detect_process_hollowing_negative(self, process_anomaly_detector, sample_process_info):
        """Test process hollowing detection with clean process."""
        result = process_anomaly_detector.detect_process_hollowing(sample_process_info)

        assert result["is_hollowed"] is False
        assert result["confidence"] == 0.0
        assert result["indicators"] == []

    def test_detect_process_hollowing_private_executable(self, process_anomaly_detector):
        """Test detection of private executable memory."""
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="test.exe",
            path="",
            cmdline="",
            create_time="",
            memory_regions=[
                {"address": "0x1000", "protection": "EXECUTE", "type": "PRIVATE", "size": 4096},
            ],
        )
        result = process_anomaly_detector.detect_process_hollowing(proc)

        assert result["is_hollowed"] is True
        assert any(i["type"] == "private_executable" for i in result["indicators"])

    def test_score_process_with_baseline(self, baseline_data):
        """Test scoring with baseline comparison."""
        detector = ProcessAnomalyDetector(baseline_path=baseline_data)

        # Process with unusual path for svchost
        unusual_svchost = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="svchost.exe",
            path="C:\\Temp\\svchost.exe",
            cmdline="",
            create_time="",
        )

        result = detector.score_process(unusual_svchost, [unusual_svchost])

        assert any("Unusual path" in rf for rf in result["risk_factors"])

    def test_suspicious_relationships_constant(self, process_anomaly_detector):
        """Test SUSPICIOUS_RELATIONSHIPS class constant."""
        assert "outlook.exe" in process_anomaly_detector.SUSPICIOUS_RELATIONSHIPS
        assert "powershell.exe" in process_anomaly_detector.SUSPICIOUS_RELATIONSHIPS["outlook.exe"]

    def test_strict_parent_rules_constant(self, process_anomaly_detector):
        """Test STRICT_PARENT_RULES class constant."""
        assert "svchost.exe" in process_anomaly_detector.STRICT_PARENT_RULES
        assert "services.exe" in process_anomaly_detector.STRICT_PARENT_RULES["svchost.exe"]

    def test_system_paths_constant(self, process_anomaly_detector):
        """Test SYSTEM_PATHS class constant."""
        assert "c:\\windows\\system32" in process_anomaly_detector.SYSTEM_PATHS


# =============================================================================
# MemoryTriagePipeline Tests
# =============================================================================


class TestMemoryTriagePipeline:
    """Tests for MemoryTriagePipeline class."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = MemoryTriagePipeline()

        assert pipeline.analyzer is not None
        assert pipeline.detector is not None
        assert pipeline.llm is None  # Lazy initialization
        assert pipeline.llm_provider == "auto"

    def test_pipeline_initialization_with_provider(self):
        """Test pipeline initialization with specific provider."""
        pipeline = MemoryTriagePipeline(llm_provider="openai")
        assert pipeline.llm_provider == "openai"

    def test_triage_clean_memory(self, sample_memory_data, capsys):
        """Test triage on clean memory data."""
        pipeline = MemoryTriagePipeline()
        report = pipeline.triage(sample_memory_data)

        assert isinstance(report, TriageReport)
        assert report.risk_level in ["low", "medium", "high", "critical"]
        assert report.timestamp is not None

    def test_triage_malicious_memory(self, malicious_memory_data, capsys):
        """Test triage on malicious memory data."""
        pipeline = MemoryTriagePipeline()
        report = pipeline.triage(malicious_memory_data)

        assert isinstance(report, TriageReport)
        assert len(report.findings) > 0
        # Should find at least the suspicious powershell and fake svchost
        suspicious_names = [f["process_name"] for f in report.findings]
        assert "powershell.exe" in suspicious_names or "svchost.exe" in suspicious_names

    def test_get_process_connections(self, malicious_memory_data):
        """Test getting connections for a specific process."""
        pipeline = MemoryTriagePipeline()
        pipeline.analyzer.memory_data = malicious_memory_data
        connections = pipeline.analyzer.extract_network_connections()

        process = ProcessInfo(
            pid=4567,
            ppid=3456,
            name="powershell.exe",
            path="",
            cmdline="",
            create_time="",
        )

        proc_conns = pipeline._get_process_connections(process, connections)

        assert len(proc_conns) == 1
        assert proc_conns[0]["remote"] == "185.234.72.19:443"

    def test_generate_report_malicious(self):
        """Test report generation with malicious findings."""
        pipeline = MemoryTriagePipeline()
        findings = [
            {
                "process_name": "malware.exe",
                "pid": 1234,
                "anomaly_score": 0.9,
                "threat_level": "malicious",
                "mitre_techniques": ["T1055"],
                "network_connections": [{"remote": "185.234.72.19:443"}],
            }
        ]

        report = pipeline._generate_report(findings)

        assert report.risk_level == "critical"
        assert "malicious" in report.summary.lower() or len(report.findings) > 0

    def test_generate_report_suspicious(self):
        """Test report generation with suspicious findings."""
        pipeline = MemoryTriagePipeline()
        findings = [
            {
                "process_name": "sus.exe",
                "pid": 1234,
                "anomaly_score": 0.6,
                "threat_level": "suspicious",
            }
        ]

        report = pipeline._generate_report(findings)

        assert report.risk_level == "high"

    def test_generate_report_high_score_no_threat_level(self):
        """Test report generation with high anomaly score but no threat level."""
        pipeline = MemoryTriagePipeline()
        findings = [
            {
                "process_name": "unknown.exe",
                "pid": 1234,
                "anomaly_score": 0.8,
            }
        ]

        report = pipeline._generate_report(findings)

        assert report.risk_level == "high"

    def test_generate_report_low_risk(self):
        """Test report generation with low risk findings."""
        pipeline = MemoryTriagePipeline()
        findings = []

        report = pipeline._generate_report(findings)

        assert report.risk_level == "low"

    def test_extract_iocs(self):
        """Test IOC extraction from findings."""
        pipeline = MemoryTriagePipeline()
        findings = [
            {
                "process_name": "malware.exe",
                "threat_level": "malicious",
                "mitre_techniques": ["T1055", "T1059"],
                "network_connections": [
                    {"remote": "185.234.72.19:443"},
                    {"remote": "10.0.0.1:445"},  # Internal, should be excluded
                ],
            }
        ]

        iocs = pipeline._extract_iocs(findings)

        assert "T1055" in iocs["mitre_techniques"]
        assert "T1059" in iocs["mitre_techniques"]
        assert "185.234.72.19" in iocs["ips"]
        # Internal IPs should be excluded
        assert "10.0.0.1" not in iocs["ips"]
        assert "malware.exe" in iocs["process_names"]

    def test_extract_iocs_excludes_private_ips(self):
        """Test that private IPs are excluded from IOCs."""
        pipeline = MemoryTriagePipeline()
        findings = [
            {
                "process_name": "test.exe",
                "threat_level": "suspicious",
                "network_connections": [
                    {"remote": "192.168.1.100:443"},
                    {"remote": "172.16.0.1:80"},
                    {"remote": "10.0.0.5:22"},
                ],
            }
        ]

        iocs = pipeline._extract_iocs(findings)

        # All private IPs should be excluded
        for ip in iocs["ips"]:
            assert not ip.startswith("192.168.")
            assert not ip.startswith("172.")
            assert not ip.startswith("10.")


# =============================================================================
# analyze_suspicious_process Tests (LLM Integration)
# =============================================================================


class TestAnalyzeSuspiciousProcess:
    """Tests for analyze_suspicious_process function."""

    @pytest.mark.requires_api
    def test_analyze_with_real_api(self, suspicious_process_info):
        """Test with real API (requires API key)."""
        from main import setup_llm

        try:
            llm = setup_llm()
            context = {"indicators": ["encoded command"], "connections": []}

            result = analyze_suspicious_process(suspicious_process_info, context, llm)

            assert "threat_level" in result
            assert "assessment" in result
        except ValueError:
            pytest.skip("No API key available")

    def test_analyze_with_mock_anthropic(self, suspicious_process_info):
        """Test with mocked Anthropic client."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [
            Mock(
                text='{"threat_level": "suspicious", "assessment": "Test", "malware_family": null, "mitre_techniques": ["T1059"], "response_actions": ["Investigate"], "investigate_next": []}'
            )
        ]
        mock_client.messages.create.return_value = mock_response

        context = {"indicators": ["encoded command"], "connections": []}
        result = analyze_suspicious_process(
            suspicious_process_info, context, ("anthropic", mock_client)
        )

        assert result["threat_level"] == "suspicious"
        assert "T1059" in result["mitre_techniques"]

    def test_analyze_with_mock_openai(self, suspicious_process_info):
        """Test with mocked OpenAI client."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.choices = [
            Mock(
                message=Mock(
                    content='{"threat_level": "malicious", "assessment": "Dangerous", "malware_family": "Cobalt Strike", "mitre_techniques": ["T1055"], "response_actions": ["Isolate"], "investigate_next": []}'
                )
            )
        ]
        mock_client.chat.completions.create.return_value = mock_response

        context = {"indicators": [], "connections": []}
        result = analyze_suspicious_process(
            suspicious_process_info, context, ("openai", mock_client)
        )

        assert result["threat_level"] == "malicious"
        assert result["malware_family"] == "Cobalt Strike"

    def test_analyze_with_mock_google(self, suspicious_process_info):
        """Test with mocked Google client."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.text = '{"threat_level": "benign", "assessment": "Safe", "malware_family": null, "mitre_techniques": [], "response_actions": [], "investigate_next": []}'
        mock_client.generate_content.return_value = mock_response

        context = {"indicators": [], "connections": []}
        result = analyze_suspicious_process(
            suspicious_process_info, context, ("google", mock_client)
        )

        assert result["threat_level"] == "benign"

    def test_analyze_handles_json_code_block(self, suspicious_process_info):
        """Test parsing JSON from markdown code block."""
        mock_client = Mock()
        mock_response = Mock()
        # Response wrapped in markdown code block
        mock_response.content = [
            Mock(
                text='```json\n{"threat_level": "suspicious", "assessment": "Test", "malware_family": null, "mitre_techniques": [], "response_actions": [], "investigate_next": []}\n```'
            )
        ]
        mock_client.messages.create.return_value = mock_response

        context = {"indicators": [], "connections": []}
        result = analyze_suspicious_process(
            suspicious_process_info, context, ("anthropic", mock_client)
        )

        assert result["threat_level"] == "suspicious"

    def test_analyze_handles_exception(self, suspicious_process_info):
        """Test graceful handling of API errors."""
        mock_client = Mock()
        mock_client.messages.create.side_effect = Exception("API Error")

        context = {"indicators": [], "connections": []}
        result = analyze_suspicious_process(
            suspicious_process_info, context, ("anthropic", mock_client)
        )

        assert result["threat_level"] == "unknown"
        assert "API Error" in result["assessment"]
        assert result["response_actions"] == ["Manual review required"]


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and data validation."""

    def test_empty_memory_data(self):
        """Test handling of completely empty memory data."""
        analyzer = MemoryAnalyzer(memory_data={})

        assert analyzer.extract_processes() == []
        assert analyzer.extract_network_connections() == []
        assert analyzer.extract_loaded_dlls(pid=1) == []
        assert analyzer.detect_injected_code() == []

    def test_malformed_process_data(self):
        """Test handling of malformed process data."""
        analyzer = MemoryAnalyzer(memory_data={"processes": [{}]})
        processes = analyzer.extract_processes()

        assert len(processes) == 1
        assert processes[0].pid == 0
        assert processes[0].name == "unknown"

    def test_process_with_high_thread_count(self, process_anomaly_detector):
        """Test anomaly detection for high thread count."""
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="test.exe",
            path="",
            cmdline="",
            create_time="",
            threads=150,  # High thread count
        )

        features = process_anomaly_detector.extract_features(proc)
        # Feature 6: thread_anomaly should be 1.0 for threads > 100
        assert features[6] == 1.0

    def test_process_with_zero_threads(self, process_anomaly_detector):
        """Test anomaly detection for zero threads."""
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="test.exe",
            path="",
            cmdline="",
            create_time="",
            threads=0,
        )

        features = process_anomaly_detector.extract_features(proc)
        # Feature 6: thread_anomaly should be 1.0 for threads == 0
        assert features[6] == 1.0

    def test_unicode_in_cmdline(self, process_anomaly_detector):
        """Test handling of unicode in command line."""
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="test.exe",
            path="",
            cmdline="test.exe --name='Cafe\u0301'",
            create_time="",
        )

        # Should not raise an exception
        features = process_anomaly_detector.extract_features(proc)
        assert isinstance(features, np.ndarray)

    def test_very_long_cmdline(self, process_anomaly_detector):
        """Test handling of very long command lines."""
        long_cmd = "powershell.exe " + "A" * 10000
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="powershell.exe",
            path="",
            cmdline=long_cmd,
            create_time="",
        )

        features = process_anomaly_detector.extract_features(proc)
        assert isinstance(features, np.ndarray)

    def test_special_characters_in_path(self):
        """Test handling of special characters in file paths."""
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="test.exe",
            path="C:\\Users\\Test User (Admin)\\Desktop\\[Special]\\test.exe",
            cmdline="",
            create_time="",
        )

        detector = ProcessAnomalyDetector()
        features = detector.extract_features(proc)
        assert isinstance(features, np.ndarray)

    def test_anomaly_score_capped_at_one(self, process_anomaly_detector):
        """Test that anomaly score is capped at 1.0."""
        # Create a process with many suspicious indicators
        proc = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="svchost.exe",
            path="C:\\Temp\\svchost.exe",  # Wrong path
            cmdline="powershell.exe -nop -w hidden -enc AAAA -ep bypass",  # Multiple flags
            create_time="",
        )

        # Create parent to trigger suspicious spawn
        parent = ProcessInfo(
            pid=1000,
            ppid=0,
            name="outlook.exe",
            path="",
            cmdline="",
            create_time="",
        )

        result = process_anomaly_detector.score_process(proc, [parent, proc])
        assert result["anomaly_score"] <= 1.0

    def test_network_connection_defaults(self):
        """Test network connection with minimal data."""
        analyzer = MemoryAnalyzer(
            memory_data={"connections": [{"pid": 1234, "state": "ESTABLISHED"}]}
        )

        connections = analyzer.extract_network_connections()

        assert len(connections) == 1
        assert connections[0].local_ip == "0.0.0.0"
        assert connections[0].remote_ip == "0.0.0.0"
        assert connections[0].protocol == "TCP"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests using real data files."""

    def test_load_sample_process_list(self):
        """Test loading sample_process_list.json."""
        data_path = (
            Path(__file__).parent.parent
            / "labs"
            / "lab13-memory-forensics-ai"
            / "data"
            / "sample_process_list.json"
        )

        if data_path.exists():
            analyzer = MemoryAnalyzer()
            analyzer.load_from_file(str(data_path))

            processes = analyzer.extract_processes()
            connections = analyzer.extract_network_connections()
            injections = analyzer.detect_injected_code()

            assert len(processes) > 0
            assert len(connections) > 0
            assert len(injections) > 0

    def test_full_triage_with_sample_data(self):
        """Test full triage pipeline with sample data."""
        data_path = (
            Path(__file__).parent.parent
            / "labs"
            / "lab13-memory-forensics-ai"
            / "data"
            / "sample_process_list.json"
        )

        if data_path.exists():
            with open(data_path) as f:
                memory_data = json.load(f)

            pipeline = MemoryTriagePipeline()
            report = pipeline.triage(memory_data)

            assert isinstance(report, TriageReport)
            assert report.risk_level in ["low", "medium", "high", "critical"]
            # Sample data has malicious processes, should have findings
            assert len(report.findings) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

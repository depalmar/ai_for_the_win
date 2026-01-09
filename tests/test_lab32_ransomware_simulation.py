#!/usr/bin/env python3
"""Tests for Lab 12: Ransomware Attack Simulation & Purple Team."""

import importlib
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab12-ransomware-simulation" / "solution")
sys.path.insert(0, lab_path)

from main import (
    AttackScenario,
    DetectionStatus,
    DetectionTest,
    DetectionValidator,
    PurpleTeamExercise,
    RansomwareFamily,
    SafeRansomwareSimulator,
    ScenarioGenerator,
    SimulationConfig,
    TestResult,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_test_dir():
    """Create temporary test directory."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def simulation_config(temp_test_dir):
    """Create SimulationConfig for testing."""
    return SimulationConfig(
        target_directory=temp_test_dir,
        file_extensions=[".txt", ".docx"],
        create_ransom_note=True,
        simulate_encryption=True,
        simulate_shadow_delete=True,
        cleanup_after=False,  # We'll test cleanup explicitly
        log_all_actions=False,
    )


@pytest.fixture
def scenario_generator():
    """Create ScenarioGenerator instance."""
    return ScenarioGenerator()


@pytest.fixture
def detection_validator():
    """Create DetectionValidator instance."""
    return DetectionValidator()


@pytest.fixture
def sample_attack_scenario():
    """Create sample attack scenario."""
    return AttackScenario(
        family=RansomwareFamily.LOCKBIT,
        name="LockBit Simulation",
        description="Fast-encrypting RaaS with double extortion",
        initial_access="Phishing",
        execution_chain=[
            "Loader drops payload",
            "C2 established",
            "Ransomware executed",
        ],
        persistence_methods=["Registry Run Key"],
        discovery_techniques=["System Info", "Network Share Enum"],
        lateral_movement=["PsExec", "WMI"],
        exfiltration=True,
        encryption_targets=["Documents", "Databases"],
        mitre_techniques=["T1486", "T1490", "T1567"],
        detection_opportunities=["Shadow deletion", "Mass encryption"],
        expected_artifacts=["Ransom notes", "Encrypted files"],
    )


# =============================================================================
# RansomwareFamily Enum Tests
# =============================================================================


class TestRansomwareFamily:
    """Tests for RansomwareFamily enum."""

    def test_family_values(self):
        """Test ransomware family enum values."""
        assert RansomwareFamily.LOCKBIT.value == "lockbit"
        assert RansomwareFamily.BLACKCAT.value == "blackcat"
        assert RansomwareFamily.CONTI.value == "conti"
        assert RansomwareFamily.REVIL.value == "revil"
        assert RansomwareFamily.RYUK.value == "ryuk"
        assert RansomwareFamily.CUSTOM.value == "custom"

    def test_family_from_value(self):
        """Test creating enum from value."""
        family = RansomwareFamily("lockbit")
        assert family == RansomwareFamily.LOCKBIT


class TestDetectionStatus:
    """Tests for DetectionStatus enum."""

    def test_status_values(self):
        """Test detection status enum values."""
        assert DetectionStatus.DETECTED.value == "detected"
        assert DetectionStatus.MISSED.value == "missed"
        assert DetectionStatus.PARTIAL.value == "partial"
        assert DetectionStatus.PENDING.value == "pending"


# =============================================================================
# ScenarioGenerator Tests
# =============================================================================


@pytest.mark.requires_api
class TestScenarioGenerator:
    """Tests for ScenarioGenerator."""

    def test_generator_initialization(self, scenario_generator):
        """Test generator initialization."""
        assert scenario_generator is not None
        assert scenario_generator.FAMILY_PROFILES is not None

    def test_family_profiles_exist(self, scenario_generator):
        """Test all family profiles exist."""
        for family in [
            RansomwareFamily.LOCKBIT,
            RansomwareFamily.BLACKCAT,
            RansomwareFamily.CONTI,
            RansomwareFamily.REVIL,
            RansomwareFamily.RYUK,
        ]:
            assert family in scenario_generator.FAMILY_PROFILES

    def test_generate_lockbit_scenario(self, scenario_generator):
        """Test LockBit scenario generation."""
        scenario = scenario_generator.generate_scenario(
            family=RansomwareFamily.LOCKBIT, complexity="medium"
        )

        assert scenario is not None
        assert scenario.family == RansomwareFamily.LOCKBIT
        assert "LOCKBIT" in scenario.name.upper()
        assert len(scenario.execution_chain) > 0
        assert len(scenario.mitre_techniques) > 0

    def test_generate_blackcat_scenario(self, scenario_generator):
        """Test BlackCat scenario generation."""
        scenario = scenario_generator.generate_scenario(
            family=RansomwareFamily.BLACKCAT, complexity="high"
        )

        assert scenario.family == RansomwareFamily.BLACKCAT
        assert scenario.exfiltration is True  # BlackCat does double extortion

    def test_generate_low_complexity_scenario(self, scenario_generator):
        """Test low complexity scenario."""
        scenario = scenario_generator.generate_scenario(
            family=RansomwareFamily.LOCKBIT, complexity="low"
        )

        # Low complexity should have simpler execution chain
        assert len(scenario.execution_chain) <= 2

    def test_generate_high_complexity_scenario(self, scenario_generator):
        """Test high complexity scenario."""
        scenario = scenario_generator.generate_scenario(
            family=RansomwareFamily.CONTI, complexity="high"
        )

        # High complexity should have more steps
        assert len(scenario.execution_chain) >= 4
        # Should include credential harvesting
        assert any("credential" in step.lower() for step in scenario.execution_chain)

    def test_generate_scenario_without_exfil(self, scenario_generator):
        """Test scenario without exfiltration."""
        scenario = scenario_generator.generate_scenario(
            family=RansomwareFamily.RYUK, include_exfil=False
        )

        assert scenario.exfiltration is False

    def test_generate_detection_tests(self, scenario_generator, sample_attack_scenario):
        """Test detection test generation."""
        tests = scenario_generator.generate_detection_tests(sample_attack_scenario)

        assert tests is not None
        assert len(tests) >= 3  # At least shadow, encryption, discovery

    def test_detection_tests_include_shadow_deletion(
        self, scenario_generator, sample_attack_scenario
    ):
        """Test detection tests include shadow deletion."""
        tests = scenario_generator.generate_detection_tests(sample_attack_scenario)

        technique_ids = [t.technique_id for t in tests]
        assert "T1490" in technique_ids  # Inhibit System Recovery

    def test_detection_tests_include_encryption(self, scenario_generator, sample_attack_scenario):
        """Test detection tests include encryption."""
        tests = scenario_generator.generate_detection_tests(sample_attack_scenario)

        technique_ids = [t.technique_id for t in tests]
        assert "T1486" in technique_ids  # Data Encrypted for Impact

    def test_detection_tests_include_exfil_when_enabled(
        self, scenario_generator, sample_attack_scenario
    ):
        """Test exfiltration detection test included when enabled."""
        sample_attack_scenario.exfiltration = True
        tests = scenario_generator.generate_detection_tests(sample_attack_scenario)

        technique_ids = [t.technique_id for t in tests]
        assert "T1567" in technique_ids  # Exfiltration Over Web Service


# =============================================================================
# SimulationConfig Tests
# =============================================================================


class TestSimulationConfig:
    """Tests for SimulationConfig."""

    def test_config_defaults(self, temp_test_dir):
        """Test SimulationConfig default values."""
        config = SimulationConfig(target_directory=temp_test_dir)

        assert config.file_extensions == [".txt", ".docx", ".xlsx"]
        assert config.create_ransom_note is True
        assert config.simulate_encryption is True
        assert config.cleanup_after is True
        assert config.log_all_actions is True

    def test_config_custom_values(self, temp_test_dir):
        """Test SimulationConfig with custom values."""
        config = SimulationConfig(
            target_directory=temp_test_dir,
            file_extensions=[".pdf"],
            create_ransom_note=False,
        )

        assert config.file_extensions == [".pdf"]
        assert config.create_ransom_note is False


# =============================================================================
# SafeRansomwareSimulator Tests
# =============================================================================


class TestSafeRansomwareSimulator:
    """Tests for SafeRansomwareSimulator."""

    def test_simulator_initialization(self, simulation_config):
        """Test simulator initialization."""
        simulator = SafeRansomwareSimulator(simulation_config)

        assert simulator is not None
        assert simulator.config == simulation_config
        assert simulator.audit_log == []
        assert simulator.created_files == []

    def test_simulator_rejects_unsafe_directory(self):
        """Test simulator rejects non-temp directories."""
        unsafe_config = SimulationConfig(target_directory="/home/user/important_data")

        with pytest.raises(ValueError) as exc_info:
            SafeRansomwareSimulator(unsafe_config)

        assert "temp" in str(exc_info.value).lower() or "test" in str(exc_info.value).lower()

    def test_setup_test_files(self, simulation_config):
        """Test test file setup."""
        simulator = SafeRansomwareSimulator(simulation_config)
        files = simulator.setup_test_files(num_files=5)

        # Should create 5 files per extension
        assert len(files) == 5 * len(simulation_config.file_extensions)

        # All files should exist
        for filepath in files:
            assert Path(filepath).exists()

    def test_simulate_file_enumeration(self, simulation_config):
        """Test file enumeration simulation."""
        simulator = SafeRansomwareSimulator(simulation_config)
        simulator.setup_test_files(num_files=3)

        discovered = simulator.simulate_file_enumeration()

        assert len(discovered) > 0
        # Check audit log
        assert any(entry["action"] == "ENUMERATE" for entry in simulator.audit_log)

    def test_simulate_encryption(self, simulation_config):
        """Test encryption simulation."""
        simulator = SafeRansomwareSimulator(simulation_config)
        files = simulator.setup_test_files(num_files=3)

        result = simulator.simulate_encryption(files)

        assert result["simulated"] is True
        assert result["files_affected"] > 0

        # Check files were renamed (not actually encrypted)
        for filepath in files:
            encrypted_path = filepath + ".encrypted"
            assert Path(encrypted_path).exists()
            assert not Path(filepath).exists()

    def test_simulate_encryption_disabled(self, temp_test_dir):
        """Test encryption simulation when disabled."""
        config = SimulationConfig(target_directory=temp_test_dir, simulate_encryption=False)
        simulator = SafeRansomwareSimulator(config)
        files = simulator.setup_test_files(num_files=2)

        result = simulator.simulate_encryption(files)

        assert result["simulated"] is False
        assert result["files_affected"] == 0

    def test_simulate_shadow_deletion(self, simulation_config):
        """Test shadow deletion simulation."""
        simulator = SafeRansomwareSimulator(simulation_config)

        result = simulator.simulate_shadow_deletion()

        assert result["simulated"] is True
        assert "commands" in result
        assert len(result["commands"]) >= 2

        # Check audit log - commands should be logged but NOT executed
        shadow_logs = [e for e in simulator.audit_log if e["action"] == "SHADOW_DELETE_SIM"]
        assert len(shadow_logs) >= 1
        for log in shadow_logs:
            assert log.get("executed") is False

    def test_simulate_shadow_deletion_disabled(self, temp_test_dir):
        """Test shadow deletion when disabled."""
        config = SimulationConfig(target_directory=temp_test_dir, simulate_shadow_delete=False)
        simulator = SafeRansomwareSimulator(config)

        result = simulator.simulate_shadow_deletion()

        assert result["simulated"] is False

    def test_create_ransom_note(self, simulation_config):
        """Test ransom note creation."""
        simulator = SafeRansomwareSimulator(simulation_config)

        note_path = simulator.create_ransom_note()

        assert note_path != ""
        assert Path(note_path).exists()

        # Check content indicates simulation
        content = Path(note_path).read_text()
        assert "SIMULATION" in content
        assert "purple team" in content.lower() or "PURPLE" in content

    def test_create_ransom_note_disabled(self, temp_test_dir):
        """Test ransom note creation when disabled."""
        config = SimulationConfig(target_directory=temp_test_dir, create_ransom_note=False)
        simulator = SafeRansomwareSimulator(config)

        note_path = simulator.create_ransom_note()

        assert note_path == ""

    def test_generate_telemetry(self, simulation_config):
        """Test telemetry generation."""
        simulator = SafeRansomwareSimulator(simulation_config)
        simulator.setup_test_files(num_files=2)
        simulator.simulate_file_enumeration()

        telemetry = simulator.generate_telemetry()

        assert len(telemetry) > 0
        assert all("timestamp" in event for event in telemetry)
        assert all("event_type" in event for event in telemetry)
        assert all("source" in event for event in telemetry)

    def test_cleanup_restores_files(self, simulation_config):
        """Test cleanup restores encrypted files before removing."""
        simulation_config.cleanup_after = True
        simulator = SafeRansomwareSimulator(simulation_config)

        files = simulator.setup_test_files(num_files=2)
        original_paths = files.copy()

        simulator.simulate_encryption(files)

        # After encryption, .encrypted files should exist
        for filepath in original_paths:
            assert Path(filepath + ".encrypted").exists()

        simulator.cleanup()

        # After cleanup, both original and encrypted should be gone
        # (cleanup restores then removes test files)
        for filepath in original_paths:
            assert not Path(filepath).exists()
            assert not Path(filepath + ".encrypted").exists()

    def test_cleanup_removes_test_files(self, simulation_config):
        """Test cleanup removes created test files."""
        simulation_config.cleanup_after = True
        simulator = SafeRansomwareSimulator(simulation_config)

        files = simulator.setup_test_files(num_files=2)
        simulator.cleanup()

        # Test files should be removed
        for filepath in files:
            assert not Path(filepath).exists()


# =============================================================================
# DetectionTest Tests
# =============================================================================


class TestDetectionTest:
    """Tests for DetectionTest dataclass."""

    def test_detection_test_creation(self):
        """Test DetectionTest creation."""
        test = DetectionTest(
            name="Test Shadow Deletion",
            technique_id="T1490",
            description="Test VSS deletion detection",
            simulation_command="vssadmin delete shadows",
            expected_detection="Alert on shadow deletion",
            detection_source="EDR",
        )

        assert test.name == "Test Shadow Deletion"
        assert test.technique_id == "T1490"


# =============================================================================
# TestResult Tests
# =============================================================================


class TestTestResult:
    """Tests for TestResult dataclass."""

    def test_result_creation(self):
        """Test TestResult creation."""
        test = DetectionTest(
            name="Test",
            technique_id="T1486",
            description="Test",
            simulation_command="test",
            expected_detection="test",
            detection_source="EDR",
        )

        result = TestResult(
            test=test,
            status=DetectionStatus.DETECTED,
            detection_time_ms=150.0,
            alert_generated=True,
            notes="Alert triggered successfully",
        )

        assert result.status == DetectionStatus.DETECTED
        assert result.alert_generated is True
        assert result.detection_time_ms == 150.0


# =============================================================================
# DetectionValidator Tests
# =============================================================================


class TestDetectionValidator:
    """Tests for DetectionValidator."""

    def test_validator_initialization(self, detection_validator):
        """Test validator initialization."""
        assert detection_validator.results == []

    def test_run_test(self, detection_validator, simulation_config):
        """Test running a detection test."""
        test = DetectionTest(
            name="Test Shadow Deletion",
            technique_id="T1490",
            description="Test",
            simulation_command="test",
            expected_detection="test",
            detection_source="EDR",
        )

        simulator = SafeRansomwareSimulator(simulation_config)
        result = detection_validator.run_test(test, simulator)

        assert result is not None
        assert result.test == test
        assert result.status == DetectionStatus.PENDING

    def test_generate_gap_analysis_empty(self, detection_validator):
        """Test gap analysis with no results."""
        analysis = detection_validator.generate_gap_analysis()

        assert analysis["total_tests"] == 0
        assert analysis["coverage_percentage"] == 0

    def test_generate_gap_analysis_with_results(self, detection_validator):
        """Test gap analysis with test results."""
        # Add some results
        for i, status in enumerate(
            [
                DetectionStatus.DETECTED,
                DetectionStatus.MISSED,
                DetectionStatus.DETECTED,
                DetectionStatus.PARTIAL,
            ]
        ):
            test = DetectionTest(
                name=f"Test {i}",
                technique_id=f"T{1000+i}",
                description="Test",
                simulation_command="test",
                expected_detection="test",
                detection_source="EDR",
            )
            detection_validator.results.append(TestResult(test=test, status=status))

        analysis = detection_validator.generate_gap_analysis()

        assert analysis["total_tests"] == 4
        assert analysis["detected"] == 2
        assert analysis["missed"] == 1
        assert analysis["partial"] == 1
        assert analysis["coverage_percentage"] == 50.0
        assert "T1001" in analysis["missed_techniques"]


# =============================================================================
# PurpleTeamExercise Tests
# =============================================================================


@pytest.mark.requires_api
class TestPurpleTeamExercise:
    """Tests for PurpleTeamExercise."""

    def test_exercise_initialization(self):
        """Test exercise initialization."""
        exercise = PurpleTeamExercise()

        assert exercise.scenario_gen is not None
        assert exercise.validator is not None

    def test_plan_exercise(self):
        """Test exercise planning."""
        exercise = PurpleTeamExercise()

        plan = exercise.plan_exercise(
            ransomware_family=RansomwareFamily.LOCKBIT, complexity="medium"
        )

        assert plan is not None
        assert "scenario" in plan
        assert "tests" in plan
        assert "phases" in plan

    def test_plan_exercise_includes_scenario(self):
        """Test plan includes valid scenario."""
        exercise = PurpleTeamExercise()

        plan = exercise.plan_exercise(ransomware_family=RansomwareFamily.BLACKCAT)

        assert plan["scenario"].family == RansomwareFamily.BLACKCAT

    def test_plan_exercise_includes_tests(self):
        """Test plan includes detection tests."""
        exercise = PurpleTeamExercise()

        plan = exercise.plan_exercise(ransomware_family=RansomwareFamily.LOCKBIT)

        assert len(plan["tests"]) >= 3

    def test_plan_exercise_includes_phases(self):
        """Test plan includes exercise phases."""
        exercise = PurpleTeamExercise()

        plan = exercise.plan_exercise(ransomware_family=RansomwareFamily.LOCKBIT)

        phases = plan["phases"]
        assert len(phases) >= 4
        phase_names = [p["name"] for p in phases]
        assert "Preparation" in phase_names
        assert "Execution" in phase_names


# =============================================================================
# AttackScenario Tests
# =============================================================================


class TestAttackScenario:
    """Tests for AttackScenario dataclass."""

    def test_attack_scenario_creation(self, sample_attack_scenario):
        """Test AttackScenario creation."""
        assert sample_attack_scenario.family == RansomwareFamily.LOCKBIT
        assert sample_attack_scenario.name == "LockBit Simulation"
        assert len(sample_attack_scenario.mitre_techniques) >= 1

    def test_attack_scenario_has_detection_opportunities(self, sample_attack_scenario):
        """Test scenario includes detection opportunities."""
        assert len(sample_attack_scenario.detection_opportunities) > 0


# =============================================================================
# Integration Tests
# =============================================================================


@pytest.mark.requires_api
class TestIntegration:
    """Integration tests for the purple team framework."""

    def test_full_simulation_workflow(self, temp_test_dir):
        """Test complete simulation workflow."""
        # 1. Generate scenario
        gen = ScenarioGenerator()
        scenario = gen.generate_scenario(family=RansomwareFamily.LOCKBIT, complexity="medium")

        # 2. Generate tests
        tests = gen.generate_detection_tests(scenario)

        # 3. Run simulation
        config = SimulationConfig(target_directory=temp_test_dir, cleanup_after=True)
        simulator = SafeRansomwareSimulator(config)

        # Setup and run
        files = simulator.setup_test_files(num_files=3)
        discovered = simulator.simulate_file_enumeration()
        encryption_result = simulator.simulate_encryption(discovered)
        shadow_result = simulator.simulate_shadow_deletion()
        note = simulator.create_ransom_note()

        # Verify actions occurred
        assert encryption_result["files_affected"] > 0
        assert shadow_result["simulated"] is True
        assert note != ""

        # 4. Validate detections
        validator = DetectionValidator()
        for test in tests:
            validator.run_test(test, simulator)

        # 5. Generate analysis
        analysis = validator.generate_gap_analysis()

        # Cleanup
        simulator.cleanup()

        assert analysis["total_tests"] > 0

    def test_exercise_planning_and_execution(self, temp_test_dir):
        """Test complete exercise planning and execution."""
        exercise = PurpleTeamExercise()

        # Plan exercise
        plan = exercise.plan_exercise(ransomware_family=RansomwareFamily.CONTI, complexity="high")

        # Verify plan structure
        assert plan["scenario"] is not None
        assert len(plan["tests"]) >= 3
        assert len(plan["phases"]) >= 4

        # Verify scenario has expected elements
        scenario = plan["scenario"]
        assert scenario.family == RansomwareFamily.CONTI
        assert len(scenario.execution_chain) >= 4  # High complexity


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

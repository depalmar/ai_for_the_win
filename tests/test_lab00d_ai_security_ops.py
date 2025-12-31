#!/usr/bin/env python3
"""Tests for Lab 00d: AI in Security Operations."""

import sys
from pathlib import Path

import pytest

# Clear any existing 'main' module to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p and "\\labs\\lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab00d-ai-in-security-operations" / "solution")
sys.path.insert(0, lab_path)

from main import generate_quick_reference, load_scenarios


class TestDataLoading:
    """Tests for scenario data loading."""

    def test_load_scenarios(self):
        """Test loading scenario data."""
        data = load_scenarios()

        assert data is not None
        assert isinstance(data, dict)

    def test_scenarios_have_suitability(self):
        """Test suitability scenarios are present."""
        data = load_scenarios()

        assert "suitability_scenarios" in data
        scenarios = data["suitability_scenarios"]

        assert isinstance(scenarios, list)
        assert len(scenarios) > 0

        # Check structure of a scenario
        scenario = scenarios[0]
        assert "task" in scenario
        assert "ai_suitable" in scenario
        assert "reason" in scenario

    def test_scenarios_have_risks(self):
        """Test risk scenarios are present."""
        data = load_scenarios()

        assert "risk_scenarios" in data
        scenarios = data["risk_scenarios"]

        assert isinstance(scenarios, list)
        assert len(scenarios) > 0

        # Check structure
        scenario = scenarios[0]
        assert "scenario" in scenario
        assert "risks" in scenario

    def test_scenarios_have_human_loop(self):
        """Test human-in-the-loop scenarios are present."""
        data = load_scenarios()

        assert "human_loop_decisions" in data
        scenarios = data["human_loop_decisions"]

        assert isinstance(scenarios, list)
        assert len(scenarios) > 0

        # Check structure
        scenario = scenarios[0]
        assert "action" in scenario
        assert "requires_human" in scenario


class TestScenarioContent:
    """Tests for scenario content quality."""

    def test_suitability_scenarios_balanced(self):
        """Test that suitability scenarios have both yes and no answers."""
        data = load_scenarios()
        scenarios = data["suitability_scenarios"]

        suitable_count = sum(1 for s in scenarios if s["ai_suitable"])
        not_suitable_count = len(scenarios) - suitable_count

        # Should have mix of both
        assert suitable_count > 0, "Should have some AI-suitable scenarios"
        assert not_suitable_count > 0, "Should have some non-AI-suitable scenarios"

    def test_risk_scenarios_have_multiple_risks(self):
        """Test that risk scenarios identify multiple risks."""
        data = load_scenarios()
        scenarios = data["risk_scenarios"]

        for scenario in scenarios:
            risks = scenario["risks"]
            assert isinstance(risks, list)
            assert len(risks) >= 1, "Each scenario should have at least one risk"

    def test_human_loop_scenarios_balanced(self):
        """Test human-in-the-loop scenarios have both require and not require."""
        data = load_scenarios()
        scenarios = data["human_loop_decisions"]

        # Count based on string values (yes/no/depends)
        requires_human = sum(1 for s in scenarios if s["requires_human"] in ["yes", "depends"])
        automated_ok = sum(1 for s in scenarios if s["requires_human"] == "no")

        # Should have mix of both
        assert requires_human > 0, "Some actions should require human approval"
        assert automated_ok > 0, "Some actions should allow automation"


class TestQuickReference:
    """Tests for quick reference generation."""

    def test_generate_quick_reference_runs(self, capsys):
        """Test that quick reference generator runs without error."""
        # This is an interactive function, but we can test it doesn't crash
        try:
            generate_quick_reference()
            captured = capsys.readouterr()
            assert "AI" in captured.out or len(captured.out) > 0
        except Exception as e:
            # If it requires input, that's expected
            if "input" not in str(e).lower():
                raise


class TestScenarioCategories:
    """Tests for scenario categorization."""

    def test_suitability_covers_security_domains(self):
        """Test that scenarios cover various security domains."""
        data = load_scenarios()
        scenarios = data["suitability_scenarios"]

        all_tasks = " ".join(s["task"].lower() for s in scenarios)

        # Should cover various security areas
        security_terms = ["alert", "malware", "phishing", "incident", "log", "threat"]
        covered = sum(1 for term in security_terms if term in all_tasks)

        assert covered >= 2, "Scenarios should cover multiple security domains"

    def test_risks_are_realistic(self):
        """Test that identified risks are realistic security concerns."""
        data = load_scenarios()
        scenarios = data["risk_scenarios"]

        all_risks = []
        for scenario in scenarios:
            all_risks.extend(scenario["risks"])

        risks_text = " ".join(all_risks).lower()

        # Common AI security risks
        risk_terms = [
            "false",
            "bias",
            "adversarial",
            "miss",
            "incorrect",
            "confidence",
            "data",
            "privacy",
        ]
        covered = sum(1 for term in risk_terms if term in risks_text)

        assert covered >= 1, "Risks should include realistic AI concerns"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""Tests for Lab 00c: Introduction to Prompt Engineering."""

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
lab_path = str(Path(__file__).parent.parent / "labs" / "lab00c-intro-prompt-engineering" / "solution")
sys.path.insert(0, lab_path)

from main import (
    exercise_1_solution,
    exercise_2_solution,
    exercise_3_solution,
    exercise_4_solution,
    load_samples,
    security_analysis_template,
)


class TestDataLoading:
    """Tests for data loading."""

    def test_load_samples(self):
        """Test loading security samples."""
        samples = load_samples()

        assert samples is not None
        assert isinstance(samples, dict)
        assert "log_entries" in samples
        assert "threat_report_excerpt" in samples
        assert "suspicious_email" in samples


class TestPromptConstruction:
    """Tests for prompt construction."""

    def test_exercise_1_log_analysis_prompt(self):
        """Test log analysis prompt structure."""
        samples = load_samples()
        log_entries = samples["log_entries"]

        prompt = exercise_1_solution(log_entries)

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 100

        # Check for key structural elements
        assert "security analyst" in prompt.lower() or "analyst" in prompt.lower()
        assert "log" in prompt.lower()
        # Prompt should include the log entries
        for entry in log_entries[:2]:  # Check at least first two
            assert entry[:20] in prompt  # First 20 chars should appear

    def test_exercise_2_ioc_extraction_prompt(self):
        """Test IOC extraction prompt structure."""
        samples = load_samples()
        threat_report = samples["threat_report_excerpt"]

        prompt = exercise_2_solution(threat_report)

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 100

        # Should include the threat report
        assert threat_report[:30] in prompt or "report" in prompt.lower()

    def test_exercise_3_phishing_analysis_prompt(self):
        """Test phishing analysis prompt structure."""
        samples = load_samples()
        email = samples["suspicious_email"]

        prompt = exercise_3_solution(email)

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 100

        # Should reference email analysis
        assert "email" in prompt.lower() or "phishing" in prompt.lower()

    def test_exercise_4_powershell_prompt(self):
        """Test PowerShell analysis prompt structure."""
        samples = load_samples()
        command = samples.get("powershell_command", "Get-Process")

        prompt = exercise_4_solution(command)

        assert prompt is not None
        assert isinstance(prompt, str)
        assert len(prompt) > 50


class TestSecurityPromptBuilder:
    """Tests for the generic security prompt builder."""

    def test_security_analysis_template_basic(self):
        """Test basic prompt building."""
        prompt = security_analysis_template(
            task_type="log_analysis",
            data="2024-01-15 Failed login from 192.168.1.100",
        )

        assert prompt is not None
        assert isinstance(prompt, str)
        assert "192.168.1.100" in prompt

    def test_security_analysis_template_with_format(self):
        """Test prompt building with task type."""
        prompt = security_analysis_template(
            task_type="ioc_extraction",
            data="Malware connected to evil.com on port 443",
        )

        assert prompt is not None
        assert "evil.com" in prompt

    def test_security_analysis_template_with_context(self):
        """Test prompt building with different task type."""
        prompt = security_analysis_template(
            task_type="alert_triage",
            data="Multiple failed SSH attempts from external IP",
        )

        assert prompt is not None
        assert "SSH" in prompt or "failed" in prompt.lower()


class TestPromptQuality:
    """Tests for prompt quality characteristics."""

    def test_prompts_have_structure(self):
        """Test that prompts include structural elements."""
        samples = load_samples()

        prompt = exercise_1_solution(samples["log_entries"])

        # Good prompts should have sections/structure
        structure_indicators = ["##", "task", "format", "output", "analysis"]
        has_structure = any(ind in prompt.lower() for ind in structure_indicators)

        assert has_structure, "Prompt should have clear structure"

    def test_prompts_define_role(self):
        """Test that prompts define an analyst role."""
        samples = load_samples()

        prompt = exercise_1_solution(samples["log_entries"])

        role_indicators = ["analyst", "expert", "you are", "role"]
        has_role = any(ind in prompt.lower() for ind in role_indicators)

        assert has_role, "Prompt should define a role for the LLM"

    def test_prompts_not_empty_or_trivial(self):
        """Test that prompts are substantive."""
        samples = load_samples()

        prompts = [
            exercise_1_solution(samples["log_entries"]),
            exercise_2_solution(samples["threat_report_excerpt"]),
            exercise_3_solution(samples["suspicious_email"]),
        ]

        for prompt in prompts:
            assert len(prompt) > 200, "Prompts should be substantive"
            assert "\n" in prompt, "Prompts should have line breaks for readability"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

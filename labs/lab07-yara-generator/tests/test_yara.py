#!/usr/bin/env python3
"""Tests for Lab 07: AI-Powered YARA Rule Generator."""

import os
import tempfile
from pathlib import Path

import pytest

# Try to import from solution
try:
    from labs.lab07_yara_generator.solution.main import (
        MalwareSampleAnalyzer,
        SampleAnalyzer,
        YARAGenerator,
        YARAPatternExtractor,
        YARARuleBuilder,
        validate_yara_rule,
    )
except ImportError:
    try:
        from solution.main import (
            MalwareSampleAnalyzer,
            SampleAnalyzer,
            YARAGenerator,
            YARAPatternExtractor,
            YARARuleBuilder,
            validate_yara_rule,
        )
    except ImportError:
        pytest.skip("Solution module not available", allow_module_level=True)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_pe_file():
    """Create a sample PE-like binary file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        # MZ header
        content = b"MZ" + b"\x00" * 58 + b"\x50\x45\x00\x00"
        content += b"\x00" * 100
        # Add some suspicious strings
        content += b"This is malware test\x00"
        content += b"http://evil-domain.com/c2\x00"
        content += b"cmd.exe /c whoami\x00"
        content += b"CreateRemoteThread\x00"
        content += b"VirtualAllocEx\x00"
        content += b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Run\x00"
        f.write(content)
        f.flush()
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def sample_analyzer():
    """Create a SampleAnalyzer instance."""
    return SampleAnalyzer()


@pytest.fixture
def yara_generator():
    """Create a YARAGenerator instance (without LLM)."""
    return YARAGenerator(llm=None)


# =============================================================================
# Sample Analysis Tests
# =============================================================================


class TestSampleAnalysis:
    """Test sample analysis functions."""

    def test_extract_strings(self, sample_analyzer, sample_pe_file):
        """Test string extraction from binary."""
        strings = sample_analyzer.extract_strings(sample_pe_file, min_length=6)

        assert isinstance(strings, list)
        assert len(strings) > 0
        # Should find our test strings
        string_values = [s.lower() for s in strings]
        assert any("evil" in s for s in string_values)

    def test_extract_hex_patterns(self, sample_analyzer, sample_pe_file):
        """Test hex pattern extraction."""
        patterns = sample_analyzer.extract_hex_patterns(sample_pe_file)

        assert isinstance(patterns, list)
        # Should find MZ header pattern
        assert any("4D 5A" in p for p in patterns)  # MZ

    def test_get_file_info(self, sample_analyzer, sample_pe_file):
        """Test file info extraction."""
        info = sample_analyzer.get_file_info(sample_pe_file)

        assert "file_size" in info
        assert "md5" in info
        assert "sha256" in info
        assert "is_pe" in info
        assert "entropy" in info

        assert info["file_size"] > 0
        assert info["is_pe"] is True
        assert len(info["sha256"]) == 64

    def test_malware_sample_analyzer_wrapper(self, sample_pe_file):
        """Test the wrapper class for tests."""
        analyzer = MalwareSampleAnalyzer()
        analysis = analyzer.analyze_sample(sample_pe_file)

        assert "file_info" in analysis
        assert "strings" in analysis
        assert "hex_patterns" in analysis


# =============================================================================
# Pattern Extraction Tests
# =============================================================================


class TestPatternExtraction:
    """Test pattern extraction."""

    def test_extract_patterns(self):
        """Test pattern extraction from analysis."""
        extractor = YARAPatternExtractor()

        analysis = {
            "strings": [{"value": "test_string", "type": "ascii"}],
            "hex_patterns": ["4D 5A 90 00"],
        }

        patterns = extractor.extract_patterns(analysis)

        assert "strings" in patterns
        assert "hex_patterns" in patterns
        assert len(patterns["strings"]) == 1
        assert len(patterns["hex_patterns"]) == 1


# =============================================================================
# Rule Building Tests
# =============================================================================


class TestRuleBuilding:
    """Test YARA rule building."""

    def test_build_basic_rule(self):
        """Test building a basic YARA rule."""
        builder = YARARuleBuilder()

        patterns = {
            "strings": [
                {"value": "malicious_string", "name": "s1"},
                {"value": "evil.com", "name": "s2"},
            ],
            "hex_patterns": ["4D 5A 90 00"],
        }

        rule = builder.build_rule(
            rule_name="Test_Malware",
            patterns=patterns,
            description="Test malware detection",
            author="Test",
        )

        assert "rule Test_Malware" in rule
        assert "malicious_string" in rule
        assert "evil.com" in rule
        assert "description" in rule
        assert "condition" in rule


# =============================================================================
# Rule Generation Tests
# =============================================================================


class TestRuleGeneration:
    """Test YARA rule generation."""

    def test_generate_template_rule(self, yara_generator, sample_pe_file):
        """Test template-based rule generation (no LLM)."""
        analyzer = SampleAnalyzer()

        file_info = analyzer.get_file_info(sample_pe_file)
        strings = analyzer.extract_strings(sample_pe_file)

        rule = yara_generator.generate_rule(
            sample_info=file_info,
            strings=strings,
            malware_family="TestFamily",
            rule_name="Test_Rule",
        )

        assert "rule Test_Rule" in rule
        assert "TestFamily" in rule
        assert "strings:" in rule
        assert "condition:" in rule

    def test_rule_contains_pe_check(self, yara_generator, sample_pe_file):
        """Test that generated rule checks for PE header."""
        analyzer = SampleAnalyzer()
        file_info = analyzer.get_file_info(sample_pe_file)
        strings = analyzer.extract_strings(sample_pe_file)

        rule = yara_generator.generate_rule(
            sample_info=file_info,
            strings=strings,
        )

        # Should check for MZ header
        assert "0x5A4D" in rule or "MZ" in rule


# =============================================================================
# Rule Validation Tests
# =============================================================================


class TestValidation:
    """Test YARA rule validation."""

    def test_validate_valid_rule(self):
        """Test validation of a valid rule."""
        valid_rule = """
rule Test_Valid {
    meta:
        description = "Test rule"
    strings:
        $s1 = "test"
    condition:
        $s1
}
"""
        result = validate_yara_rule(valid_rule)
        # If yara-python is installed, should return True
        # If not installed, returns None
        assert result is True or result is None

    def test_validate_invalid_rule(self):
        """Test validation of an invalid rule."""
        invalid_rule = """
rule Test_Invalid {
    strings:
        $s1 = "test"
    condition:
        $s1 and $s2  // $s2 not defined
}
"""
        result = validate_yara_rule(invalid_rule)
        # If yara-python is installed, should return False
        # If not installed, returns None
        assert result is False or result is None


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Test full YARA generation pipeline."""

    def test_full_pipeline(self, sample_pe_file):
        """Test complete analysis to rule generation."""
        # 1. Analyze sample
        analyzer = SampleAnalyzer()
        file_info = analyzer.get_file_info(sample_pe_file)
        strings = analyzer.extract_strings(sample_pe_file)

        # 2. Generate rule
        generator = YARAGenerator(llm=None)
        rule = generator.generate_rule(
            sample_info=file_info,
            strings=strings,
            malware_family="TestMalware",
        )

        # 3. Validate rule
        validation = validate_yara_rule(rule)

        # Rule should be generated
        assert rule is not None
        assert len(rule) > 100

        # If yara is available, should be valid
        if validation is not None:
            assert validation is True

    def test_wrapper_api(self, sample_pe_file):
        """Test using the wrapper API expected by tests."""
        # Use the test-compatible classes
        analyzer = MalwareSampleAnalyzer()
        extractor = YARAPatternExtractor()
        builder = YARARuleBuilder()

        # Analyze
        analysis = analyzer.analyze_sample(sample_pe_file)

        # Extract patterns
        patterns = extractor.extract_patterns(analysis)

        # Build rule
        rule = builder.build_rule(
            rule_name="Wrapper_Test",
            patterns=patterns,
            description="Test via wrapper API",
        )

        assert "rule Wrapper_Test" in rule


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

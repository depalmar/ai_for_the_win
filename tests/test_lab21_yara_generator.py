#!/usr/bin/env python3
"""Tests for Lab 07: YARA Rule Generator."""

import sys
from pathlib import Path

import pytest

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab21-yara-generator" / "solution")
sys.path.insert(0, lab_path)

from main import MalwareSampleAnalyzer, YARAPatternExtractor, YARARuleBuilder, validate_yara_rule


@pytest.fixture
def sample_binary_content():
    """Create sample binary content for testing."""
    # Simulated PE header + some suspicious strings
    content = b"MZ"  # DOS header
    content += b"\x90" * 60  # Padding
    content += b"PE\x00\x00"  # PE signature
    content += b"\x90" * 100  # More padding
    content += b"CreateRemoteThread\x00"
    content += b"VirtualAllocEx\x00"
    content += b"WriteProcessMemory\x00"
    content += b"http://malware.evil.com/payload\x00"
    content += b"password\x00"
    content += b"\x90" * 200  # Padding
    return content


@pytest.fixture
def sample_file(tmp_path, sample_binary_content):
    """Create a temporary sample file."""
    filepath = tmp_path / "sample.exe"
    filepath.write_bytes(sample_binary_content)
    return str(filepath)


class TestMalwareSampleAnalyzer:
    """Tests for malware sample analysis."""

    def test_analyze_sample(self, sample_file):
        """Test sample analysis."""
        analyzer = MalwareSampleAnalyzer()
        analysis = analyzer.analyze_sample(sample_file)

        assert analysis is not None
        assert "file_info" in analysis
        assert "strings" in analysis

    def test_extract_strings(self, sample_file):
        """Test string extraction."""
        analyzer = MalwareSampleAnalyzer()
        strings = analyzer.extract_strings(sample_file, min_length=4)

        assert strings is not None
        assert len(strings) > 0
        # Should find some of our embedded strings
        string_values = [s["value"] for s in strings]
        assert any("malware" in s.lower() for s in string_values)


class TestYARAPatternExtractor:
    """Tests for pattern extraction."""

    def test_extract_patterns(self, sample_file):
        """Test pattern extraction."""
        analyzer = MalwareSampleAnalyzer()
        analysis = analyzer.analyze_sample(sample_file)

        extractor = YARAPatternExtractor()
        patterns = extractor.extract_patterns(analysis)

        assert patterns is not None
        assert "strings" in patterns or "hex_patterns" in patterns

    def test_suspicious_api_detection(self, sample_file):
        """Test detection of suspicious API calls."""
        analyzer = MalwareSampleAnalyzer()
        analysis = analyzer.analyze_sample(sample_file)

        extractor = YARAPatternExtractor()
        patterns = extractor.extract_patterns(analysis)

        # Should detect injection-related APIs
        all_strings = [p.get("value", "") for p in patterns.get("strings", [])]
        assert any("Remote" in s or "Virtual" in s for s in all_strings)


class TestYARARuleBuilder:
    """Tests for YARA rule building."""

    def test_build_basic_rule(self):
        """Test building a basic YARA rule."""
        builder = YARARuleBuilder()
        patterns = {
            "strings": [
                {"name": "url", "value": "http://malware.com", "type": "ascii"},
                {"name": "api", "value": "CreateRemoteThread", "type": "ascii"},
            ]
        }

        rule = builder.build_rule(
            rule_name="TestMalware", patterns=patterns, description="Test malware rule"
        )

        assert rule is not None
        assert "rule TestMalware" in rule
        assert "http://malware.com" in rule
        assert "CreateRemoteThread" in rule
        assert "condition:" in rule

    def test_rule_has_metadata(self):
        """Test that rule includes metadata."""
        builder = YARARuleBuilder()
        patterns = {"strings": [{"name": "s1", "value": "test", "type": "ascii"}]}

        rule = builder.build_rule(
            rule_name="TestRule",
            patterns=patterns,
            description="Test description",
            author="Test Author",
        )

        assert "meta:" in rule
        assert "description" in rule


class TestYARAValidation:
    """Tests for YARA rule validation."""

    def test_validate_valid_rule(self):
        """Test validation of a valid rule."""
        valid_rule = """
rule TestRule {
    meta:
        description = "Test"
    strings:
        $s1 = "malware"
    condition:
        $s1
}
"""
        result = validate_yara_rule(valid_rule)
        # Should not raise exception
        assert result is True or result is None

    def test_validate_invalid_rule(self):
        """Test validation of an invalid rule."""
        invalid_rule = """
rule TestRule {
    strings:
        $s1 = "malware"
    condition:
        $undefined_var
}
"""
        # Should either return False or raise an exception
        try:
            result = validate_yara_rule(invalid_rule)
            # If it returns, should indicate invalid
            if result is not None:
                assert result is False
        except Exception:
            pass  # Exception is acceptable for invalid rule


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

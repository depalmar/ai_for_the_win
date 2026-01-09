"""Tests for Lab 07a: Binary Analysis Basics."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "lab07a-binary-basics" / "solution"))


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        PE_HEADER_SIGNATURES,
        analyze_pe_structure,
        check_suspicious_sections,
        detect_packers,
    )


def test_pe_header_signatures_defined():
    """Test that PE header signatures are defined."""
    from main import PE_HEADER_SIGNATURES

    assert "MZ" in PE_HEADER_SIGNATURES
    assert "PE" in PE_HEADER_SIGNATURES


def test_pe_structure_analysis():
    """Test PE structure analysis with sample data."""
    from main import analyze_pe_structure

    # Minimal PE-like structure
    sample_headers = {
        "machine": "0x14c",  # i386
        "num_sections": 4,
        "timestamp": "2024-01-15 10:30:00",
        "characteristics": ["EXECUTABLE_IMAGE", "32BIT_MACHINE"],
    }

    analysis = analyze_pe_structure(sample_headers)

    assert "architecture" in analysis
    assert "sections" in analysis


def test_suspicious_sections_detection():
    """Test detection of suspicious sections."""
    from main import check_suspicious_sections

    sections = [
        {"name": ".text", "characteristics": ["EXECUTE", "READ"]},
        {"name": ".UPX0", "characteristics": ["EXECUTE", "READ", "WRITE"]},
        {"name": ".data", "characteristics": ["READ", "WRITE"]},
    ]

    suspicious = check_suspicious_sections(sections)

    # Should flag UPX section as suspicious (packer indicator)
    assert len(suspicious) > 0


def test_packer_detection():
    """Test packer detection."""
    from main import detect_packers

    sections = [{"name": ".UPX0"}, {"name": ".UPX1"}, {"name": ".rsrc"}]
    packers = detect_packers(sections)

    assert "UPX" in packers or len(packers) > 0


def test_clean_binary_no_false_positives():
    """Test that clean binaries don't trigger false positives excessively."""
    from main import check_suspicious_sections

    # Normal sections
    normal_sections = [
        {"name": ".text", "characteristics": ["EXECUTE", "READ"]},
        {"name": ".data", "characteristics": ["READ", "WRITE"]},
        {"name": ".rdata", "characteristics": ["READ"]},
        {"name": ".rsrc", "characteristics": ["READ"]},
    ]

    suspicious = check_suspicious_sections(normal_sections)
    # Normal binary should have minimal suspicious indicators
    assert len(suspicious) <= 1

"""Tests for Lab 11a: Ransomware Fundamentals."""

import sys
from pathlib import Path

import pytest

# Add labs to path
sys.path.insert(
    0, str(Path(__file__).parent.parent / "labs" / "lab11a-ransomware-fundamentals" / "solution")
)


def test_solution_imports():
    """Test that solution imports without errors."""
    from main import (
        RANSOMWARE_INDICATORS,
        RansomwareIndicator,
        analyze_file_extension,
        calculate_entropy,
        check_ransom_note_patterns,
    )


def test_ransomware_indicators_defined():
    """Test that ransomware indicators are defined."""
    from main import RANSOMWARE_INDICATORS

    assert len(RANSOMWARE_INDICATORS) > 0
    # Should include common ransomware extensions
    extensions = [
        ind.indicator for ind in RANSOMWARE_INDICATORS if ind.indicator_type == "extension"
    ]
    assert any(".encrypted" in ext or ".locked" in ext for ext in extensions)


def test_analyze_file_extension_suspicious():
    """Test detection of suspicious file extensions."""
    from main import analyze_file_extension

    result = analyze_file_extension("document.docx.encrypted")
    assert result["suspicious"] is True
    assert result["ransomware_probability"] > 0.5


def test_analyze_file_extension_normal():
    """Test normal file extensions don't trigger."""
    from main import analyze_file_extension

    result = analyze_file_extension("document.docx")
    assert result["suspicious"] is False


def test_ransom_note_patterns():
    """Test ransom note pattern detection."""
    from main import check_ransom_note_patterns

    ransom_text = """
    YOUR FILES HAVE BEEN ENCRYPTED!
    To decrypt your files, send 0.5 BTC to the following wallet:
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    """

    result = check_ransom_note_patterns(ransom_text)

    assert result["is_ransom_note"] is True
    assert result["confidence"] > 0.7


def test_ransom_note_patterns_normal():
    """Test normal text doesn't trigger ransom note detection."""
    from main import check_ransom_note_patterns

    normal_text = "Hello, please find the attached document for your review."

    result = check_ransom_note_patterns(normal_text)

    assert result["is_ransom_note"] is False


def test_entropy_calculation():
    """Test entropy calculation."""
    from main import calculate_entropy

    # Low entropy (repetitive)
    low_entropy = calculate_entropy(b"AAAAAAAA")
    assert low_entropy < 1.0

    # Higher entropy (random-like)
    high_entropy = calculate_entropy(bytes(range(256)))
    assert high_entropy > 7.0

    # Encrypted data typically has entropy > 7.5
    assert high_entropy > low_entropy

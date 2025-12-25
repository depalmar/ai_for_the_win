#!/usr/bin/env python3
"""
Lab 07: AI-Powered YARA Rule Generator - Starter Code

Use LLMs to generate and optimize YARA rules from malware samples.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from rich.console import Console

console = Console()


# =============================================================================
# Task 1: Sample Analysis
# =============================================================================


class SampleAnalyzer:
    """Extract features from samples for YARA rule generation."""

    def extract_strings(self, filepath: str, min_length: int = 6) -> List[str]:
        """
        Extract strings from binary file.

        TODO:
        1. Read binary content
        2. Extract ASCII strings (min_length chars)
        3. Extract Unicode strings
        4. Filter out common/noisy strings
        5. Return unique strings
        """
        # YOUR CODE HERE
        pass

    def extract_hex_patterns(self, filepath: str, pattern_length: int = 16) -> List[str]:
        """
        Extract interesting hex patterns from binary.

        TODO:
        1. Read binary content
        2. Find repeated byte sequences
        3. Look for high-entropy sections
        4. Return hex patterns
        """
        # YOUR CODE HERE
        pass

    def get_file_info(self, filepath: str) -> dict:
        """
        Get basic file information.

        TODO:
        1. Get file size
        2. Calculate hashes (MD5, SHA256)
        3. Detect file type
        4. Return info dict
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 2: LLM Rule Generator
# =============================================================================

YARA_SYSTEM_PROMPT = """You are a YARA rule expert. Generate detection rules following these guidelines:

BEST PRACTICES:
1. Use specific strings that are unique to the malware
2. Avoid common Windows API names unless combined with other indicators
3. Include file size limits to improve performance
4. Use wildcards (??) sparingly in hex patterns
5. Add meaningful metadata

CONDITION LOGIC:
- Combine strings with AND/OR appropriately
- Use "X of ($strings*)" for flexibility
- Include PE header checks for executables
- Consider entropy checks for packed samples

OUTPUT FORMAT:
Return only the YARA rule, no explanation. The rule should be valid YARA syntax."""


class YARAGenerator:
    """Generate YARA rules using LLM."""

    def __init__(self, llm=None):
        """Initialize with LLM client."""
        # YOUR CODE HERE
        pass

    def generate_rule(
        self,
        sample_info: dict,
        strings: List[str],
        malware_family: str = None,
        rule_name: str = None,
    ) -> str:
        """
        Generate YARA rule from sample features.

        TODO:
        1. Format sample info for LLM
        2. Include extracted strings
        3. Ask LLM to generate rule
        4. Return YARA rule text
        """
        # YOUR CODE HERE
        pass

    def optimize_rule(self, rule: str, feedback: str = None) -> str:
        """
        Optimize/improve a YARA rule.

        TODO:
        1. Analyze current rule
        2. Apply LLM suggestions
        3. Return optimized rule
        """
        # YOUR CODE HERE
        pass


# =============================================================================
# Task 3: Rule Validation
# =============================================================================


def validate_yara_rule(rule_text: str) -> dict:
    """
    Validate YARA rule syntax.

    TODO:
    1. Attempt to compile rule
    2. Check for syntax errors
    3. Return validation result
    """
    # YOUR CODE HERE
    pass


def test_rule_on_samples(
    rule_text: str, positive_samples: List[str], negative_samples: List[str]
) -> dict:
    """
    Test rule against known samples.

    TODO:
    1. Compile rule
    2. Scan positive samples (should match)
    3. Scan negative samples (should not match)
    4. Calculate accuracy metrics
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Main
# =============================================================================


def main():
    """Main execution."""
    console.print("[bold]Lab 07: YARA Rule Generator[/bold]")

    if not YARA_AVAILABLE:
        console.print(
            "[yellow]yara-python not installed. Install: pip install yara-python[/yellow]"
        )

    # Create sample file for testing
    sample_path = Path(__file__).parent.parent / "samples" / "test_sample.bin"
    sample_path.parent.mkdir(exist_ok=True)

    # Create a simple test binary
    test_content = b"MZ" + b"\x00" * 58 + b"\x50\x45\x00\x00"  # PE header
    test_content += b"This is a test malware sample\x00"
    test_content += b"http://evil-domain.com/callback\x00"
    test_content += b"cmd.exe /c whoami\x00"
    sample_path.write_bytes(test_content)

    console.print(f"Created test sample: {sample_path}")

    # Analyze sample
    console.print("\n[yellow]Analyzing sample...[/yellow]")
    analyzer = SampleAnalyzer()

    strings = analyzer.extract_strings(str(sample_path))
    if strings:
        console.print(f"Extracted {len(strings)} strings")
    else:
        console.print("[red]No strings extracted. Complete the TODO![/red]")

    # Generate rule
    console.print("\n[yellow]Generating YARA rule...[/yellow]")
    # generator = YARAGenerator()
    # rule = generator.generate_rule(...)

    console.print("\nComplete the TODO sections to generate YARA rules!")


if __name__ == "__main__":
    main()

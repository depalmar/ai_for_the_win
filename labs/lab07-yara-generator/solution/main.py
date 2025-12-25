#!/usr/bin/env python3
"""
Lab 07: AI-Powered YARA Rule Generator - Solution

Complete implementation of LLM-powered YARA rule generation.
"""

import hashlib
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
from rich.syntax import Syntax

console = Console()


# Common strings to filter out
COMMON_STRINGS = {
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "advapi32.dll",
    "GetProcAddress",
    "LoadLibrary",
    "GetModuleHandle",
    "Microsoft",
    "Windows",
    "Copyright",
    "Error",
    "Warning",
    "C:\\Windows",
    "System32",
    ".dll",
    ".exe",
}


# =============================================================================
# Forward declarations and wrappers for test compatibility
# (These will be defined after SampleAnalyzer and YARAGenerator)
# =============================================================================

# Placeholder - will be set after class definitions
_sample_analyzer_instance = None
_yara_generator_instance = None


class MalwareSampleAnalyzer:
    """Wrapper for SampleAnalyzer to match test expectations."""

    def __init__(self):
        """Initialize using the SampleAnalyzer class."""
        self._analyzer = None

    def _get_analyzer(self):
        """Lazy load analyzer to avoid circular dependency."""
        if self._analyzer is None:
            # SampleAnalyzer is defined later in this file
            self._analyzer = globals()["SampleAnalyzer"]()
        return self._analyzer

    def analyze_sample(self, filepath: str) -> dict:
        """Analyze a malware sample."""
        analyzer = self._get_analyzer()
        return {
            "file_info": analyzer.get_file_info(filepath),
            "strings": self.extract_strings(filepath),
            "hex_patterns": analyzer.extract_hex_patterns(filepath),
        }

    def extract_strings(self, filepath: str, min_length: int = 6) -> List[dict]:
        """Extract strings in dict format expected by tests."""
        analyzer = self._get_analyzer()
        strings = analyzer.extract_strings(filepath, min_length)
        return [{"value": s, "type": "ascii"} for s in strings]


class YARAPatternExtractor:
    """Extract patterns for YARA rules."""

    def extract_patterns(self, analysis: dict) -> dict:
        """Extract patterns from analysis results."""
        return {
            "strings": analysis.get("strings", []),
            "hex_patterns": analysis.get("hex_patterns", []),
        }


class YARARuleBuilder:
    """Build YARA rules from patterns."""

    def build_rule(self, rule_name: str, patterns: dict, description: str = "") -> str:
        """Build a YARA rule from patterns."""
        strings_section = ""
        strings_list = patterns.get("strings", [])

        for i, pattern in enumerate(strings_list):
            value = pattern.get("value", "")
            name = pattern.get("name", f"s{i+1}")
            strings_section += f'\t\t${name} = "{value}" ascii\n'

        hex_patterns = patterns.get("hex_patterns", [])
        for i, hex_pattern in enumerate(hex_patterns):
            name = f"hex{i+1}"
            strings_section += f"\t\t${name} = {{ {hex_pattern} }}\n"

        rule = f"""rule {rule_name} {{
\tmeta:
\t\tdescription = "{description}"
\t\tauthor = "YARA Generator"

\tstrings:
{strings_section}
\tcondition:
\t\tany of them
}}
"""
        return rule


# =============================================================================
# Task 1: Sample Analysis - SOLUTION
# =============================================================================


class SampleAnalyzer:
    """Extract features from samples for YARA rule generation."""

    def extract_strings(self, filepath: str, min_length: int = 6) -> List[str]:
        """Extract strings from binary file."""
        with open(filepath, "rb") as f:
            content = f.read()

        strings = set()

        # Extract ASCII strings
        ascii_pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        for match in re.finditer(ascii_pattern, content):
            s = match.group().decode("ascii", errors="ignore")
            if self._is_interesting_string(s):
                strings.add(s)

        # Extract Unicode strings (UTF-16LE)
        unicode_pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
        for match in re.finditer(unicode_pattern, content):
            try:
                s = match.group().decode("utf-16-le", errors="ignore")
                if self._is_interesting_string(s):
                    strings.add(s)
            except:
                pass

        return sorted(list(strings))

    def _is_interesting_string(self, s: str) -> bool:
        """Check if string is interesting for YARA rules."""
        if len(s) < 6:
            return False
        if s in COMMON_STRINGS:
            return False
        # Filter out strings that are just common words
        if s.lower() in {"error", "warning", "success", "failed", "true", "false"}:
            return False
        return True

    def extract_hex_patterns(self, filepath: str, pattern_length: int = 16) -> List[str]:
        """Extract interesting hex patterns from binary."""
        with open(filepath, "rb") as f:
            content = f.read()

        patterns = []

        # Look for PE header patterns
        pe_offset = content.find(b"PE\x00\x00")
        if pe_offset > 0:
            # Extract some bytes around PE header
            pattern = content[pe_offset : pe_offset + 16]
            hex_str = " ".join(f"{b:02X}" for b in pattern)
            patterns.append(hex_str)

        # Look for MZ header
        if content[:2] == b"MZ":
            pattern = content[:8]
            hex_str = " ".join(f"{b:02X}" for b in pattern)
            patterns.append(hex_str)

        return patterns

    def get_file_info(self, filepath: str) -> dict:
        """Get basic file information."""
        with open(filepath, "rb") as f:
            content = f.read()

        info = {
            "file_size": len(content),
            "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "is_pe": content[:2] == b"MZ",
            "entropy": self._calculate_entropy(content),
        }

        return info

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        import math

        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# =============================================================================
# Task 2: LLM Rule Generator - SOLUTION
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
- Include PE header checks for executables (uint16(0) == 0x5A4D)
- Consider entropy checks for packed samples

OUTPUT FORMAT:
Return ONLY the YARA rule, no explanation or markdown. The rule must be valid YARA syntax."""


class YARAGenerator:
    """Generate YARA rules using LLM."""

    def __init__(self, llm=None):
        """Initialize with LLM client."""
        if llm:
            self.llm = llm
        elif LANGCHAIN_AVAILABLE and os.getenv("ANTHROPIC_API_KEY"):
            self.llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        else:
            self.llm = None

    def generate_rule(
        self,
        sample_info: dict,
        strings: List[str],
        malware_family: str = None,
        rule_name: str = None,
    ) -> str:
        """Generate YARA rule from sample features."""
        if not self.llm:
            return self._generate_template_rule(sample_info, strings, malware_family, rule_name)

        # Prepare context
        rule_name = rule_name or f"Malware_{sample_info.get('sha256', 'Unknown')[:8]}"
        family = malware_family or "Unknown"

        # Select best strings (limit to avoid token limits)
        selected_strings = strings[:20]

        prompt = f"""Generate a YARA rule for this malware sample:

Rule Name: {rule_name}
Malware Family: {family}
File Size: {sample_info.get('file_size', 0)} bytes
SHA256: {sample_info.get('sha256', 'Unknown')}
Is PE: {sample_info.get('is_pe', False)}
Entropy: {sample_info.get('entropy', 0):.2f}

Extracted Strings:
{json.dumps(selected_strings, indent=2)}

Generate a YARA rule that:
1. Uses 3-5 of the most distinctive strings
2. Includes appropriate metadata
3. Has a condition that checks for PE header if applicable
4. Limits file size appropriately

Return only the YARA rule, no explanation."""

        messages = [
            SystemMessage(content=YARA_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        response = self.llm.invoke(messages)
        rule = response.content.strip()

        # Clean up any markdown formatting
        rule = re.sub(r"^```\w*\n?", "", rule)
        rule = re.sub(r"\n?```$", "", rule)

        return rule

    def _generate_template_rule(
        self,
        sample_info: dict,
        strings: List[str],
        malware_family: str = None,
        rule_name: str = None,
    ) -> str:
        """Generate rule without LLM (template-based)."""
        rule_name = rule_name or f"Malware_{sample_info.get('sha256', 'Sample')[:8]}"
        family = malware_family or "Unknown"

        # Select strings
        selected = strings[:5] if strings else ["placeholder"]

        string_defs = []
        for i, s in enumerate(selected):
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')
            string_defs.append(f'        $s{i} = "{escaped}"')

        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects {family} malware"
        author = "AI Security Training"
        date = "2024-01-15"
        hash = "{sample_info.get('sha256', 'unknown')}"

    strings:
{chr(10).join(string_defs)}

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of ($s*)
}}"""
        return rule

    def optimize_rule(self, rule: str, feedback: str = None) -> str:
        """Optimize/improve a YARA rule."""
        if not self.llm:
            return rule

        prompt = f"""Optimize this YARA rule:

{rule}

{f'Feedback: {feedback}' if feedback else ''}

Improve:
1. String selection for lower false positives
2. Condition logic for better performance
3. Metadata completeness

Return only the optimized YARA rule."""

        messages = [
            SystemMessage(content=YARA_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        response = self.llm.invoke(messages)
        return response.content.strip()


# =============================================================================
# Task 3: Rule Validation - SOLUTION
# =============================================================================


def validate_yara_rule(rule_text: str) -> dict:
    """Validate YARA rule syntax."""
    if not YARA_AVAILABLE:
        return {"valid": None, "error": "yara-python not installed"}

    try:
        yara.compile(source=rule_text)
        return {"valid": True, "error": None}
    except yara.SyntaxError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def test_rule_on_samples(
    rule_text: str, positive_samples: List[str], negative_samples: List[str]
) -> dict:
    """Test rule against known samples."""
    if not YARA_AVAILABLE:
        return {"error": "yara-python not installed"}

    try:
        rule = yara.compile(source=rule_text)
    except Exception as e:
        return {"error": f"Compilation failed: {e}"}

    results = {
        "true_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "details": [],
    }

    # Test positive samples (should match)
    for sample_path in positive_samples:
        if Path(sample_path).exists():
            matches = rule.match(sample_path)
            if matches:
                results["true_positives"] += 1
            else:
                results["false_negatives"] += 1
            results["details"].append(
                {"file": sample_path, "expected": True, "matched": bool(matches)}
            )

    # Test negative samples (should not match)
    for sample_path in negative_samples:
        if Path(sample_path).exists():
            matches = rule.match(sample_path)
            if matches:
                results["false_positives"] += 1
            else:
                results["true_negatives"] += 1
            results["details"].append(
                {"file": sample_path, "expected": False, "matched": bool(matches)}
            )

    # Calculate metrics
    total_pos = results["true_positives"] + results["false_negatives"]
    total_neg = results["true_negatives"] + results["false_positives"]

    if total_pos > 0:
        results["detection_rate"] = results["true_positives"] / total_pos
    if total_neg > 0:
        results["false_positive_rate"] = results["false_positives"] / total_neg

    return results


# =============================================================================
# Main - SOLUTION
# =============================================================================


def main():
    """Main execution."""
    console.print("[bold]Lab 07: YARA Rule Generator - SOLUTION[/bold]")

    # Create sample file for testing
    sample_path = Path(__file__).parent.parent / "samples" / "test_sample.bin"
    sample_path.parent.mkdir(parents=True, exist_ok=True)

    # Create a test binary with malware-like characteristics
    test_content = b"MZ" + b"\x00" * 58 + b"\x50\x45\x00\x00"
    test_content += b"\x00" * 100
    test_content += b"This is a test malware sample\x00"
    test_content += b"http://evil-domain.com/callback\x00"
    test_content += b"cmd.exe /c whoami\x00"
    test_content += b"CreateRemoteThread\x00"
    test_content += b"VirtualAllocEx\x00"
    sample_path.write_bytes(test_content)

    console.print(f"\nCreated test sample: {sample_path}")

    # Analyze sample
    console.print("\n[yellow]Step 1: Analyzing sample...[/yellow]")
    analyzer = SampleAnalyzer()

    file_info = analyzer.get_file_info(str(sample_path))
    console.print(f"File size: {file_info['file_size']} bytes")
    console.print(f"SHA256: {file_info['sha256']}")
    console.print(f"Entropy: {file_info['entropy']:.2f}")

    strings = analyzer.extract_strings(str(sample_path))
    console.print(f"Extracted {len(strings)} strings:")
    for s in strings[:5]:
        console.print(f"  - {s}")

    # Generate rule
    console.print("\n[yellow]Step 2: Generating YARA rule...[/yellow]")
    generator = YARAGenerator()

    rule = generator.generate_rule(
        sample_info=file_info,
        strings=strings,
        malware_family="TestMalware",
        rule_name="Test_Malware_Sample",
    )

    console.print("\n[green]Generated YARA Rule:[/green]")
    syntax = Syntax(rule, "yara", theme="monokai", line_numbers=True)
    console.print(syntax)

    # Validate rule
    console.print("\n[yellow]Step 3: Validating rule...[/yellow]")
    validation = validate_yara_rule(rule)

    if validation["valid"]:
        console.print("[green]Rule is valid![/green]")
    elif validation["valid"] is None:
        console.print("[yellow]Cannot validate (yara-python not installed)[/yellow]")
    else:
        console.print(f"[red]Rule is invalid: {validation['error']}[/red]")

    # Test rule
    if YARA_AVAILABLE and validation["valid"]:
        console.print("\n[yellow]Step 4: Testing rule...[/yellow]")
        results = test_rule_on_samples(
            rule, positive_samples=[str(sample_path)], negative_samples=[]
        )
        console.print(f"True Positives: {results['true_positives']}")
        console.print(f"Detection Rate: {results.get('detection_rate', 'N/A')}")

    # Save rule
    output_dir = Path(__file__).parent.parent / "rules" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    rule_file = output_dir / "test_malware.yar"
    rule_file.write_text(rule)
    console.print(f"\n[green]Rule saved to: {rule_file}[/green]")


if __name__ == "__main__":
    main()

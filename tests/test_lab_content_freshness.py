"""
Test lab content freshness and completeness.

Ensures that foundational labs (02, 03) contain required concepts
and don't reference outdated models, tools, or techniques.
"""

import re
from pathlib import Path

import pytest

# Get the repository root
ROOT = Path(__file__).parent.parent


class TestLab02PromptEngineeringContent:
    """Test Lab 02 contains required prompt engineering concepts."""

    @pytest.fixture
    def lab02_content(self):
        """Load Lab 02 README content."""
        readme = ROOT / "labs" / "lab02-intro-prompt-engineering" / "README.md"
        return readme.read_text(encoding="utf-8")

    def test_has_chain_of_thought_section(self, lab02_content):
        """Lab 02 should cover Chain-of-Thought (CoT) prompting."""
        assert (
            "chain-of-thought" in lab02_content.lower()
            or "chain of thought" in lab02_content.lower()
        ), (
            "Lab 02 is missing Chain-of-Thought prompting content. "
            "CoT is a fundamental technique that should be covered."
        )

    def test_has_few_shot_learning(self, lab02_content):
        """Lab 02 should cover few-shot learning."""
        assert "few-shot" in lab02_content.lower() or "few shot" in lab02_content.lower(), (
            "Lab 02 is missing few-shot learning content. "
            "Few-shot examples are the most impactful prompting technique."
        )

    def test_has_prompt_injection_content(self, lab02_content):
        """Lab 02 should cover prompt injection as a security concern."""
        assert "prompt injection" in lab02_content.lower(), (
            "Lab 02 is missing prompt injection content. "
            "This is #1 on OWASP LLM Top 10 and critical for security curriculum."
        )

    def test_has_hallucination_content(self, lab02_content):
        """Lab 02 should cover LLM hallucinations."""
        assert "hallucin" in lab02_content.lower(), (
            "Lab 02 is missing hallucination content. "
            "Understanding LLM hallucinations is essential for security work."
        )

    def test_has_structured_output_content(self, lab02_content):
        """Lab 02 should cover structured output (JSON mode)."""
        assert "json" in lab02_content.lower() and (
            "structured" in lab02_content.lower() or "format" in lab02_content.lower()
        ), (
            "Lab 02 is missing structured output/JSON mode content. "
            "Structured outputs are critical for automation."
        )

    def test_no_legacy_lab_31_reference(self, lab02_content):
        """Lab 02 should not reference itself as 'Lab 31' (legacy numbering)."""
        # Check for "Lab 31" in contexts that suggest it's referring to this lab
        patterns = [
            r"YOU ARE HERE:?\s*Lab 31",
            r"build on Lab 31",
            r"from Lab 31",
        ]
        for pattern in patterns:
            match = re.search(pattern, lab02_content, re.IGNORECASE)
            assert match is None, (
                f"Lab 02 contains legacy 'Lab 31' reference: {match.group()}\n"
                "This should be updated to 'Lab 02'."
            )


class TestLab03VibeCodingContent:
    """Test Lab 03 contains required vibe coding concepts."""

    @pytest.fixture
    def lab03_content(self):
        """Load Lab 03 README content."""
        readme = ROOT / "labs" / "lab03-vibe-coding-with-ai" / "README.md"
        return readme.read_text(encoding="utf-8")

    def test_has_vibe_coding_origin(self, lab03_content):
        """Lab 03 should mention the origin of 'vibe coding' term."""
        assert "karpathy" in lab03_content.lower(), (
            "Lab 03 is missing Andrej Karpathy reference. "
            "He coined 'vibe coding' in Feb 2025 - important context for students."
        )

    def test_has_mcp_content(self, lab03_content):
        """Lab 03 should cover Model Context Protocol (MCP)."""
        assert (
            "mcp" in lab03_content.lower() or "model context protocol" in lab03_content.lower()
        ), (
            "Lab 03 is missing MCP (Model Context Protocol) content. "
            "MCP is now an industry standard adopted by OpenAI, Microsoft, Google."
        )

    def test_has_security_warnings(self, lab03_content):
        """Lab 03 should include security warnings about AI-generated code."""
        security_keywords = ["security", "vulnerab", "review", "understand"]
        found = sum(1 for kw in security_keywords if kw in lab03_content.lower())
        assert found >= 3, (
            "Lab 03 may be missing adequate security warnings. "
            "Nearly 50% of AI-generated code contains security flaws."
        )

    def test_has_tool_comparison(self, lab03_content):
        """Lab 03 should compare multiple AI coding tools."""
        tools = ["cursor", "copilot", "claude code"]
        found = sum(1 for tool in tools if tool in lab03_content.lower())
        assert found >= 2, (
            "Lab 03 should compare multiple AI coding tools. "
            f"Found {found}/3 expected tools (Cursor, Copilot, Claude Code)."
        )


class TestModelReferences:
    """Test that model references are current."""

    # Current model names that SHOULD appear in foundational labs
    CURRENT_MODELS_LAB02 = [
        "sonnet",  # Claude Sonnet
        "opus",  # Claude Opus
        "gpt-4o",  # GPT-4o or similar
    ]

    def test_lab02_has_current_model_references(self):
        """Lab 02 should reference current model versions."""
        readme = ROOT / "labs" / "lab02-intro-prompt-engineering" / "README.md"
        content = readme.read_text(encoding="utf-8").lower()

        found_models = [m for m in self.CURRENT_MODELS_LAB02 if m in content]
        assert len(found_models) >= 2, (
            f"Lab 02 should reference current model versions.\n"
            f"Found: {found_models}\n"
            f"Expected at least 2 of: {self.CURRENT_MODELS_LAB02}\n"
            "Model references may be outdated - update the model table."
        )

    def test_model_table_has_versions(self):
        """Lab 02 model table should include version numbers."""
        readme = ROOT / "labs" / "lab02-intro-prompt-engineering" / "README.md"
        content = readme.read_text(encoding="utf-8")

        # Check for model table with versioned models
        # The table should have specific versions like "Sonnet 4.5" or "GPT-4o"
        has_claude_version = bool(re.search(r"Claude\s+(?:Sonnet|Opus)\s+\d", content))
        has_gpt_version = bool(re.search(r"GPT-4o|o1|o3", content))
        has_gemini_version = bool(re.search(r"Gemini\s+\d", content))

        versions_found = sum([has_claude_version, has_gpt_version, has_gemini_version])
        assert versions_found >= 2, (
            f"Lab 02 model table should include specific model versions.\n"
            f"Found Claude version: {has_claude_version}\n"
            f"Found GPT version: {has_gpt_version}\n"
            f"Found Gemini version: {has_gemini_version}\n"
            "Update the model table with current versioned models."
        )


class TestProgressionPathContent:
    """Test that progression paths don't contain legacy references."""

    def test_no_labs_01_03_in_next_from_02(self):
        """Lab 02 progression shouldn't say 'NEXT: Labs 01-03' (confusing)."""
        readme = ROOT / "labs" / "lab02-intro-prompt-engineering" / "README.md"
        content = readme.read_text(encoding="utf-8")

        # This pattern was wrong - you can't go to Labs 01-03 FROM Lab 02
        pattern = r"NEXT:\s*Labs?\s*01-03"
        match = re.search(pattern, content, re.IGNORECASE)
        assert match is None, (
            "Lab 02 has confusing progression 'NEXT: Labs 01-03'\n"
            "You can't go to Lab 01 from Lab 02 - fix the progression path."
        )


class TestRequiredSections:
    """Test that required sections exist in foundational labs."""

    REQUIRED_SECTIONS_LAB02 = [
        ("learning objectives", "Learning Objectives"),
        ("prerequisite", "Prerequisites"),
        ("what are llm", "LLM explanation"),
        ("prompt", "Prompt examples"),
        ("exercise", "Hands-on exercises"),
    ]

    REQUIRED_SECTIONS_LAB03 = [
        ("learning objectives", "Learning Objectives"),
        ("prerequisite", "Prerequisites"),
        ("vibe coding", "Vibe coding definition"),
        ("exercise", "Hands-on exercises"),
        ("spark", "SPARK framework or similar"),
    ]

    def test_lab02_has_required_sections(self):
        """Lab 02 should have all required sections."""
        readme = ROOT / "labs" / "lab02-intro-prompt-engineering" / "README.md"
        content = readme.read_text(encoding="utf-8").lower()

        missing = []
        for pattern, section_name in self.REQUIRED_SECTIONS_LAB02:
            if pattern not in content:
                missing.append(section_name)

        assert not missing, "Lab 02 is missing required sections:\n" + "\n".join(
            f"  - {section}" for section in missing
        )

    def test_lab03_has_required_sections(self):
        """Lab 03 should have all required sections."""
        readme = ROOT / "labs" / "lab03-vibe-coding-with-ai" / "README.md"
        content = readme.read_text(encoding="utf-8").lower()

        missing = []
        for pattern, section_name in self.REQUIRED_SECTIONS_LAB03:
            if pattern not in content:
                missing.append(section_name)

        assert not missing, "Lab 03 is missing required sections:\n" + "\n".join(
            f"  - {section}" for section in missing
        )


class TestYearReferences:
    """Test that year references are not stale."""

    # Files that should have current year references
    CURRENT_YEAR_FILES = [
        "labs/lab02-intro-prompt-engineering/README.md",
        "labs/lab03-vibe-coding-with-ai/README.md",
    ]

    def test_no_2023_year_references_in_current_content(self):
        """Foundational labs shouldn't reference 2023 as 'current'."""
        for file_path in self.CURRENT_YEAR_FILES:
            full_path = ROOT / file_path
            if not full_path.exists():
                continue

            content = full_path.read_text(encoding="utf-8")

            # Look for patterns like "in 2023" or "2023 update" that suggest current context
            patterns = [
                r"(?:current|latest|new|recent).*2023",
                r"2023.*(?:current|latest|new|update)",
                r"as of 2023",
            ]

            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    pytest.fail(
                        f"{file_path} has potentially stale 2023 reference:\n"
                        f"  '{match.group()}'\n"
                        "Update to reference current year if this is meant to be current."
                    )

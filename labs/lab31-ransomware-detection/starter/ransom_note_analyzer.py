#!/usr/bin/env python3
"""
Lab 11: Ransom Note Analyzer
----------------------------
LLM-powered analysis of ransom notes for threat intelligence extraction.

This module uses Claude to analyze ransom notes and extract:
- IOCs (Bitcoin addresses, Tor URLs, email addresses)
- Ransomware family identification
- Threat actor attribution clues
- Sophistication assessment

Author: AI Security Training Labs
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None  # Will fail gracefully if not installed


@dataclass
class RansomNoteIntel:
    """Extracted intelligence from ransom note."""

    ransomware_family: str
    threat_actor: Optional[str]
    bitcoin_addresses: List[str] = field(default_factory=list)
    onion_urls: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    ransom_amount: Optional[str] = None
    deadline: Optional[str] = None
    language_indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    sophistication_level: str = "unknown"  # low, medium, high, advanced


class RansomNoteAnalyzer:
    """
    LLM-powered ransom note analysis.

    Capabilities:
    - Extract IOCs using regex and LLM
    - Identify ransomware family from language patterns
    - Assess threat actor sophistication
    - Map to known ransomware campaigns
    """

    # Regex patterns for IOC extraction
    BITCOIN_PATTERN = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
    ONION_PATTERN = r"\b[a-z2-7]{16,56}\.onion\b"
    EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

    # Known ransomware family signatures (simplified)
    FAMILY_SIGNATURES = {
        "lockbit": ["lockbit", "your files are encrypted", "publish your data"],
        "blackcat": ["alphv", "blackcat", "data leak site"],
        "conti": ["conti", "your network is locked"],
        "revil": ["revil", "sodinokibi", "happy blog"],
        "ryuk": ["ryuk", "balance of shadow universe"],
        "wannacry": ["wannacry", "wcry", "wanna decryptor"],
        "maze": ["maze", "cartel", "newsroom"],
        "dharma": ["dharma", "crysis", ".dharma"],
    }

    def __init__(self):
        """Initialize the analyzer with Anthropic client."""
        if Anthropic:
            self.client = Anthropic()
        else:
            self.client = None
            print("Warning: anthropic package not installed. LLM features disabled.")

    def analyze(self, note_content: str) -> RansomNoteIntel:
        """
        Analyze ransom note and extract intelligence.

        This is the main analysis function that combines regex-based IOC
        extraction with LLM-powered semantic analysis.

        Args:
            note_content: Full text of the ransom note

        Returns:
            RansomNoteIntel with extracted information

        # TODO: Ask your AI assistant:
        # "Write Python code to analyze a ransom note. First extract IOCs
        # using regex patterns for Bitcoin addresses, .onion URLs, and emails.
        # Then use Claude API to identify the ransomware family, assess
        # sophistication, and extract additional intelligence."
        #
        # Then review and test the generated code.
        """
        pass

    def extract_iocs(self, note_content: str) -> Dict[str, List[str]]:
        """
        Extract indicators of compromise from note using regex.

        This provides a fast, offline extraction of known IOC patterns.

        Args:
            note_content: Full text of the ransom note

        Returns:
            Dict with keys: bitcoin_addresses, onion_urls, email_addresses

        # TODO: Ask your AI assistant:
        # "Write Python code to extract IOCs from text using regex.
        # Find all Bitcoin addresses (starting with 1 or 3, 25-34 chars),
        # .onion URLs (base32 encoded), and email addresses.
        # Return deduplicated results in a dictionary."
        #
        # Then review and test the generated code.
        """
        pass

    def identify_family(self, note_content: str) -> str:
        """
        Identify ransomware family from note patterns.

        Uses keyword matching against known family signatures.

        Args:
            note_content: Full text of the ransom note

        Returns:
            Ransomware family name or "unknown"

        # TODO: Ask your AI assistant:
        # "Write Python code to identify ransomware family from note text.
        # Check the lowercase note content against FAMILY_SIGNATURES dict.
        # Return the family name with most keyword matches, or 'unknown'."
        #
        # Then review and test the generated code.
        """
        pass

    def assess_sophistication(self, note_content: str) -> str:
        """
        Assess threat actor sophistication level.

        Factors:
        - Grammar and spelling quality
        - Professional formatting
        - Multiple payment options
        - Data leak threats
        - Negotiation instructions

        Args:
            note_content: Full text of the ransom note

        Returns:
            Sophistication level: "low", "medium", "high", or "advanced"

        # TODO: Ask your AI assistant:
        # "Write Python code to assess ransomware sophistication from note text.
        # Score based on: (1) grammar quality, (2) professional tone,
        # (3) multiple contact methods, (4) deadline/escalation threats,
        # (5) data leak references. Map score to sophistication level."
        #
        # Then review and test the generated code.
        """
        pass

    def extract_with_llm(self, note_content: str) -> Dict:
        """
        Use Claude to extract additional intelligence.

        LLM analysis can capture:
        - Unusual language patterns suggesting nationality
        - References to specific industries or targets
        - Links to known threat actor communication styles
        - Implicit threats or deadlines

        Args:
            note_content: Full text of the ransom note

        Returns:
            Dict with LLM-extracted intelligence

        # TODO: Ask your AI assistant:
        # "Write Python code to use Claude API for ransom note analysis.
        # Create a prompt asking Claude to extract: (1) likely nationality
        # based on language patterns, (2) sophistication assessment,
        # (3) any time-based threats, (4) potential target industry.
        # Parse the structured response."
        #
        # Then review and test the generated code.
        """
        pass

    def map_to_mitre(self, family: str) -> List[str]:
        """
        Map ransomware family to MITRE ATT&CK techniques.

        Args:
            family: Ransomware family name

        Returns:
            List of MITRE technique IDs

        # TODO: Ask your AI assistant:
        # "Write Python code to map ransomware families to MITRE ATT&CK.
        # Create a mapping dict with families as keys and lists of
        # technique IDs as values. Include T1486 (encryption), T1490
        # (shadow deletion), T1083 (file discovery) as common techniques."
        #
        # Then review and test the generated code.
        """
        pass

    def generate_report(self, intel: RansomNoteIntel) -> str:
        """
        Generate a formatted intelligence report.

        Args:
            intel: Extracted intelligence data

        Returns:
            Formatted markdown report

        # TODO: Ask your AI assistant:
        # "Write Python code to generate a markdown report from RansomNoteIntel.
        # Include sections for: Executive Summary, IOCs, Attribution,
        # MITRE ATT&CK Mapping, and Recommendations."
        #
        # Then review and test the generated code.
        """
        pass


def main():
    """Demo the ransom note analyzer."""
    # Sample ransom note (fictional)
    sample_note = """
    !!! YOUR FILES HAVE BEEN ENCRYPTED !!!

    All your important files have been encrypted using military-grade encryption.
    The only way to recover your files is to pay the ransom and obtain the decryption key.

    To decrypt your files:
    1. Send 0.5 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    2. Email us at: decrypt@protonmail.com with your unique ID
    3. Or visit our support portal: lockbitxyzabc123456.onion

    You have 72 hours to pay. After that, the price doubles.
    After 7 days, your data will be published on our leak site.

    Your unique ID: LOCKBIT-20240115-ABC123

    DO NOT TRY TO DECRYPT FILES YOURSELF - THEY WILL BE DESTROYED.
    """

    analyzer = RansomNoteAnalyzer()

    # Extract IOCs with regex
    iocs = analyzer.extract_iocs(sample_note)
    print("Extracted IOCs:")
    for ioc_type, values in iocs.items():
        print(f"  {ioc_type}: {values}")

    # Identify family
    family = analyzer.identify_family(sample_note)
    print(f"\nIdentified family: {family}")

    # Full analysis (requires API key)
    intel = analyzer.analyze(sample_note)
    if intel:
        print(f"\nFull analysis: {intel}")


if __name__ == "__main__":
    main()

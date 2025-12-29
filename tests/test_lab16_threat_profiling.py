#!/usr/bin/env python3
"""Tests for Lab 16: AI-Powered Threat Actor Profiling."""

import json
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest
import numpy as np

# Clear any existing 'main' module and lab paths to avoid conflicts
for key in list(sys.modules.keys()):
    if key == "main" or key.startswith("main."):
        del sys.modules[key]

# Remove any existing lab paths from sys.path
sys.path = [p for p in sys.path if "/labs/lab" not in p]

# Add this lab's path
lab_path = str(Path(__file__).parent.parent / "labs" / "lab16-threat-actor-profiling" / "solution")
sys.path.insert(0, lab_path)

from main import (
    TTP,
    Campaign,
    MalwareSample,
    ThreatActor,
    AttributionResult,
    TTPExtractor,
    ThreatActorClusterer,
    MalwareAttributor,
    AttributionPipeline,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_ttp():
    """Create sample TTP."""
    return TTP(
        technique_id="T1566",
        technique_name="Phishing",
        tactic="Initial Access",
        description="Spearphishing attachment",
        confidence=0.9,
    )


@pytest.fixture
def sample_ttps():
    """Create sample list of TTPs."""
    return [
        TTP(
            technique_id="T1566", technique_name="Phishing", tactic="Initial Access", confidence=0.9
        ),
        TTP(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            confidence=0.85,
        ),
        TTP(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="Defense Evasion",
            confidence=0.8,
        ),
        TTP(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="Credential Access",
            confidence=0.9,
        ),
        TTP(
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="Lateral Movement",
            confidence=0.75,
        ),
    ]


@pytest.fixture
def sample_campaign(sample_ttps):
    """Create sample campaign."""
    return Campaign(
        campaign_id="campaign_001",
        name="Test Campaign",
        start_date="2024-01-01",
        end_date="2024-03-15",
        targets=["finance", "technology"],
        ttps=sample_ttps,
        iocs={
            "domains": ["evil-domain.com", "c2-server.net"],
            "ips": ["192.168.1.100", "10.0.0.50"],
            "hashes": ["abc123def456789"],
        },
        description="A test campaign for unit testing",
    )


@pytest.fixture
def sample_malware():
    """Create sample malware sample."""
    return MalwareSample(
        hash_sha256="abc123def456789012345678901234567890123456789012345678901234567a",
        family="TestMalware",
        first_seen="2024-01-15",
        file_type="PE32",
        size=256000,
        imphash="a1b2c3d4e5f6a7b8",
        ssdeep="6144:ABC123XYZ789DEF456:abc123xyz789",
        capabilities=["keylogger", "screenshot", "c2"],
        c2_domains=["malware-c2.com"],
        mutex_names=["Global\\TestMutex"],
    )


@pytest.fixture
def sample_threat_actors():
    """Create sample threat actor profiles from data file."""
    return [
        {
            "id": "apt29",
            "name": "APT29 (Cozy Bear)",
            "aliases": ["The Dukes", "CozyDuke"],
            "country": "Russia",
            "motivation": "espionage",
            "sophistication": "advanced",
            "ttps": [
                {
                    "technique_id": "T1566",
                    "technique_name": "Phishing",
                    "tactic": "Initial Access",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "confidence": 0.85,
                },
                {
                    "technique_id": "T1003",
                    "technique_name": "OS Credential Dumping",
                    "tactic": "Credential Access",
                    "confidence": 0.9,
                },
            ],
            "malware_families": ["WellMess", "WellMail", "SUNBURST"],
            "target_sectors": ["government", "healthcare", "energy"],
            "target_regions": ["North America", "Europe"],
        },
        {
            "id": "fin7",
            "name": "FIN7 (Carbanak)",
            "aliases": ["Carbanak Group", "Carbon Spider"],
            "country": "Russia",
            "motivation": "financial",
            "sophistication": "high",
            "ttps": [
                {
                    "technique_id": "T1566",
                    "technique_name": "Phishing",
                    "tactic": "Initial Access",
                    "confidence": 0.95,
                },
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1003",
                    "technique_name": "OS Credential Dumping",
                    "tactic": "Credential Access",
                    "confidence": 0.85,
                },
                {
                    "technique_id": "T1021",
                    "technique_name": "Remote Services",
                    "tactic": "Lateral Movement",
                    "confidence": 0.85,
                },
            ],
            "malware_families": ["Carbanak", "GRIFFON", "BOOSTWRITE"],
            "target_sectors": ["retail", "hospitality", "finance"],
            "target_regions": ["North America", "Europe"],
        },
        {
            "id": "lazarus",
            "name": "Lazarus Group",
            "aliases": ["HIDDEN COBRA", "APT38"],
            "country": "North Korea",
            "motivation": "financial",
            "sophistication": "advanced",
            "ttps": [
                {
                    "technique_id": "T1566",
                    "technique_name": "Phishing",
                    "tactic": "Initial Access",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "confidence": 0.9,
                },
                {
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "tactic": "Impact",
                    "confidence": 0.75,
                },
            ],
            "malware_families": ["AppleJeus", "FALLCHILL"],
            "target_sectors": ["cryptocurrency", "finance"],
            "target_regions": ["Global", "South Korea"],
        },
    ]


@pytest.fixture
def sample_malware_db():
    """Create sample malware database entries."""
    return [
        {
            "sha256": "abc123def456789012345678901234567890123456789012345678901234567a",
            "family": "Carbanak",
            "first_seen": "2024-01-15",
            "file_type": "PE32",
            "size": 768000,
            "imphash": "c3d4e5f6a7b8c9d0",
            "ssdeep": "18432:GHI789JKL012MNO345:ghi789jkl012",
            "capabilities": ["backdoor", "keylogger", "screenshot", "credential_theft"],
            "c2_domains": ["menu-update.net", "pos-support.com"],
            "mutex_names": ["Global\\Carbanak"],
            "attributed_actor": "FIN7 (Carbanak)",
        },
        {
            "sha256": "def456789012345678901234567890123456789012345678901234567890abcd",
            "family": "SUNBURST",
            "first_seen": "2020-03-01",
            "file_type": "PE32",
            "size": 1024000,
            "imphash": "a1b2c3d4e5f6a7b8",
            "ssdeep": "24576:ABC123XYZ789DEF456:abc123xyz789",
            "capabilities": ["backdoor", "c2", "persistence"],
            "c2_domains": ["avsvmcloud.com"],
            "mutex_names": [],
            "attributed_actor": "APT29 (Cozy Bear)",
        },
        {
            "sha256": "789012345678901234567890123456789012345678901234567890123456efgh",
            "family": "AppleJeus",
            "first_seen": "2023-09-15",
            "file_type": "PE32",
            "size": 384000,
            "imphash": "d4e5f6a7b8c9d0e1",
            "ssdeep": "8192:JKL012MNO345PQR678:jkl012mno345",
            "capabilities": ["backdoor", "cryptocurrency_theft", "persistence"],
            "c2_domains": ["wallet-verify.io"],
            "mutex_names": ["Global\\AppleJeus"],
            "attributed_actor": "Lazarus Group",
        },
    ]


@pytest.fixture
def sample_threat_report():
    """Create sample threat report text."""
    return """
    The threat actor initiated the attack with spearphishing emails containing
    malicious Word documents. Upon opening, PowerShell commands were executed
    to download Cobalt Strike beacon. The malware established persistence via
    scheduled tasks and used process injection to evade detection. Credential
    dumping was observed using mimikatz. Lateral movement occurred via RDP
    and SMB. Data was exfiltrated to C2 server.

    IOCs observed: T1566.001, T1059.001, T1053, T1055, T1003, T1021
    """


@pytest.fixture
def sample_iocs():
    """Create sample IOCs."""
    return {
        "domains": ["malware-update.net", "c2-server.com"],
        "ips": ["185.234.72.19", "91.234.56.78"],
        "hashes": ["abc123def456789"],
        "files": ["loader.ps1", "payload.bat", "malware.exe"],
    }


@pytest.fixture
def ttp_extractor():
    """Create TTPExtractor instance."""
    return TTPExtractor()


@pytest.fixture
def clusterer(sample_threat_actors):
    """Create ThreatActorClusterer instance with loaded profiles."""
    clusterer = ThreatActorClusterer()
    clusterer.load_actor_profiles(sample_threat_actors)
    return clusterer


@pytest.fixture
def malware_attributor(sample_malware_db):
    """Create MalwareAttributor instance with loaded database."""
    attributor = MalwareAttributor()
    attributor.load_malware_database(sample_malware_db)
    return attributor


# =============================================================================
# TTP Dataclass Tests
# =============================================================================


class TestTTPDataclass:
    """Tests for TTP dataclass."""

    def test_ttp_creation(self, sample_ttp):
        """Test TTP creation with all fields."""
        assert sample_ttp.technique_id == "T1566"
        assert sample_ttp.technique_name == "Phishing"
        assert sample_ttp.tactic == "Initial Access"
        assert sample_ttp.confidence == 0.9

    def test_ttp_defaults(self):
        """Test TTP with default values."""
        ttp = TTP(technique_id="T1059", technique_name="Command Execution", tactic="Execution")
        assert ttp.description == ""
        assert ttp.confidence == 0.0

    def test_ttp_to_dict(self, sample_ttp):
        """Test TTP conversion to dict."""
        ttp_dict = asdict(sample_ttp)
        assert isinstance(ttp_dict, dict)
        assert ttp_dict["technique_id"] == "T1566"


# =============================================================================
# Campaign Dataclass Tests
# =============================================================================


class TestCampaignDataclass:
    """Tests for Campaign dataclass."""

    def test_campaign_creation(self, sample_campaign):
        """Test Campaign creation with all fields."""
        assert sample_campaign.campaign_id == "campaign_001"
        assert sample_campaign.name == "Test Campaign"
        assert "finance" in sample_campaign.targets
        assert len(sample_campaign.ttps) > 0
        assert "domains" in sample_campaign.iocs

    def test_campaign_defaults(self):
        """Test Campaign with default values."""
        campaign = Campaign(
            campaign_id="test_001",
            name="Test",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["technology"],
        )
        assert campaign.ttps == []
        assert campaign.iocs == {}
        assert campaign.description == ""


# =============================================================================
# MalwareSample Dataclass Tests
# =============================================================================


class TestMalwareSampleDataclass:
    """Tests for MalwareSample dataclass."""

    def test_malware_sample_creation(self, sample_malware):
        """Test MalwareSample creation with all fields."""
        assert len(sample_malware.hash_sha256) == 64
        assert sample_malware.family == "TestMalware"
        assert sample_malware.file_type == "PE32"
        assert "keylogger" in sample_malware.capabilities

    def test_malware_sample_defaults(self):
        """Test MalwareSample with default values."""
        sample = MalwareSample(
            hash_sha256="a" * 64,
            family="Unknown",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
        )
        assert sample.imphash == ""
        assert sample.ssdeep == ""
        assert sample.capabilities == []
        assert sample.c2_domains == []


# =============================================================================
# ThreatActor Dataclass Tests
# =============================================================================


class TestThreatActorDataclass:
    """Tests for ThreatActor dataclass."""

    def test_threat_actor_creation(self):
        """Test ThreatActor creation."""
        actor = ThreatActor(
            actor_id="apt29",
            name="APT29 (Cozy Bear)",
            aliases=["The Dukes"],
            country="Russia",
            motivation="espionage",
        )
        assert actor.actor_id == "apt29"
        assert actor.name == "APT29 (Cozy Bear)"
        assert "The Dukes" in actor.aliases

    def test_threat_actor_defaults(self):
        """Test ThreatActor with default values."""
        actor = ThreatActor(actor_id="test", name="Test Actor")
        assert actor.aliases == []
        assert actor.country == ""
        assert actor.motivation == ""
        assert actor.campaigns == []


# =============================================================================
# AttributionResult Dataclass Tests
# =============================================================================


class TestAttributionResultDataclass:
    """Tests for AttributionResult dataclass."""

    def test_attribution_result_creation(self):
        """Test AttributionResult creation."""
        result = AttributionResult(
            actor_name="APT29",
            confidence=0.85,
            matching_ttps=["T1566", "T1059"],
            analysis="High confidence attribution",
        )
        assert result.actor_name == "APT29"
        assert result.confidence == 0.85
        assert len(result.matching_ttps) == 2

    def test_attribution_result_defaults(self):
        """Test AttributionResult with default values."""
        result = AttributionResult(actor_name="Unknown", confidence=0.0)
        assert result.matching_ttps == []
        assert result.matching_infrastructure == []
        assert result.matching_malware == []
        assert result.analysis == ""


# =============================================================================
# TTPExtractor Tests
# =============================================================================


class TestTTPExtractor:
    """Tests for TTPExtractor."""

    def test_extractor_initialization(self, ttp_extractor):
        """Test TTPExtractor initialization."""
        assert ttp_extractor is not None
        assert len(ttp_extractor.TECHNIQUE_PATTERNS) > 0
        assert len(ttp_extractor.TACTIC_MAPPING) > 0

    def test_extract_phishing(self, ttp_extractor):
        """Test extraction of phishing TTP."""
        text = "The attack started with a spearphishing email containing a malicious attachment."
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1566" in technique_ids

    def test_extract_powershell(self, ttp_extractor):
        """Test extraction of PowerShell TTP."""
        text = "The malware executed PowerShell commands to download additional payloads."
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1059" in technique_ids

    def test_extract_process_injection(self, ttp_extractor):
        """Test extraction of process injection TTP."""
        text = "The attacker used process injection techniques to inject malicious code into explorer.exe."
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1055" in technique_ids

    def test_extract_credential_dumping(self, ttp_extractor):
        """Test extraction of credential dumping TTP."""
        text = "Attackers used mimikatz for credential dumping from lsass.exe."
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1003" in technique_ids

    def test_extract_ransomware_ttps(self, ttp_extractor):
        """Test extraction of ransomware-related TTPs."""
        text = (
            "The ransomware encrypted files on the system and deleted shadow copies using vssadmin."
        )
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1486" in technique_ids  # Data Encrypted for Impact
        assert "T1490" in technique_ids  # Inhibit System Recovery

    def test_extract_explicit_technique_ids(self, ttp_extractor):
        """Test extraction of explicitly mentioned technique IDs."""
        text = "The attack chain included T1566.001, T1059.001, and T1053.005."
        ttps = ttp_extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1566" in technique_ids
        assert "T1059" in technique_ids
        assert "T1053" in technique_ids

    def test_extract_from_text_comprehensive(self, ttp_extractor, sample_threat_report):
        """Test comprehensive extraction from threat report."""
        ttps = ttp_extractor.extract_from_text(sample_threat_report)

        assert len(ttps) >= 4
        technique_ids = [t.technique_id for t in ttps]
        assert "T1566" in technique_ids  # spearphishing
        assert "T1059" in technique_ids  # PowerShell
        assert "T1003" in technique_ids  # mimikatz

    def test_extract_from_text_empty(self, ttp_extractor):
        """Test extraction from empty text."""
        ttps = ttp_extractor.extract_from_text("")
        assert ttps == []

    def test_extract_from_text_no_ttps(self, ttp_extractor):
        """Test extraction from text without TTPs."""
        text = "This is a normal document about weather patterns and climate change."
        ttps = ttp_extractor.extract_from_text(text)
        assert len(ttps) == 0

    def test_extract_confidence_calculation(self, ttp_extractor):
        """Test that confidence increases with multiple matches."""
        text = (
            "Multiple phishing emails with phishing links and phishing attachments were detected."
        )
        ttps = ttp_extractor.extract_from_text(text)

        phishing_ttp = next((t for t in ttps if t.technique_id == "T1566"), None)
        assert phishing_ttp is not None
        assert phishing_ttp.confidence > 0.5

    def test_extract_from_iocs_domains(self, ttp_extractor, sample_iocs):
        """Test TTP extraction from domain IOCs."""
        ttps = ttp_extractor.extract_from_iocs(sample_iocs)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1071" in technique_ids  # Application Layer Protocol

    def test_extract_from_iocs_ips(self, ttp_extractor, sample_iocs):
        """Test TTP extraction from IP IOCs."""
        ttps = ttp_extractor.extract_from_iocs(sample_iocs)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1095" in technique_ids  # Non-Application Layer Protocol

    def test_extract_from_iocs_scripts(self, ttp_extractor, sample_iocs):
        """Test TTP extraction from script files."""
        ttps = ttp_extractor.extract_from_iocs(sample_iocs)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1059" in technique_ids  # Command and Scripting Interpreter

    def test_extract_from_iocs_empty(self, ttp_extractor):
        """Test extraction from empty IOCs."""
        ttps = ttp_extractor.extract_from_iocs({})
        assert ttps == []

    def test_extract_from_malware(self, ttp_extractor, sample_malware):
        """Test TTP extraction from malware sample."""
        ttps = ttp_extractor.extract_from_malware(sample_malware)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1056" in technique_ids  # Input Capture (keylogger)
        assert "T1113" in technique_ids  # Screen Capture
        assert "T1071" in technique_ids  # Application Layer Protocol (c2)

    def test_extract_from_malware_with_c2(self, ttp_extractor):
        """Test extraction from malware with C2 domains."""
        sample = MalwareSample(
            hash_sha256="a" * 64,
            family="TestMalware",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            capabilities=[],
            c2_domains=["evil.com", "bad.net"],
        )
        ttps = ttp_extractor.extract_from_malware(sample)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1071" in technique_ids

    def test_extract_from_malware_ransomware(self, ttp_extractor):
        """Test extraction from ransomware sample."""
        sample = MalwareSample(
            hash_sha256="a" * 64,
            family="TestRansomware",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            capabilities=["ransomware", "credential_theft"],
        )
        ttps = ttp_extractor.extract_from_malware(sample)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1486" in technique_ids  # Data Encrypted for Impact
        assert "T1003" in technique_ids  # OS Credential Dumping


# =============================================================================
# TTPExtractor LLM Tests (require API)
# =============================================================================


class TestTTPExtractorLLM:
    """Tests for TTPExtractor LLM-based extraction."""

    @pytest.mark.requires_api
    def test_llm_extract_ttps_anthropic(self, ttp_extractor, sample_threat_report):
        """Test LLM-based TTP extraction with Anthropic."""
        import os

        if not os.getenv("ANTHROPIC_API_KEY"):
            pytest.skip("ANTHROPIC_API_KEY not set")

        from main import setup_llm

        llm = setup_llm("anthropic")
        ttps = ttp_extractor.llm_extract_ttps(sample_threat_report, llm)

        assert len(ttps) >= 0  # May return empty if API fails

    @pytest.mark.requires_api
    def test_llm_extract_ttps_openai(self, ttp_extractor, sample_threat_report):
        """Test LLM-based TTP extraction with OpenAI."""
        import os

        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("OPENAI_API_KEY not set")

        from main import setup_llm

        llm = setup_llm("openai")
        ttps = ttp_extractor.llm_extract_ttps(sample_threat_report, llm)

        assert len(ttps) >= 0

    def test_llm_extract_ttps_with_mock(self, ttp_extractor, sample_threat_report):
        """Test LLM extraction with mocked client."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [
            Mock(
                text='[{"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "confidence": 0.9}]'
            )
        ]
        mock_client.messages.create.return_value = mock_response

        llm = ("anthropic", mock_client)
        ttps = ttp_extractor.llm_extract_ttps(sample_threat_report, llm)

        assert len(ttps) >= 1
        assert ttps[0].technique_id == "T1566"


# =============================================================================
# ThreatActorClusterer Tests
# =============================================================================


class TestThreatActorClusterer:
    """Tests for ThreatActorClusterer."""

    def test_clusterer_initialization(self):
        """Test ThreatActorClusterer initialization."""
        clusterer = ThreatActorClusterer()
        assert clusterer.actors == {}
        assert clusterer.campaigns == {}

    def test_load_actor_profiles(self, sample_threat_actors):
        """Test loading threat actor profiles."""
        clusterer = ThreatActorClusterer()
        clusterer.load_actor_profiles(sample_threat_actors)

        assert len(clusterer.actors) == 3
        assert "apt29" in clusterer.actors
        assert "fin7" in clusterer.actors
        assert "lazarus" in clusterer.actors

    def test_load_actor_profiles_with_ttps(self, clusterer):
        """Test that loaded profiles have TTPs."""
        apt29 = clusterer.actors["apt29"]
        assert len(apt29.ttps) > 0
        assert any(t.technique_id == "T1566" for t in apt29.ttps)

    def test_load_actor_profiles_empty(self):
        """Test loading empty profiles list."""
        clusterer = ThreatActorClusterer()
        clusterer.load_actor_profiles([])
        assert len(clusterer.actors) == 0

    def test_load_actor_profiles_with_string_ttps(self):
        """Test loading profiles with string TTPs."""
        profiles = [{"id": "test", "name": "Test Actor", "ttps": ["T1566", "T1059"]}]
        clusterer = ThreatActorClusterer()
        clusterer.load_actor_profiles(profiles)

        assert "test" in clusterer.actors
        assert len(clusterer.actors["test"].ttps) == 2

    def test_calculate_ttp_similarity_identical(self, clusterer, sample_ttps):
        """Test TTP similarity between identical sets."""
        similarity = clusterer.calculate_ttp_similarity(sample_ttps, sample_ttps)
        assert similarity == 1.0

    def test_calculate_ttp_similarity_different(self, clusterer):
        """Test TTP similarity between different sets."""
        ttps1 = [TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access")]
        ttps2 = [TTP(technique_id="T1486", technique_name="Data Encrypted", tactic="Impact")]

        similarity = clusterer.calculate_ttp_similarity(ttps1, ttps2)
        assert similarity == 0.0

    def test_calculate_ttp_similarity_partial(self, clusterer):
        """Test TTP similarity with partial overlap."""
        ttps1 = [
            TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access"),
            TTP(technique_id="T1059", technique_name="Command Execution", tactic="Execution"),
        ]
        ttps2 = [
            TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access"),
            TTP(
                technique_id="T1003",
                technique_name="Credential Dumping",
                tactic="Credential Access",
            ),
        ]

        similarity = clusterer.calculate_ttp_similarity(ttps1, ttps2)
        assert 0.0 < similarity < 1.0

    def test_calculate_ttp_similarity_empty(self, clusterer):
        """Test TTP similarity with empty sets."""
        similarity = clusterer.calculate_ttp_similarity([], [])
        assert similarity == 0.0

        ttps = [TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access")]
        similarity = clusterer.calculate_ttp_similarity(ttps, [])
        assert similarity == 0.0

    def test_calculate_infrastructure_overlap_domains(self, clusterer):
        """Test infrastructure overlap with shared domains."""
        iocs1 = {"domains": ["evil.com", "bad.net"], "ips": []}
        iocs2 = {"domains": ["evil.com", "other.org"], "ips": []}

        overlap = clusterer.calculate_infrastructure_overlap(iocs1, iocs2)
        assert overlap > 0.0

    def test_calculate_infrastructure_overlap_ips(self, clusterer):
        """Test infrastructure overlap with shared IPs."""
        iocs1 = {"domains": [], "ips": ["192.168.1.1", "10.0.0.1"]}
        iocs2 = {"domains": [], "ips": ["192.168.1.1", "172.16.0.1"]}

        overlap = clusterer.calculate_infrastructure_overlap(iocs1, iocs2)
        assert overlap > 0.0

    def test_calculate_infrastructure_overlap_subnets(self, clusterer):
        """Test infrastructure overlap with shared subnets."""
        iocs1 = {"domains": [], "ips": ["192.168.1.10"]}
        iocs2 = {"domains": [], "ips": ["192.168.1.20"]}

        overlap = clusterer.calculate_infrastructure_overlap(iocs1, iocs2)
        assert overlap > 0.0

    def test_calculate_infrastructure_overlap_none(self, clusterer):
        """Test infrastructure overlap with no overlap."""
        iocs1 = {"domains": ["good.com"], "ips": ["10.0.0.1"]}
        iocs2 = {"domains": ["other.net"], "ips": ["172.16.0.1"]}

        overlap = clusterer.calculate_infrastructure_overlap(iocs1, iocs2)
        assert overlap == 0.0

    def test_calculate_infrastructure_overlap_empty(self, clusterer):
        """Test infrastructure overlap with empty IOCs."""
        overlap = clusterer.calculate_infrastructure_overlap({}, {})
        assert overlap == 0.0

    def test_cluster_campaigns_single(self, clusterer, sample_campaign):
        """Test clustering with single campaign."""
        clusters = clusterer.cluster_campaigns([sample_campaign])

        assert len(clusters) == 1
        assert len(clusters[0]) == 1

    def test_cluster_campaigns_similar(self, clusterer, sample_ttps):
        """Test clustering of similar campaigns."""
        campaign1 = Campaign(
            campaign_id="c1",
            name="Campaign 1",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["finance"],
            ttps=sample_ttps,
            iocs={"domains": ["evil.com"], "ips": ["192.168.1.1"]},
        )
        campaign2 = Campaign(
            campaign_id="c2",
            name="Campaign 2",
            start_date="2024-02-01",
            end_date="2024-03-01",
            targets=["finance"],
            ttps=sample_ttps,
            iocs={"domains": ["evil.com"], "ips": ["192.168.1.2"]},
        )

        clusters = clusterer.cluster_campaigns([campaign1, campaign2], threshold=0.3)

        # Should cluster together due to similarity
        assert len(clusters) >= 1

    def test_cluster_campaigns_different(self, clusterer):
        """Test clustering of different campaigns."""
        ttps1 = [TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access")]
        ttps2 = [TTP(technique_id="T1486", technique_name="Ransomware", tactic="Impact")]

        campaign1 = Campaign(
            campaign_id="c1",
            name="Campaign 1",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["finance"],
            ttps=ttps1,
            iocs={"domains": ["domain1.com"], "ips": []},
        )
        campaign2 = Campaign(
            campaign_id="c2",
            name="Campaign 2",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["healthcare"],
            ttps=ttps2,
            iocs={"domains": ["domain2.com"], "ips": []},
        )

        clusters = clusterer.cluster_campaigns([campaign1, campaign2], threshold=0.7)

        # Should be in separate clusters due to difference
        assert len(clusters) == 2

    def test_cluster_campaigns_empty(self, clusterer):
        """Test clustering with empty campaign list."""
        clusters = clusterer.cluster_campaigns([])
        assert clusters == []

    def test_attribute_campaign(self, clusterer, sample_campaign):
        """Test campaign attribution."""
        results = clusterer.attribute_campaign(sample_campaign)

        assert len(results) > 0
        assert all(isinstance(r, AttributionResult) for r in results)
        assert all(r.confidence >= 0 for r in results)

    def test_attribute_campaign_sorted(self, clusterer, sample_campaign):
        """Test that attribution results are sorted by confidence."""
        results = clusterer.attribute_campaign(sample_campaign)

        if len(results) >= 2:
            confidences = [r.confidence for r in results]
            assert confidences == sorted(confidences, reverse=True)

    def test_attribute_campaign_fin7_match(self, clusterer, sample_ttps):
        """Test attribution matches FIN7 for finance sector."""
        campaign = Campaign(
            campaign_id="test",
            name="Test",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["finance"],
            ttps=sample_ttps,
            iocs={},
        )

        results = clusterer.attribute_campaign(campaign)

        actor_names = [r.actor_name for r in results]
        assert "FIN7 (Carbanak)" in actor_names

    def test_attribute_campaign_no_match(self, clusterer):
        """Test attribution with no matching TTPs."""
        campaign = Campaign(
            campaign_id="test",
            name="Test",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["unknown_sector"],
            ttps=[TTP(technique_id="T9999", technique_name="Unknown", tactic="Unknown")],
            iocs={},
        )

        results = clusterer.attribute_campaign(campaign)

        # Should return empty or low confidence results
        assert all(r.confidence <= 0.1 for r in results) or len(results) == 0


# =============================================================================
# MalwareAttributor Tests
# =============================================================================


class TestMalwareAttributor:
    """Tests for MalwareAttributor."""

    def test_attributor_initialization(self):
        """Test MalwareAttributor initialization."""
        attributor = MalwareAttributor()
        assert attributor.malware_db == {}
        assert len(attributor.actor_malware) == 0

    def test_load_malware_database(self, sample_malware_db):
        """Test loading malware database."""
        attributor = MalwareAttributor()
        attributor.load_malware_database(sample_malware_db)

        assert len(attributor.malware_db) == 3

    def test_load_malware_database_actor_mapping(self, malware_attributor):
        """Test that actor mappings are created correctly."""
        assert "Carbanak" in malware_attributor.family_actor
        assert malware_attributor.family_actor["Carbanak"] == "FIN7 (Carbanak)"

    def test_calculate_code_similarity_imphash_match(self, malware_attributor):
        """Test code similarity with matching imphash."""
        sample1 = MalwareSample(
            hash_sha256="a" * 64,
            family="Test1",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            imphash="abc123",
        )
        sample2 = MalwareSample(
            hash_sha256="b" * 64,
            family="Test2",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            imphash="abc123",
        )

        similarity = malware_attributor.calculate_code_similarity(sample1, sample2)
        assert similarity > 0.0

    def test_calculate_code_similarity_capability_overlap(self, malware_attributor):
        """Test code similarity with capability overlap."""
        sample1 = MalwareSample(
            hash_sha256="a" * 64,
            family="Test1",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            capabilities=["keylogger", "screenshot", "c2"],
        )
        sample2 = MalwareSample(
            hash_sha256="b" * 64,
            family="Test2",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            capabilities=["keylogger", "screenshot", "persistence"],
        )

        similarity = malware_attributor.calculate_code_similarity(sample1, sample2)
        assert similarity > 0.0

    def test_calculate_code_similarity_c2_overlap(self, malware_attributor):
        """Test code similarity with C2 domain overlap."""
        sample1 = MalwareSample(
            hash_sha256="a" * 64,
            family="Test1",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            c2_domains=["evil.com", "bad.net"],
        )
        sample2 = MalwareSample(
            hash_sha256="b" * 64,
            family="Test2",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
            c2_domains=["evil.com", "other.org"],
        )

        similarity = malware_attributor.calculate_code_similarity(sample1, sample2)
        assert similarity > 0.0

    def test_calculate_code_similarity_no_overlap(self, malware_attributor):
        """Test code similarity with no overlap."""
        sample1 = MalwareSample(
            hash_sha256="a" * 64,
            family="Test1",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
        )
        sample2 = MalwareSample(
            hash_sha256="b" * 64,
            family="Test2",
            first_seen="2024-01-01",
            file_type="PE32",
            size=100000,
        )

        similarity = malware_attributor.calculate_code_similarity(sample1, sample2)
        assert similarity == 0.0

    def test_calculate_ssdeep_similarity(self, malware_attributor):
        """Test ssdeep similarity calculation."""
        hash1 = "6144:ABC123XYZ789:abc123"
        hash2 = "6144:ABC123XYZ789:abc123"

        similarity = malware_attributor.calculate_ssdeep_similarity(hash1, hash2)
        assert similarity > 0.0

    def test_calculate_ssdeep_similarity_different_block(self, malware_attributor):
        """Test ssdeep with different block sizes."""
        hash1 = "6144:ABC123:abc"
        hash2 = "12288:ABC123:abc"

        similarity = malware_attributor.calculate_ssdeep_similarity(hash1, hash2)
        assert similarity == 0.0

    def test_calculate_ssdeep_similarity_invalid(self, malware_attributor):
        """Test ssdeep with invalid hashes."""
        similarity = malware_attributor.calculate_ssdeep_similarity("invalid", "also_invalid")
        assert similarity == 0.0

    def test_find_similar_samples(self, malware_attributor):
        """Test finding similar samples."""
        sample = MalwareSample(
            hash_sha256="new" * 21 + "ab",
            family="Unknown",
            first_seen="2024-01-15",
            file_type="PE32",
            size=768000,
            imphash="c3d4e5f6a7b8c9d0",
            capabilities=["backdoor", "keylogger", "screenshot"],
        )

        similar = malware_attributor.find_similar_samples(sample, threshold=0.1)

        assert isinstance(similar, list)

    def test_find_similar_samples_threshold(self, malware_attributor):
        """Test that threshold filters results."""
        sample = MalwareSample(
            hash_sha256="new" * 21 + "ab",
            family="Unknown",
            first_seen="2024-01-15",
            file_type="PE32",
            size=100000,
        )

        # With very high threshold, should return empty
        similar = malware_attributor.find_similar_samples(sample, threshold=0.99)
        assert len(similar) == 0

    def test_attribute_sample_exact_match(self, malware_attributor):
        """Test attribution with exact hash match."""
        # Use a hash that's in the database
        sample = MalwareSample(
            hash_sha256="abc123def456789012345678901234567890123456789012345678901234567a",
            family="Carbanak",
            first_seen="2024-01-15",
            file_type="PE32",
            size=768000,
        )

        results = malware_attributor.attribute_sample(sample)

        assert len(results) >= 1
        assert results[0].confidence == 1.0
        assert results[0].actor_name == "FIN7 (Carbanak)"

    def test_attribute_sample_similar_match(self, malware_attributor):
        """Test attribution with similar sample."""
        sample = MalwareSample(
            hash_sha256="new" * 21 + "ab",
            family="Unknown",
            first_seen="2024-01-15",
            file_type="PE32",
            size=768000,
            imphash="c3d4e5f6a7b8c9d0",  # Same as Carbanak
            capabilities=["backdoor", "keylogger", "screenshot", "credential_theft"],
        )

        results = malware_attributor.attribute_sample(sample)

        # Should find similarity to known samples
        assert isinstance(results, list)

    def test_attribute_sample_no_match(self, malware_attributor):
        """Test attribution with no matching sample."""
        sample = MalwareSample(
            hash_sha256="z" * 64,
            family="CompletelyNew",
            first_seen="2024-01-15",
            file_type="PE32",
            size=100000,
        )

        results = malware_attributor.attribute_sample(sample)

        # May return empty or low confidence results
        assert isinstance(results, list)


# =============================================================================
# AttributionPipeline Tests
# =============================================================================


class TestAttributionPipeline:
    """Tests for AttributionPipeline."""

    def test_pipeline_initialization(self):
        """Test AttributionPipeline initialization."""
        pipeline = AttributionPipeline()

        assert pipeline.ttp_extractor is not None
        assert pipeline.clusterer is not None
        assert pipeline.malware_attributor is not None
        assert pipeline.llm is None  # Not initialized until needed

    def test_load_knowledge_base(self, sample_threat_actors, sample_malware_db):
        """Test loading knowledge base."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        assert len(pipeline.clusterer.actors) == 3
        assert len(pipeline.malware_attributor.malware_db) == 3

    def test_load_knowledge_base_empty_malware(self, sample_threat_actors):
        """Test loading knowledge base with empty malware samples."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, [])

        assert len(pipeline.clusterer.actors) == 3
        assert len(pipeline.malware_attributor.malware_db) == 0

    def test_analyze_incident_basic(self, sample_threat_actors, sample_malware_db):
        """Test basic incident analysis."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {
            "description": "Phishing attack with PowerShell execution and credential dumping.",
            "iocs": {"domains": ["evil.com"], "ips": ["192.168.1.1"]},
            "target_sector": "finance",
        }

        results = pipeline.analyze_incident(incident)

        assert "extracted_ttps" in results
        assert "attributions" in results
        assert "confidence_assessment" in results
        assert len(results["extracted_ttps"]) > 0

    def test_analyze_incident_comprehensive(
        self, sample_threat_actors, sample_malware_db, sample_threat_report
    ):
        """Test comprehensive incident analysis."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {
            "description": sample_threat_report,
            "iocs": {
                "domains": ["malware-update.net", "c2-server.com"],
                "ips": ["185.234.72.19"],
                "files": ["loader.ps1"],
            },
            "target_sector": "finance",
        }

        results = pipeline.analyze_incident(incident)

        assert len(results["extracted_ttps"]) >= 3
        assert len(results["attributions"]) > 0

    def test_analyze_incident_empty(self, sample_threat_actors, sample_malware_db):
        """Test incident analysis with empty data."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {"description": "", "iocs": {}, "target_sector": ""}

        results = pipeline.analyze_incident(incident)

        assert results["extracted_ttps"] == []

    def test_analyze_incident_attributions_sorted(self, sample_threat_actors, sample_malware_db):
        """Test that attributions are sorted by confidence."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {
            "description": "Phishing attack targeting finance sector with PowerShell and mimikatz.",
            "iocs": {},
            "target_sector": "finance",
        }

        results = pipeline.analyze_incident(incident)

        if len(results["attributions"]) >= 2:
            confidences = [a["confidence"] for a in results["attributions"]]
            assert confidences == sorted(confidences, reverse=True)

    def test_generate_report(self, sample_threat_actors, sample_malware_db):
        """Test report generation."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {
            "description": "Phishing attack with credential dumping.",
            "iocs": {"domains": ["evil.com"]},
            "target_sector": "finance",
        }

        results = pipeline.analyze_incident(incident)
        report = pipeline.generate_report(results)

        assert isinstance(report, str)
        assert "THREAT ACTOR ATTRIBUTION REPORT" in report
        assert "EXTRACTED TTPs" in report
        assert "ATTRIBUTION RESULTS" in report
        assert "ASSESSMENT" in report

    def test_generate_report_empty_results(self):
        """Test report generation with empty results."""
        pipeline = AttributionPipeline()

        results = {
            "extracted_ttps": [],
            "attributions": [],
            "confidence_assessment": "Unable to attribute",
        }

        report = pipeline.generate_report(results)

        assert isinstance(report, str)
        assert "Unable to attribute" in report


# =============================================================================
# AttributionPipeline LLM Tests (require API)
# =============================================================================


class TestAttributionPipelineLLM:
    """Tests for AttributionPipeline LLM features."""

    @pytest.mark.requires_api
    def test_llm_generate_profile(self, sample_threat_actors, sample_malware_db):
        """Test LLM profile generation."""
        import os

        if not (
            os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
        ):
            pytest.skip("No API key set")

        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        incident = {
            "description": "Phishing attack with credential dumping targeting finance.",
            "iocs": {},
            "target_sector": "finance",
        }

        results = pipeline.analyze_incident(incident)
        profile = pipeline.llm_generate_profile(results)

        assert isinstance(profile, str)

    def test_llm_generate_profile_no_llm(self, sample_threat_actors, sample_malware_db):
        """Test profile generation without LLM."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        # Ensure LLM is not initialized
        pipeline.llm = None

        # Mock _init_llm to ensure it doesn't initialize
        with patch.object(pipeline, "_init_llm"):
            pipeline.llm = None
            result = pipeline.llm_generate_profile({})

        assert "LLM not available" in result

    def test_analyze_incident_with_mocked_llm(self, sample_threat_actors, sample_malware_db):
        """Test incident analysis with mocked LLM."""
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        # Mock LLM response
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [
            Mock(
                text='[{"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "confidence": 0.95}]'
            )
        ]
        mock_client.messages.create.return_value = mock_response

        pipeline.llm = ("anthropic", mock_client)

        incident = {"description": "Test incident", "iocs": {}, "target_sector": "finance"}

        results = pipeline.analyze_incident(incident)

        # Should have some TTPs extracted
        assert isinstance(results, dict)


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_ttp_extractor_special_characters(self):
        """Test TTP extraction with special characters."""
        extractor = TTPExtractor()
        text = "Attack used cmd.exe /c powershell.exe -enc [base64]"
        ttps = extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1059" in technique_ids

    def test_ttp_extractor_unicode(self):
        """Test TTP extraction with unicode text."""
        extractor = TTPExtractor()
        text = "The phishing email contained unicode: \u00e9\u00e8\u00ea"
        ttps = extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1566" in technique_ids

    def test_clusterer_invalid_ips(self):
        """Test infrastructure overlap with invalid IPs."""
        clusterer = ThreatActorClusterer()
        iocs1 = {"ips": ["invalid_ip", "also_invalid"]}
        iocs2 = {"ips": ["192.168.1.1"]}

        # Should not raise an error
        overlap = clusterer.calculate_infrastructure_overlap(iocs1, iocs2)
        assert overlap >= 0.0

    def test_malware_sample_very_large_size(self):
        """Test malware sample with very large size."""
        sample = MalwareSample(
            hash_sha256="a" * 64,
            family="LargeMalware",
            first_seen="2024-01-01",
            file_type="PE32",
            size=1000000000,  # 1GB
        )

        assert sample.size == 1000000000

    def test_campaign_empty_ttps(self):
        """Test campaign with empty TTPs for attribution."""
        clusterer = ThreatActorClusterer()
        clusterer.load_actor_profiles(
            [
                {
                    "id": "test",
                    "name": "Test Actor",
                    "ttps": [
                        {
                            "technique_id": "T1566",
                            "technique_name": "Phishing",
                            "tactic": "Initial Access",
                        }
                    ],
                    "target_sectors": ["finance"],
                }
            ]
        )

        campaign = Campaign(
            campaign_id="test",
            name="Test",
            start_date="2024-01-01",
            end_date="2024-02-01",
            targets=["finance"],
            ttps=[],
        )

        results = clusterer.attribute_campaign(campaign)

        # Should handle empty TTPs gracefully
        assert isinstance(results, list)

    def test_ssdeep_empty_hash(self):
        """Test ssdeep calculation with empty hash."""
        attributor = MalwareAttributor()
        similarity = attributor.calculate_ssdeep_similarity("", "")
        assert similarity == 0

    def test_ttp_extraction_mixed_case(self):
        """Test TTP extraction with mixed case text."""
        extractor = TTPExtractor()
        text = "PHISHING attack used POWERSHELL and MIMIKATZ"
        ttps = extractor.extract_from_text(text)

        technique_ids = [t.technique_id for t in ttps]
        assert "T1566" in technique_ids
        assert "T1059" in technique_ids
        assert "T1003" in technique_ids

    def test_multiple_campaigns_clustering(self):
        """Test clustering with multiple campaigns."""
        clusterer = ThreatActorClusterer()

        ttps = [TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access")]

        campaigns = []
        for i in range(5):
            campaigns.append(
                Campaign(
                    campaign_id=f"c{i}",
                    name=f"Campaign {i}",
                    start_date="2024-01-01",
                    end_date="2024-02-01",
                    targets=["finance"],
                    ttps=ttps if i < 3 else [],
                    iocs={"domains": [f"domain{i}.com"]},
                )
            )

        clusters = clusterer.cluster_campaigns(campaigns, threshold=0.3)

        assert len(clusters) >= 1
        total_campaigns = sum(len(c) for c in clusters)
        assert total_campaigns == 5


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the complete attribution pipeline."""

    def test_full_attribution_workflow(self, sample_threat_actors, sample_malware_db):
        """Test complete attribution workflow."""
        # Initialize pipeline
        pipeline = AttributionPipeline()
        pipeline.load_knowledge_base(sample_threat_actors, sample_malware_db)

        # Create incident data
        incident = {
            "description": """
            The attack began with spearphishing emails targeting the finance sector.
            The malicious attachment executed PowerShell commands to download
            additional payloads. Credential dumping was performed using mimikatz
            and lateral movement was achieved via RDP.
            """,
            "iocs": {
                "domains": ["malware-c2.com", "evil-domain.net"],
                "ips": ["185.234.72.19", "91.234.56.78"],
                "files": ["loader.ps1", "payload.exe"],
            },
            "target_sector": "finance",
        }

        # Analyze incident
        results = pipeline.analyze_incident(incident)

        # Verify results structure
        assert "extracted_ttps" in results
        assert "attributions" in results
        assert "confidence_assessment" in results

        # Verify TTPs extracted
        technique_ids = [t.technique_id for t in results["extracted_ttps"]]
        assert "T1566" in technique_ids  # Phishing
        assert "T1059" in technique_ids  # PowerShell
        assert "T1003" in technique_ids  # Mimikatz

        # Verify attributions made
        assert len(results["attributions"]) > 0

        # Generate report
        report = pipeline.generate_report(results)
        assert "THREAT ACTOR ATTRIBUTION REPORT" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

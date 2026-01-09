"""
Lab 16: AI-Powered Threat Actor Profiling - Starter Code

Build a threat actor profiling system that extracts TTPs, clusters campaigns,
and performs malware attribution using ML and LLMs.

Complete the TODOs to build a threat actor profiling pipeline.
"""

import json
import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import numpy as np


# LLM setup - supports multiple providers
def setup_llm(provider: str = "auto"):
    """Initialize LLM client based on available API keys."""
    if provider == "auto":
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("GOOGLE_API_KEY"):
            provider = "google"
        else:
            raise ValueError(
                "No API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY"
            )

    if provider == "anthropic":
        from anthropic import Anthropic

        return ("anthropic", Anthropic())
    elif provider == "openai":
        from openai import OpenAI

        return ("openai", OpenAI())
    elif provider == "google":
        import google.generativeai as genai

        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        return ("google", genai.GenerativeModel("gemini-2.5-pro"))
    else:
        raise ValueError(f"Unknown provider: {provider}")


@dataclass
class TTP:
    """MITRE ATT&CK TTP."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    confidence: float = 0.0


@dataclass
class Campaign:
    """Threat actor campaign."""

    campaign_id: str
    name: str
    start_date: str
    end_date: str
    targets: List[str]
    ttps: List[TTP]
    iocs: Dict[str, List[str]]
    description: str = ""


@dataclass
class MalwareSample:
    """Malware sample for attribution."""

    hash_sha256: str
    family: str
    first_seen: str
    file_type: str
    size: int
    imphash: str = ""
    ssdeep: str = ""
    capabilities: List[str] = field(default_factory=list)
    c2_domains: List[str] = field(default_factory=list)
    mutex_names: List[str] = field(default_factory=list)


@dataclass
class ThreatActor:
    """Threat actor profile."""

    actor_id: str
    name: str
    aliases: List[str]
    country: str
    motivation: str  # financial, espionage, hacktivism, destruction
    sophistication: str  # low, medium, high, advanced
    campaigns: List[str]
    ttps: List[TTP]
    malware_families: List[str]
    target_sectors: List[str]
    target_regions: List[str]


@dataclass
class AttributionResult:
    """Result of threat actor attribution."""

    actor_name: str
    confidence: float
    matching_ttps: List[str]
    matching_infrastructure: List[str]
    matching_malware: List[str]
    analysis: str


class TTPExtractor:
    """Extract TTPs from threat reports and indicators."""

    # MITRE ATT&CK technique patterns
    TECHNIQUE_PATTERNS = {
        "T1566": r"phishing|spearphishing|malicious attachment",
        "T1059": r"command.?line|powershell|cmd\.exe|bash|script",
        "T1055": r"process injection|dll injection|hollow",
        "T1053": r"scheduled task|cron|at job",
        "T1078": r"valid account|credential|stolen password",
        "T1021": r"remote service|rdp|ssh|winrm|smb",
        "T1071": r"application layer protocol|http|https|dns",
        "T1105": r"ingress tool transfer|download|stage",
        "T1027": r"obfuscate|encode|pack|encrypt",
        "T1082": r"system information discovery|systeminfo|hostname",
        "T1083": r"file.{0,10}directory discovery|dir|ls",
        "T1057": r"process discovery|tasklist|ps aux",
        "T1003": r"credential dump|mimikatz|lsass|sam",
        "T1486": r"data encrypted|ransomware|encrypt files",
        "T1490": r"inhibit system recovery|delete shadow|vssadmin",
    }

    TACTIC_MAPPING = {
        "T1566": "Initial Access",
        "T1059": "Execution",
        "T1055": "Defense Evasion",
        "T1053": "Persistence",
        "T1078": "Initial Access",
        "T1021": "Lateral Movement",
        "T1071": "Command and Control",
        "T1105": "Command and Control",
        "T1027": "Defense Evasion",
        "T1082": "Discovery",
        "T1083": "Discovery",
        "T1057": "Discovery",
        "T1003": "Credential Access",
        "T1486": "Impact",
        "T1490": "Impact",
    }

    def extract_from_text(self, text: str) -> List[TTP]:
        """
        Extract TTPs from threat report text.

        TODO: Implement TTP extraction
        - Search for technique patterns in text
        - Extract technique IDs mentioned directly
        - Calculate confidence based on context

        Args:
            text: Threat report or description text

        Returns:
            List of extracted TTPs
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to extract TTPs from threat report text by:
        # 1. Searching for technique patterns using TECHNIQUE_PATTERNS regex dict
        # 2. Extracting technique IDs mentioned directly (e.g., T1566, T1059)
        # 3. Looking up tactics from TACTIC_MAPPING
        # 4. Calculating confidence based on match context
        # 5. Returning a list of TTP dataclass objects"
        #
        # Then review and test the generated code.
        pass

    def extract_from_iocs(self, iocs: dict) -> List[TTP]:
        """
        Infer TTPs from IOCs.

        TODO: Implement IOC-based TTP inference
        - File extensions suggest certain techniques
        - Domain patterns suggest C2 methods
        - Hash types indicate malware capabilities

        Args:
            iocs: Dictionary of IOC types and values

        Returns:
            List of inferred TTPs
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to infer TTPs from IOCs (Indicators of Compromise) by:
        # 1. Analyzing file extensions to suggest techniques (e.g., .ps1 -> T1059 PowerShell)
        # 2. Checking domain patterns for C2 methods (e.g., DGA patterns -> T1071)
        # 3. Examining hash types to indicate malware capabilities
        # 4. Creating TTP objects with appropriate technique IDs, names, and tactics
        # 5. Returning a list of inferred TTPs"
        #
        # Then review and test the generated code.
        pass

    def extract_from_malware(self, sample: MalwareSample) -> List[TTP]:
        """
        Extract TTPs from malware capabilities.

        TODO: Implement malware TTP extraction
        - Map capabilities to techniques
        - Infer tactics from behaviors

        Args:
            sample: Malware sample with capabilities

        Returns:
            List of TTPs used by malware
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to extract TTPs from a MalwareSample's capabilities by:
        # 1. Mapping capability strings (e.g., 'keylogger', 'screenshot', 'file_exfil')
        #    to MITRE ATT&CK technique IDs
        # 2. Inferring tactics from the malware's behaviors (e.g., keylogger -> Credential Access)
        # 3. Using the sample's c2_domains and mutex_names for additional TTP inference
        # 4. Creating TTP objects with technique ID, name, tactic, and confidence
        # 5. Returning a list of TTPs representing the malware's capabilities"
        #
        # Then review and test the generated code.
        pass

    def llm_extract_ttps(self, text: str, llm_client) -> List[TTP]:
        """
        Use LLM to extract TTPs from text.

        TODO: Implement LLM-based extraction
        - Build prompt with text
        - Request structured TTP output
        - Parse and validate results

        Args:
            text: Text to analyze
            llm_client: LLM client instance

        Returns:
            List of extracted TTPs
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to use an LLM to extract TTPs from text by:
        # 1. Building a prompt that asks the LLM to identify MITRE ATT&CK techniques
        # 2. Sending the text to the LLM client (handle Anthropic, OpenAI, or Google)
        # 3. Requesting structured JSON output with technique IDs, names, and tactics
        # 4. Parsing the LLM response and validating technique IDs
        # 5. Creating and returning a list of TTP dataclass objects"
        #
        # Then review and test the generated code.
        pass


class ThreatActorClusterer:
    """Cluster campaigns and attribute to threat actors."""

    def __init__(self):
        self.actors = {}
        self.campaigns = {}

    def load_actor_profiles(self, profiles: List[dict]):
        """
        Load known threat actor profiles.

        TODO: Implement profile loading
        - Parse actor profiles
        - Build lookup indices

        Args:
            profiles: List of threat actor profile dicts
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to load threat actor profiles into the clusterer by:
        # 1. Parsing the list of actor profile dictionaries
        # 2. Creating ThreatActor dataclass objects from the profile data
        # 3. Storing actors in self.actors dict indexed by actor_id
        # 4. Building lookup indices for quick access by alias, malware family, etc.
        # 5. Handling missing or malformed profile data gracefully"
        #
        # Then review and test the generated code.
        pass

    def calculate_ttp_similarity(self, ttps1: List[TTP], ttps2: List[TTP]) -> float:
        """
        Calculate similarity between two TTP sets.

        TODO: Implement TTP similarity
        - Use Jaccard similarity for technique IDs
        - Weight by tactic overlap
        - Consider technique hierarchy

        Args:
            ttps1: First TTP set
            ttps2: Second TTP set

        Returns:
            Similarity score between 0 and 1
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate similarity between two TTP sets by:
        # 1. Extracting technique IDs from both TTP lists
        # 2. Computing Jaccard similarity (intersection / union) of technique ID sets
        # 3. Weighting the score by tactic overlap (same tactics = higher similarity)
        # 4. Considering technique hierarchy (sub-techniques under same parent)
        # 5. Returning a similarity score between 0.0 and 1.0"
        #
        # Then review and test the generated code.
        pass

    def calculate_infrastructure_overlap(self, iocs1: dict, iocs2: dict) -> float:
        """
        Calculate infrastructure overlap between campaigns.

        TODO: Implement infrastructure comparison
        - Compare domains, IPs, URLs
        - Check for subnet similarity
        - Consider historical infrastructure reuse

        Args:
            iocs1: First campaign IOCs
            iocs2: Second campaign IOCs

        Returns:
            Overlap score between 0 and 1
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate infrastructure overlap between campaigns by:
        # 1. Comparing domain IOCs for exact matches and similar patterns
        # 2. Comparing IP addresses and checking for subnet similarity (e.g., same /24)
        # 3. Comparing URLs for shared paths or parameters
        # 4. Considering historical infrastructure reuse patterns
        # 5. Returning an overlap score between 0.0 and 1.0"
        #
        # Then review and test the generated code.
        pass

    def cluster_campaigns(
        self, campaigns: List[Campaign], threshold: float = 0.6
    ) -> List[List[Campaign]]:
        """
        Cluster campaigns by similarity.

        TODO: Implement campaign clustering
        - Calculate pairwise similarities
        - Use hierarchical or density-based clustering
        - Group related campaigns

        Args:
            campaigns: List of campaigns to cluster
            threshold: Similarity threshold for clustering

        Returns:
            List of campaign clusters
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to cluster campaigns by similarity using:
        # 1. Calculating pairwise similarity combining TTP and infrastructure overlap
        # 2. Building a similarity matrix for all campaign pairs
        # 3. Applying hierarchical or density-based clustering (e.g., DBSCAN, agglomerative)
        # 4. Grouping campaigns that exceed the threshold similarity
        # 5. Returning a list of campaign clusters (each cluster is a list of Campaign objects)"
        #
        # Then review and test the generated code.
        pass

    def attribute_campaign(self, campaign: Campaign) -> List[AttributionResult]:
        """
        Attribute a campaign to known threat actors.

        TODO: Implement attribution
        - Compare TTPs to known actor profiles
        - Compare infrastructure to known actor IOCs
        - Compare targeting to known actor focus
        - Calculate confidence scores

        Args:
            campaign: Campaign to attribute

        Returns:
            List of attribution results sorted by confidence
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to attribute a campaign to known threat actors by:
        # 1. Comparing campaign TTPs against known actor TTP profiles using calculate_ttp_similarity
        # 2. Comparing campaign IOCs against known actor infrastructure
        # 3. Matching target sectors and regions to actor targeting preferences
        # 4. Calculating a weighted confidence score from all comparisons
        # 5. Returning a sorted list of AttributionResult objects (highest confidence first)"
        #
        # Then review and test the generated code.
        pass


class MalwareAttributor:
    """Attribute malware samples to threat actors."""

    def __init__(self):
        self.malware_db = {}
        self.actor_malware = defaultdict(list)

    def load_malware_database(self, samples: List[dict]):
        """
        Load known malware samples.

        TODO: Implement database loading
        - Index by various attributes
        - Build family relationships

        Args:
            samples: List of malware sample dicts
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to load known malware samples into the database by:
        # 1. Parsing the list of malware sample dictionaries
        # 2. Creating MalwareSample dataclass objects from the data
        # 3. Indexing samples in self.malware_db by hash_sha256
        # 4. Building additional indices by imphash, family, and capabilities
        # 5. Populating self.actor_malware to map actors to their associated malware"
        #
        # Then review and test the generated code.
        pass

    def calculate_code_similarity(self, sample1: MalwareSample, sample2: MalwareSample) -> float:
        """
        Calculate code similarity between samples.

        TODO: Implement code similarity
        - Use imphash comparison
        - Use ssdeep fuzzy hashing
        - Consider capability overlap

        Args:
            sample1: First malware sample
            sample2: Second malware sample

        Returns:
            Similarity score between 0 and 1
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate code similarity between two malware samples by:
        # 1. Comparing imphash values (exact match = high similarity)
        # 2. Using ssdeep fuzzy hashing via calculate_ssdeep_similarity method
        # 3. Computing Jaccard similarity of capability lists
        # 4. Weighting and combining these similarity components
        # 5. Returning a combined similarity score between 0.0 and 1.0"
        #
        # Then review and test the generated code.
        pass

    def calculate_ssdeep_similarity(self, hash1: str, hash2: str) -> float:
        """
        Calculate ssdeep fuzzy hash similarity.

        TODO: Implement ssdeep comparison
        - Parse ssdeep hash format
        - Calculate chunk similarity

        Args:
            hash1: First ssdeep hash
            hash2: Second ssdeep hash

        Returns:
            Similarity score between 0 and 100
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to calculate ssdeep fuzzy hash similarity by:
        # 1. Parsing the ssdeep hash format (blocksize:chunk1:chunk2)
        # 2. Comparing block sizes (must be equal or double/half for comparison)
        # 3. Finding common substrings in the chunk portions
        # 4. Calculating similarity based on longest common substring length
        # 5. Returning a similarity score between 0 and 100"
        #
        # Then review and test the generated code.
        pass

    def find_similar_samples(
        self, sample: MalwareSample, threshold: float = 0.5
    ) -> List[Tuple[MalwareSample, float]]:
        """
        Find similar samples in the database.

        TODO: Implement similar sample search
        - Compare against all known samples
        - Filter by threshold
        - Return with similarity scores

        Args:
            sample: Sample to find matches for
            threshold: Minimum similarity threshold

        Returns:
            List of (sample, similarity) tuples
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to find similar malware samples in the database by:
        # 1. Iterating through all samples in self.malware_db
        # 2. Calculating code similarity using calculate_code_similarity method
        # 3. Filtering results to only include samples above the threshold
        # 4. Sorting by similarity score in descending order
        # 5. Returning a list of (MalwareSample, similarity_score) tuples"
        #
        # Then review and test the generated code.
        pass

    def attribute_sample(self, sample: MalwareSample) -> List[AttributionResult]:
        """
        Attribute a malware sample to threat actors.

        TODO: Implement sample attribution
        - Find similar known samples
        - Map to associated threat actors
        - Calculate confidence

        Args:
            sample: Sample to attribute

        Returns:
            List of attribution results
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to attribute a malware sample to threat actors by:
        # 1. Finding similar samples using find_similar_samples method
        # 2. Looking up threat actors associated with matching samples via self.actor_malware
        # 3. Aggregating evidence (matching malware families, capabilities, infrastructure)
        # 4. Calculating confidence scores based on similarity and evidence strength
        # 5. Returning a sorted list of AttributionResult objects (highest confidence first)"
        #
        # Then review and test the generated code.
        pass


class AttributionPipeline:
    """End-to-end threat actor attribution pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        """Initialize the pipeline."""
        self.ttp_extractor = TTPExtractor()
        self.clusterer = ThreatActorClusterer()
        self.malware_attributor = MalwareAttributor()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        """Lazy initialization of LLM."""
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def load_knowledge_base(self, actor_profiles: List[dict], malware_samples: List[dict]):
        """
        Load threat intelligence knowledge base.

        TODO: Implement knowledge base loading
        - Load actor profiles
        - Load malware database
        - Build indices

        Args:
            actor_profiles: Known threat actor profiles
            malware_samples: Known malware samples
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to load the threat intelligence knowledge base by:
        # 1. Calling self.clusterer.load_actor_profiles with actor_profiles
        # 2. Calling self.malware_attributor.load_malware_database with malware_samples
        # 3. Building any additional cross-reference indices needed
        # 4. Handling empty or malformed input data gracefully
        # 5. Logging the number of loaded profiles and samples"
        #
        # Then review and test the generated code.
        pass

    def analyze_incident(self, incident_data: dict) -> dict:
        """
        Analyze an incident for threat actor attribution.

        TODO: Implement incident analysis
        1. Extract TTPs from incident description
        2. Extract TTPs from IOCs
        3. Attribute any malware samples
        4. Find matching campaigns
        5. Generate attribution assessment

        Args:
            incident_data: Incident details with IOCs and description

        Returns:
            Attribution analysis results
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to analyze an incident for threat actor attribution by:
        # 1. Extracting TTPs from incident description using self.ttp_extractor.extract_from_text
        # 2. Extracting TTPs from IOCs using self.ttp_extractor.extract_from_iocs
        # 3. Attributing any malware hashes using self.malware_attributor.attribute_sample
        # 4. Finding matching campaigns using self.clusterer.attribute_campaign
        # 5. Combining results into a dict with 'ttps', 'attributions', 'campaigns', 'confidence'"
        #
        # Then review and test the generated code.
        pass

    def llm_generate_profile(self, attribution: dict) -> str:
        """
        Use LLM to generate a threat actor profile summary.

        TODO: Implement profile generation
        - Build prompt with attribution data
        - Request structured profile
        - Include confidence assessment

        Args:
            attribution: Attribution results

        Returns:
            Generated profile text
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to use an LLM to generate a threat actor profile summary by:
        # 1. Initializing the LLM with self._init_llm() if not already done
        # 2. Building a prompt with attribution data (TTPs, campaigns, malware, confidence)
        # 3. Requesting a structured profile including actor assessment and recommendations
        # 4. Handling different LLM providers (Anthropic, OpenAI, Google) via self.llm
        # 5. Returning the generated profile text with confidence assessment"
        #
        # Then review and test the generated code.
        pass

    def generate_report(self, results: dict) -> str:
        """
        Generate attribution report.

        TODO: Implement report generation

        Args:
            results: Analysis results

        Returns:
            Formatted report string
        """
        # TODO: Ask your AI assistant:
        # "Write Python code to generate a formatted attribution report by:
        # 1. Extracting key findings from results dict (TTPs, attributions, confidence)
        # 2. Formatting a structured report with sections for Executive Summary, TTPs, Attribution
        # 3. Including confidence levels and supporting evidence for each finding
        # 4. Adding recommendations based on the identified threat actor
        # 5. Returning a formatted string suitable for security analysts"
        #
        # Then review and test the generated code.
        pass


def main():
    """Main entry point for Lab 16."""
    print("=" * 60)
    print("Lab 16: AI-Powered Threat Actor Profiling")
    print("=" * 60)

    # Load sample data
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "threat_actor_profiles.json"), "r") as f:
            profiles = json.load(f)
        with open(os.path.join(data_dir, "campaign_data.json"), "r") as f:
            campaigns = json.load(f)
        print(f"\nLoaded {len(profiles.get('actors', []))} threat actor profiles")
        print(f"Loaded {len(campaigns.get('campaigns', []))} campaigns")
    except FileNotFoundError:
        print("Sample data not found. Using mock data.")
        profiles = {"actors": []}
        campaigns = {"campaigns": []}

    # Task 1: TTP Extraction
    print("\n--- Task 1: TTP Extraction ---")
    extractor = TTPExtractor()

    sample_text = """
    The threat actor initiated the attack with spearphishing emails containing
    malicious Word documents. Upon opening, PowerShell commands were executed
    to download additional payloads. The malware established persistence via
    scheduled tasks and used process injection to evade detection.
    """

    ttps = extractor.extract_from_text(sample_text)
    if ttps:
        print(f"Extracted {len(ttps)} TTPs:")
        for ttp in ttps[:5]:
            print(f"  - {ttp.technique_id}: {ttp.technique_name}")
    else:
        print("TODO: Implement extract_from_text()")

    # Task 2: Campaign Clustering
    print("\n--- Task 2: Campaign Clustering ---")
    clusterer = ThreatActorClusterer()
    clusterer.load_actor_profiles(profiles.get("actors", []))

    campaign_objects = []
    for c in campaigns.get("campaigns", []):
        campaign_objects.append(
            Campaign(
                campaign_id=c.get("id", ""),
                name=c.get("name", ""),
                start_date=c.get("start_date", ""),
                end_date=c.get("end_date", ""),
                targets=c.get("targets", []),
                ttps=[],
                iocs=c.get("iocs", {}),
                description=c.get("description", ""),
            )
        )

    clusters = clusterer.cluster_campaigns(campaign_objects)
    if clusters:
        print(f"Found {len(clusters)} campaign clusters")
    else:
        print("TODO: Implement cluster_campaigns()")

    # Task 3: Malware Attribution
    print("\n--- Task 3: Malware Attribution ---")
    attributor = MalwareAttributor()

    sample = MalwareSample(
        hash_sha256="abc123def456",
        family="unknown",
        first_seen="2024-01-15",
        file_type="PE32",
        size=245760,
        imphash="d32e5b6c7a8f9012",
        ssdeep="384:ABC123XYZ789:def456",
        capabilities=["keylogger", "screenshot", "file_exfil"],
    )

    attributions = attributor.attribute_sample(sample)
    if attributions:
        print(f"Top attribution: {attributions[0].actor_name}")
        print(f"  Confidence: {attributions[0].confidence:.2%}")
    else:
        print("TODO: Implement attribute_sample()")

    # Task 4: Full Pipeline
    print("\n--- Task 4: Attribution Pipeline ---")
    pipeline = AttributionPipeline()
    pipeline.load_knowledge_base(profiles.get("actors", []), campaigns.get("malware_samples", []))

    incident = {
        "description": sample_text,
        "iocs": {
            "domains": ["evil-c2.com", "malware-update.net"],
            "ips": ["185.234.72.19"],
            "hashes": ["abc123def456"],
        },
        "target_sector": "finance",
        "target_region": "North America",
    }

    results = pipeline.analyze_incident(incident)
    if results:
        print(f"Analysis complete")
        if results.get("attributions"):
            print(f"  Top attribution: {results['attributions'][0].get('actor_name', 'unknown')}")
    else:
        print("TODO: Implement analyze_incident()")

    print("\n" + "=" * 60)
    print("Complete the TODOs in this file to finish Lab 16!")
    print("=" * 60)


if __name__ == "__main__":
    main()

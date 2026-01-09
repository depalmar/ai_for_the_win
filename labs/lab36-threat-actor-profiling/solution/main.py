"""
Lab 16: AI-Powered Threat Actor Profiling - Solution

Build a threat actor profiling system that extracts TTPs, clusters campaigns,
and performs malware attribution using ML and LLMs.
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
            raise ValueError("No API key found.")

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
    ttps: List[TTP] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
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
    aliases: List[str] = field(default_factory=list)
    country: str = ""
    motivation: str = ""
    sophistication: str = ""
    campaigns: List[str] = field(default_factory=list)
    ttps: List[TTP] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)


@dataclass
class AttributionResult:
    """Result of threat actor attribution."""

    actor_name: str
    confidence: float
    matching_ttps: List[str] = field(default_factory=list)
    matching_infrastructure: List[str] = field(default_factory=list)
    matching_malware: List[str] = field(default_factory=list)
    analysis: str = ""


class TTPExtractor:
    """Extract TTPs from threat reports and indicators."""

    TECHNIQUE_PATTERNS = {
        "T1566": (r"phishing|spearphishing|malicious attachment|malicious email", "Phishing"),
        "T1059": (
            r"command.?line|powershell|cmd\.exe|bash|script|wscript|cscript",
            "Command and Scripting Interpreter",
        ),
        "T1055": (r"process injection|dll injection|hollow|inject.*process", "Process Injection"),
        "T1053": (r"scheduled task|cron|at job|task scheduler", "Scheduled Task/Job"),
        "T1078": (
            r"valid account|credential|stolen password|compromised credential",
            "Valid Accounts",
        ),
        "T1021": (r"remote service|rdp|ssh|winrm|smb|remote desktop", "Remote Services"),
        "T1071": (
            r"application layer protocol|http|https|dns tunnel|c2 over",
            "Application Layer Protocol",
        ),
        "T1105": (
            r"ingress tool transfer|download|stage|retrieve payload",
            "Ingress Tool Transfer",
        ),
        "T1027": (r"obfuscat|encod|pack|encrypt|xor|base64", "Obfuscated Files or Information"),
        "T1082": (
            r"system information discovery|systeminfo|hostname|environment",
            "System Information Discovery",
        ),
        "T1083": (
            r"file.{0,10}directory discovery|dir |ls |find |enumerate file",
            "File and Directory Discovery",
        ),
        "T1057": (r"process discovery|tasklist|ps aux|process list", "Process Discovery"),
        "T1003": (
            r"credential dump|mimikatz|lsass|sam|ntds|password hash",
            "OS Credential Dumping",
        ),
        "T1486": (r"data encrypted|ransomware|encrypt files|ransom", "Data Encrypted for Impact"),
        "T1490": (
            r"inhibit system recovery|delete shadow|vssadmin|backup delete",
            "Inhibit System Recovery",
        ),
        "T1547": (
            r"boot.*autostart|registry run|startup folder|persistence",
            "Boot or Logon Autostart Execution",
        ),
        "T1070": (r"indicator removal|clear log|delete log|cover track", "Indicator Removal"),
        "T1041": (r"exfiltrat|data.*c2|send data|upload stolen", "Exfiltration Over C2 Channel"),
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
        "T1547": "Persistence",
        "T1070": "Defense Evasion",
        "T1041": "Exfiltration",
    }

    def extract_from_text(self, text: str) -> List[TTP]:
        """Extract TTPs from threat report text."""
        ttps = []
        text_lower = text.lower()

        # Search for technique patterns
        for technique_id, (pattern, name) in self.TECHNIQUE_PATTERNS.items():
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                confidence = min(len(matches) * 0.2 + 0.5, 1.0)
                ttps.append(
                    TTP(
                        technique_id=technique_id,
                        technique_name=name,
                        tactic=self.TACTIC_MAPPING.get(technique_id, "Unknown"),
                        description=f"Detected via pattern match: {matches[0]}",
                        confidence=confidence,
                    )
                )

        # Look for explicit technique IDs
        explicit_ids = re.findall(r"T\d{4}(?:\.\d{3})?", text)
        for tid in explicit_ids:
            base_id = tid.split(".")[0]
            if base_id not in [t.technique_id for t in ttps]:
                ttps.append(
                    TTP(
                        technique_id=base_id,
                        technique_name=f"Technique {base_id}",
                        tactic=self.TACTIC_MAPPING.get(base_id, "Unknown"),
                        description="Explicitly mentioned in text",
                        confidence=0.9,
                    )
                )

        return ttps

    def extract_from_iocs(self, iocs: dict) -> List[TTP]:
        """Infer TTPs from IOCs."""
        ttps = []

        # Domain-based inference
        domains = iocs.get("domains", [])
        if domains:
            ttps.append(
                TTP(
                    technique_id="T1071",
                    technique_name="Application Layer Protocol",
                    tactic="Command and Control",
                    description=f"C2 domains: {', '.join(domains[:3])}",
                    confidence=0.7,
                )
            )

        # IP-based inference
        ips = iocs.get("ips", [])
        if ips:
            ttps.append(
                TTP(
                    technique_id="T1095",
                    technique_name="Non-Application Layer Protocol",
                    tactic="Command and Control",
                    description=f"C2 IPs detected",
                    confidence=0.6,
                )
            )

        # File-based inference
        files = iocs.get("files", []) + iocs.get("hashes", [])
        for f in files:
            if isinstance(f, str):
                if any(ext in f.lower() for ext in [".ps1", ".bat", ".vbs"]):
                    ttps.append(
                        TTP(
                            technique_id="T1059",
                            technique_name="Command and Scripting Interpreter",
                            tactic="Execution",
                            description=f"Script file: {f}",
                            confidence=0.8,
                        )
                    )
                    break

        return ttps

    def extract_from_malware(self, sample: MalwareSample) -> List[TTP]:
        """Extract TTPs from malware capabilities."""
        ttps = []

        capability_mapping = {
            "keylogger": ("T1056", "Input Capture", "Collection"),
            "screenshot": ("T1113", "Screen Capture", "Collection"),
            "file_exfil": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
            "persistence": ("T1547", "Boot or Logon Autostart Execution", "Persistence"),
            "credential_theft": ("T1003", "OS Credential Dumping", "Credential Access"),
            "lateral_movement": ("T1021", "Remote Services", "Lateral Movement"),
            "ransomware": ("T1486", "Data Encrypted for Impact", "Impact"),
            "rootkit": ("T1014", "Rootkit", "Defense Evasion"),
            "process_injection": ("T1055", "Process Injection", "Defense Evasion"),
            "c2": ("T1071", "Application Layer Protocol", "Command and Control"),
        }

        for capability in sample.capabilities:
            if capability.lower() in capability_mapping:
                tid, name, tactic = capability_mapping[capability.lower()]
                ttps.append(
                    TTP(
                        technique_id=tid,
                        technique_name=name,
                        tactic=tactic,
                        description=f"Capability: {capability}",
                        confidence=0.85,
                    )
                )

        # Infer from C2 domains
        if sample.c2_domains:
            ttps.append(
                TTP(
                    technique_id="T1071",
                    technique_name="Application Layer Protocol",
                    tactic="Command and Control",
                    description=f"C2: {', '.join(sample.c2_domains[:3])}",
                    confidence=0.9,
                )
            )

        return ttps

    def llm_extract_ttps(self, text: str, llm_client) -> List[TTP]:
        """Use LLM to extract TTPs from text."""
        provider, client = llm_client

        prompt = f"""Analyze this threat report and extract MITRE ATT&CK TTPs.

Report:
{text[:2000]}

Return JSON array with:
- technique_id: MITRE technique ID (e.g., T1566)
- technique_name: Name of technique
- tactic: MITRE tactic name
- confidence: 0-1 confidence score

Only include TTPs clearly indicated by the text."""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                result_text = response.content[0].text
            elif provider == "openai":
                response = client.chat.completions.create(
                    model="gpt-5",
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                )
                result_text = response.choices[0].message.content
            elif provider == "google":
                response = client.generate_content(prompt)
                result_text = response.text

            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]

            data = json.loads(result_text)
            ttps = []
            for item in data if isinstance(data, list) else data.get("ttps", []):
                ttps.append(
                    TTP(
                        technique_id=item.get("technique_id", ""),
                        technique_name=item.get("technique_name", ""),
                        tactic=item.get("tactic", ""),
                        confidence=item.get("confidence", 0.5),
                    )
                )
            return ttps
        except Exception as e:
            return []


class ThreatActorClusterer:
    """Cluster campaigns and attribute to threat actors."""

    def __init__(self):
        self.actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, Campaign] = {}

    def load_actor_profiles(self, profiles: List[dict]):
        """Load known threat actor profiles."""
        for p in profiles:
            ttps = []
            for t in p.get("ttps", []):
                if isinstance(t, dict):
                    ttps.append(
                        TTP(
                            technique_id=t.get("technique_id", ""),
                            technique_name=t.get("technique_name", ""),
                            tactic=t.get("tactic", ""),
                            confidence=t.get("confidence", 0.8),
                        )
                    )
                elif isinstance(t, str):
                    ttps.append(TTP(technique_id=t, technique_name=t, tactic="Unknown"))

            actor = ThreatActor(
                actor_id=p.get("id", ""),
                name=p.get("name", ""),
                aliases=p.get("aliases", []),
                country=p.get("country", ""),
                motivation=p.get("motivation", ""),
                sophistication=p.get("sophistication", ""),
                campaigns=p.get("campaigns", []),
                ttps=ttps,
                malware_families=p.get("malware_families", []),
                target_sectors=p.get("target_sectors", []),
                target_regions=p.get("target_regions", []),
            )
            self.actors[actor.actor_id] = actor

        print(f"  Loaded {len(self.actors)} threat actor profiles")

    def calculate_ttp_similarity(self, ttps1: List[TTP], ttps2: List[TTP]) -> float:
        """Calculate similarity between two TTP sets."""
        if not ttps1 or not ttps2:
            return 0.0

        ids1 = set(t.technique_id for t in ttps1)
        ids2 = set(t.technique_id for t in ttps2)

        # Jaccard similarity
        intersection = len(ids1 & ids2)
        union = len(ids1 | ids2)

        if union == 0:
            return 0.0

        jaccard = intersection / union

        # Tactic overlap bonus
        tactics1 = set(t.tactic for t in ttps1)
        tactics2 = set(t.tactic for t in ttps2)
        tactic_overlap = len(tactics1 & tactics2) / max(len(tactics1 | tactics2), 1)

        return jaccard * 0.7 + tactic_overlap * 0.3

    def calculate_infrastructure_overlap(self, iocs1: dict, iocs2: dict) -> float:
        """Calculate infrastructure overlap between campaigns."""
        overlap_score = 0.0
        comparisons = 0

        # Domain overlap
        domains1 = set(iocs1.get("domains", []))
        domains2 = set(iocs2.get("domains", []))
        if domains1 or domains2:
            if domains1 & domains2:
                overlap_score += len(domains1 & domains2) / max(len(domains1 | domains2), 1)
            comparisons += 1

        # IP overlap
        ips1 = set(iocs1.get("ips", []))
        ips2 = set(iocs2.get("ips", []))
        if ips1 or ips2:
            if ips1 & ips2:
                overlap_score += len(ips1 & ips2) / max(len(ips1 | ips2), 1)

            # Subnet similarity (check /24)
            subnets1 = set(".".join(ip.split(".")[:3]) for ip in ips1 if ip.count(".") == 3)
            subnets2 = set(".".join(ip.split(".")[:3]) for ip in ips2 if ip.count(".") == 3)
            if subnets1 & subnets2:
                overlap_score += 0.5 * len(subnets1 & subnets2) / max(len(subnets1 | subnets2), 1)
            comparisons += 1

        return overlap_score / max(comparisons, 1)

    def cluster_campaigns(
        self, campaigns: List[Campaign], threshold: float = 0.4
    ) -> List[List[Campaign]]:
        """Cluster campaigns by similarity."""
        if len(campaigns) < 2:
            return [[c] for c in campaigns]

        # Calculate pairwise similarities
        n = len(campaigns)
        similarity_matrix = np.zeros((n, n))

        for i in range(n):
            for j in range(i + 1, n):
                ttp_sim = self.calculate_ttp_similarity(campaigns[i].ttps, campaigns[j].ttps)
                infra_sim = self.calculate_infrastructure_overlap(
                    campaigns[i].iocs, campaigns[j].iocs
                )

                # Target overlap
                targets1 = set(campaigns[i].targets)
                targets2 = set(campaigns[j].targets)
                target_sim = (
                    len(targets1 & targets2) / max(len(targets1 | targets2), 1)
                    if targets1 or targets2
                    else 0
                )

                total_sim = ttp_sim * 0.4 + infra_sim * 0.4 + target_sim * 0.2
                similarity_matrix[i, j] = total_sim
                similarity_matrix[j, i] = total_sim

        # Simple agglomerative clustering
        clusters = [[i] for i in range(n)]
        cluster_map = {i: i for i in range(n)}

        while True:
            best_sim = 0
            best_pair = None

            for i, cluster_i in enumerate(clusters):
                for j, cluster_j in enumerate(clusters):
                    if i >= j:
                        continue

                    # Average linkage
                    total = 0
                    count = 0
                    for ci in cluster_i:
                        for cj in cluster_j:
                            total += similarity_matrix[ci, cj]
                            count += 1
                    avg_sim = total / count if count > 0 else 0

                    if avg_sim > best_sim:
                        best_sim = avg_sim
                        best_pair = (i, j)

            if best_sim < threshold or best_pair is None:
                break

            # Merge clusters
            i, j = best_pair
            clusters[i].extend(clusters[j])
            clusters.pop(j)

        # Convert indices to campaigns
        return [[campaigns[idx] for idx in cluster] for cluster in clusters]

    def attribute_campaign(self, campaign: Campaign) -> List[AttributionResult]:
        """Attribute a campaign to known threat actors."""
        results = []

        for actor_id, actor in self.actors.items():
            matching_ttps = []
            matching_infra = []
            matching_malware = []

            # TTP matching
            campaign_ttp_ids = set(t.technique_id for t in campaign.ttps)
            actor_ttp_ids = set(t.technique_id for t in actor.ttps)
            matching_ttps = list(campaign_ttp_ids & actor_ttp_ids)

            # Targeting match
            target_match = any(t in actor.target_sectors for t in campaign.targets)

            # Calculate confidence
            confidence = 0.0
            if matching_ttps:
                confidence += len(matching_ttps) / max(len(actor_ttp_ids), 1) * 0.5
            if target_match:
                confidence += 0.2

            if confidence > 0.1:
                results.append(
                    AttributionResult(
                        actor_name=actor.name,
                        confidence=min(confidence, 1.0),
                        matching_ttps=matching_ttps,
                        matching_infrastructure=matching_infra,
                        matching_malware=matching_malware,
                        analysis=f"TTP overlap: {len(matching_ttps)}, Target match: {target_match}",
                    )
                )

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results


class MalwareAttributor:
    """Attribute malware samples to threat actors."""

    def __init__(self):
        self.malware_db: Dict[str, MalwareSample] = {}
        self.actor_malware: Dict[str, List[str]] = defaultdict(list)
        self.family_actor: Dict[str, str] = {}

    def load_malware_database(self, samples: List[dict]):
        """Load known malware samples."""
        for s in samples:
            sample = MalwareSample(
                hash_sha256=s.get("sha256", ""),
                family=s.get("family", ""),
                first_seen=s.get("first_seen", ""),
                file_type=s.get("file_type", ""),
                size=s.get("size", 0),
                imphash=s.get("imphash", ""),
                ssdeep=s.get("ssdeep", ""),
                capabilities=s.get("capabilities", []),
                c2_domains=s.get("c2_domains", []),
                mutex_names=s.get("mutex_names", []),
            )
            self.malware_db[sample.hash_sha256] = sample

            # Track actor associations
            if s.get("attributed_actor"):
                self.actor_malware[s["attributed_actor"]].append(sample.hash_sha256)
                self.family_actor[sample.family] = s["attributed_actor"]

        print(f"  Loaded {len(self.malware_db)} malware samples")

    def calculate_code_similarity(self, sample1: MalwareSample, sample2: MalwareSample) -> float:
        """Calculate code similarity between samples."""
        similarity = 0.0
        factors = 0

        # Imphash match (strong indicator)
        if sample1.imphash and sample2.imphash:
            if sample1.imphash == sample2.imphash:
                similarity += 1.0
            factors += 1

        # SSDeep similarity
        if sample1.ssdeep and sample2.ssdeep:
            ssdeep_sim = self.calculate_ssdeep_similarity(sample1.ssdeep, sample2.ssdeep)
            similarity += ssdeep_sim / 100
            factors += 1

        # Capability overlap
        if sample1.capabilities and sample2.capabilities:
            caps1 = set(sample1.capabilities)
            caps2 = set(sample2.capabilities)
            cap_sim = len(caps1 & caps2) / max(len(caps1 | caps2), 1)
            similarity += cap_sim
            factors += 1

        # C2 overlap
        if sample1.c2_domains and sample2.c2_domains:
            c2_1 = set(sample1.c2_domains)
            c2_2 = set(sample2.c2_domains)
            if c2_1 & c2_2:
                similarity += 1.0
            factors += 1

        return similarity / max(factors, 1)

    def calculate_ssdeep_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate ssdeep fuzzy hash similarity."""
        # Simplified ssdeep comparison
        # Real implementation would use proper ssdeep library
        try:
            parts1 = hash1.split(":")
            parts2 = hash2.split(":")

            if len(parts1) < 3 or len(parts2) < 3:
                return 0

            # Block size comparison
            if parts1[0] != parts2[0]:
                return 0

            # Chunk comparison (simplified)
            chunk1 = parts1[1]
            chunk2 = parts2[1]

            common = sum(1 for c in chunk1 if c in chunk2)
            similarity = common / max(len(chunk1), len(chunk2), 1) * 100

            return similarity
        except Exception:
            return 0

    def find_similar_samples(
        self, sample: MalwareSample, threshold: float = 0.3
    ) -> List[Tuple[MalwareSample, float]]:
        """Find similar samples in the database."""
        similar = []

        for hash_val, known_sample in self.malware_db.items():
            if hash_val == sample.hash_sha256:
                continue

            similarity = self.calculate_code_similarity(sample, known_sample)
            if similarity >= threshold:
                similar.append((known_sample, similarity))

        similar.sort(key=lambda x: x[1], reverse=True)
        return similar

    def attribute_sample(self, sample: MalwareSample) -> List[AttributionResult]:
        """Attribute a malware sample to threat actors."""
        results = []

        # Check for exact hash match
        if sample.hash_sha256 in self.malware_db:
            known = self.malware_db[sample.hash_sha256]
            if known.family in self.family_actor:
                actor = self.family_actor[known.family]
                results.append(
                    AttributionResult(
                        actor_name=actor,
                        confidence=1.0,
                        matching_malware=[known.family],
                        analysis=f"Exact hash match to {known.family}",
                    )
                )
                return results

        # Find similar samples
        similar = self.find_similar_samples(sample)

        actor_scores = defaultdict(lambda: {"confidence": 0, "matches": []})

        for similar_sample, similarity in similar:
            if similar_sample.family in self.family_actor:
                actor = self.family_actor[similar_sample.family]
                actor_scores[actor]["confidence"] = max(
                    actor_scores[actor]["confidence"], similarity
                )
                actor_scores[actor]["matches"].append(similar_sample.family)

        for actor, data in actor_scores.items():
            results.append(
                AttributionResult(
                    actor_name=actor,
                    confidence=data["confidence"],
                    matching_malware=list(set(data["matches"])),
                    analysis=f"Similar to: {', '.join(set(data['matches']))}",
                )
            )

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results


class AttributionPipeline:
    """End-to-end threat actor attribution pipeline."""

    def __init__(self, llm_provider: str = "auto"):
        self.ttp_extractor = TTPExtractor()
        self.clusterer = ThreatActorClusterer()
        self.malware_attributor = MalwareAttributor()
        self.llm = None
        self.llm_provider = llm_provider

    def _init_llm(self):
        if self.llm is None:
            try:
                self.llm = setup_llm(provider=self.llm_provider)
            except Exception:
                self.llm = None

    def load_knowledge_base(self, actor_profiles: List[dict], malware_samples: List[dict]):
        """Load threat intelligence knowledge base."""
        self.clusterer.load_actor_profiles(actor_profiles)
        self.malware_attributor.load_malware_database(malware_samples or [])

    def analyze_incident(self, incident_data: dict) -> dict:
        """Analyze an incident for threat actor attribution."""
        results = {
            "extracted_ttps": [],
            "attributions": [],
            "malware_attribution": [],
            "confidence_assessment": "",
        }

        # 1. Extract TTPs from description
        description = incident_data.get("description", "")
        if description:
            ttps_from_text = self.ttp_extractor.extract_from_text(description)
            results["extracted_ttps"].extend(ttps_from_text)

        # 2. Extract TTPs from IOCs
        iocs = incident_data.get("iocs", {})
        ttps_from_iocs = self.ttp_extractor.extract_from_iocs(iocs)
        results["extracted_ttps"].extend(ttps_from_iocs)

        # 3. LLM-based extraction if available
        self._init_llm()
        if self.llm and description:
            llm_ttps = self.ttp_extractor.llm_extract_ttps(description, self.llm)
            # Merge without duplicates
            existing_ids = set(t.technique_id for t in results["extracted_ttps"])
            for ttp in llm_ttps:
                if ttp.technique_id not in existing_ids:
                    results["extracted_ttps"].append(ttp)

        # 4. Create campaign object for attribution
        campaign = Campaign(
            campaign_id="incident_" + datetime.now().strftime("%Y%m%d_%H%M%S"),
            name="Analyzed Incident",
            start_date=datetime.now().isoformat(),
            end_date=datetime.now().isoformat(),
            targets=[incident_data.get("target_sector", "")],
            ttps=results["extracted_ttps"],
            iocs=iocs,
        )

        # 5. Attribute campaign
        attributions = self.clusterer.attribute_campaign(campaign)
        results["attributions"] = [
            {
                "actor_name": a.actor_name,
                "confidence": a.confidence,
                "matching_ttps": a.matching_ttps,
                "analysis": a.analysis,
            }
            for a in attributions[:5]
        ]

        # 6. Confidence assessment
        if attributions:
            top = attributions[0]
            if top.confidence > 0.7:
                results["confidence_assessment"] = (
                    f"High confidence attribution to {top.actor_name}"
                )
            elif top.confidence > 0.4:
                results["confidence_assessment"] = (
                    f"Medium confidence attribution to {top.actor_name}"
                )
            else:
                results["confidence_assessment"] = (
                    "Low confidence - insufficient matching indicators"
                )
        else:
            results["confidence_assessment"] = "Unable to attribute - no matching threat actors"

        return results

    def llm_generate_profile(self, attribution: dict) -> str:
        """Use LLM to generate a threat actor profile summary."""
        self._init_llm()
        if not self.llm:
            return "LLM not available for profile generation"

        provider, client = self.llm

        prompt = f"""Generate a brief threat actor profile based on this attribution analysis:

Attribution Results:
{json.dumps(attribution, indent=2, default=str)}

Create a concise profile including:
1. Most likely threat actor
2. Confidence level and reasoning
3. Key matching indicators
4. Recommended defensive actions
5. Intelligence gaps to address"""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text
            elif provider == "openai":
                response = client.chat.completions.create(
                    model="gpt-5", messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content
            elif provider == "google":
                response = client.generate_content(prompt)
                return response.text
        except Exception as e:
            return f"Error generating profile: {e}"

    def generate_report(self, results: dict) -> str:
        """Generate attribution report."""
        lines = []
        lines.append("=" * 60)
        lines.append("THREAT ACTOR ATTRIBUTION REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")

        lines.append("--- EXTRACTED TTPs ---")
        for ttp in results.get("extracted_ttps", [])[:10]:
            lines.append(f"  {ttp.technique_id}: {ttp.technique_name} ({ttp.tactic})")
            lines.append(f"    Confidence: {ttp.confidence:.1%}")
        lines.append("")

        lines.append("--- ATTRIBUTION RESULTS ---")
        for attr in results.get("attributions", [])[:5]:
            lines.append(f"  {attr['actor_name']}: {attr['confidence']:.1%}")
            if attr.get("matching_ttps"):
                lines.append(f"    Matching TTPs: {', '.join(attr['matching_ttps'][:5])}")
        lines.append("")

        lines.append("--- ASSESSMENT ---")
        lines.append(f"  {results.get('confidence_assessment', 'N/A')}")

        return "\n".join(lines)


def main():
    """Main entry point for Lab 16."""
    print("=" * 60)
    print("Lab 16: AI-Powered Threat Actor Profiling - Solution")
    print("=" * 60)

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")

    try:
        with open(os.path.join(data_dir, "threat_actor_profiles.json"), "r") as f:
            profiles = json.load(f)
        with open(os.path.join(data_dir, "campaign_data.json"), "r") as f:
            campaigns = json.load(f)
        print(f"\nLoaded {len(profiles.get('actors', []))} threat actor profiles")
        print(f"Loaded {len(campaigns.get('campaigns', []))} campaigns")
    except FileNotFoundError:
        print("Sample data not found. Creating mock data.")
        profiles, campaigns = create_mock_data()

    # Initialize pipeline
    print("\n" + "-" * 40)
    print("Initializing Attribution Pipeline")
    print("-" * 40)

    pipeline = AttributionPipeline()
    pipeline.load_knowledge_base(profiles.get("actors", []), campaigns.get("malware_samples", []))

    # Analyze sample incident
    print("\n--- Analyzing Incident ---")
    incident = {
        "description": """
        The threat actor initiated the attack with spearphishing emails containing
        malicious Word documents targeting the finance sector. Upon opening,
        PowerShell commands were executed to download Cobalt Strike beacon.
        The malware established persistence via scheduled tasks and used process
        injection to evade detection. Credential dumping was observed using mimikatz.
        Lateral movement occurred via RDP and SMB. Data was exfiltrated to C2.
        """,
        "iocs": {
            "domains": ["malware-update.net", "c2-server.com"],
            "ips": ["185.234.72.19", "91.234.56.78"],
            "hashes": ["abc123def456789"],
        },
        "target_sector": "finance",
        "target_region": "North America",
    }

    results = pipeline.analyze_incident(incident)

    # Generate and print report
    report = pipeline.generate_report(results)
    print("\n" + report)

    # LLM profile generation
    print("\n--- LLM Profile Generation ---")
    profile = pipeline.llm_generate_profile(results)
    if not profile.startswith("Error") and not profile.startswith("LLM not"):
        print(profile[:500] + "..." if len(profile) > 500 else profile)
    else:
        print("LLM profile generation skipped (no API key)")


def create_mock_data():
    """Create mock data for demo."""
    profiles = {
        "actors": [
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
                    },
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "tactic": "Execution",
                    },
                    {
                        "technique_id": "T1055",
                        "technique_name": "Process Injection",
                        "tactic": "Defense Evasion",
                    },
                    {
                        "technique_id": "T1003",
                        "technique_name": "OS Credential Dumping",
                        "tactic": "Credential Access",
                    },
                ],
                "malware_families": ["WellMess", "WellMail", "SoreFang"],
                "target_sectors": ["government", "think_tank", "healthcare"],
                "target_regions": ["North America", "Europe"],
            },
            {
                "id": "apt41",
                "name": "APT41 (Double Dragon)",
                "aliases": ["Winnti", "Barium"],
                "country": "China",
                "motivation": "financial",
                "sophistication": "advanced",
                "ttps": [
                    {
                        "technique_id": "T1566",
                        "technique_name": "Phishing",
                        "tactic": "Initial Access",
                    },
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "tactic": "Execution",
                    },
                    {
                        "technique_id": "T1053",
                        "technique_name": "Scheduled Task",
                        "tactic": "Persistence",
                    },
                    {
                        "technique_id": "T1021",
                        "technique_name": "Remote Services",
                        "tactic": "Lateral Movement",
                    },
                ],
                "malware_families": ["ShadowPad", "Winnti", "PlugX"],
                "target_sectors": ["gaming", "technology", "finance"],
                "target_regions": ["Asia", "North America"],
            },
            {
                "id": "fin7",
                "name": "FIN7",
                "aliases": ["Carbanak", "Carbon Spider"],
                "country": "Russia",
                "motivation": "financial",
                "sophistication": "high",
                "ttps": [
                    {
                        "technique_id": "T1566",
                        "technique_name": "Phishing",
                        "tactic": "Initial Access",
                    },
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "tactic": "Execution",
                    },
                    {
                        "technique_id": "T1055",
                        "technique_name": "Process Injection",
                        "tactic": "Defense Evasion",
                    },
                    {
                        "technique_id": "T1003",
                        "technique_name": "OS Credential Dumping",
                        "tactic": "Credential Access",
                    },
                    {
                        "technique_id": "T1021",
                        "technique_name": "Remote Services",
                        "tactic": "Lateral Movement",
                    },
                ],
                "malware_families": ["Carbanak", "GRIFFON", "BOOSTWRITE"],
                "target_sectors": ["retail", "hospitality", "finance"],
                "target_regions": ["North America", "Europe"],
            },
        ]
    }

    campaigns = {
        "campaigns": [
            {
                "id": "campaign_001",
                "name": "Operation CloudHopper",
                "start_date": "2024-01-01",
                "end_date": "2024-03-15",
                "targets": ["technology", "msp"],
                "description": "Supply chain compromise targeting MSPs",
                "iocs": {"domains": ["evil-cloud.com"], "ips": ["185.234.72.19"]},
            }
        ],
        "malware_samples": [
            {
                "sha256": "abc123def456789",
                "family": "Carbanak",
                "first_seen": "2024-01-15",
                "file_type": "PE32",
                "size": 245760,
                "imphash": "d32e5b6c7a8f9012",
                "capabilities": ["keylogger", "screenshot", "credential_theft"],
                "attributed_actor": "FIN7",
            }
        ],
    }

    return profiles, campaigns


if __name__ == "__main__":
    main()

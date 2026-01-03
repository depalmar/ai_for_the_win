# Lab 16: AI-Powered Threat Actor Profiling

Build AI systems to profile threat actors based on TTPs, malware characteristics, and campaign patterns. Learn to attribute attacks and predict adversary behavior.

## 🎯 Learning Objectives

By completing this lab, you will:

1. Extract and analyze TTPs from incident data
2. Build ML models for threat actor clustering and attribution
3. Use LLMs to generate threat actor profiles and reports
4. Predict adversary behavior based on historical patterns
5. Map campaigns to known threat groups

---

## ⏱️ Estimated Time

1.5-2 hours (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 05 (Threat Intel Agent), 11 (Ransomware Detection)
- Familiarity with MITRE ATT&CK framework
- Understanding of threat intelligence concepts

---

## 📖 Background

### Threat Actor Attribution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     THREAT ACTOR PROFILING PIPELINE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Incident          TTP             Feature          Clustering            │
│   Data         ──►  Extraction  ──►  Engineering  ──►  & Attribution       │
│                                                                             │
│   ┌─────────┐      ┌───────────┐    ┌────────────┐   ┌─────────────┐       │
│   │Malware  │      │ ATT&CK    │    │ TTP        │   │ APT28       │       │
│   │Samples  │      │ Techniques│    │ Vectors    │   │ Lazarus     │       │
│   │Network  │      │ Tools     │    │ Tool       │   │ APT41       │       │
│   │IOCs     │      │ Infra     │    │ Signatures │   │ Unknown     │       │
│   │Reports  │      │ Targets   │    │ Target     │   │             │       │
│   └─────────┘      └───────────┘    │ Profiles   │   └─────────────┘       │
│                                     └────────────┘                          │
│                                                                             │
│   ATTRIBUTION INDICATORS:                                                   │
│   ───────────────────────                                                   │
│   • Malware code similarities                                               │
│   • Infrastructure overlap                                                  │
│   • TTP consistency                                                         │
│   • Targeting patterns                                                      │
│   • Operational timing                                                      │
│   • Language artifacts                                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK for Attribution

| Category | Attribution Value | Examples |
|----------|-------------------|----------|
| Initial Access | Medium | Spearphishing vs watering hole |
| Execution | High | Custom loaders, unique techniques |
| Persistence | Medium | Registry keys, scheduled tasks |
| Defense Evasion | High | Code signing, obfuscation methods |
| C2 | Very High | Custom protocols, infrastructure |
| Exfiltration | Medium | Methods, timing, volume |

### Known Threat Actor Characteristics

| Actor | Primary Targets | Signature TTPs | Tools |
|-------|-----------------|----------------|-------|
| APT28 | Government, Defense | OAuth phishing, zebrocy | X-Agent, Sofacy |
| APT29 | Government, Think tanks | Supply chain, steganography | SUNBURST, Cobalt Strike |
| Lazarus | Financial, Crypto | Watering holes, custom malware | HOPLIGHT, Manuscrypt |
| APT41 | Tech, Healthcare | Supply chain, gaming | Winnti, ShadowPad |
| FIN7 | Retail, Hospitality | Spearphishing, POS malware | Carbanak, GRIFFON |

---

## Tasks

### Task 1: TTP Extraction and Encoding

Extract and encode TTPs from incident reports and malware analysis.

```python
# TODO: Implement TTP extraction
from typing import List, Dict
import numpy as np

class TTPExtractor:
    def __init__(self, llm_provider: str = "auto"):
        self.llm = setup_llm(provider=llm_provider)
        self.attack_matrix = self._load_attack_matrix()

    def extract_ttps_from_report(self, report_text: str) -> List[dict]:
        """
        Use LLM to extract TTPs from incident report.

        Returns:
            List of TTPs with technique ID, name, and confidence
        """
        prompt = f"""
        Analyze this incident report and extract all MITRE ATT&CK techniques.

        REPORT:
        {report_text}

        For each technique found, provide:
        1. Technique ID (e.g., T1566.001)
        2. Technique name
        3. Evidence from the report
        4. Confidence (high/medium/low)

        Return as JSON array.
        """
        pass

    def extract_ttps_from_malware(self, analysis: dict) -> List[dict]:
        """
        Extract TTPs from malware analysis results.

        Args:
            analysis: Static/dynamic analysis output

        Returns:
            List of observed TTPs
        """
        pass

    def encode_ttps_vector(self, ttps: List[str]) -> np.ndarray:
        """
        Encode TTPs as a binary vector for ML.

        Args:
            ttps: List of technique IDs (e.g., ['T1566.001', 'T1059.001'])

        Returns:
            Binary vector of shape (num_techniques,)
        """
        # ATT&CK has ~200 techniques, create binary encoding
        pass

    def calculate_ttp_similarity(
        self,
        ttps_a: List[str],
        ttps_b: List[str]
    ) -> float:
        """Calculate Jaccard similarity between TTP sets."""
        set_a = set(ttps_a)
        set_b = set(ttps_b)
        if not set_a or not set_b:
            return 0.0
        return len(set_a & set_b) / len(set_a | set_b)
```

### Task 2: Threat Actor Clustering

Cluster incidents to identify potential threat actor groups.

```python
# TODO: Implement threat actor clustering
from sklearn.cluster import DBSCAN, AgglomerativeClustering
from sklearn.metrics import silhouette_score

class ThreatActorClusterer:
    def __init__(self):
        self.feature_extractor = TTPExtractor()
        self.known_actors = self._load_known_actors()

    def extract_campaign_features(self, campaign: dict) -> np.ndarray:
        """
        Extract features from a campaign for clustering.

        Features:
        - TTP vector (binary encoding of techniques)
        - Target sector encoding
        - Geographic targeting
        - Tool signatures
        - Infrastructure patterns
        - Temporal patterns
        """
        features = []

        # TTP features
        ttp_vector = self.feature_extractor.encode_ttps_vector(
            campaign.get('ttps', [])
        )
        features.extend(ttp_vector)

        # Target sector (one-hot)
        # TODO: Implement sector encoding

        # Tool signatures
        # TODO: Extract tool features

        return np.array(features)

    def cluster_campaigns(
        self,
        campaigns: List[dict],
        method: str = "dbscan"
    ) -> Dict[int, List[dict]]:
        """
        Cluster campaigns into potential threat actor groups.

        Args:
            campaigns: List of campaign data
            method: Clustering method ('dbscan', 'hierarchical')

        Returns:
            Dictionary mapping cluster ID to campaigns
        """
        # Extract features
        features = np.array([
            self.extract_campaign_features(c) for c in campaigns
        ])

        # Cluster
        if method == "dbscan":
            clusterer = DBSCAN(eps=0.3, min_samples=2, metric='jaccard')
        else:
            clusterer = AgglomerativeClustering(
                n_clusters=None,
                distance_threshold=0.5,
                linkage='average'
            )

        labels = clusterer.fit_predict(features)

        # Group campaigns by cluster
        clusters = {}
        for i, label in enumerate(labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(campaigns[i])

        return clusters

    def match_to_known_actors(
        self,
        cluster_ttps: List[str]
    ) -> List[dict]:
        """
        Match cluster TTPs to known threat actors.

        Returns:
            List of potential matches with confidence scores
        """
        matches = []
        for actor_name, actor_data in self.known_actors.items():
            similarity = self.feature_extractor.calculate_ttp_similarity(
                cluster_ttps,
                actor_data['ttps']
            )
            if similarity > 0.3:  # Threshold
                matches.append({
                    'actor': actor_name,
                    'similarity': similarity,
                    'matching_ttps': set(cluster_ttps) & set(actor_data['ttps']),
                    'unique_ttps': set(cluster_ttps) - set(actor_data['ttps'])
                })

        return sorted(matches, key=lambda x: x['similarity'], reverse=True)
```

### Task 3: Malware Code Similarity Analysis

Analyze malware code for attribution indicators.

```python
# TODO: Implement code similarity analysis
import hashlib
from collections import Counter

class MalwareAttributor:
    def __init__(self):
        self.known_malware_families = self._load_malware_db()

    def extract_code_features(self, sample: dict) -> dict:
        """
        Extract attribution-relevant features from malware.

        Features:
        - Import hash (imphash)
        - Section hashes
        - String patterns
        - Compiler artifacts
        - PDB paths
        - Timestamps
        - Code signing info
        """
        features = {
            'imphash': sample.get('imphash'),
            'section_hashes': self._hash_sections(sample),
            'strings': self._extract_attribution_strings(sample),
            'compiler': self._detect_compiler(sample),
            'pdb_path': sample.get('pdb_path'),
            'timestamp': sample.get('compile_time'),
            'code_signing': sample.get('signature_info')
        }
        return features

    def _extract_attribution_strings(self, sample: dict) -> dict:
        """
        Extract strings useful for attribution.

        Look for:
        - Language-specific strings
        - Campaign markers
        - Unique identifiers
        - Error messages
        - Debug strings
        """
        strings = sample.get('strings', [])
        attribution_strings = {
            'language_indicators': [],
            'campaign_markers': [],
            'unique_strings': [],
            'pdb_paths': []
        }

        for s in strings:
            # Check for language indicators
            if self._detect_language(s):
                attribution_strings['language_indicators'].append(s)
            # Check for PDB paths
            if '.pdb' in s.lower():
                attribution_strings['pdb_paths'].append(s)

        return attribution_strings

    def calculate_code_similarity(
        self,
        sample_a: dict,
        sample_b: dict
    ) -> dict:
        """
        Calculate code similarity between two samples.

        Returns:
            Similarity scores for different aspects
        """
        similarities = {}

        # Import hash match
        if sample_a.get('imphash') and sample_b.get('imphash'):
            similarities['imphash_match'] = (
                sample_a['imphash'] == sample_b['imphash']
            )

        # String overlap
        strings_a = set(sample_a.get('strings', []))
        strings_b = set(sample_b.get('strings', []))
        if strings_a and strings_b:
            similarities['string_similarity'] = (
                len(strings_a & strings_b) / len(strings_a | strings_b)
            )

        # Section similarity
        # TODO: Compare section hashes

        # Function similarity (requires disassembly)
        # TODO: Implement function-level comparison

        return similarities

    def find_related_samples(
        self,
        sample: dict,
        threshold: float = 0.5
    ) -> List[dict]:
        """Find related samples from known malware database."""
        pass
```

### Task 4: LLM-Powered Threat Actor Profiling

Use LLMs to generate comprehensive threat actor profiles.

```python
# TODO: Implement LLM profiling
class ThreatActorProfiler:
    def __init__(self, llm_provider: str = "auto"):
        self.llm = setup_llm(provider=llm_provider)
        self.ttp_extractor = TTPExtractor(llm_provider)

    def generate_profile(
        self,
        campaigns: List[dict],
        malware_samples: List[dict],
        iocs: List[dict]
    ) -> dict:
        """
        Generate comprehensive threat actor profile from evidence.

        Returns:
            Structured profile with TTPs, capabilities, targets, etc.
        """
        # Aggregate TTPs
        all_ttps = []
        for campaign in campaigns:
            all_ttps.extend(campaign.get('ttps', []))
        ttp_counts = Counter(all_ttps)

        # Build profile prompt
        prompt = f"""
        Generate a comprehensive threat actor profile based on:

        CAMPAIGNS ({len(campaigns)} total):
        {self._summarize_campaigns(campaigns)}

        MALWARE SAMPLES ({len(malware_samples)} total):
        {self._summarize_malware(malware_samples)}

        IOCs:
        {self._summarize_iocs(iocs)}

        TOP TTPs (by frequency):
        {self._format_ttp_counts(ttp_counts)}

        Generate a profile including:
        1. Threat Actor Summary
           - Likely motivation (espionage, financial, hacktivism)
           - Assessed sophistication level
           - Likely nation-state affiliation (if any)

        2. Targeting
           - Primary sectors
           - Geographic focus
           - Victim selection criteria

        3. Capabilities
           - Technical sophistication
           - Custom tooling
           - Operational security

        4. TTPs Analysis
           - Signature techniques
           - Tool preferences
           - Infrastructure patterns

        5. Diamond Model Analysis
           - Adversary characteristics
           - Capability assessment
           - Infrastructure patterns
           - Victim patterns

        6. Attribution Confidence
           - Confidence level (high/medium/low)
           - Key attribution indicators
           - Alternative hypotheses

        Return as structured JSON.
        """
        pass

    def compare_to_known_actors(
        self,
        profile: dict,
        known_actors: List[dict]
    ) -> List[dict]:
        """
        Compare profile to known threat actors.

        Returns:
            Ranked list of potential matches with reasoning
        """
        prompt = f"""
        Compare this threat actor profile to known groups:

        UNKNOWN ACTOR PROFILE:
        {json.dumps(profile, indent=2)}

        KNOWN THREAT ACTORS:
        {json.dumps(known_actors, indent=2)}

        For each potential match:
        1. Calculate similarity score (0-100%)
        2. List matching characteristics
        3. List differences
        4. Assess likelihood this is the same actor
        5. Consider if this could be a new subgroup or evolution

        Return ranked matches as JSON.
        """
        pass

    def predict_next_moves(self, profile: dict) -> dict:
        """
        Predict likely next actions based on actor profile.

        Returns:
            Predicted TTPs, targets, and timing
        """
        prompt = f"""
        Based on this threat actor profile, predict likely next actions:

        ACTOR PROFILE:
        {json.dumps(profile, indent=2)}

        Predict:
        1. Most likely next target sectors
        2. Probable attack vectors
        3. Expected TTPs
        4. Potential new capabilities
        5. Geographic expansion
        6. Timing considerations (geopolitical events, holidays)

        For each prediction, provide:
        - Confidence level
        - Supporting evidence from profile
        - Historical precedent (if any)

        Return as JSON.
        """
        pass
```

### Task 5: Attribution Pipeline

Build an end-to-end attribution pipeline.

```python
# TODO: Implement attribution pipeline
class AttributionPipeline:
    def __init__(self, llm_provider: str = "auto"):
        self.ttp_extractor = TTPExtractor(llm_provider)
        self.clusterer = ThreatActorClusterer()
        self.malware_attributor = MalwareAttributor()
        self.profiler = ThreatActorProfiler(llm_provider)
        self.known_actors = self._load_threat_actor_db()

    def analyze_incident(self, incident: dict) -> dict:
        """
        Full attribution analysis of an incident.

        Args:
            incident: Incident data with IOCs, logs, malware

        Returns:
            Attribution report with confidence levels
        """
        results = {
            'incident_id': incident.get('id'),
            'analysis_timestamp': datetime.now().isoformat(),
            'ttps': [],
            'malware_analysis': [],
            'infrastructure_analysis': {},
            'attribution': {},
            'recommendations': []
        }

        # 1. Extract TTPs from incident report
        if incident.get('report'):
            results['ttps'] = self.ttp_extractor.extract_ttps_from_report(
                incident['report']
            )

        # 2. Analyze malware samples
        for sample in incident.get('malware_samples', []):
            analysis = self.malware_attributor.extract_code_features(sample)
            related = self.malware_attributor.find_related_samples(sample)
            results['malware_analysis'].append({
                'sample': sample.get('hash'),
                'features': analysis,
                'related_samples': related
            })

        # 3. Infrastructure analysis
        results['infrastructure_analysis'] = self._analyze_infrastructure(
            incident.get('iocs', {}).get('domains', []),
            incident.get('iocs', {}).get('ips', [])
        )

        # 4. Match to known actors
        ttp_list = [t['technique_id'] for t in results['ttps']]
        actor_matches = self.clusterer.match_to_known_actors(ttp_list)

        # 5. Generate attribution assessment
        results['attribution'] = {
            'potential_actors': actor_matches[:3],
            'confidence': self._calculate_attribution_confidence(results),
            'key_indicators': self._identify_key_indicators(results)
        }

        # 6. LLM-powered profile generation
        if not actor_matches or actor_matches[0]['similarity'] < 0.7:
            # Potentially new actor - generate profile
            results['new_actor_profile'] = self.profiler.generate_profile(
                campaigns=[incident],
                malware_samples=incident.get('malware_samples', []),
                iocs=incident.get('iocs', {})
            )

        return results

    def _analyze_infrastructure(
        self,
        domains: List[str],
        ips: List[str]
    ) -> dict:
        """Analyze infrastructure for attribution indicators."""
        analysis = {
            'domains': [],
            'ips': [],
            'hosting_providers': [],
            'registrars': [],
            'temporal_patterns': []
        }

        # TODO: WHOIS analysis, passive DNS, hosting patterns

        return analysis

    def _calculate_attribution_confidence(self, results: dict) -> str:
        """Calculate overall attribution confidence."""
        indicators = 0

        # Count strong indicators
        if results['malware_analysis']:
            for m in results['malware_analysis']:
                if m.get('related_samples'):
                    indicators += 2

        if len(results['ttps']) > 5:
            indicators += 1

        if indicators >= 4:
            return "high"
        elif indicators >= 2:
            return "medium"
        else:
            return "low"

    def generate_report(self, analysis: dict) -> str:
        """Generate human-readable attribution report."""
        prompt = f"""
        Generate a professional threat actor attribution report:

        ANALYSIS DATA:
        {json.dumps(analysis, indent=2)}

        Structure:
        1. Executive Summary
        2. Incident Overview
        3. Technical Findings
           - Malware Analysis
           - Infrastructure Analysis
           - TTP Analysis
        4. Attribution Assessment
           - Primary Hypothesis
           - Alternative Hypotheses
           - Confidence Level & Reasoning
        5. Recommendations
        6. Appendix: IOCs

        Use professional threat intelligence report format.
        """
        pass
```

---

## Sample Data

The `data/` directory contains:
- `threat_actor_profiles.json` - Known threat actor profiles with TTPs
- `campaign_data.json` - Historical campaign data for clustering
- `malware_samples.json` - Malware analysis results with attribution features
- `incident_reports/` - Sample incident reports for TTP extraction
- `attack_matrix.json` - MITRE ATT&CK technique mappings

---

## Hints

<details>
<summary>Hint 1: TTP Vector Encoding</summary>

Use the MITRE ATT&CK Enterprise matrix as your feature space:
```python
ATTACK_TECHNIQUES = [
    "T1566.001", "T1566.002",  # Phishing
    "T1059.001", "T1059.003",  # Scripting
    # ... all techniques
]

def encode_ttps(ttps, technique_list=ATTACK_TECHNIQUES):
    vector = np.zeros(len(technique_list))
    for ttp in ttps:
        if ttp in technique_list:
            vector[technique_list.index(ttp)] = 1
    return vector
```
</details>

<details>
<summary>Hint 2: Similarity Metrics</summary>

Different metrics for different comparison types:
```python
# TTPs: Jaccard similarity (set overlap)
def jaccard(a, b):
    return len(a & b) / len(a | b)

# Malware: Cosine similarity on feature vectors
from sklearn.metrics.pairwise import cosine_similarity

# Timing: Compare operational hours
def timing_similarity(times_a, times_b):
    # Bin by hour, compare distributions
    pass
```
</details>

<details>
<summary>Hint 3: Attribution Confidence Levels</summary>

Define clear criteria for confidence:
```python
CONFIDENCE_CRITERIA = {
    'high': [
        'Code reuse from known samples',
        'Infrastructure overlap',
        '3+ unique TTPs match',
        'Consistent targeting'
    ],
    'medium': [
        '2 of high criteria',
        'Similar but not identical TTPs',
        'Related but new infrastructure'
    ],
    'low': [
        'Only TTP similarity',
        'Generic techniques used',
        'Insufficient evidence'
    ]
}
```
</details>

---

## Bonus Challenges

1. **Real-time Campaign Tracking**: Build a system to track ongoing campaigns
2. **Infrastructure Prediction**: Predict likely C2 infrastructure based on actor patterns
3. **Fake Flag Detection**: Identify potential false flag operations
4. **Multi-source Intelligence Fusion**: Combine OSINT, TECHINT, and HUMINT

---

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [The Diamond Model of Intrusion Analysis](https://www.threatintel.academy/diamond/)
- [MISP Threat Actor Galaxy](https://github.com/MISP/misp-galaxy)
- [APT Groups and Operations](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/)
- [Mandiant APT Reports](https://www.mandiant.com/resources/reports)

---

> **Stuck?** See the [Lab 16 Walkthrough](../../docs/walkthroughs/lab16-threat-actor-profiling-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 17 - Adversarial Machine Learning](../lab17-adversarial-ml/)
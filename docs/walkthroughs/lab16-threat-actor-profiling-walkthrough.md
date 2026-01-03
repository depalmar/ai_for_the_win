# Lab 16: Threat Actor Profiling - Solution Walkthrough

## Overview

Build an AI-powered threat actor profiling system for TTP extraction, campaign clustering, and attribution analysis.

**Time:** 4-5 hours
**Difficulty:** Expert

---

## Task 1: TTP Extraction

### Extracting Tactics, Techniques, and Procedures

```python
import anthropic
import json
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class ThreatReport:
    id: str
    title: str
    content: str
    source: str
    published_date: datetime
    iocs: list[dict] = field(default_factory=list)
    ttps: list[dict] = field(default_factory=list)

class TTPExtractor:
    def __init__(self):
        self.client = anthropic.Anthropic()
        self.mitre_techniques = self._load_mitre_techniques()

    def _load_mitre_techniques(self) -> dict:
        """Load MITRE ATT&CK technique mappings."""
        # Simplified mapping - in production, load full ATT&CK matrix
        return {
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
            'T1059.001': {'name': 'PowerShell', 'tactic': 'Execution'},
            'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
            'T1566.001': {'name': 'Spearphishing Attachment', 'tactic': 'Initial Access'},
            'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
            'T1003.001': {'name': 'LSASS Memory', 'tactic': 'Credential Access'},
            'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
            # Add more as needed
        }

    def extract_ttps(self, report: ThreatReport) -> list[dict]:
        """Extract TTPs from threat report using AI."""

        prompt = f"""Analyze this threat intelligence report and extract MITRE ATT&CK TTPs:

## Report Title
{report.title}

## Report Content
{report.content[:5000]}

Extract TTPs in JSON format:
{{
    "ttps": [
        {{
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": 0.9,
            "evidence": "Quote from report supporting this TTP",
            "tools_used": ["tool1", "tool2"]
        }}
    ],
    "kill_chain_phases": ["reconnaissance", "weaponization", ...],
    "sophistication_level": "high/medium/low"
}}

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            result = json.loads(response.content[0].text)
            return result.get('ttps', [])
        except json.JSONDecodeError:
            return []

    def map_to_mitre(self, ttps: list[dict]) -> list[dict]:
        """Validate and enrich TTPs with MITRE data."""

        enriched = []
        for ttp in ttps:
            technique_id = ttp.get('technique_id', '')

            if technique_id in self.mitre_techniques:
                mitre_data = self.mitre_techniques[technique_id]
                ttp['validated'] = True
                ttp['mitre_name'] = mitre_data['name']
                ttp['mitre_tactic'] = mitre_data['tactic']
            else:
                ttp['validated'] = False

            enriched.append(ttp)

        return enriched

# Extract TTPs
extractor = TTPExtractor()

report = ThreatReport(
    id="RPT-001",
    title="APT29 Campaign Analysis",
    content="""
    The threat actor gained initial access through spearphishing emails containing
    malicious Word documents. Upon opening, PowerShell scripts were executed to
    download Cobalt Strike beacons. The actors used Mimikatz to dump credentials
    from LSASS memory, then moved laterally using RDP and WMI. Data was exfiltrated
    via HTTPS to actor-controlled infrastructure.
    """,
    source="Internal Analysis",
    published_date=datetime.now()
)

ttps = extractor.extract_ttps(report)
enriched_ttps = extractor.map_to_mitre(ttps)

for ttp in enriched_ttps:
    print(f"{ttp['technique_id']}: {ttp.get('technique_name', 'Unknown')}")
```

---

## Task 2: Campaign Clustering

### Grouping Related Campaigns

```python
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sentence_transformers import SentenceTransformer

class CampaignClusterer:
    def __init__(self):
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        self.tfidf = TfidfVectorizer(max_features=500)

    def create_campaign_vector(self, report: ThreatReport) -> np.ndarray:
        """Create feature vector for campaign."""

        features = []

        # Text embedding of content
        text_embedding = self.encoder.encode(report.content[:2000])
        features.extend(text_embedding)

        # TTP-based features
        ttp_ids = [ttp.get('technique_id', '') for ttp in report.ttps]
        ttp_vector = self._encode_ttps(ttp_ids)
        features.extend(ttp_vector)

        # IOC-based features
        ioc_types = [ioc.get('type', '') for ioc in report.iocs]
        ioc_vector = self._encode_ioc_types(ioc_types)
        features.extend(ioc_vector)

        return np.array(features)

    def _encode_ttps(self, ttp_ids: list[str], num_techniques: int = 50) -> list[float]:
        """One-hot encode TTP IDs."""
        # Simplified - map common techniques to indices
        technique_map = {
            'T1059.001': 0, 'T1566.001': 1, 'T1003.001': 2,
            'T1021.001': 3, 'T1486': 4, 'T1547.001': 5,
            # Add more mappings
        }

        vector = [0.0] * num_techniques
        for ttp_id in ttp_ids:
            if ttp_id in technique_map:
                vector[technique_map[ttp_id]] = 1.0

        return vector

    def _encode_ioc_types(self, ioc_types: list[str]) -> list[float]:
        """Encode IOC type distribution."""
        type_counts = {'ip': 0, 'domain': 0, 'hash': 0, 'email': 0, 'url': 0}

        for ioc_type in ioc_types:
            if ioc_type in type_counts:
                type_counts[ioc_type] += 1

        total = sum(type_counts.values()) or 1
        return [count / total for count in type_counts.values()]

    def cluster_campaigns(self, reports: list[ThreatReport],
                         eps: float = 0.5,
                         min_samples: int = 2) -> dict:
        """Cluster campaigns based on similarity."""

        # Create vectors
        vectors = np.array([self.create_campaign_vector(r) for r in reports])

        # Normalize
        from sklearn.preprocessing import normalize
        vectors_normalized = normalize(vectors)

        # Cluster
        clustering = DBSCAN(eps=eps, min_samples=min_samples, metric='cosine')
        labels = clustering.fit_predict(vectors_normalized)

        # Group by cluster
        clusters = {}
        for i, label in enumerate(labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append({
                'report_id': reports[i].id,
                'title': reports[i].title,
                'source': reports[i].source
            })

        return {
            'num_clusters': len(set(labels)) - (1 if -1 in labels else 0),
            'noise_points': sum(1 for l in labels if l == -1),
            'clusters': clusters
        }

# Cluster campaigns
clusterer = CampaignClusterer()

# Multiple reports
reports = [report]  # Add more reports
cluster_results = clusterer.cluster_campaigns(reports)

print(f"Found {cluster_results['num_clusters']} campaign clusters")
```

---

## Task 3: Actor Profile Generation

### Building Threat Actor Profiles

```python
@dataclass
class ThreatActorProfile:
    name: str
    aliases: list[str]
    first_seen: datetime
    last_seen: datetime
    origin: Optional[str]
    motivation: str  # espionage, financial, hacktivism
    sophistication: str  # low, medium, high, advanced
    target_sectors: list[str]
    target_regions: list[str]
    ttps: list[dict]
    tools: list[str]
    infrastructure: list[dict]
    campaigns: list[str]

class ActorProfiler:
    def __init__(self):
        self.client = anthropic.Anthropic()
        self.known_actors = self._load_known_actors()

    def _load_known_actors(self) -> dict:
        """Load known threat actor database."""
        return {
            'APT29': {
                'aliases': ['Cozy Bear', 'The Dukes', 'YTTRIUM'],
                'origin': 'Russia',
                'motivation': 'espionage',
                'sophistication': 'advanced'
            },
            'APT41': {
                'aliases': ['Winnti', 'Barium', 'Wicked Panda'],
                'origin': 'China',
                'motivation': 'espionage,financial',
                'sophistication': 'advanced'
            },
            'Lazarus': {
                'aliases': ['Hidden Cobra', 'Zinc', 'APT38'],
                'origin': 'North Korea',
                'motivation': 'financial,espionage',
                'sophistication': 'high'
            }
        }

    def generate_profile(self, reports: list[ThreatReport],
                        cluster_info: dict) -> ThreatActorProfile:
        """Generate threat actor profile from clustered reports."""

        # Aggregate TTPs
        all_ttps = []
        all_tools = set()
        all_iocs = []

        for report in reports:
            all_ttps.extend(report.ttps)
            all_iocs.extend(report.iocs)

            # Extract tools from TTPs
            for ttp in report.ttps:
                tools = ttp.get('tools_used', [])
                all_tools.update(tools)

        # Use AI to synthesize profile
        profile_data = self._synthesize_profile(reports, all_ttps, list(all_tools))

        return ThreatActorProfile(
            name=profile_data.get('suggested_name', 'Unknown Actor'),
            aliases=profile_data.get('aliases', []),
            first_seen=min(r.published_date for r in reports),
            last_seen=max(r.published_date for r in reports),
            origin=profile_data.get('origin'),
            motivation=profile_data.get('motivation', 'unknown'),
            sophistication=profile_data.get('sophistication', 'medium'),
            target_sectors=profile_data.get('target_sectors', []),
            target_regions=profile_data.get('target_regions', []),
            ttps=all_ttps,
            tools=list(all_tools),
            infrastructure=[{'type': ioc['type'], 'value': ioc['value']}
                          for ioc in all_iocs[:20]],
            campaigns=[r.id for r in reports]
        )

    def _synthesize_profile(self, reports: list[ThreatReport],
                           ttps: list[dict], tools: list[str]) -> dict:
        """Use AI to synthesize actor profile."""

        report_summaries = [
            {'title': r.title, 'source': r.source}
            for r in reports[:10]
        ]

        prompt = f"""Based on these threat intelligence reports, synthesize a threat actor profile:

## Reports Analyzed
{json.dumps(report_summaries, indent=2)}

## TTPs Observed (sample)
{json.dumps(ttps[:20], indent=2)}

## Tools Used
{tools}

Generate a profile with:
{{
    "suggested_name": "Descriptive name if unknown actor",
    "potential_attribution": "Known group name if matches pattern",
    "confidence": 0.0-1.0,
    "origin": "Country/region if determinable",
    "motivation": "espionage/financial/hacktivism/unknown",
    "sophistication": "low/medium/high/advanced",
    "target_sectors": ["sector1", "sector2"],
    "target_regions": ["region1", "region2"],
    "key_characteristics": ["characteristic1", "characteristic2"],
    "similar_actors": ["actor1", "actor2"]
}}

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            return json.loads(response.content[0].text)
        except json.JSONDecodeError:
            return {}

# Generate profile
profiler = ActorProfiler()
profile = profiler.generate_profile([report], cluster_results)

print(f"Actor: {profile.name}")
print(f"Motivation: {profile.motivation}")
print(f"Sophistication: {profile.sophistication}")
```

---

## Task 4: Attribution Analysis

### Assessing Attribution Confidence

```python
class AttributionAnalyzer:
    def __init__(self):
        self.client = anthropic.Anthropic()
        self.attribution_factors = [
            'infrastructure_overlap',
            'ttp_similarity',
            'tool_reuse',
            'targeting_pattern',
            'timing_correlation',
            'code_similarity',
            'linguistic_indicators'
        ]

    def analyze_attribution(self, profile: ThreatActorProfile,
                           known_actors: dict) -> dict:
        """Analyze attribution to known threat actors."""

        results = {
            'candidates': [],
            'confidence_factors': {},
            'assessment': ''
        }

        for actor_name, actor_data in known_actors.items():
            score = self._calculate_similarity(profile, actor_data)
            if score > 0.3:  # Minimum threshold
                results['candidates'].append({
                    'actor': actor_name,
                    'aliases': actor_data.get('aliases', []),
                    'similarity_score': round(score, 3),
                    'matching_factors': self._get_matching_factors(profile, actor_data)
                })

        # Sort by score
        results['candidates'].sort(key=lambda x: x['similarity_score'], reverse=True)

        # AI assessment
        results['assessment'] = self._generate_assessment(profile, results['candidates'])

        return results

    def _calculate_similarity(self, profile: ThreatActorProfile,
                            known_actor: dict) -> float:
        """Calculate similarity score between profile and known actor."""

        score = 0.0
        factors = 0

        # Motivation match
        if profile.motivation in known_actor.get('motivation', ''):
            score += 0.2
        factors += 1

        # Origin match (if known)
        if profile.origin and profile.origin == known_actor.get('origin'):
            score += 0.3
        factors += 1

        # Sophistication match
        if profile.sophistication == known_actor.get('sophistication'):
            score += 0.15
        factors += 1

        # Tool overlap
        known_tools = set(known_actor.get('tools', []))
        profile_tools = set(profile.tools)
        if known_tools and profile_tools:
            overlap = len(known_tools & profile_tools) / len(known_tools | profile_tools)
            score += overlap * 0.35
        factors += 1

        return score / factors if factors > 0 else 0

    def _get_matching_factors(self, profile: ThreatActorProfile,
                             known_actor: dict) -> list[str]:
        """Get list of matching attribution factors."""

        factors = []

        if profile.motivation in known_actor.get('motivation', ''):
            factors.append('motivation_match')
        if profile.origin == known_actor.get('origin'):
            factors.append('origin_match')
        if profile.sophistication == known_actor.get('sophistication'):
            factors.append('sophistication_match')

        known_tools = set(known_actor.get('tools', []))
        profile_tools = set(profile.tools)
        if known_tools & profile_tools:
            factors.append('tool_overlap')

        return factors

    def _generate_assessment(self, profile: ThreatActorProfile,
                            candidates: list[dict]) -> str:
        """Generate AI attribution assessment."""

        prompt = f"""Provide an attribution assessment for this threat actor:

## Actor Profile
- Name: {profile.name}
- Motivation: {profile.motivation}
- Sophistication: {profile.sophistication}
- Origin: {profile.origin}
- Tools: {profile.tools[:10]}
- TTPs: {[t.get('technique_id') for t in profile.ttps[:10]]}

## Attribution Candidates
{json.dumps(candidates, indent=2)}

Provide:
1. Most likely attribution (if any)
2. Confidence level (high/medium/low/insufficient)
3. Key factors supporting attribution
4. Key factors against attribution
5. Intelligence gaps that need filling
6. Recommendations for further investigation"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Analyze attribution
attr_analyzer = AttributionAnalyzer()
attribution = attr_analyzer.analyze_attribution(profile, profiler.known_actors)

print("Attribution Candidates:")
for candidate in attribution['candidates']:
    print(f"  {candidate['actor']}: {candidate['similarity_score']}")

print("\nAssessment:")
print(attribution['assessment'])
```

---

## Task 5: Complete Profiling Pipeline

### Integrated Threat Actor Profiling System

```python
class ThreatActorProfilingPipeline:
    def __init__(self):
        self.ttp_extractor = TTPExtractor()
        self.clusterer = CampaignClusterer()
        self.profiler = ActorProfiler()
        self.attribution = AttributionAnalyzer()

    def process_reports(self, reports: list[ThreatReport]) -> dict:
        """Complete threat actor profiling pipeline."""

        results = {
            'timestamp': datetime.now().isoformat(),
            'reports_processed': len(reports),
            'profiles': [],
            'attributions': []
        }

        # Step 1: Extract TTPs from all reports
        print("[1/4] Extracting TTPs...")
        for report in reports:
            ttps = self.ttp_extractor.extract_ttps(report)
            report.ttps = self.ttp_extractor.map_to_mitre(ttps)

        # Step 2: Cluster campaigns
        print("[2/4] Clustering campaigns...")
        clusters = self.clusterer.cluster_campaigns(reports)

        # Step 3: Generate profiles for each cluster
        print("[3/4] Generating profiles...")
        for cluster_id, cluster_reports in clusters['clusters'].items():
            if cluster_id == -1:  # Skip noise
                continue

            # Get full reports for cluster
            cluster_report_objs = [
                r for r in reports
                if r.id in [cr['report_id'] for cr in cluster_reports]
            ]

            profile = self.profiler.generate_profile(
                cluster_report_objs, {'id': cluster_id}
            )
            results['profiles'].append(profile)

        # Step 4: Attribution analysis
        print("[4/4] Analyzing attribution...")
        for profile in results['profiles']:
            attribution = self.attribution.analyze_attribution(
                profile, self.profiler.known_actors
            )
            results['attributions'].append({
                'profile_name': profile.name,
                'attribution': attribution
            })

        return results

    def generate_intelligence_report(self, results: dict) -> str:
        """Generate comprehensive intelligence report."""

        prompt = f"""Generate a threat intelligence report from this analysis:

## Analysis Results
- Reports Processed: {results['reports_processed']}
- Actor Profiles Generated: {len(results['profiles'])}

## Profiles
{json.dumps([{
    'name': p.name,
    'motivation': p.motivation,
    'sophistication': p.sophistication,
    'campaigns': len(p.campaigns),
    'ttps': len(p.ttps)
} for p in results['profiles']], indent=2)}

## Attributions
{json.dumps(results['attributions'], indent=2, default=str)}

Generate a formal intelligence report with:
1. Executive Summary
2. Key Findings
3. Actor Profiles (detailed)
4. Attribution Assessment
5. Strategic Implications
6. Recommended Defensive Actions
7. Intelligence Gaps"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Run pipeline
pipeline = ThreatActorProfilingPipeline()
results = pipeline.process_reports([report])

print(f"Generated {len(results['profiles'])} actor profiles")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Poor TTP extraction | Provide more context, use few-shot examples |
| Over-clustering | Increase DBSCAN eps parameter |
| Under-clustering | Decrease eps, lower min_samples |
| Wrong attribution | Add more attribution factors |
| Missing context | Enrich with external threat intel |

---

## Next Steps

- Integrate with MISP for IOC sharing
- Add diamond model analysis
- Build real-time campaign tracking
- Add geographic analysis
- Create threat landscape dashboards

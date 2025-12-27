# Lab 11: AI-Powered Ransomware Detection & Response

Build an AI system that detects ransomware behavior, analyzes samples, and automates incident response.

## Learning Objectives

1. Understand ransomware attack patterns and TTPs
2. Build ML models to detect ransomware behavior
3. Use LLMs to analyze ransom notes and extract IOCs
4. Create automated response playbooks
5. Generate detection rules (YARA/Sigma) from ransomware samples

## Estimated Time

4-5 hours

## Prerequisites

- Completed Labs 03 (Anomaly Detection), 07 (YARA Generator)
- Understanding of file system operations and encryption
- Familiarity with MITRE ATT&CK ransomware techniques

## Background

### Ransomware Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RANSOMWARE KILL CHAIN                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Initial Access    2. Execution       3. Persistence    4. Discovery    │
│  ┌──────────────┐    ┌──────────────┐   ┌──────────────┐  ┌──────────────┐ │
│  │ Phishing     │───►│ Loader/      │──►│ Registry     │─►│ Network      │ │
│  │ Exploit      │    │ Dropper      │   │ Scheduled    │  │ File Shares  │ │
│  │ RDP Brute    │    │              │   │ Task         │  │ AD Enum      │ │
│  └──────────────┘    └──────────────┘   └──────────────┘  └──────────────┘ │
│                                                                    │        │
│  ┌─────────────────────────────────────────────────────────────────┘        │
│  │                                                                          │
│  ▼                                                                          │
│  5. Lateral Movement  6. Collection     7. Exfiltration   8. Impact        │
│  ┌──────────────┐    ┌──────────────┐   ┌──────────────┐  ┌──────────────┐ │
│  │ PsExec       │───►│ Data Staging │──►│ Cloud Upload │─►│ ENCRYPTION   │ │
│  │ WMI          │    │ Compression  │   │ C2 Transfer  │  │ Shadow Del   │ │
│  │ RDP          │    │              │   │              │  │ Ransom Note  │ │
│  └──────────────┘    └──────────────┘   └──────────────┘  └──────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Techniques

| Technique | ID | Description |
|-----------|-----|-------------|
| Data Encrypted for Impact | T1486 | Core ransomware behavior |
| Inhibit System Recovery | T1490 | Deleting shadow copies |
| System Information Discovery | T1082 | Identifying encryption targets |
| File and Directory Discovery | T1083 | Finding files to encrypt |
| Data Destruction | T1485 | Some variants destroy vs encrypt |

## Tasks

### Task 1: Ransomware Behavior Detection (60 min)

Build an ML model to detect ransomware-like file system behavior.

**Behavioral Indicators**:
- Rapid file enumeration
- High-entropy file writes (encrypted content)
- Mass file extension changes
- Shadow copy deletion
- Ransom note creation patterns

```python
# starter/behavior_detector.py
from dataclasses import dataclass
from typing import List, Dict
import numpy as np

@dataclass
class FileEvent:
    """Represents a file system event."""
    timestamp: float
    process_name: str
    operation: str  # CREATE, WRITE, DELETE, RENAME
    file_path: str
    file_extension: str
    entropy: float  # 0-8 (8 = random/encrypted)
    size_bytes: int

class RansomwareBehaviorDetector:
    """
    Detects ransomware behavior from file system events.

    TODO: Implement detection logic for:
    1. High-volume file operations
    2. Entropy-based encryption detection
    3. Suspicious extension patterns
    4. Known ransomware indicators
    """

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        self.baseline_stats = {}

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        # TODO: Implement entropy calculation
        pass

    def analyze_events(self, events: List[FileEvent]) -> Dict:
        """
        Analyze file events for ransomware behavior.

        Returns:
            Dict with detection results and confidence scores
        """
        # TODO: Implement behavioral analysis
        pass

    def detect_encryption_pattern(self, events: List[FileEvent]) -> float:
        """Detect mass encryption patterns."""
        # TODO: Look for high-entropy writes following reads
        pass

    def detect_shadow_deletion(self, events: List[FileEvent]) -> bool:
        """Detect VSS/shadow copy deletion attempts."""
        # TODO: Check for vssadmin, wmic shadowcopy commands
        pass
```

### Task 2: Ransom Note Analyzer (45 min)

Use LLMs to extract intelligence from ransom notes.

```python
# starter/ransom_note_analyzer.py
from anthropic import Anthropic
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class RansomNoteIntel:
    """Extracted intelligence from ransom note."""
    ransomware_family: str
    threat_actor: Optional[str]
    bitcoin_addresses: List[str]
    onion_urls: List[str]
    email_addresses: List[str]
    ransom_amount: Optional[str]
    deadline: Optional[str]
    language_indicators: List[str]
    mitre_techniques: List[str]

class RansomNoteAnalyzer:
    """
    LLM-powered ransom note analysis.

    TODO: Implement analysis pipeline:
    1. Extract IOCs (BTC addresses, .onion URLs, emails)
    2. Identify ransomware family
    3. Assess threat actor sophistication
    4. Map to known campaigns
    """

    def __init__(self):
        self.client = Anthropic()

    def analyze(self, note_content: str) -> RansomNoteIntel:
        """
        Analyze ransom note and extract intelligence.

        TODO: Use Claude to:
        1. Extract all IOCs
        2. Identify ransomware family based on language patterns
        3. Assess professionalism/sophistication
        4. Look for attribution clues
        """
        pass

    def extract_iocs(self, note_content: str) -> Dict[str, List[str]]:
        """Extract indicators of compromise from note."""
        # TODO: Regex + LLM extraction
        pass

    def identify_family(self, note_content: str) -> str:
        """Identify ransomware family from note patterns."""
        # TODO: Compare against known ransom note templates
        pass
```

### Task 3: Automated Response Playbook (45 min)

Create an AI-driven incident response system for ransomware.

```python
# starter/ransomware_responder.py
from enum import Enum
from typing import List, Dict
from dataclasses import dataclass

class ResponseAction(Enum):
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    BLOCK_NETWORK = "block_network"
    PRESERVE_EVIDENCE = "preserve_evidence"
    NOTIFY_TEAM = "notify_team"
    ESCALATE = "escalate"

@dataclass
class IncidentContext:
    """Context about the ransomware incident."""
    affected_hosts: List[str]
    affected_shares: List[str]
    ransomware_family: str
    encryption_progress: float  # 0-100%
    lateral_movement_detected: bool
    exfiltration_detected: bool

class RansomwareResponder:
    """
    Automated ransomware incident response.

    TODO: Implement response logic:
    1. Immediate containment actions
    2. Evidence preservation
    3. Scope assessment
    4. Recovery planning
    """

    def __init__(self, auto_contain: bool = False):
        self.auto_contain = auto_contain

    def assess_severity(self, context: IncidentContext) -> str:
        """Assess incident severity (Critical/High/Medium/Low)."""
        # TODO: Score based on spread, data sensitivity, etc.
        pass

    def generate_playbook(self, context: IncidentContext) -> List[ResponseAction]:
        """
        Generate response playbook based on incident context.

        TODO: Create prioritized action list
        """
        pass

    def containment_recommendation(self, context: IncidentContext) -> Dict:
        """
        Generate containment recommendations.

        TODO: Consider:
        - Network isolation scope
        - Process termination
        - Share access revocation
        """
        pass

    def recovery_plan(self, context: IncidentContext) -> Dict:
        """
        Generate recovery plan.

        TODO: Include:
        - Backup availability check
        - Decryptor availability
        - Rebuild timeline
        """
        pass
```

### Task 4: Detection Rule Generator (45 min)

Generate YARA and Sigma rules for ransomware detection.

```python
# starter/rule_generator.py
from typing import List, Dict

class RansomwareRuleGenerator:
    """
    Generate detection rules for ransomware.

    TODO: Implement rule generation for:
    1. YARA rules for ransomware binaries
    2. Sigma rules for behavioral detection
    3. Network signatures
    """

    def generate_yara_rule(
        self,
        family_name: str,
        strings: List[str],
        behaviors: List[str]
    ) -> str:
        """
        Generate YARA rule for ransomware family.

        TODO: Include:
        - Ransom note strings
        - Encryption routine patterns
        - File markers
        - Import patterns
        """
        pass

    def generate_sigma_rule(
        self,
        technique: str,
        indicators: Dict
    ) -> str:
        """
        Generate Sigma rule for behavioral detection.

        TODO: Cover:
        - VSS deletion (T1490)
        - Mass file encryption (T1486)
        - Suspicious process chains
        """
        pass

    def generate_network_signature(
        self,
        c2_patterns: List[str]
    ) -> str:
        """Generate Suricata/Snort rules for C2 detection."""
        pass
```

### Task 5: Full Detection Pipeline (45 min)

Integrate all components into a unified detection system.

```python
# starter/detection_pipeline.py
from behavior_detector import RansomwareBehaviorDetector
from ransom_note_analyzer import RansomNoteAnalyzer
from ransomware_responder import RansomwareResponder
from rule_generator import RansomwareRuleGenerator

class RansomwareDetectionPipeline:
    """
    End-to-end ransomware detection and response.

    Pipeline:
    1. Monitor file system events
    2. Detect ransomware behavior
    3. Analyze any ransom notes found
    4. Generate response recommendations
    5. Create detection rules for future
    """

    def __init__(self):
        self.behavior_detector = RansomwareBehaviorDetector()
        self.note_analyzer = RansomNoteAnalyzer()
        self.responder = RansomwareResponder()
        self.rule_generator = RansomwareRuleGenerator()

    def process_alert(self, alert_data: Dict) -> Dict:
        """
        Process ransomware alert through full pipeline.

        TODO: Implement end-to-end processing
        """
        pass

    def generate_report(self, incident_id: str) -> str:
        """Generate incident report with LLM assistance."""
        pass
```

## Success Criteria

- [ ] Behavior detector achieves >90% detection rate on test data
- [ ] Ransom note analyzer extracts IOCs with >95% accuracy
- [ ] Response playbook covers all critical actions
- [ ] Generated YARA rules detect sample ransomware families
- [ ] Generated Sigma rules produce no false positives on baseline

## Sample Data

Test your implementation with the provided sample data:

- `data/file_events.json` - Simulated file system events (benign + ransomware)
- `data/ransom_notes/` - Sample ransom notes from various families
- `data/ransomware_samples.json` - Metadata about ransomware samples
- `data/baseline_events.json` - Normal file system activity for baseline

## Resources

- [MITRE ATT&CK: Ransomware](https://attack.mitre.org/software/?platforms=ransomware)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [Ransomware Tracker](https://ransomwaretracker.abuse.ch/)

## Extension Challenges

1. **Real-time Detection**: Implement streaming detection with sub-second latency
2. **Decryptor Finder**: Build a system to check for available decryptors
3. **Threat Intel Integration**: Correlate with threat intel feeds
4. **Recovery Automation**: Automate backup restoration workflows

---

> **Stuck?** See the [Lab 11 Walkthrough](../../docs/walkthroughs/lab11-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 12 - Ransomware Attack Simulation & Purple Team](../lab12-ransomware-simulation/)
# Lab 16b: AI-Powered Threat Actors - Solution Walkthrough

## Overview

Understand how adversaries leverage AI in modern attacks, detect AI-generated content, and build defenses against AI-powered threats.

**Time:** 1.5-2 hours
**Difficulty:** Expert (Bridge Lab)

---

## Task 1: AI-Generated Phishing Detection

### Understanding AI Phishing Indicators

AI-generated phishing differs from traditional phishing:

```python
from dataclasses import dataclass
from typing import List, Optional
import re
import math


@dataclass
class PhishingAnalysis:
    """Results of AI-generated content analysis."""

    text: str
    ai_probability: float  # 0.0-1.0
    indicators: List[str]
    confidence: str  # low, medium, high
    recommendations: List[str]


class AIPhishingDetector:
    """
    Detect AI-generated phishing content.

    Key indicators of AI-generated text:
    - Unusually consistent quality across messages
    - Lack of typical human typos/mistakes
    - Generic personalization patterns
    - Statistically "too perfect" language
    """

    def __init__(self):
        # Common AI-generated phrases
        self.ai_phrases = [
            "I hope this email finds you well",
            "As per our previous conversation",
            "Please find attached",
            "At your earliest convenience",
            "I wanted to reach out",
            "I trust this message finds you",
            "Thank you for your prompt attention",
        ]

        # Urgency patterns common in AI phishing
        self.urgency_patterns = [
            r"urgent.*action.*required",
            r"immediate.*attention",
            r"within.*\d+.*hours",
            r"failure.*to.*respond",
            r"account.*suspend",
            r"verify.*immediately",
        ]

    def analyze(self, email_text: str) -> PhishingAnalysis:
        """Analyze email for AI-generated phishing indicators."""
        indicators = []
        scores = []

        # Check for perfect grammar
        score, indicator = self._check_perfect_grammar(email_text)
        if indicator:
            indicators.append(indicator)
        scores.append(score)

        # Check for urgency patterns
        score, indicator = self._check_urgency(email_text)
        if indicator:
            indicators.append(indicator)
        scores.append(score)

        # Check for template patterns
        score, indicator = self._check_templates(email_text)
        if indicator:
            indicators.append(indicator)
        scores.append(score)

        # Calculate overall probability
        ai_probability = sum(scores) / len(scores) if scores else 0.0

        confidence = "high" if ai_probability > 0.8 else "medium" if ai_probability > 0.5 else "low"

        return PhishingAnalysis(
            text=email_text[:200] + "..." if len(email_text) > 200 else email_text,
            ai_probability=ai_probability,
            indicators=indicators,
            confidence=confidence,
            recommendations=self._get_recommendations(ai_probability),
        )

    def _check_perfect_grammar(self, text: str) -> tuple[float, Optional[str]]:
        """AI text often lacks common human errors."""
        human_errors = [r"\bi\b", r"\.{2}", r"\s{2,}"]
        error_count = sum(1 for p in human_errors if re.search(p, text))

        if len(text) > 500 and error_count == 0:
            return 0.7, "Suspiciously perfect grammar (no typical human errors)"
        return 0.2, None

    def _check_urgency(self, text: str) -> tuple[float, Optional[str]]:
        """Check for generic urgency patterns."""
        matches = sum(1 for p in self.urgency_patterns if re.search(p, text.lower()))
        if matches >= 2:
            return 0.7, f"Generic urgency patterns detected ({matches} found)"
        return 0.2, None

    def _check_templates(self, text: str) -> tuple[float, Optional[str]]:
        """Check for common AI template patterns."""
        matches = sum(1 for phrase in self.ai_phrases if phrase.lower() in text.lower())
        if matches >= 2:
            return 0.6, f"AI-common phrases detected ({matches} found)"
        return 0.2, None

    def _get_recommendations(self, probability: float) -> List[str]:
        """Generate recommendations based on risk level."""
        if probability > 0.7:
            return [
                "HIGH RISK: Treat as likely AI-generated phishing",
                "Do NOT click any links or download attachments",
                "Verify sender through out-of-band communication",
                "Report to security team immediately",
            ]
        elif probability > 0.4:
            return [
                "MEDIUM RISK: Exercise caution",
                "Verify sender identity before taking action",
                "Check for lookalike domains",
            ]
        return ["LOW RISK: Standard vigilance recommended"]


# Usage
detector = AIPhishingDetector()

# Test with suspicious email
suspicious_email = """
Dear Valued Customer,

I hope this email finds you well. I wanted to reach out regarding your account.

Urgent action is required within 24 hours to verify your credentials.
Failure to respond will result in account suspension.

Please find attached the verification form.

Thank you for your prompt attention to this matter.

Best regards,
IT Security Team
"""

result = detector.analyze(suspicious_email)
print(f"AI Probability: {result.ai_probability:.1%}")
print(f"Confidence: {result.confidence}")
print(f"Indicators: {result.indicators}")
```

**Key Insight:** AI-generated phishing lacks the "human fingerprint" - typos, inconsistent tone, and natural language quirks that humans exhibit.

---

## Task 2: Voice Cloning Defense

### Building a Vishing Detection Framework

```python
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum


class DeepfakeIndicator(Enum):
    """Indicators of synthetic voice."""

    UNNATURAL_PAUSES = "unnatural_pauses"
    BREATHING_ANOMALIES = "breathing_anomalies"
    RESPONSE_LATENCY = "response_latency"
    CONTEXT_CONFUSION = "context_confusion"


@dataclass
class VoiceAnalysis:
    """Analysis of potential voice deepfake."""

    synthetic_probability: float
    indicators: List[DeepfakeIndicator]
    confidence: str
    recommendations: List[str]


class VishingDetector:
    """
    Framework for detecting AI-powered vishing attacks.

    Key defense strategies:
    - Out-of-band verification
    - Challenge questions
    - Code word systems
    """

    def __init__(self):
        self.high_risk_scenarios = [
            "wire_transfer_request",
            "credential_request",
            "mfa_bypass_request",
            "emergency_access_request",
        ]

        # Questions that expose AI limitations
        self.challenge_questions = [
            "What did we discuss in our last meeting?",
            "Can you remind me of the project we worked on together?",
            "What floor is your office on?",
        ]

    def analyze_call(
        self,
        request_type: str,
        urgency_level: str,
        callback_offered: bool,
        verification_accepted: bool,
    ) -> VoiceAnalysis:
        """Analyze call context for vishing indicators."""
        indicators = []
        risk_score = 0.0

        # High-risk request types
        if request_type in self.high_risk_scenarios:
            risk_score += 0.3
            indicators.append(DeepfakeIndicator.CONTEXT_CONFUSION)

        # Urgency is a major red flag
        if urgency_level in ["critical", "emergency"]:
            risk_score += 0.25

        # Refusing callback/verification is suspicious
        if not callback_offered:
            risk_score += 0.2
        if not verification_accepted:
            risk_score += 0.25

        confidence = "high" if risk_score > 0.6 else "medium" if risk_score > 0.3 else "low"

        return VoiceAnalysis(
            synthetic_probability=min(risk_score, 1.0),
            indicators=indicators,
            confidence=confidence,
            recommendations=self._get_recommendations(risk_score),
        )

    def get_verification_protocol(self, caller_claims: str) -> List[str]:
        """Get verification steps based on claimed identity."""
        protocol = [
            "1. Tell caller you need to verify - legitimate callers expect this",
            "2. Get a callback number and verify it independently",
            "3. Call back using a known-good number from company directory",
            "4. Use a pre-established code word if available",
        ]

        if "executive" in caller_claims.lower() or "ceo" in caller_claims.lower():
            protocol.extend([
                "5. EXECUTIVE CLAIM: Contact their assistant directly",
                "6. Verify through secondary channel (Slack, Teams)",
            ])

        return protocol

    def _get_recommendations(self, risk_score: float) -> List[str]:
        """Generate recommendations based on risk."""
        if risk_score > 0.6:
            return [
                "⚠️ HIGH RISK: Likely vishing attempt",
                "Do NOT comply with any requests",
                "End the call and report to security",
            ]
        elif risk_score > 0.3:
            return [
                "⚡ ELEVATED RISK: Proceed with caution",
                "Require callback verification",
                "Use challenge questions",
            ]
        return ["✅ LOWER RISK: Follow standard procedures"]


# Real-world example: Scattered Spider attack pattern
print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│              SCATTERED SPIDER VISHING ATTACK PATTERN                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. RECONNAISSANCE                                                          │
│     • Scrape LinkedIn for IT helpdesk staff names                          │
│     • Identify new employees (easier targets)                               │
│                                                                             │
│  2. VOICE CLONING PREPARATION                                              │
│     • Obtain voice samples from earnings calls, YouTube                    │
│     • Generate synthetic voice of known executive/IT staff                  │
│                                                                             │
│  3. VISHING ATTACK                                                          │
│     • Call helpdesk claiming to be executive                               │
│     • Request MFA reset or password reset                                   │
│     • Use urgency: "I'm about to board a flight"                           │
│                                                                             │
│  DEFENSE: Out-of-band verification, code words, security awareness         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
""")
```

---

## Task 3: AI-Enhanced Malware Analysis

### Understanding AI-Assisted Malware Development

```python
from dataclasses import dataclass
from typing import List, Set
from enum import Enum


class AIEnhancement(Enum):
    """Types of AI enhancement in malware."""

    POLYMORPHIC_CODE = "polymorphic_code"
    EVASION_OPTIMIZATION = "evasion_optimization"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class MalwareAIIndicators:
    """Indicators of AI-assisted malware development."""

    ai_enhancements: List[AIEnhancement]
    detection_difficulty: str
    analysis_notes: str


class AIMalwareAnalyzer:
    """
    Analyze malware samples for AI-assisted development indicators.

    AI-generated malware often shows:
    - Rapid variant generation
    - Sophisticated string obfuscation
    - Intelligent anti-analysis
    - Adaptive behavior
    """

    def __init__(self):
        self.ai_indicators = {
            "rapid_variants": "Multiple variants with similar functionality",
            "smart_obfuscation": "Obfuscation optimized for specific AV products",
            "adaptive_behavior": "Malware changes behavior based on environment",
        }

        # Known AI-assisted malware families
        self.ai_families = {
            "BlackMamba": {
                "description": "Polymorphic keylogger using LLM",
                "ai_capability": "Runtime payload generation via GPT",
            },
            "WormGPT_Variants": {
                "description": "Malware generated using underground LLM tools",
                "ai_capability": "Phishing and malware code generation",
            },
        }

    def get_detection_strategies(self, enhancement_type: AIEnhancement) -> List[str]:
        """Get detection strategies for specific AI enhancement types."""
        strategies = {
            AIEnhancement.POLYMORPHIC_CODE: [
                "Focus on behavioral detection over signatures",
                "Monitor for code generation API calls",
                "Use ML-based detection that generalizes across variants",
            ],
            AIEnhancement.EVASION_OPTIMIZATION: [
                "Implement defense-in-depth (multiple detection layers)",
                "Use canary/honeypot techniques",
                "Deploy behavioral analysis in sandboxes",
            ],
            AIEnhancement.SOCIAL_ENGINEERING: [
                "Train users on AI-generated content indicators",
                "Implement email authentication (DMARC, DKIM, SPF)",
                "Use AI-based phishing detection (fight AI with AI)",
            ],
        }

        return strategies.get(enhancement_type, [
            "Monitor for unusual patterns",
            "Implement behavioral detection",
        ])


# Key defender insights
print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│                 AI-ENHANCED MALWARE: DEFENDER'S GUIDE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  OFFENSIVE AI CAPABILITIES         │  DEFENSIVE COUNTERMEASURES            │
│  ──────────────────────────────    │  ───────────────────────────────      │
│                                    │                                        │
│  • Polymorphic code generation     │  • Behavioral analysis                 │
│                                    │                                        │
│  • Automated vulnerability         │  • Aggressive patching                 │
│    discovery & exploitation        │                                        │
│                                    │                                        │
│  • Evasion testing at scale        │  • Defense-in-depth                    │
│                                    │                                        │
│  • Social engineering at scale     │  • AI-powered email filtering          │
│                                    │                                        │
│  KEY INSIGHT: Traditional signatures are losing effectiveness.              │
│  The future of detection is behavioral and AI-assisted.                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
""")
```

---

## Task 4: AI Threat Intelligence Generation

### Creating Intelligence Products About AI-Powered Threats

```python
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime
from enum import Enum


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AIThreatReport:
    """Structured AI threat intelligence report."""

    title: str
    tlp: str  # Traffic Light Protocol
    report_date: str
    threat_level: ThreatLevel
    executive_summary: str
    ai_techniques_observed: List[str]
    mitigations: List[str]


class AIThreatIntelGenerator:
    """Generate threat intelligence about AI-powered attacks."""

    def __init__(self):
        self.threat_db = {
            "ai_phishing_patterns": {
                "description": "LLM-generated BEC attacks",
                "indicators": [
                    "Perfect grammar in traditionally error-prone campaigns",
                    "Highly personalized content referencing real projects",
                ],
                "mitigations": [
                    "AI-based email filtering",
                    "Out-of-band verification for financial requests",
                ],
            },
            "voice_cloning_attacks": {
                "description": "Deepfake audio of executives for fraud",
                "indicators": [
                    "Unusual requests via phone only",
                    "Resistance to callback verification",
                ],
                "mitigations": [
                    "Code word verification system",
                    "Mandatory callback protocols",
                ],
            },
        }

    def generate_brief(self, threat_type: str) -> AIThreatReport:
        """Generate a threat intelligence brief."""
        threat_info = self.threat_db.get(threat_type, {})

        summaries = {
            "ai_phishing_patterns": (
                "Threat actors are leveraging LLMs to generate highly convincing "
                "phishing emails at scale. These AI-generated messages lack traditional "
                "indicators like grammatical errors. Organizations should implement "
                "AI-based email filtering and strengthen verification procedures."
            ),
            "voice_cloning_attacks": (
                "Voice cloning technology has enabled sophisticated vishing attacks. "
                "Recent high-profile incidents (e.g., Scattered Spider campaigns) "
                "demonstrate the effectiveness of this technique. Organizations must "
                "implement out-of-band verification and code word systems."
            ),
        }

        return AIThreatReport(
            title=f"AI Threat Brief: {threat_type.replace('_', ' ').title()}",
            tlp="AMBER",
            report_date=datetime.now().strftime("%Y-%m-%d"),
            threat_level=ThreatLevel.HIGH,
            executive_summary=summaries.get(threat_type, "AI-powered threats require adaptive defenses."),
            ai_techniques_observed=[threat_info.get("description", "")],
            mitigations=threat_info.get("mitigations", []),
        )


# Generate a threat brief
generator = AIThreatIntelGenerator()
report = generator.generate_brief("voice_cloning_attacks")
print(f"Title: {report.title}")
print(f"TLP: {report.tlp}")
print(f"Threat Level: {report.threat_level.value}")
print(f"\nExecutive Summary:\n{report.executive_summary}")
print(f"\nMitigations:")
for mitigation in report.mitigations:
    print(f"  • {mitigation}")
```

---

## Key Takeaways

1. **AI-Generated Content Detection**
   - Look for "too perfect" grammar and consistency
   - Watch for template-like patterns and generic personalization
   - Use statistical analysis to identify AI fingerprints

2. **Voice Cloning Defenses**
   - Always verify through out-of-band communication
   - Implement code word systems for sensitive requests
   - Train staff to recognize high-risk scenarios

3. **AI-Enhanced Malware**
   - Signature-based detection is losing effectiveness
   - Focus on behavioral detection and ML-based classification
   - Implement defense-in-depth strategies

4. **Threat Intelligence**
   - Stay current on AI-powered threat actor TTPs
   - Share intelligence within trusted communities
   - Continuously update detection capabilities

---

## Resources

| Resource | Description |
|----------|-------------|
| [MITRE ATLAS](https://atlas.mitre.org) | Adversarial ML Threat Matrix |
| [AI Village](https://aivillage.org) | DEF CON AI security research |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | AI Risk Management Framework |

---

## Next Steps

- **Lab 17**: Adversarial ML - Attack and defend ML models
- **Lab 20**: LLM Red Teaming - Offensive security for LLM systems
- **Lab 20b**: AI-Assisted Purple Team - Collaborative AI exercises

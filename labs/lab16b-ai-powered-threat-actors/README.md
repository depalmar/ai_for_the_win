# Lab 16b: Understanding AI-Powered Threat Actors

## How Adversaries Leverage AI in Modern Attacks

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AI-POWERED THREAT LANDSCAPE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RECONNAISSANCE          WEAPONIZATION           DELIVERY                  │
│   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐            │
│   │ AI-Powered  │        │ AI-Generated│        │ Deepfake    │            │
│   │ OSINT       │───────>│ Malware     │───────>│ Phishing    │            │
│   │ Scraping    │        │ Variants    │        │ Vishing     │            │
│   └─────────────┘        └─────────────┘        └─────────────┘            │
│                                                                             │
│   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐            │
│   │ Automated   │        │ Polymorphic │        │ AI-Enhanced │            │
│   │ Target      │───────>│ Code        │───────>│ Social      │            │
│   │ Research    │        │ Generation  │        │ Engineering │            │
│   └─────────────┘        └─────────────┘        └─────────────┘            │
│                                                                             │
│   DEFENSE IMPLICATIONS:                                                     │
│   • Traditional signatures fail against AI-generated variants               │
│   • Human-based detection struggles with deepfakes                          │
│   • Volume of attacks increases exponentially                               │
│   • Personalization makes phishing more effective                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. **Understand AI attack vectors** - How threat actors leverage LLMs and generative AI
2. **Identify AI-generated content** - Detect synthetic phishing, deepfakes, and generated text
3. **Analyze AI-enhanced malware** - Recognize polymorphic and AI-assisted code
4. **Build detection strategies** - Create defenses against AI-powered attacks
5. **Assess organizational risk** - Evaluate exposure to AI-enhanced threats

---

## ⏱️ Estimated Time

1.5-2 hours (with AI assistance)

---

## 📋 Prerequisites

- Completed Lab 16 (Threat Actor Profiling)
- Understanding of social engineering concepts
- Familiarity with phishing detection
- Basic knowledge of generative AI

---

## 📖 Background

### The AI-Powered Threat Evolution

Threat actors have rapidly adopted AI tools to enhance their operations:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    THREAT ACTOR AI ADOPTION TIMELINE                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  2020-2021          2022-2023              2024-2025           2026+        │
│  ──────────         ──────────             ──────────          ─────        │
│  • Basic chatbot    • LLM-powered          • Deepfake          • Autonomous │
│    phishing           phishing               voice/video         attack     │
│  • Simple text      • AI code              • AI malware          chains    │
│    generation         assistance             development       • AI vs AI   │
│  • Automated        • Synthetic            • Automated           warfare   │
│    reconnaissance     identities             reconnaissance    • Adaptive   │
│                     • Voice cloning        • Real-time           evasion   │
│                                              adaptation                     │
│                                                                             │
│  SOPHISTICATION: ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━▶     │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Attack Categories

| Category | AI Enhancement | Detection Difficulty |
|----------|---------------|---------------------|
| **Phishing** | Personalized, grammatically perfect, context-aware | High |
| **Vishing** | Voice cloning, real-time conversation | Very High |
| **Malware** | Polymorphic variants, evasion-aware | High |
| **Social Engineering** | Deep research, synthetic personas | Very High |
| **Reconnaissance** | Automated OSINT, correlation | Medium |
| **Credential Attacks** | Smart password generation | Medium |

### Known AI-Enabled Attack Groups

| Group | AI Capabilities | Notable Campaigns |
|-------|----------------|-------------------|
| **FIN7/Carbanak** | AI-generated business emails | Financial sector BEC |
| **Scattered Spider** | Voice cloning for helpdesk attacks | UK Retail Breaches 2025 |
| **Various APTs** | LLM-assisted code development | Multiple campaigns |
| **Cybercrime Groups** | Deepfake CEO fraud | Wire transfer fraud |

---

## 🔬 Lab Exercises

### Exercise 1: AI-Generated Phishing Detection

Learn to identify characteristics of AI-generated phishing content.

```python
"""
Exercise 1: Build an AI-generated phishing detector

AI-generated phishing often has subtle tells:
- Unusually consistent quality across messages
- Lack of typical human typos/mistakes
- Generic personalization patterns
- Statistically "too perfect" language
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
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
    
    This detector looks for patterns common in AI-generated text
    that may indicate automated phishing campaigns.
    """
    
    def __init__(self):
        # Patterns that suggest AI generation
        self.ai_indicators = {
            "perfect_grammar": self._check_perfect_grammar,
            "generic_urgency": self._check_generic_urgency,
            "template_patterns": self._check_template_patterns,
            "unusual_formality": self._check_formality,
            "statistical_anomalies": self._check_statistical_anomalies,
        }
        
        # Common AI phishing phrases
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
    
    def analyze(self, email_text: str, metadata: Optional[Dict] = None) -> PhishingAnalysis:
        """
        Analyze email for AI-generated phishing indicators.
        
        Args:
            email_text: The email body text
            metadata: Optional email metadata (sender, headers, etc.)
            
        Returns:
            PhishingAnalysis with probability and indicators
        """
        indicators = []
        scores = []
        
        # Run all indicator checks
        for name, check_func in self.ai_indicators.items():
            score, indicator = check_func(email_text)
            if indicator:
                indicators.append(indicator)
            scores.append(score)
        
        # Calculate overall AI probability
        ai_probability = sum(scores) / len(scores) if scores else 0.0
        
        # Determine confidence
        if ai_probability > 0.8:
            confidence = "high"
        elif ai_probability > 0.5:
            confidence = "medium"
        else:
            confidence = "low"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(ai_probability, indicators)
        
        return PhishingAnalysis(
            text=email_text[:200] + "..." if len(email_text) > 200 else email_text,
            ai_probability=ai_probability,
            indicators=indicators,
            confidence=confidence,
            recommendations=recommendations,
        )
    
    def _check_perfect_grammar(self, text: str) -> tuple[float, Optional[str]]:
        """Check for suspiciously perfect grammar."""
        # AI text often lacks common human errors
        human_errors = [
            r"\bi\b",  # Uncapitalized "i"
            r"\.{2}",  # Double periods
            r"\s{2,}",  # Multiple spaces
            r"[a-z]\.[A-Z]",  # Missing space after period
        ]
        
        error_count = sum(1 for p in human_errors if re.search(p, text))
        
        # Suspiciously perfect if no errors in long text
        if len(text) > 500 and error_count == 0:
            return 0.7, "Suspiciously perfect grammar (no typical human errors)"
        elif len(text) > 200 and error_count == 0:
            return 0.4, "Very clean text (minimal human errors)"
        
        return 0.1, None
    
    def _check_generic_urgency(self, text: str) -> tuple[float, Optional[str]]:
        """Check for generic urgency patterns."""
        text_lower = text.lower()
        matches = []
        
        for pattern in self.urgency_patterns:
            if re.search(pattern, text_lower):
                matches.append(pattern)
        
        if len(matches) >= 3:
            return 0.9, f"Multiple urgency patterns detected ({len(matches)} found)"
        elif len(matches) >= 2:
            return 0.6, "Generic urgency language detected"
        elif len(matches) == 1:
            return 0.3, None
        
        return 0.1, None
    
    def _check_template_patterns(self, text: str) -> tuple[float, Optional[str]]:
        """Check for common AI template patterns."""
        text_lower = text.lower()
        matches = sum(1 for phrase in self.ai_phrases if phrase.lower() in text_lower)
        
        if matches >= 3:
            return 0.8, f"Multiple AI-common phrases detected ({matches} found)"
        elif matches >= 2:
            return 0.5, "Template-like language patterns"
        
        return 0.2, None
    
    def _check_formality(self, text: str) -> tuple[float, Optional[str]]:
        """Check for unusual formality consistency."""
        # AI often maintains unnaturally consistent formality
        formal_words = ["therefore", "consequently", "furthermore", "regarding", "pertaining"]
        informal_words = ["gonna", "wanna", "kinda", "stuff", "things"]
        
        formal_count = sum(1 for w in formal_words if w in text.lower())
        informal_count = sum(1 for w in informal_words if w in text.lower())
        
        # Pure formal with no informal in business context is suspicious
        if formal_count >= 3 and informal_count == 0:
            return 0.5, "Unnaturally consistent formal tone"
        
        return 0.2, None
    
    def _check_statistical_anomalies(self, text: str) -> tuple[float, Optional[str]]:
        """Check for statistical patterns common in AI text."""
        words = text.split()
        if len(words) < 50:
            return 0.2, None
        
        # Check sentence length variance (AI tends to be consistent)
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if len(sentences) >= 5:
            lengths = [len(s.split()) for s in sentences]
            avg_len = sum(lengths) / len(lengths)
            variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
            std_dev = math.sqrt(variance)
            
            # Very consistent sentence lengths suggest AI
            if std_dev < 3 and avg_len > 10:
                return 0.6, "Unusually consistent sentence structure"
        
        return 0.2, None
    
    def _generate_recommendations(
        self, probability: float, indicators: List[str]
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if probability > 0.7:
            recommendations.extend([
                "HIGH RISK: Treat as likely AI-generated phishing",
                "Do NOT click any links or download attachments",
                "Verify sender through out-of-band communication",
                "Report to security team immediately",
            ])
        elif probability > 0.4:
            recommendations.extend([
                "MEDIUM RISK: Exercise caution with this message",
                "Verify sender identity before taking action",
                "Check for lookalike domains in sender address",
                "Contact IT if requesting sensitive information",
            ])
        else:
            recommendations.append("LOW RISK: Standard vigilance recommended")
        
        return recommendations


# TODO: Implement the detector and test with sample emails
# detector = AIPhishingDetector()
# result = detector.analyze(suspicious_email)
# print(f"AI Probability: {result.ai_probability:.1%}")
```

### Exercise 2: Deepfake Audio Detection

Understanding voice cloning attacks used in vishing campaigns.

```python
"""
Exercise 2: Deepfake voice detection framework

Voice cloning has enabled sophisticated vishing attacks.
Understanding detection indicators helps build defenses.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class DeepfakeIndicator(Enum):
    """Indicators of synthetic voice."""
    
    UNNATURAL_PAUSES = "unnatural_pauses"
    BREATHING_ANOMALIES = "breathing_anomalies"
    EMOTION_INCONSISTENCY = "emotion_inconsistency"
    BACKGROUND_ARTIFACTS = "background_artifacts"
    RESPONSE_LATENCY = "response_latency"
    PHRASE_REPETITION = "phrase_repetition"
    CONTEXT_CONFUSION = "context_confusion"


@dataclass
class VoiceAnalysis:
    """Analysis of potential voice deepfake."""
    
    synthetic_probability: float
    indicators: List[DeepfakeIndicator]
    confidence: str
    call_metadata: Dict
    recommendations: List[str]


class VishingDetector:
    """
    Framework for detecting AI-powered vishing attacks.
    
    Focuses on behavioral and contextual indicators since
    audio analysis requires specialized tools.
    """
    
    def __init__(self):
        # High-risk scenarios for voice cloning
        self.high_risk_scenarios = [
            "wire_transfer_request",
            "credential_request",
            "mfa_bypass_request",
            "emergency_access_request",
            "vendor_payment_change",
        ]
        
        # Questions that expose AI limitations
        self.challenge_questions = [
            "What did we discuss in our last meeting?",
            "Can you remind me of the project we worked on together?",
            "What's your opinion on [recent company event]?",
            "Tell me about your weekend plans",
            "What floor is your office on?",
        ]
    
    def analyze_call_context(
        self,
        caller_claims: str,
        request_type: str,
        urgency_level: str,
        callback_offered: bool,
        verification_accepted: bool,
    ) -> VoiceAnalysis:
        """
        Analyze call context for vishing indicators.
        
        Args:
            caller_claims: Who the caller claims to be
            request_type: What they're requesting
            urgency_level: How urgent they claim it is
            callback_offered: Did they offer a callback number?
            verification_accepted: Did they accept verification?
            
        Returns:
            VoiceAnalysis with risk assessment
        """
        indicators = []
        risk_score = 0.0
        
        # Check for high-risk request types
        if request_type in self.high_risk_scenarios:
            risk_score += 0.3
            indicators.append(DeepfakeIndicator.CONTEXT_CONFUSION)
        
        # Urgency is a major red flag
        if urgency_level in ["critical", "emergency", "immediate"]:
            risk_score += 0.25
        
        # Refusing callback is suspicious
        if not callback_offered:
            risk_score += 0.2
            indicators.append(DeepfakeIndicator.RESPONSE_LATENCY)
        
        # Refusing verification is very suspicious
        if not verification_accepted:
            risk_score += 0.25
        
        # Determine confidence
        confidence = "high" if risk_score > 0.6 else "medium" if risk_score > 0.3 else "low"
        
        recommendations = self._generate_vishing_recommendations(
            risk_score, caller_claims, request_type
        )
        
        return VoiceAnalysis(
            synthetic_probability=min(risk_score, 1.0),
            indicators=indicators,
            confidence=confidence,
            call_metadata={
                "caller_claims": caller_claims,
                "request_type": request_type,
                "urgency": urgency_level,
            },
            recommendations=recommendations,
        )
    
    def get_verification_protocol(self, caller_claims: str) -> List[str]:
        """
        Get verification steps based on claimed identity.
        
        Returns protocol to verify caller is legitimate.
        """
        base_protocol = [
            "1. Tell caller you need to verify - legitimate callers expect this",
            "2. Get a callback number and verify it independently",
            "3. Call back using a known-good number from company directory",
            "4. Use a pre-established code word if available",
        ]
        
        if "executive" in caller_claims.lower() or "ceo" in caller_claims.lower():
            base_protocol.extend([
                "5. EXECUTIVE CLAIM: Contact their assistant directly",
                "6. Verify through secondary channel (Slack, Teams, etc.)",
                "7. Involve your manager before taking any action",
            ])
        
        if "it" in caller_claims.lower() or "helpdesk" in caller_claims.lower():
            base_protocol.extend([
                "5. IT CLAIM: Check if ticket exists for this request",
                "6. Verify caller's employee ID and department",
                "7. Never provide credentials over the phone",
            ])
        
        return base_protocol
    
    def _generate_vishing_recommendations(
        self, risk_score: float, caller_claims: str, request_type: str
    ) -> List[str]:
        """Generate recommendations based on risk."""
        recs = []
        
        if risk_score > 0.6:
            recs.extend([
                "⚠️ HIGH RISK: Likely vishing attempt",
                "Do NOT comply with any requests",
                "End the call and report to security",
                "Document caller ID, time, and request details",
            ])
        elif risk_score > 0.3:
            recs.extend([
                "⚡ ELEVATED RISK: Proceed with caution",
                "Require callback verification before any action",
                "Use challenge questions to verify identity",
                "Involve supervisor for sensitive requests",
            ])
        else:
            recs.append("✅ LOWER RISK: Follow standard verification procedures")
        
        return recs


# Real-world case study: Scattered Spider attack pattern
SCATTERED_SPIDER_TTPs = """
┌─────────────────────────────────────────────────────────────────────────────┐
│              SCATTERED SPIDER VISHING ATTACK PATTERN                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. RECONNAISSANCE                                                          │
│     • Scrape LinkedIn for IT helpdesk staff names                          │
│     • Identify new employees (easier targets)                               │
│     • Research company's IT processes                                       │
│                                                                             │
│  2. VOICE CLONING PREPARATION                                              │
│     • Obtain voice samples from earnings calls, YouTube, podcasts          │
│     • Generate synthetic voice of known executive/IT staff                  │
│     • Prepare scripts for common scenarios                                  │
│                                                                             │
│  3. VISHING ATTACK                                                          │
│     • Call helpdesk claiming to be executive                               │
│     • Request MFA reset or password reset                                   │
│     • Use urgency: "I'm about to board a flight"                           │
│     • May use deepfake video for Teams/Zoom calls                          │
│                                                                             │
│  4. ACCESS & LATERAL MOVEMENT                                               │
│     • Use obtained credentials to access VPN/Okta                          │
│     • Deploy remote access tools (AnyDesk, TeamViewer)                     │
│     • Move to high-value targets (finance, crypto wallets)                 │
│                                                                             │
│  DEFENSE: Out-of-band verification, code words, security awareness         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
"""
```

### Exercise 3: AI-Enhanced Malware Analysis

Understanding how AI assists malware development.

```python
"""
Exercise 3: AI-enhanced malware pattern analysis

Threat actors use AI to:
- Generate polymorphic variants
- Evade detection signatures
- Automate exploit development
- Create convincing lures
"""

from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum


class AIEnhancement(Enum):
    """Types of AI enhancement in malware."""
    
    POLYMORPHIC_CODE = "polymorphic_code"
    EVASION_OPTIMIZATION = "evasion_optimization"
    PAYLOAD_GENERATION = "payload_generation"
    C2_COMMUNICATION = "c2_communication"
    TARGET_SELECTION = "target_selection"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class MalwareAIIndicators:
    """Indicators of AI-assisted malware development."""
    
    sample_hash: str
    ai_enhancements: List[AIEnhancement]
    variant_count: int
    evasion_techniques: List[str]
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
        # Indicators of AI-assisted development
        self.ai_indicators = {
            "rapid_variants": "Multiple variants with similar functionality but different signatures",
            "smart_obfuscation": "Obfuscation that appears optimized for specific AV products",
            "adaptive_behavior": "Malware that changes behavior based on environment",
            "generated_strings": "Strings that appear LLM-generated (convincing but generic)",
            "optimized_evasion": "Evasion techniques that seem systematically tested",
        }
        
        # Known AI-assisted malware families
        self.ai_families = {
            "BlackMamba": {
                "description": "Proof-of-concept polymorphic keylogger using LLM",
                "ai_capability": "Runtime payload generation via GPT",
                "first_seen": "2023",
            },
            "WormGPT_Variants": {
                "description": "Malware generated using underground LLM tools",
                "ai_capability": "Phishing and malware code generation",
                "first_seen": "2023",
            },
        }
    
    def analyze_variant_patterns(
        self,
        samples: List[Dict],
    ) -> Dict[str, any]:
        """
        Analyze multiple samples for AI-generated variant patterns.
        
        AI-generated variants often show:
        - Similar structure, different implementation
        - Consistent functionality with varying signatures
        - Systematic mutation patterns
        """
        if len(samples) < 2:
            return {"error": "Need multiple samples for variant analysis"}
        
        analysis = {
            "total_samples": len(samples),
            "variant_clusters": [],
            "ai_probability": 0.0,
            "indicators": [],
        }
        
        # Check for systematic variation patterns
        # (Simplified - real analysis would compare code structure)
        
        unique_hashes = set(s.get("hash", "") for s in samples)
        common_functions = self._find_common_functions(samples)
        
        if len(unique_hashes) > 10 and len(common_functions) > 5:
            analysis["ai_probability"] = 0.7
            analysis["indicators"].append(
                "High variant count with common functionality suggests automated generation"
            )
        
        return analysis
    
    def _find_common_functions(self, samples: List[Dict]) -> Set[str]:
        """Find functions common across samples."""
        if not samples:
            return set()
        
        # Get functions from first sample
        common = set(samples[0].get("functions", []))
        
        # Intersect with all other samples
        for sample in samples[1:]:
            common &= set(sample.get("functions", []))
        
        return common
    
    def get_detection_strategies(
        self,
        enhancement_type: AIEnhancement
    ) -> List[str]:
        """
        Get detection strategies for specific AI enhancement types.
        """
        strategies = {
            AIEnhancement.POLYMORPHIC_CODE: [
                "Focus on behavioral detection over signatures",
                "Monitor for code generation API calls",
                "Track process behavior patterns across variants",
                "Use ML-based detection that generalizes across variants",
            ],
            AIEnhancement.EVASION_OPTIMIZATION: [
                "Implement defense-in-depth (multiple detection layers)",
                "Use canary/honeypot techniques",
                "Monitor for systematic AV testing behavior",
                "Deploy behavioral analysis in sandboxes",
            ],
            AIEnhancement.SOCIAL_ENGINEERING: [
                "Train users on AI-generated content indicators",
                "Implement email authentication (DMARC, DKIM, SPF)",
                "Use AI-based phishing detection",
                "Require out-of-band verification for sensitive requests",
            ],
        }
        
        return strategies.get(enhancement_type, [
            "Monitor for unusual patterns",
            "Implement behavioral detection",
            "Share IOCs with threat intel community",
        ])


# Key concepts for defenders
AI_MALWARE_LANDSCAPE = """
┌─────────────────────────────────────────────────────────────────────────────┐
│                 AI-ENHANCED MALWARE: DEFENDER'S GUIDE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  OFFENSIVE AI CAPABILITIES         │  DEFENSIVE COUNTERMEASURES            │
│  ──────────────────────────────    │  ───────────────────────────────      │
│                                    │                                        │
│  • Polymorphic code generation     │  • Behavioral analysis                 │
│    (new variants per victim)       │    (focus on actions, not code)       │
│                                    │                                        │
│  • Automated vulnerability         │  • Aggressive patching                 │
│    discovery & exploitation        │    (reduce attack surface)            │
│                                    │                                        │
│  • Evasion testing at scale        │  • Defense-in-depth                    │
│    (test against multiple AVs)     │    (multiple detection layers)        │
│                                    │                                        │
│  • Social engineering at scale     │  • AI-powered email filtering          │
│    (personalized phishing)         │    (fight AI with AI)                 │
│                                    │                                        │
│  • Adaptive C2 communication       │  • Network behavior analysis           │
│    (evade traffic analysis)        │    (pattern detection)                │
│                                    │                                        │
│  KEY INSIGHT: Traditional signatures are losing effectiveness.              │
│  The future of detection is behavioral and AI-assisted.                    │
│                                    │                                        │
└─────────────────────────────────────────────────────────────────────────────┘
"""
```

### Exercise 4: Building AI Threat Intelligence

Create intelligence products about AI-powered threats.

```python
"""
Exercise 4: AI Threat Intelligence Generation

Build structured intelligence about how threat actors use AI.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AIThreatActor:
    """Profile of a threat actor's AI capabilities."""
    
    name: str
    aliases: List[str]
    ai_capabilities: List[str]
    observed_techniques: List[str]
    target_sectors: List[str]
    sophistication: str  # basic, intermediate, advanced
    first_ai_use_observed: str
    assessment_confidence: str


@dataclass
class AIThreatReport:
    """Structured AI threat intelligence report."""
    
    title: str
    tlp: str  # Traffic Light Protocol
    report_date: str
    threat_level: ThreatLevel
    executive_summary: str
    ai_techniques_observed: List[str]
    indicators: List[Dict]
    mitigations: List[str]
    references: List[str]


class AIThreatIntelGenerator:
    """
    Generate threat intelligence about AI-powered attacks.
    
    Use AI to help analyze and summarize AI-related threats.
    """
    
    def __init__(self, llm=None):
        self.llm = llm
        self.threat_db = self._load_threat_database()
    
    def _load_threat_database(self) -> Dict:
        """Load known AI threat patterns."""
        return {
            "ai_phishing_patterns": [
                {
                    "name": "LLM-generated BEC",
                    "description": "Business email compromise using AI-written emails",
                    "indicators": [
                        "Perfect grammar in traditionally error-prone campaigns",
                        "Highly personalized content referencing real projects",
                        "Consistent style across multiple targets",
                    ],
                    "mitigations": [
                        "AI-based email filtering",
                        "Out-of-band verification for financial requests",
                        "Training on AI content detection",
                    ],
                },
            ],
            "voice_cloning_attacks": [
                {
                    "name": "Executive Voice Cloning",
                    "description": "Deepfake audio of executives for fraud",
                    "indicators": [
                        "Unusual requests via phone only",
                        "Resistance to callback verification",
                        "Urgency combined with authority claims",
                    ],
                    "mitigations": [
                        "Code word verification system",
                        "Mandatory callback protocols",
                        "Multi-person authorization for transfers",
                    ],
                },
            ],
            "ai_malware_development": [
                {
                    "name": "LLM-Assisted Malware",
                    "description": "Malware with AI-generated components",
                    "indicators": [
                        "Rapid variant generation",
                        "Sophisticated obfuscation patterns",
                        "Code that references LLM concepts",
                    ],
                    "mitigations": [
                        "Behavioral detection over signatures",
                        "ML-based malware classification",
                        "Sandbox analysis with behavior focus",
                    ],
                },
            ],
        }
    
    def generate_threat_brief(
        self,
        threat_type: str,
        recent_incidents: Optional[List[Dict]] = None,
    ) -> AIThreatReport:
        """
        Generate a threat intelligence brief about AI threats.
        
        Args:
            threat_type: Type of AI threat to brief on
            recent_incidents: Recent incident data to include
            
        Returns:
            Structured threat intelligence report
        """
        # Get base threat info
        threat_info = self.threat_db.get(threat_type, {})
        
        # Build report
        report = AIThreatReport(
            title=f"AI Threat Brief: {threat_type.replace('_', ' ').title()}",
            tlp="AMBER",  # Default to AMBER for sharing within community
            report_date=datetime.now().strftime("%Y-%m-%d"),
            threat_level=ThreatLevel.HIGH,
            executive_summary=self._generate_executive_summary(threat_type, threat_info),
            ai_techniques_observed=self._extract_techniques(threat_info),
            indicators=self._extract_indicators(threat_info),
            mitigations=self._extract_mitigations(threat_info),
            references=self._get_references(threat_type),
        )
        
        return report
    
    def _generate_executive_summary(
        self, threat_type: str, threat_info: List[Dict]
    ) -> str:
        """Generate executive summary."""
        summaries = {
            "ai_phishing_patterns": (
                "Threat actors are leveraging Large Language Models to generate "
                "highly convincing phishing emails at scale. These AI-generated "
                "messages lack traditional indicators like grammatical errors and "
                "can be personalized using scraped OSINT data. Organizations should "
                "implement AI-based email filtering and strengthen verification "
                "procedures for sensitive requests."
            ),
            "voice_cloning_attacks": (
                "Voice cloning technology has enabled sophisticated vishing attacks "
                "where threat actors impersonate executives and IT staff. Recent "
                "high-profile incidents (e.g., Scattered Spider campaigns) demonstrate "
                "the effectiveness of this technique. Organizations must implement "
                "out-of-band verification and consider code word systems for "
                "high-risk requests."
            ),
            "ai_malware_development": (
                "Threat actors are using AI tools to accelerate malware development, "
                "generate polymorphic variants, and optimize evasion techniques. "
                "This reduces the time and expertise needed to create effective "
                "malware. Defenders should prioritize behavioral detection over "
                "signature-based approaches."
            ),
        }
        return summaries.get(threat_type, "AI-powered threats require adaptive defenses.")
    
    def _extract_techniques(self, threat_info: List[Dict]) -> List[str]:
        """Extract observed techniques."""
        techniques = []
        for item in threat_info:
            if "description" in item:
                techniques.append(item["description"])
        return techniques
    
    def _extract_indicators(self, threat_info: List[Dict]) -> List[Dict]:
        """Extract indicators of compromise/activity."""
        indicators = []
        for item in threat_info:
            for ind in item.get("indicators", []):
                indicators.append({"type": "behavioral", "value": ind})
        return indicators
    
    def _extract_mitigations(self, threat_info: List[Dict]) -> List[str]:
        """Extract mitigation recommendations."""
        mitigations = []
        for item in threat_info:
            mitigations.extend(item.get("mitigations", []))
        return list(set(mitigations))  # Deduplicate
    
    def _get_references(self, threat_type: str) -> List[str]:
        """Get relevant references."""
        references = {
            "ai_phishing_patterns": [
                "https://attack.mitre.org/techniques/T1566/",
                "https://www.ncsc.gov.uk/collection/phishing-scams",
            ],
            "voice_cloning_attacks": [
                "https://attack.mitre.org/techniques/T1598/",
                "https://www.fbi.gov/news/stories/voice-cloning-scams",
            ],
            "ai_malware_development": [
                "https://attack.mitre.org/techniques/T1027/",
                "https://atlas.mitre.org/",
            ],
        }
        return references.get(threat_type, [])


# TODO: Use the generator to create threat briefs
# generator = AIThreatIntelGenerator()
# report = generator.generate_threat_brief("voice_cloning_attacks")
# print(report.executive_summary)
```

---

## 🧪 Challenge Exercises

### Challenge 1: AI Content Detection Pipeline

Build a comprehensive pipeline to detect AI-generated content across multiple channels (email, chat, documents).

### Challenge 2: Deepfake Detection Framework

Create a framework for organizational deepfake detection, including procedures, technology recommendations, and training materials.

### Challenge 3: AI Threat Hunting Playbook

Develop threat hunting queries and procedures specifically for AI-powered attack patterns.

---

## 📚 Resources

### Industry Research

| Resource | Description | Link |
|----------|-------------|------|
| MITRE ATLAS | Adversarial ML Threat Matrix | [atlas.mitre.org](https://atlas.mitre.org) |
| AI Village | DEF CON AI security research | [aivillage.org](https://aivillage.org) |
| NIST AI RMF | AI Risk Management Framework | [nist.gov](https://www.nist.gov/itl/ai-risk-management-framework) |

### Threat Intelligence

| Source | Focus | Link |
|--------|-------|------|
| **Google TAG** | AI-enabled threat actors | [blog.google/threat-analysis-group](https://blog.google/threat-analysis-group/) |
| **Microsoft Security** | Deepfake and AI threats | [microsoft.com/security/blog](https://www.microsoft.com/security/blog/) |
| **Recorded Future** | AI threat landscape | [recordedfuture.com](https://www.recordedfuture.com) |

### SANS Resources

| Resource | Description |
|----------|-------------|
| **SEC595** | Applied Data Science and AI/ML for Cybersecurity |
| **FOR578** | Cyber Threat Intelligence |

---

## ✅ Success Criteria

You've successfully completed this lab when you can:

- [ ] Identify indicators of AI-generated phishing content
- [ ] Explain voice cloning attack patterns and defenses
- [ ] Analyze malware for AI-assisted development indicators
- [ ] Generate threat intelligence about AI-powered attacks
- [ ] Recommend organizational defenses against AI threats

---

## 🔗 Next Steps

- **Lab 17**: Adversarial ML - Attack and defend ML models
- **Lab 20**: LLM Red Teaming - Offensive security for LLM systems
- **Lab 20b**: AI-Assisted Purple Team - Collaborative AI exercises

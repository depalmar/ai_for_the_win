"""
Lab 16b: Understanding AI-Powered Threat Actors - Solution

Complete implementation of AI threat detection capabilities.
"""

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PhishingAnalysis:
    """Results of AI-generated content analysis."""

    text: str
    ai_probability: float
    indicators: List[str]
    confidence: str
    recommendations: List[str]


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


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AIThreatReport:
    """Structured AI threat intelligence report."""

    title: str
    tlp: str
    report_date: str
    threat_level: ThreatLevel
    executive_summary: str
    ai_techniques_observed: List[str]
    indicators: List[Dict]
    mitigations: List[str]
    references: List[str]


# =============================================================================
# Exercise 1: AI-Generated Phishing Detection (Complete)
# =============================================================================


class AIPhishingDetector:
    """
    Detect AI-generated phishing content.

    This detector looks for patterns common in AI-generated text
    that may indicate automated phishing campaigns.
    """

    def __init__(self):
        self.ai_indicators = {
            "perfect_grammar": self._check_perfect_grammar,
            "generic_urgency": self._check_generic_urgency,
            "template_patterns": self._check_template_patterns,
            "unusual_formality": self._check_formality,
            "statistical_anomalies": self._check_statistical_anomalies,
        }

        self.ai_phrases = [
            "I hope this email finds you well",
            "As per our previous conversation",
            "Please find attached",
            "At your earliest convenience",
            "I wanted to reach out",
            "I trust this message finds you",
            "Thank you for your prompt attention",
            "I am reaching out regarding",
            "Please do not hesitate to contact",
            "Looking forward to hearing from you",
        ]

        self.urgency_patterns = [
            r"urgent.*action.*required",
            r"immediate.*attention",
            r"within.*\d+.*hours",
            r"failure.*to.*respond",
            r"account.*suspend",
            r"verify.*immediately",
            r"time.*sensitive",
            r"act.*now",
            r"expires?\s*(today|soon|shortly)",
        ]

    def analyze(self, email_text: str, metadata: Optional[Dict] = None) -> PhishingAnalysis:
        """
        Analyze email for AI-generated phishing indicators.
        """
        indicators = []
        scores = []

        for name, check_func in self.ai_indicators.items():
            score, indicator = check_func(email_text)
            if indicator:
                indicators.append(indicator)
            scores.append(score)

        ai_probability = sum(scores) / len(scores) if scores else 0.0

        if ai_probability > 0.8:
            confidence = "high"
        elif ai_probability > 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        recommendations = self._generate_recommendations(ai_probability, indicators)

        return PhishingAnalysis(
            text=email_text[:200] + "..." if len(email_text) > 200 else email_text,
            ai_probability=ai_probability,
            indicators=indicators,
            confidence=confidence,
            recommendations=recommendations,
        )

    def _check_perfect_grammar(self, text: str) -> tuple:
        """Check for suspiciously perfect grammar."""
        human_errors = [
            r"\bi\b",  # Uncapitalized "i"
            r"\.{2}",  # Double periods
            r"\s{2,}",  # Multiple spaces
            r"[a-z]\.[A-Z]",  # Missing space after period
            r"!{2,}",  # Multiple exclamation marks
            r"\?\?",  # Multiple question marks
        ]

        error_count = sum(1 for p in human_errors if re.search(p, text))

        if len(text) > 500 and error_count == 0:
            return 0.7, "Suspiciously perfect grammar (no typical human errors)"
        elif len(text) > 200 and error_count == 0:
            return 0.4, "Very clean text (minimal human errors)"

        return 0.1, None

    def _check_generic_urgency(self, text: str) -> tuple:
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
            return 0.3, "Single urgency pattern found"

        return 0.1, None

    def _check_template_patterns(self, text: str) -> tuple:
        """Check for common AI template patterns."""
        text_lower = text.lower()
        matches = sum(1 for phrase in self.ai_phrases if phrase.lower() in text_lower)

        if matches >= 3:
            return 0.8, f"Multiple AI-common phrases detected ({matches} found)"
        elif matches >= 2:
            return 0.5, "Template-like language patterns"
        elif matches == 1:
            return 0.25, None

        return 0.1, None

    def _check_formality(self, text: str) -> tuple:
        """Check for unusual formality consistency."""
        formal_words = [
            "therefore",
            "consequently",
            "furthermore",
            "regarding",
            "pertaining",
            "pursuant",
            "hereby",
            "aforementioned",
        ]
        informal_words = [
            "gonna",
            "wanna",
            "kinda",
            "stuff",
            "things",
            "yeah",
            "ok",
            "lol",
            "btw",
            "asap",
            "fyi",
        ]

        text_lower = text.lower()
        formal_count = sum(1 for w in formal_words if w in text_lower)
        informal_count = sum(1 for w in informal_words if w in text_lower)

        if formal_count >= 3 and informal_count == 0:
            return 0.5, "Unnaturally consistent formal tone"

        return 0.2, None

    def _check_statistical_anomalies(self, text: str) -> tuple:
        """Check for statistical patterns common in AI text."""
        words = text.split()
        if len(words) < 50:
            return 0.2, None

        sentences = re.split(r"[.!?]+", text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if len(sentences) >= 5:
            lengths = [len(s.split()) for s in sentences]
            avg_len = sum(lengths) / len(lengths)
            variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
            std_dev = math.sqrt(variance)

            if std_dev < 3 and avg_len > 10:
                return 0.6, "Unusually consistent sentence structure"

        return 0.2, None

    def _generate_recommendations(self, probability: float, indicators: List[str]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if probability > 0.7:
            recommendations.extend(
                [
                    "⚠️ HIGH RISK: Treat as likely AI-generated phishing",
                    "Do NOT click any links or download attachments",
                    "Verify sender through out-of-band communication",
                    "Report to security team immediately",
                ]
            )
        elif probability > 0.4:
            recommendations.extend(
                [
                    "⚡ MEDIUM RISK: Exercise caution with this message",
                    "Verify sender identity before taking action",
                    "Check for lookalike domains in sender address",
                    "Contact IT if requesting sensitive information",
                ]
            )
        else:
            recommendations.append("✅ LOW RISK: Standard vigilance recommended")

        return recommendations


# =============================================================================
# Exercise 2: Vishing Detection Framework (Complete)
# =============================================================================


class VishingDetector:
    """
    Framework for detecting AI-powered vishing attacks.
    """

    def __init__(self):
        self.high_risk_scenarios = [
            "wire_transfer_request",
            "credential_request",
            "mfa_bypass_request",
            "emergency_access_request",
            "vendor_payment_change",
            "password_reset_request",
            "vpn_access_request",
        ]

        self.challenge_questions = [
            "What did we discuss in our last meeting?",
            "Can you remind me of the project we worked on together?",
            "What's your opinion on [recent company event]?",
            "Tell me about your weekend plans",
            "What floor is your office on?",
            "Who else is on your team?",
        ]

    def analyze_call(
        self,
        request_type: str,
        urgency_level: str,
        callback_offered: bool,
        verification_accepted: bool,
        caller_claims: str = "",
    ) -> Dict:
        """
        Simplified call analysis for testing.
        Returns a dict with synthetic_probability.
        """
        result = self.analyze_call_context(
            caller_claims=caller_claims,
            request_type=request_type,
            urgency_level=urgency_level,
            callback_offered=callback_offered,
            verification_accepted=verification_accepted,
        )
        return {
            "synthetic_probability": result.synthetic_probability,
            "confidence": result.confidence,
            "indicators": [i.value for i in result.indicators],
            "recommendations": result.recommendations,
        }

    def analyze_call_context(
        self,
        caller_claims: str,
        request_type: str,
        urgency_level: str,
        callback_offered: bool,
        verification_accepted: bool,
    ) -> VoiceAnalysis:
        """Analyze call context for vishing indicators."""
        indicators = []
        risk_score = 0.0

        # Check for high-risk request types
        if request_type in self.high_risk_scenarios:
            risk_score += 0.3
            indicators.append(DeepfakeIndicator.CONTEXT_CONFUSION)

        # Urgency is a major red flag
        if urgency_level in ["critical", "emergency", "immediate"]:
            risk_score += 0.25
            indicators.append(DeepfakeIndicator.RESPONSE_LATENCY)
        elif urgency_level in ["high", "urgent"]:
            risk_score += 0.15

        # Refusing callback is suspicious
        if not callback_offered:
            risk_score += 0.2

        # Refusing verification is very suspicious
        if not verification_accepted:
            risk_score += 0.25
            indicators.append(DeepfakeIndicator.CONTEXT_CONFUSION)

        # Executive impersonation adds risk
        executive_terms = ["ceo", "cfo", "cto", "president", "director", "vp"]
        if any(term in caller_claims.lower() for term in executive_terms):
            risk_score += 0.1

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
                "callback_offered": callback_offered,
                "verification_accepted": verification_accepted,
            },
            recommendations=recommendations,
        )

    def get_verification_protocol(self, caller_claims: str) -> List[str]:
        """Get verification steps based on claimed identity."""
        base_protocol = [
            "1. Tell caller you need to verify - legitimate callers expect this",
            "2. Get a callback number and verify it independently",
            "3. Call back using a known-good number from company directory",
            "4. Use a pre-established code word if available",
        ]

        caller_lower = caller_claims.lower()

        if any(term in caller_lower for term in ["executive", "ceo", "cfo", "cto", "president"]):
            base_protocol.extend(
                [
                    "5. EXECUTIVE CLAIM: Contact their assistant directly",
                    "6. Verify through secondary channel (Slack, Teams, email)",
                    "7. Involve your manager before taking any action",
                    "8. Never process financial requests from voice-only requests",
                ]
            )

        elif any(term in caller_lower for term in ["it", "helpdesk", "tech support"]):
            base_protocol.extend(
                [
                    "5. IT CLAIM: Check if ticket exists for this request",
                    "6. Verify caller's employee ID and department",
                    "7. Never provide credentials over the phone",
                    "8. IT should never need your password - they can reset it",
                ]
            )

        elif any(term in caller_lower for term in ["vendor", "supplier", "contractor"]):
            base_protocol.extend(
                [
                    "5. VENDOR CLAIM: Verify against vendor contact list",
                    "6. Call the vendor using known-good number",
                    "7. Verify any payment changes through procurement",
                    "8. Require email confirmation from known address",
                ]
            )

        return base_protocol

    def _generate_vishing_recommendations(
        self, risk_score: float, caller_claims: str, request_type: str
    ) -> List[str]:
        """Generate recommendations based on risk."""
        recs = []

        if risk_score > 0.6:
            recs.extend(
                [
                    "⚠️ HIGH RISK: Likely vishing attempt",
                    "Do NOT comply with any requests",
                    "End the call and report to security",
                    "Document caller ID, time, and request details",
                    "Warn colleagues about this attack pattern",
                ]
            )
        elif risk_score > 0.3:
            recs.extend(
                [
                    "⚡ ELEVATED RISK: Proceed with caution",
                    "Require callback verification before any action",
                    "Use challenge questions to verify identity",
                    "Involve supervisor for sensitive requests",
                ]
            )
        else:
            recs.append("✅ LOWER RISK: Follow standard verification procedures")

        return recs


# =============================================================================
# Exercise 3: AI Malware Analysis (Complete)
# =============================================================================


class AIMalwareAnalyzer:
    """
    Analyze malware samples for AI-assisted development indicators.
    """

    def __init__(self):
        self.ai_indicators = {
            "rapid_variants": "Multiple variants with similar functionality but different signatures",
            "smart_obfuscation": "Obfuscation optimized for specific AV products",
            "adaptive_behavior": "Malware that changes behavior based on environment",
            "generated_strings": "Strings that appear LLM-generated",
            "optimized_evasion": "Systematically tested evasion techniques",
        }

        self.ai_families = {
            "BlackMamba": {
                "description": "Proof-of-concept polymorphic keylogger using LLM",
                "ai_capability": "Runtime payload generation via GPT",
                "first_seen": "2023",
                "techniques": ["T1059.006", "T1027"],
            },
            "WormGPT_Variants": {
                "description": "Malware generated using underground LLM tools",
                "ai_capability": "Phishing and malware code generation",
                "first_seen": "2023",
                "techniques": ["T1566", "T1059"],
            },
        }

    def analyze_variant_patterns(self, samples: List[Dict]) -> Dict:
        """Analyze multiple samples for AI-generated variant patterns."""
        if len(samples) < 2:
            return {"error": "Need multiple samples for variant analysis"}

        analysis = {
            "total_samples": len(samples),
            "variant_clusters": [],
            "ai_probability": 0.0,
            "indicators": [],
            "analysis_timestamp": datetime.now().isoformat(),
        }

        unique_hashes = set(s.get("hash", "") for s in samples)
        common_functions = self._find_common_functions(samples)

        if len(unique_hashes) > 10 and len(common_functions) > 5:
            analysis["ai_probability"] = 0.7
            analysis["indicators"].append(
                "High variant count with common functionality suggests automated generation"
            )
        elif len(unique_hashes) > 5 and len(common_functions) > 3:
            analysis["ai_probability"] = 0.5
            analysis["indicators"].append("Moderate variant count with shared code patterns")

        # Check for rapid generation timestamps
        timestamps = [s.get("first_seen") for s in samples if s.get("first_seen")]
        if len(timestamps) >= 5:
            # Multiple variants in short time = likely automated
            analysis["indicators"].append(
                f"Multiple variants ({len(timestamps)}) detected - possible automation"
            )

        return analysis

    def _find_common_functions(self, samples: List[Dict]) -> Set[str]:
        """Find functions common across samples."""
        if not samples:
            return set()

        common = set(samples[0].get("functions", []))
        for sample in samples[1:]:
            common &= set(sample.get("functions", []))

        return common

    def get_detection_strategies(self, enhancement_type: AIEnhancement) -> List[str]:
        """Get detection strategies for specific AI enhancement types."""
        strategies = {
            AIEnhancement.POLYMORPHIC_CODE: [
                "Focus on behavioral detection over signatures",
                "Monitor for code generation API calls",
                "Track process behavior patterns across variants",
                "Use ML-based detection that generalizes across variants",
                "Deploy YARA rules based on code structure, not strings",
            ],
            AIEnhancement.EVASION_OPTIMIZATION: [
                "Implement defense-in-depth (multiple detection layers)",
                "Use canary/honeypot techniques",
                "Monitor for systematic AV testing behavior",
                "Deploy behavioral analysis in sandboxes",
                "Use heuristic detection for suspicious patterns",
            ],
            AIEnhancement.SOCIAL_ENGINEERING: [
                "Train users on AI-generated content indicators",
                "Implement email authentication (DMARC, DKIM, SPF)",
                "Use AI-based phishing detection",
                "Require out-of-band verification for sensitive requests",
                "Deploy link analysis and sandboxing",
            ],
            AIEnhancement.C2_COMMUNICATION: [
                "Monitor for unusual DNS patterns",
                "Deploy ML-based network traffic analysis",
                "Track beaconing behavior patterns",
                "Implement JA3/JA3S fingerprinting",
                "Use threat intel for known C2 infrastructure",
            ],
        }

        return strategies.get(
            enhancement_type,
            [
                "Monitor for unusual patterns",
                "Implement behavioral detection",
                "Share IOCs with threat intel community",
            ],
        )


# =============================================================================
# Exercise 4: AI Threat Intelligence Generator (Complete)
# =============================================================================


class AIThreatIntelGenerator:
    """Generate threat intelligence about AI-powered attacks."""

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
                    "mitre_techniques": ["T1566.001", "T1534"],
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
                    "mitre_techniques": ["T1598.001", "T1656"],
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
                    "mitre_techniques": ["T1027", "T1059"],
                },
            ],
            "deepfake_attacks": [
                {
                    "name": "Video Conference Deepfakes",
                    "description": "Real-time deepfake video in meetings",
                    "indicators": [
                        "Unusual lighting/background artifacts",
                        "Lip sync issues",
                        "Unnatural eye movements",
                    ],
                    "mitigations": [
                        "Require multi-factor verification",
                        "Use secure channels for sensitive discussions",
                        "Train employees on deepfake indicators",
                    ],
                    "mitre_techniques": ["T1598", "T1656"],
                },
            ],
        }

    def generate_threat_brief(
        self,
        threat_type: str,
        recent_incidents: Optional[List[Dict]] = None,
    ) -> AIThreatReport:
        """Generate a threat intelligence brief."""
        threat_info = self.threat_db.get(threat_type, [])

        report = AIThreatReport(
            title=f"AI Threat Brief: {threat_type.replace('_', ' ').title()}",
            tlp="AMBER",
            report_date=datetime.now().strftime("%Y-%m-%d"),
            threat_level=ThreatLevel.HIGH,
            executive_summary=self._generate_executive_summary(threat_type, threat_info),
            ai_techniques_observed=self._extract_techniques(threat_info),
            indicators=self._extract_indicators(threat_info),
            mitigations=self._extract_mitigations(threat_info),
            references=self._get_references(threat_type),
        )

        return report

    def _generate_executive_summary(self, threat_type: str, threat_info: List[Dict]) -> str:
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
            "deepfake_attacks": (
                "Real-time deepfake technology has advanced to the point where "
                "video conference impersonation is feasible. Attackers can create "
                "convincing video of known individuals for social engineering. "
                "Organizations should implement multi-factor verification for "
                "sensitive decisions and train staff on deepfake indicators."
            ),
        }
        return summaries.get(threat_type, "AI-powered threats require adaptive defenses.")

    def _extract_techniques(self, threat_info: List[Dict]) -> List[str]:
        """Extract observed techniques."""
        techniques = []
        for item in threat_info:
            if "description" in item:
                techniques.append(item["description"])
            techniques.extend(item.get("mitre_techniques", []))
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
        return list(set(mitigations))

    def _get_references(self, threat_type: str) -> List[str]:
        """Get relevant references."""
        references = {
            "ai_phishing_patterns": [
                "https://attack.mitre.org/techniques/T1566/",
                "https://atlas.mitre.org/",
            ],
            "voice_cloning_attacks": [
                "https://attack.mitre.org/techniques/T1598/",
                "https://www.cisa.gov/topics/cyber-threats-and-advisories",
            ],
            "ai_malware_development": [
                "https://attack.mitre.org/techniques/T1027/",
                "https://atlas.mitre.org/",
            ],
            "deepfake_attacks": [
                "https://attack.mitre.org/techniques/T1656/",
                "https://www.nist.gov/itl/ai-risk-management-framework",
            ],
        }
        return references.get(threat_type, ["https://atlas.mitre.org/"])

    def assess_organizational_risk(self, org_profile: Dict) -> Dict:
        """Assess organization's risk to AI-powered threats."""
        risk_score = 0.0
        risk_factors = []

        # High-profile executives increase voice cloning risk
        if org_profile.get("public_executives", 0) > 3:
            risk_score += 0.2
            risk_factors.append("Multiple public-facing executives increase voice cloning risk")

        # Financial sector is high-target
        high_target_sectors = ["financial", "healthcare", "government", "defense"]
        if org_profile.get("sector", "").lower() in high_target_sectors:
            risk_score += 0.2
            risk_factors.append(f"Sector ({org_profile.get('sector')}) is high-value target")

        # Large employee count = larger attack surface
        if org_profile.get("employee_count", 0) > 1000:
            risk_score += 0.15
            risk_factors.append("Large employee count increases social engineering surface")

        # Check for existing controls
        if not org_profile.get("has_security_awareness_training", False):
            risk_score += 0.15
            risk_factors.append("Missing security awareness training")

        if not org_profile.get("has_email_filtering", False):
            risk_score += 0.15
            risk_factors.append("Missing AI-based email filtering")

        if not org_profile.get("has_callback_verification", False):
            risk_score += 0.15
            risk_factors.append("Missing callback verification procedures")

        # Determine risk level
        if risk_score > 0.7:
            risk_level = "CRITICAL"
        elif risk_score > 0.5:
            risk_level = "HIGH"
        elif risk_score > 0.3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "overall_risk_score": min(risk_score, 1.0),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendations": self._generate_risk_recommendations(risk_factors),
        }

    def _generate_risk_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []

        if any("voice cloning" in f for f in risk_factors):
            recommendations.append("Implement code word system for executive verification")

        if any("awareness training" in f for f in risk_factors):
            recommendations.append("Deploy AI threat awareness training program")

        if any("email filtering" in f for f in risk_factors):
            recommendations.append("Implement AI-based email security solution")

        if any("callback" in f for f in risk_factors):
            recommendations.append(
                "Establish mandatory callback verification for sensitive requests"
            )

        recommendations.append("Conduct AI threat tabletop exercises")
        recommendations.append("Share threat intelligence with industry peers")

        return recommendations


# =============================================================================
# Main Demo
# =============================================================================


def main():
    """Demonstrate AI threat detection capabilities."""

    print("=" * 70)
    print("Lab 16b: Understanding AI-Powered Threat Actors - SOLUTION")
    print("=" * 70)

    # Load sample data
    data_path = Path(__file__).parent.parent / "data" / "ai_threat_samples.json"

    if data_path.exists():
        with open(data_path) as f:
            samples = json.load(f)
    else:
        samples = {
            "phishing_emails": [
                {
                    "id": "ai_generated_1",
                    "subject": "Urgent: Wire Transfer Required",
                    "body": (
                        "I hope this email finds you well. I am reaching out regarding "
                        "an urgent matter that requires your immediate attention. As per "
                        "our previous conversation, we need to process a wire transfer "
                        "within the next 24 hours. Please find attached the payment "
                        "details. Thank you for your prompt attention to this matter. "
                        "At your earliest convenience, please confirm receipt of this "
                        "message. Looking forward to hearing from you."
                    ),
                    "is_ai_generated": True,
                },
                {
                    "id": "human_written_1",
                    "subject": "hey quick question",
                    "body": (
                        "Hey, do you have a sec? I tried to call but your line was busy.. "
                        "Can you send me the Q4 numbers when you get a chance? No rush, "
                        "just need them for the meeting tmrw. thx!"
                    ),
                    "is_ai_generated": False,
                },
                {
                    "id": "ai_generated_2",
                    "subject": "Account Verification Required",
                    "body": (
                        "I trust this message finds you in good health. We are writing "
                        "to inform you that your account requires immediate verification. "
                        "Failure to respond within 48 hours may result in account suspension. "
                        "Please find attached the verification form. Thank you for your "
                        "prompt attention to this matter."
                    ),
                    "is_ai_generated": True,
                },
            ],
            "vishing_scenarios": [
                {
                    "id": "attack_1",
                    "caller_claims": "CEO - John Smith",
                    "request": "wire_transfer_request",
                    "urgency": "critical",
                    "callback_offered": False,
                    "verification_accepted": False,
                    "is_attack": True,
                },
                {
                    "id": "legitimate_1",
                    "caller_claims": "IT Helpdesk - Sarah",
                    "request": "password_assistance",
                    "urgency": "normal",
                    "callback_offered": True,
                    "verification_accepted": True,
                    "is_attack": False,
                },
            ],
        }

    # Demo: Phishing Detection
    print("\n" + "=" * 70)
    print("[1] AI-Generated Phishing Detection")
    print("=" * 70)

    detector = AIPhishingDetector()

    for email in samples.get("phishing_emails", []):
        print(f"\n📧 Analyzing: {email['subject']}")
        print("-" * 50)
        result = detector.analyze(email["body"])
        print(f"  AI Probability: {result.ai_probability:.1%}")
        print(f"  Confidence: {result.confidence.upper()}")
        print(f"  Indicators Found: {len(result.indicators)}")
        for indicator in result.indicators:
            print(f"    • {indicator}")
        print(
            f"  Ground Truth: {'🤖 AI-generated' if email.get('is_ai_generated') else '👤 Human'}"
        )
        correct = (result.ai_probability > 0.5) == email.get("is_ai_generated", False)
        print(f"  Detection: {'✅ Correct' if correct else '❌ Incorrect'}")

    # Demo: Vishing Detection
    print("\n" + "=" * 70)
    print("[2] Vishing Detection Framework")
    print("=" * 70)

    vishing_detector = VishingDetector()

    for scenario in samples.get("vishing_scenarios", []):
        print(f"\n📞 Analyzing call from: {scenario['caller_claims']}")
        print("-" * 50)
        result = vishing_detector.analyze_call_context(
            caller_claims=scenario["caller_claims"],
            request_type=scenario["request"],
            urgency_level=scenario["urgency"],
            callback_offered=scenario["callback_offered"],
            verification_accepted=scenario["verification_accepted"],
        )
        print(f"  Risk Score: {result.synthetic_probability:.1%}")
        print(f"  Confidence: {result.confidence.upper()}")
        print(f"  Ground Truth: {'🚨 Attack' if scenario.get('is_attack') else '✅ Legitimate'}")

        correct = (result.synthetic_probability > 0.5) == scenario.get("is_attack", False)
        print(f"  Detection: {'✅ Correct' if correct else '❌ Incorrect'}")

        # Show verification protocol
        print(f"\n  Verification Protocol:")
        for step in vishing_detector.get_verification_protocol(scenario["caller_claims"])[:4]:
            print(f"    {step}")

    # Demo: Threat Intelligence
    print("\n" + "=" * 70)
    print("[3] AI Threat Intelligence Generation")
    print("=" * 70)

    intel_generator = AIThreatIntelGenerator()

    for threat_type in ["voice_cloning_attacks", "ai_phishing_patterns"]:
        report = intel_generator.generate_threat_brief(threat_type)
        print(f"\n📋 {report.title}")
        print("-" * 50)
        print(f"  TLP: {report.tlp}")
        print(f"  Threat Level: {report.threat_level.value.upper()}")
        print(f"\n  Executive Summary:")
        print(f"  {report.executive_summary[:200]}...")
        print(f"\n  Mitigations: {len(report.mitigations)}")
        for mit in report.mitigations[:3]:
            print(f"    • {mit}")

    # Demo: Organization Risk Assessment
    print("\n" + "=" * 70)
    print("[4] Organizational Risk Assessment")
    print("=" * 70)

    sample_org = {
        "name": "Acme Financial",
        "sector": "financial",
        "employee_count": 5000,
        "public_executives": 5,
        "has_security_awareness_training": True,
        "has_email_filtering": False,
        "has_callback_verification": False,
    }

    risk_assessment = intel_generator.assess_organizational_risk(sample_org)

    print(f"\n🏢 Organization: {sample_org['name']}")
    print("-" * 50)
    print(f"  Overall Risk Score: {risk_assessment['overall_risk_score']:.1%}")
    print(f"  Risk Level: {risk_assessment['risk_level']}")
    print(f"\n  Risk Factors:")
    for factor in risk_assessment["risk_factors"]:
        print(f"    ⚠️ {factor}")
    print(f"\n  Recommendations:")
    for rec in risk_assessment["recommendations"][:4]:
        print(f"    → {rec}")

    print("\n" + "=" * 70)
    print("Lab 16b Complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()

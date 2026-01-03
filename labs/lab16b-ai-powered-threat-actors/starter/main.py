"""
Lab 16b: Understanding AI-Powered Threat Actors - Starter Code

Learn to detect and analyze AI-enhanced attack patterns.
"""

import json
import re
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum
from pathlib import Path


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PhishingAnalysis:
    """Results of AI-generated content analysis."""
    
    text: str
    ai_probability: float  # 0.0-1.0
    indicators: List[str]
    confidence: str  # low, medium, high
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


# =============================================================================
# Exercise 1: AI-Generated Phishing Detection
# =============================================================================


class AIPhishingDetector:
    """
    Detect AI-generated phishing content.
    
    TODO: Implement the detection methods to identify AI-generated text.
    """
    
    def __init__(self):
        # Common AI phishing phrases - these often appear in LLM-generated content
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
        
        TODO: Implement analysis logic that checks for:
        1. Perfect grammar (no human errors)
        2. Generic urgency patterns
        3. Template-like phrases
        4. Unusual formality
        5. Statistical anomalies in sentence structure
        
        Args:
            email_text: The email body text
            metadata: Optional email metadata (sender, headers, etc.)
            
        Returns:
            PhishingAnalysis with probability and indicators
        """
        indicators = []
        scores = []
        
        # TODO: Implement perfect grammar check
        # Hint: Look for common human errors that are MISSING
        # grammar_score, grammar_indicator = self._check_perfect_grammar(email_text)
        
        # TODO: Implement urgency pattern check
        # Hint: Use self.urgency_patterns with regex
        # urgency_score, urgency_indicator = self._check_generic_urgency(email_text)
        
        # TODO: Implement template pattern check
        # Hint: Count matches against self.ai_phrases
        # template_score, template_indicator = self._check_template_patterns(email_text)
        
        # TODO: Calculate overall AI probability from scores
        ai_probability = 0.0  # Replace with actual calculation
        
        # Determine confidence level
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
        """
        Check for suspiciously perfect grammar.
        
        TODO: Implement this method
        
        Hint: AI text often lacks common human errors like:
        - Uncapitalized "i"
        - Double periods
        - Multiple spaces
        - Missing space after period
        """
        pass
    
    def _check_generic_urgency(self, text: str) -> tuple:
        """
        Check for generic urgency patterns.
        
        TODO: Implement this method
        
        Hint: Use regex to match against self.urgency_patterns
        """
        pass
    
    def _check_template_patterns(self, text: str) -> tuple:
        """
        Check for common AI template patterns.
        
        TODO: Implement this method
        
        Hint: Count how many phrases from self.ai_phrases appear in the text
        """
        pass
    
    def _generate_recommendations(
        self, probability: float, indicators: List[str]
    ) -> List[str]:
        """Generate actionable recommendations based on risk level."""
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
            ])
        else:
            recommendations.append("LOW RISK: Standard vigilance recommended")
        
        return recommendations


# =============================================================================
# Exercise 2: Vishing Detection Framework
# =============================================================================


class VishingDetector:
    """
    Framework for detecting AI-powered vishing attacks.
    
    TODO: Implement the detection and verification methods.
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
        
        # Challenge questions that expose AI limitations
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
        
        TODO: Implement risk scoring based on:
        1. Request type (check against high_risk_scenarios)
        2. Urgency level (critical/emergency = red flag)
        3. Callback offered (refusing = suspicious)
        4. Verification accepted (refusing = very suspicious)
        
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
        
        # TODO: Check for high-risk request types
        # if request_type in self.high_risk_scenarios:
        #     risk_score += 0.3
        
        # TODO: Check urgency level
        # TODO: Check callback willingness
        # TODO: Check verification acceptance
        
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
        
        TODO: Implement verification protocol generation
        
        Returns:
            List of verification steps
        """
        # TODO: Return appropriate verification steps based on who
        # the caller claims to be (executive, IT, vendor, etc.)
        pass
    
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
            ])
        elif risk_score > 0.3:
            recs.extend([
                "⚡ ELEVATED RISK: Proceed with caution",
                "Require callback verification before any action",
            ])
        else:
            recs.append("✅ LOWER RISK: Follow standard verification procedures")
        
        return recs


# =============================================================================
# Exercise 3: AI Threat Intelligence
# =============================================================================


class AIThreatIntelGenerator:
    """
    Generate threat intelligence about AI-powered attacks.
    
    TODO: Implement intelligence generation methods.
    """
    
    def __init__(self):
        self.threat_categories = [
            "ai_phishing_patterns",
            "voice_cloning_attacks",
            "ai_malware_development",
            "deepfake_attacks",
            "automated_reconnaissance",
        ]
    
    def generate_threat_brief(self, threat_type: str) -> Dict:
        """
        Generate a threat intelligence brief.
        
        TODO: Implement threat brief generation
        
        Should include:
        - Executive summary
        - Observed techniques
        - Indicators
        - Mitigations
        - References
        """
        pass
    
    def assess_organizational_risk(self, org_profile: Dict) -> Dict:
        """
        Assess organization's risk to AI-powered threats.
        
        TODO: Implement risk assessment based on:
        - Industry sector
        - Public profile (executives, etc.)
        - Current security controls
        - Past incidents
        """
        pass


# =============================================================================
# Main Demo
# =============================================================================


def main():
    """Demonstrate AI threat detection capabilities."""
    
    print("=" * 70)
    print("Lab 16b: Understanding AI-Powered Threat Actors")
    print("=" * 70)
    
    # Load sample data
    data_path = Path(__file__).parent.parent / "data" / "ai_threat_samples.json"
    
    if data_path.exists():
        with open(data_path) as f:
            samples = json.load(f)
    else:
        # Demo samples
        samples = {
            "phishing_emails": [
                {
                    "id": "sample_1",
                    "subject": "Urgent: Wire Transfer Required",
                    "body": (
                        "I hope this email finds you well. I am reaching out regarding "
                        "an urgent matter that requires your immediate attention. As per "
                        "our previous conversation, we need to process a wire transfer "
                        "within the next 24 hours. Please find attached the payment "
                        "details. Thank you for your prompt attention to this matter."
                    ),
                    "is_ai_generated": True,
                },
                {
                    "id": "sample_2", 
                    "subject": "hey quick question",
                    "body": (
                        "Hey, do you have a sec? I tried to call but your line was busy.. "
                        "Can you send me the Q4 numbers when you get a chance? No rush, "
                        "just need them for the meeting tmrw. thx!"
                    ),
                    "is_ai_generated": False,
                },
            ],
            "vishing_scenarios": [
                {
                    "id": "vish_1",
                    "caller_claims": "CEO - John Smith",
                    "request": "wire_transfer_request",
                    "urgency": "critical",
                    "callback_offered": False,
                    "verification_accepted": False,
                    "is_attack": True,
                },
            ],
        }
    
    # Demo: Phishing Detection
    print("\n[1] AI-Generated Phishing Detection")
    print("-" * 40)
    
    detector = AIPhishingDetector()
    
    for email in samples.get("phishing_emails", []):
        print(f"\nAnalyzing: {email['subject']}")
        result = detector.analyze(email["body"])
        print(f"  AI Probability: {result.ai_probability:.1%}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Indicators: {len(result.indicators)}")
        print(f"  Ground Truth: {'AI-generated' if email.get('is_ai_generated') else 'Human'}")
    
    # Demo: Vishing Detection
    print("\n\n[2] Vishing Detection Framework")
    print("-" * 40)
    
    vishing_detector = VishingDetector()
    
    for scenario in samples.get("vishing_scenarios", []):
        print(f"\nAnalyzing call from: {scenario['caller_claims']}")
        result = vishing_detector.analyze_call_context(
            caller_claims=scenario["caller_claims"],
            request_type=scenario["request"],
            urgency_level=scenario["urgency"],
            callback_offered=scenario["callback_offered"],
            verification_accepted=scenario["verification_accepted"],
        )
        print(f"  Risk Score: {result.synthetic_probability:.1%}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Ground Truth: {'Attack' if scenario.get('is_attack') else 'Legitimate'}")
    
    print("\n" + "=" * 70)
    print("TODO: Implement the detection methods in the classes above!")
    print("=" * 70)


if __name__ == "__main__":
    main()

"""
Lab 17a: ML Security Foundations (Starter)

Analyze ML systems for security vulnerabilities.
Complete the TODOs to build a threat assessment framework.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================================
# DATA STRUCTURES
# ============================================================================


class RiskLevel(Enum):
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"


class AttackType(Enum):
    EVASION = "Evasion"
    POISONING = "Poisoning"
    BACKDOOR = "Backdoor"
    EXTRACTION = "Extraction"
    INVERSION = "Inversion"


@dataclass
class Vulnerability:
    """A security vulnerability in an ML system."""

    name: str
    attack_type: AttackType
    risk_level: RiskLevel
    description: str
    mitigation: str
    component: str  # Which part of pipeline


@dataclass
class MLPipeline:
    """Represents an ML system to assess."""

    name: str
    description: str
    data_sources: list
    training_process: list
    deployment_config: dict
    inference_api: dict


# ============================================================================
# SAMPLE ML SYSTEM TO ANALYZE
# ============================================================================

MALWARE_CLASSIFIER = MLPipeline(
    name="Malware Classification System",
    description="ML-based malware detection for endpoint protection",
    data_sources=[
        {"name": "VirusTotal feed", "type": "public", "trust": "medium"},
        {"name": "Customer submissions", "type": "user_input", "trust": "low"},
        {"name": "Internal malware farm", "type": "controlled", "trust": "high"},
        {"name": "Open source datasets", "type": "public", "trust": "low"},
    ],
    training_process=[
        {"step": "Data collection", "automated": True, "validated": False},
        {"step": "Labeling", "source": "AV vendor consensus", "manual_review": False},
        {"step": "Feature extraction", "method": "PE headers + strings"},
        {"step": "Model training", "algorithm": "Random Forest", "adversarial": False},
        {"step": "Validation", "method": "holdout set", "adversarial_test": False},
    ],
    deployment_config={
        "model_storage": "S3 bucket",
        "encryption": False,
        "access_control": "IAM roles",
        "versioning": True,
    },
    inference_api={
        "rate_limiting": False,
        "authentication": True,
        "logging": True,
        "confidence_threshold": None,
        "max_file_size": "50MB",
    },
)


# ============================================================================
# TODO 1: Map attack surface
# ============================================================================


def map_attack_surface(pipeline: MLPipeline) -> dict:
    """
    Map the attack surface of an ML pipeline.

    Identify where attacks could occur:
    - Data collection: Poisoning via source
    - Training: Backdoor implantation
    - Deployment: Model theft
    - Inference: Evasion attacks

    Args:
        pipeline: The ML pipeline to analyze

    Returns:
        Dict with attack surface by component
    """
    attack_surface = {
        "data_collection": [],
        "training": [],
        "deployment": [],
        "inference": [],
    }

    # TODO: Analyze data sources for poisoning risk
    # Hint: Check trust level and type
    # - Public sources = higher risk
    # - User input = highest risk
    # - Controlled sources = lower risk

    # TODO: Analyze training process
    # Hint: Check for validation and adversarial testing

    # TODO: Analyze deployment config
    # Hint: Check encryption, access control

    # TODO: Analyze inference API
    # Hint: Check rate limiting, logging

    # Your code here:

    return attack_surface


# ============================================================================
# TODO 2: Identify evasion vectors
# ============================================================================


def identify_evasion_vectors(pipeline: MLPipeline) -> list:
    """
    Identify potential evasion attack vectors.

    For a malware classifier, attackers might:
    - Append benign code sections
    - Obfuscate malicious strings
    - Use uncommon file formats
    - Add decoy features

    Args:
        pipeline: The ML pipeline to analyze

    Returns:
        List of potential evasion vectors
    """
    vectors = []

    # TODO: Based on the pipeline, identify evasion risks
    # Consider:
    # - What features does the model use?
    # - Can attackers manipulate those features?
    # - Is there adversarial testing in validation?
    # - Are there confidence thresholds?

    # Your code here:

    return vectors


# ============================================================================
# TODO 3: Assess poisoning risks
# ============================================================================


def assess_poisoning_risks(pipeline: MLPipeline) -> list:
    """
    Assess data poisoning risks in the pipeline.

    Args:
        pipeline: The ML pipeline to analyze

    Returns:
        List of Vulnerability objects for poisoning risks
    """
    vulnerabilities = []

    # TODO: Analyze each data source for poisoning risk
    # Consider:
    # - Can attackers influence this source?
    # - Is there validation before training?
    # - Is there anomaly detection on data?

    # Hint: Create Vulnerability objects like:
    # Vulnerability(
    #     name="Poisoning via customer submissions",
    #     attack_type=AttackType.POISONING,
    #     risk_level=RiskLevel.HIGH,
    #     description="Attackers can submit mislabeled samples",
    #     mitigation="Add anomaly detection and manual review",
    #     component="data_collection"
    # )

    # Your code here:

    return vulnerabilities


# ============================================================================
# TODO 4: Design defenses
# ============================================================================


def recommend_defenses(vulnerabilities: list) -> dict:
    """
    Recommend defenses based on identified vulnerabilities.

    Args:
        vulnerabilities: List of identified vulnerabilities

    Returns:
        Dict of defense recommendations by priority
    """
    defenses = {
        "immediate": [],
        "near_term": [],
        "long_term": [],
    }

    # TODO: For each vulnerability, recommend appropriate defenses
    # Prioritize by risk level:
    # - CRITICAL/HIGH → Immediate
    # - MEDIUM → Near-term
    # - LOW → Long-term

    # Defense options:
    # - Rate limiting (extraction)
    # - Adversarial training (evasion)
    # - Data validation (poisoning)
    # - Confidence thresholds (evasion)
    # - Ensemble models (all)
    # - Monitoring (all)

    # Your code here:

    return defenses


# ============================================================================
# TODO 5: Generate threat model document
# ============================================================================


def generate_threat_model(pipeline: MLPipeline) -> str:
    """
    Generate a comprehensive threat model document.

    Args:
        pipeline: The ML pipeline to analyze

    Returns:
        Formatted threat model as string
    """
    # TODO: Combine all analyses into a threat model
    # Include:
    # 1. System description
    # 2. Attack surface map
    # 3. Vulnerabilities by attack type
    # 4. Risk assessment
    # 5. Defense recommendations

    # Your code here:
    report = f"ML Security Threat Model: {pipeline.name}\n"
    report += "=" * 50 + "\n\n"
    report += "TODO: Complete the threat model generation\n"

    return report


# ============================================================================
# MAIN
# ============================================================================


def main():
    print("🔒 ML Security Assessment Framework")
    print("=" * 55)

    pipeline = MALWARE_CLASSIFIER
    print(f"\n📊 Analyzing: {pipeline.name}")
    print(f"   {pipeline.description}")

    # TODO 1: Attack surface
    print("\n" + "=" * 55)
    print("1. Attack Surface Mapping")
    print("-" * 55)

    surface = map_attack_surface(pipeline)
    if any(surface.values()):
        for component, risks in surface.items():
            if risks:
                print(f"\n   {component.upper()}:")
                for risk in risks:
                    print(f"     • {risk}")
    else:
        print("   ❌ Complete TODO 1 to map attack surface")

    # TODO 2: Evasion vectors
    print("\n" + "=" * 55)
    print("2. Evasion Attack Vectors")
    print("-" * 55)

    vectors = identify_evasion_vectors(pipeline)
    if vectors:
        for vector in vectors:
            print(f"   • {vector}")
    else:
        print("   ❌ Complete TODO 2 to identify evasion vectors")

    # TODO 3: Poisoning risks
    print("\n" + "=" * 55)
    print("3. Poisoning Risk Assessment")
    print("-" * 55)

    poison_vulns = assess_poisoning_risks(pipeline)
    if poison_vulns:
        for vuln in poison_vulns:
            print(f"\n   {vuln.risk_level.value}: {vuln.name}")
            print(f"     {vuln.description}")
            print(f"     Mitigation: {vuln.mitigation}")
    else:
        print("   ❌ Complete TODO 3 to assess poisoning risks")

    # TODO 4: Defenses
    print("\n" + "=" * 55)
    print("4. Defense Recommendations")
    print("-" * 55)

    all_vulns = poison_vulns  # Add other vuln types here
    defenses = recommend_defenses(all_vulns)
    if any(defenses.values()):
        for priority, items in defenses.items():
            if items:
                print(f"\n   {priority.upper()}:")
                for item in items:
                    print(f"     • {item}")
    else:
        print("   ❌ Complete TODO 4 to recommend defenses")

    # Summary
    print("\n" + "=" * 55)
    completed = sum(
        [
            any(surface.values()),
            len(vectors) > 0,
            len(poison_vulns) > 0,
            any(defenses.values()),
        ]
    )
    print(f"Progress: {completed}/4 core TODOs complete")

    if completed >= 3:
        print("\n✅ You understand ML security! Ready for Lab 17.")
    else:
        print("\n📝 Keep working on the TODOs!")


if __name__ == "__main__":
    main()

"""
Lab 17a: ML Security Foundations (Solution)

A complete ML security threat assessment framework.
"""

from dataclasses import dataclass
from enum import Enum


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
    component: str


@dataclass
class MLPipeline:
    """Represents an ML system to assess."""

    name: str
    description: str
    data_sources: list
    training_process: list
    deployment_config: dict
    inference_api: dict


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


def map_attack_surface(pipeline: MLPipeline) -> dict:
    """Map the attack surface of an ML pipeline."""
    attack_surface = {
        "data_collection": [],
        "training": [],
        "deployment": [],
        "inference": [],
    }

    # Analyze data sources
    for source in pipeline.data_sources:
        if source["trust"] == "low":
            attack_surface["data_collection"].append(
                f"[HIGH RISK] {source['name']} ({source['type']}) - Low trust, poisoning vector"
            )
        elif source["trust"] == "medium":
            attack_surface["data_collection"].append(
                f"[MEDIUM RISK] {source['name']} ({source['type']}) - Medium trust"
            )

    # Analyze training process
    for step in pipeline.training_process:
        if step.get("automated") and not step.get("validated"):
            attack_surface["training"].append(
                f"[RISK] {step['step']} is automated without validation"
            )
        if step.get("adversarial") == False:
            attack_surface["training"].append(f"[RISK] {step['step']} lacks adversarial testing")

    # Analyze deployment
    if not pipeline.deployment_config.get("encryption"):
        attack_surface["deployment"].append("[RISK] Model storage not encrypted - extraction risk")

    # Analyze inference API
    if not pipeline.inference_api.get("rate_limiting"):
        attack_surface["inference"].append(
            "[HIGH RISK] No rate limiting - model extraction possible"
        )
    if not pipeline.inference_api.get("confidence_threshold"):
        attack_surface["inference"].append(
            "[MEDIUM RISK] No confidence threshold - low-confidence predictions exposed"
        )

    return attack_surface


def identify_evasion_vectors(pipeline: MLPipeline) -> list:
    """Identify potential evasion attack vectors."""
    vectors = []

    # Based on feature extraction method
    for step in pipeline.training_process:
        if step.get("method") == "PE headers + strings":
            vectors.append("Append benign PE sections to shift header features")
            vectors.append("Obfuscate/encode malicious strings")
            vectors.append("Use string-less shellcode")
            vectors.append("Import functions by ordinal instead of name")

    # Based on validation gaps
    has_adversarial_test = any(step.get("adversarial_test") for step in pipeline.training_process)
    if not has_adversarial_test:
        vectors.append("Model not tested against adversarial examples - likely vulnerable")

    # Based on API config
    if not pipeline.inference_api.get("confidence_threshold"):
        vectors.append("No confidence threshold - boundary samples accepted")

    return vectors


def assess_poisoning_risks(pipeline: MLPipeline) -> list:
    """Assess data poisoning risks in the pipeline."""
    vulnerabilities = []

    for source in pipeline.data_sources:
        if source["type"] == "user_input":
            vulnerabilities.append(
                Vulnerability(
                    name=f"Poisoning via {source['name']}",
                    attack_type=AttackType.POISONING,
                    risk_level=RiskLevel.HIGH,
                    description="Attackers can submit mislabeled malware as benign",
                    mitigation="Add anomaly detection, manual review queue, submission limits",
                    component="data_collection",
                )
            )
        elif source["type"] == "public" and source["trust"] == "low":
            vulnerabilities.append(
                Vulnerability(
                    name=f"Poisoning via {source['name']}",
                    attack_type=AttackType.POISONING,
                    risk_level=RiskLevel.MEDIUM,
                    description="Public datasets can be manipulated by attackers",
                    mitigation="Validate samples, cross-reference with trusted sources",
                    component="data_collection",
                )
            )

    # Check for validation in training
    has_validation = any(step.get("validated") for step in pipeline.training_process)
    if not has_validation:
        vulnerabilities.append(
            Vulnerability(
                name="No data validation in training pipeline",
                attack_type=AttackType.POISONING,
                risk_level=RiskLevel.HIGH,
                description="Poisoned samples flow directly into training",
                mitigation="Add data validation layer with outlier detection",
                component="training",
            )
        )

    return vulnerabilities


def assess_extraction_risks(pipeline: MLPipeline) -> list:
    """Assess model extraction risks."""
    vulnerabilities = []

    if not pipeline.inference_api.get("rate_limiting"):
        vulnerabilities.append(
            Vulnerability(
                name="Model extraction via unlimited queries",
                attack_type=AttackType.EXTRACTION,
                risk_level=RiskLevel.HIGH,
                description="Attacker can query API thousands of times to clone model",
                mitigation="Implement rate limiting, monitor for systematic queries",
                component="inference",
            )
        )

    if not pipeline.deployment_config.get("encryption"):
        vulnerabilities.append(
            Vulnerability(
                name="Model theft from storage",
                attack_type=AttackType.EXTRACTION,
                risk_level=RiskLevel.MEDIUM,
                description="Unencrypted model files could be stolen",
                mitigation="Encrypt model at rest, strict access controls",
                component="deployment",
            )
        )

    return vulnerabilities


def recommend_defenses(vulnerabilities: list) -> dict:
    """Recommend defenses based on identified vulnerabilities."""
    defenses = {
        "immediate": [],
        "near_term": [],
        "long_term": [],
    }

    for vuln in vulnerabilities:
        if vuln.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            defenses["immediate"].append(f"[{vuln.attack_type.value}] {vuln.mitigation}")
        elif vuln.risk_level == RiskLevel.MEDIUM:
            defenses["near_term"].append(f"[{vuln.attack_type.value}] {vuln.mitigation}")
        else:
            defenses["long_term"].append(f"[{vuln.attack_type.value}] {vuln.mitigation}")

    # Add general recommendations
    defenses["immediate"].extend(
        [
            "[General] Enable comprehensive API logging",
            "[General] Set up alerting for anomalous query patterns",
        ]
    )

    defenses["near_term"].extend(
        [
            "[Evasion] Implement adversarial training pipeline",
            "[General] Deploy ensemble of diverse models",
        ]
    )

    defenses["long_term"].extend(
        [
            "[Privacy] Implement differential privacy for outputs",
            "[General] Establish ML red team program",
        ]
    )

    return defenses


def generate_threat_model(pipeline: MLPipeline) -> str:
    """Generate a comprehensive threat model document."""
    lines = []

    lines.append(f"🔒 ML Security Threat Model")
    lines.append("=" * 60)
    lines.append(f"\nSYSTEM: {pipeline.name}")
    lines.append(f"{pipeline.description}")
    lines.append("-" * 60)

    # Attack surface
    lines.append("\n📍 ATTACK SURFACE:")
    surface = map_attack_surface(pipeline)
    for component, risks in surface.items():
        if risks:
            lines.append(f"\n   {component.upper()}:")
            for risk in risks:
                lines.append(f"     {risk}")

    # Vulnerabilities
    lines.append("\n\n🎯 VULNERABILITIES:")

    all_vulns = []
    all_vulns.extend(assess_poisoning_risks(pipeline))
    all_vulns.extend(assess_extraction_risks(pipeline))

    for vuln in all_vulns:
        lines.append(f"\n   {vuln.risk_level.value}: {vuln.name}")
        lines.append(f"     Type: {vuln.attack_type.value}")
        lines.append(f"     Component: {vuln.component}")
        lines.append(f"     Description: {vuln.description}")
        lines.append(f"     Mitigation: {vuln.mitigation}")

    # Evasion vectors
    lines.append("\n\n⚔️ EVASION ATTACK VECTORS:")
    vectors = identify_evasion_vectors(pipeline)
    for vector in vectors:
        lines.append(f"   • {vector}")

    # Defenses
    lines.append("\n\n🛡️ RECOMMENDED DEFENSES:")
    defenses = recommend_defenses(all_vulns)
    for priority, items in defenses.items():
        if items:
            lines.append(f"\n   {priority.upper()}:")
            for item in items:
                lines.append(f"     • {item}")

    # Summary
    critical_count = sum(1 for v in all_vulns if v.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for v in all_vulns if v.risk_level == RiskLevel.HIGH)

    lines.append("\n\n📊 RISK SUMMARY:")
    lines.append(f"   Critical: {critical_count}")
    lines.append(f"   High: {high_count}")
    lines.append(f"   Total vulnerabilities: {len(all_vulns)}")
    lines.append(f"   Evasion vectors: {len(vectors)}")

    return "\n".join(lines)


def main():
    print("🔒 ML Security Assessment Framework")
    print("=" * 60)

    pipeline = MALWARE_CLASSIFIER

    # Generate and print full threat model
    threat_model = generate_threat_model(pipeline)
    print(threat_model)

    # Key takeaways
    print("\n" + "=" * 60)
    print("📚 KEY TAKEAWAYS")
    print("=" * 60)
    print(
        """
   1. ML systems have multiple attack vectors:
      - Data poisoning at training time
      - Evasion attacks at inference time
      - Model extraction via API queries
   
   2. Defense requires multiple layers:
      - Input validation and rate limiting
      - Adversarial training
      - Monitoring and anomaly detection
   
   3. Security is an ongoing process:
      - Attackers adapt to defenses
      - Regular red team exercises needed
      - Continuous monitoring essential
   
   Ready for Lab 17 (Adversarial ML Attacks)!
    """
    )


if __name__ == "__main__":
    main()

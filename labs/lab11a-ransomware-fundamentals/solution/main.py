#!/usr/bin/env python3
"""
Lab 11a: Ransomware Fundamentals - Solution

Complete implementation of ransomware family identification,
MITRE ATT&CK mapping, and recovery decision framework.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

# =============================================================================
# Test-Compatible Functions
# =============================================================================


@dataclass
class RansomwareIndicator:
    """An indicator of ransomware activity."""

    indicator_type: str  # extension, note_pattern, process
    indicator: str
    family: str
    confidence: float


# List of known ransomware indicators for detection
RANSOMWARE_INDICATORS = [
    RansomwareIndicator("extension", ".encrypted", "generic", 0.8),
    RansomwareIndicator("extension", ".locked", "generic", 0.8),
    RansomwareIndicator("extension", ".crypto", "generic", 0.7),
    RansomwareIndicator("extension", ".crypt", "generic", 0.7),
    RansomwareIndicator("extension", ".lockbit", "lockbit", 0.95),
    RansomwareIndicator("extension", ".blackcat", "blackcat", 0.95),
    RansomwareIndicator("extension", ".conti", "conti", 0.95),
    RansomwareIndicator("extension", ".ryuk", "ryuk", 0.95),
    RansomwareIndicator("extension", ".wannacry", "wannacry", 0.95),
    RansomwareIndicator("extension", ".petya", "petya", 0.95),
]


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    High entropy (>7.5) often indicates encrypted data.
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def analyze_file_extension(filename: str) -> dict:
    """
    Analyze a filename for ransomware-related extensions.

    Returns:
        Dict with suspicious flag, probability, and matched indicators
    """
    filename_lower = filename.lower()

    suspicious_extensions = [
        ".encrypted",
        ".locked",
        ".crypto",
        ".crypt",
        ".enc",
        ".lockbit",
        ".blackcat",
        ".conti",
        ".ryuk",
        ".petya",
        ".locky",
        ".cerber",
        ".zepto",
        ".odin",
        ".thor",
        ".aesir",
        ".zzzzz",
        ".micro",
        ".vvv",
        ".ccc",
    ]

    matched = []
    for ext in suspicious_extensions:
        if ext in filename_lower:
            matched.append(ext)

    # Check for double extensions (document.docx.encrypted)
    has_double_extension = any(
        filename_lower.endswith(ext) and "." in filename_lower[: -len(ext)]
        for ext in suspicious_extensions
    )

    suspicious = len(matched) > 0 or has_double_extension
    probability = 0.9 if has_double_extension else (0.7 if matched else 0.0)

    return {
        "suspicious": suspicious,
        "ransomware_probability": probability,
        "matched_extensions": matched,
        "has_double_extension": has_double_extension,
    }


def check_ransom_note_patterns(text: str) -> dict:
    """
    Check text for common ransom note patterns.

    Returns:
        Dict with is_ransom_note flag, confidence, and matched patterns
    """
    text_lower = text.lower()

    ransom_patterns = [
        (r"your files have been encrypted", 0.9),
        (r"all your files are encrypted", 0.9),
        (r"to decrypt your files", 0.8),
        (r"send.*btc", 0.7),
        (r"bitcoin.*wallet", 0.7),
        (r"pay.*ransom", 0.9),
        (r"decrypt.*key", 0.6),
        (r"files.*locked", 0.6),
        (r"restore.*files", 0.5),
        (r"personal.*id", 0.4),
        (r"\.onion", 0.7),
        (r"deadline|hours.*pay|days.*pay", 0.6),
    ]

    matched_patterns = []
    total_confidence = 0.0

    for pattern, weight in ransom_patterns:
        if re.search(pattern, text_lower):
            matched_patterns.append(pattern)
            total_confidence += weight

    # Normalize confidence to 0-1 range
    confidence = min(total_confidence / 3.0, 1.0) if matched_patterns else 0.0

    return {
        "is_ransom_note": confidence > 0.5,
        "confidence": confidence,
        "matched_patterns": matched_patterns,
    }


# =============================================================================
# Ransomware Family Database
# =============================================================================


class RansomwareFamily(Enum):
    """Known ransomware families."""

    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CONTI = "conti"
    ROYAL = "royal"
    PLAY = "play"
    AKIRA = "akira"
    CLOP = "clop"
    RHYSIDA = "rhysida"
    UNKNOWN = "unknown"


FAMILY_SIGNATURES = {
    RansomwareFamily.LOCKBIT: {
        "extensions": [".lockbit", ".abcd", ".LockBit"],
        "note_patterns": ["lockbit", "restore-my-files", "LOCKBIT 3.0", "lockbit 3.0"],
        "note_files": ["Restore-My-Files.txt", "restore-my-files.txt"],
    },
    RansomwareFamily.BLACKCAT: {
        "extensions": [".alphv", ".ALPHV"],
        "note_patterns": ["alphv", "blackcat", "RECOVER-FILES", "recover-files"],
        "note_files": ["RECOVER-FILES.txt"],
    },
    RansomwareFamily.CONTI: {
        "extensions": [".CONTI", ".conti"],
        "note_patterns": ["conti", "CONTI_README", "conti_readme"],
        "note_files": ["readme.txt", "CONTI_README.txt"],
    },
    RansomwareFamily.ROYAL: {
        "extensions": [".royal", ".ROYAL"],
        "note_patterns": ["royal", "royal ransomware"],
        "note_files": ["README.TXT", "readme.txt"],
    },
    RansomwareFamily.PLAY: {
        "extensions": [".play", ".PLAY"],
        "note_patterns": ["play", "play ransomware"],
        "note_files": ["ReadMe.txt"],
    },
    RansomwareFamily.AKIRA: {
        "extensions": [".akira", ".AKIRA"],
        "note_patterns": ["akira", "akira_readme"],
        "note_files": ["akira_readme.txt"],
    },
    RansomwareFamily.CLOP: {
        "extensions": [".clop", ".Clop", ".CIop"],
        "note_patterns": ["clop", "cl0p", "ClopReadMe"],
        "note_files": ["ClopReadMe.txt", "!_READ_ME.txt"],
    },
    RansomwareFamily.RHYSIDA: {
        "extensions": [".rhysida"],
        "note_patterns": ["rhysida", "CriticalBreachDetected"],
        "note_files": ["CriticalBreachDetected.pdf"],
    },
}


# =============================================================================
# Task 1: Identify Ransomware Family - SOLUTION
# =============================================================================


@dataclass
class RansomwareArtifacts:
    """Artifacts collected from an infected system."""

    encrypted_extension: str
    ransom_note_filename: str
    ransom_note_content: str
    suspicious_processes: List[str]


def identify_ransomware_family(artifacts: RansomwareArtifacts) -> Dict:
    """
    Identify the ransomware family based on collected artifacts.
    """
    matched_indicators = []
    family_scores = {family: 0 for family in RansomwareFamily}

    # Check extension matches
    for family, sigs in FAMILY_SIGNATURES.items():
        if artifacts.encrypted_extension.lower() in [ext.lower() for ext in sigs["extensions"]]:
            family_scores[family] += 3  # High weight for extension match
            matched_indicators.append(
                f"Extension match: {artifacts.encrypted_extension} -> {family.value}"
            )

    # Check ransom note filename
    for family, sigs in FAMILY_SIGNATURES.items():
        for note_file in sigs["note_files"]:
            if artifacts.ransom_note_filename.lower() == note_file.lower():
                family_scores[family] += 2
                matched_indicators.append(
                    f"Note filename match: {artifacts.ransom_note_filename} -> {family.value}"
                )

    # Check ransom note content
    note_lower = artifacts.ransom_note_content.lower()
    for family, sigs in FAMILY_SIGNATURES.items():
        for pattern in sigs["note_patterns"]:
            if pattern.lower() in note_lower:
                family_scores[family] += 2
                matched_indicators.append(f"Content pattern: '{pattern}' -> {family.value}")

    # Find best match
    best_family = max(family_scores, key=family_scores.get)
    best_score = family_scores[best_family]

    # Calculate confidence (max possible score is ~7)
    confidence = min(best_score / 7.0, 1.0) if best_score > 0 else 0.0

    if best_score == 0:
        best_family = RansomwareFamily.UNKNOWN

    return {
        "family": best_family,
        "confidence": confidence,
        "matched_indicators": matched_indicators,
    }


# =============================================================================
# Task 2: Map Attack to MITRE ATT&CK - SOLUTION
# =============================================================================

MITRE_TECHNIQUES = {
    "phishing": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    "macro": {"id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution"},
    "powershell": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    "cmd": {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
    "scheduled_task": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
    "registry_run": {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
    "service": {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"},
    "ad_enum": {"id": "T1087.002", "name": "Domain Account Discovery", "tactic": "Discovery"},
    "adfind": {
        "id": "T1087.002",
        "name": "Domain Account Discovery (AdFind)",
        "tactic": "Discovery",
    },
    "network_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "file_discovery": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "psexec": {
        "id": "T1569.002",
        "name": "Service Execution (PsExec)",
        "tactic": "Lateral Movement",
    },
    "wmi": {"id": "T1047", "name": "WMI", "tactic": "Execution/Lateral Movement"},
    "rdp": {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "smb": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "archive": {"id": "T1560", "name": "Archive Collected Data", "tactic": "Collection"},
    "rclone": {
        "id": "T1567.002",
        "name": "Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
    },
    "exfil_cloud": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
    },
    "vssadmin": {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    "shadow_delete": {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    "encrypt": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "service_stop": {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
    "beacon": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "cobalt_strike": {
        "id": "T1071.001",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
}

# Keyword to technique mapping
KEYWORD_MAPPINGS = {
    "phishing": ["phishing"],
    "macro": ["macro"],
    "powershell": ["powershell"],
    "beacon": ["beacon", "download"],
    "scheduled task": ["scheduled_task"],
    "persistence": ["scheduled_task", "registry_run", "service"],
    "adfind": ["adfind", "ad_enum"],
    "active directory": ["ad_enum"],
    "enumeration": ["ad_enum"],
    "psexec": ["psexec"],
    "lateral": ["psexec", "smb", "wmi"],
    "spreads": ["psexec", "smb"],
    "rclone": ["rclone", "exfil_cloud"],
    "upload": ["exfil_cloud"],
    "cloud": ["exfil_cloud"],
    "vssadmin": ["vssadmin", "shadow_delete"],
    "shadow": ["shadow_delete"],
    "encrypt": ["encrypt"],
    ".lockbit": ["encrypt"],
    ".encrypted": ["encrypt"],
}


@dataclass
class AttackEvent:
    """A single event in an attack timeline."""

    timestamp: str
    description: str
    techniques: List[str] = None


def map_event_to_mitre(event_description: str) -> List[Dict]:
    """
    Map an attack event description to MITRE ATT&CK techniques.
    """
    matches = []
    description_lower = event_description.lower()
    matched_techniques = set()

    # Search for keywords
    for keyword, technique_keys in KEYWORD_MAPPINGS.items():
        if keyword in description_lower:
            for tech_key in technique_keys:
                if tech_key in MITRE_TECHNIQUES and tech_key not in matched_techniques:
                    tech = MITRE_TECHNIQUES[tech_key]
                    matches.append(
                        {
                            "technique_id": tech["id"],
                            "technique_name": tech["name"],
                            "tactic": tech["tactic"],
                            "matched_keyword": keyword,
                            "confidence": 0.8,
                        }
                    )
                    matched_techniques.add(tech_key)

    return matches


def map_attack_timeline(events: List[AttackEvent]) -> List[Dict]:
    """Map an entire attack timeline to MITRE ATT&CK."""
    enriched = []
    for event in events:
        techniques = map_event_to_mitre(event.description)
        enriched.append(
            {
                "timestamp": event.timestamp,
                "description": event.description,
                "techniques": techniques,
            }
        )
    return enriched


# =============================================================================
# Task 3: Extract IOCs from Ransom Note - SOLUTION
# =============================================================================


def extract_iocs_from_note(note_content: str) -> Dict:
    """Extract Indicators of Compromise from a ransom note."""
    iocs = {
        "onion_urls": [],
        "bitcoin_addresses": [],
        "email_addresses": [],
        "victim_id": None,
        "deadlines": [],
        "ransom_amount": None,
    }

    # Extract .onion URLs
    onion_pattern = r"[a-z2-7]{16,56}\.onion"
    onion_matches = re.findall(onion_pattern, note_content, re.IGNORECASE)
    iocs["onion_urls"] = list(set(onion_matches))

    # Also look for full URLs
    full_onion = r"https?://[a-z2-7]{16,56}\.onion[^\s]*"
    full_matches = re.findall(full_onion, note_content, re.IGNORECASE)
    iocs["onion_urls"].extend(full_matches)
    iocs["onion_urls"] = list(set(iocs["onion_urls"]))

    # Extract Bitcoin addresses
    btc_pattern = r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"
    btc_matches = re.findall(btc_pattern, note_content)
    # findall returns tuples when there are groups, reconstruct full address
    btc_full = re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", note_content)
    iocs["bitcoin_addresses"] = list(set(btc_full))

    # Extract email addresses
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    iocs["email_addresses"] = list(set(re.findall(email_pattern, note_content)))

    # Look for victim IDs (common patterns)
    victim_patterns = [
        r"(?:personal\s*id|victim\s*id|your\s*id)[:\s]*([A-Z0-9-]{8,})",
        r"ID[:\s]*([A-F0-9-]{8,})",
    ]
    for pattern in victim_patterns:
        match = re.search(pattern, note_content, re.IGNORECASE)
        if match:
            iocs["victim_id"] = match.group(1)
            break

    # Look for deadlines
    deadline_patterns = [
        r"(\d+)\s*(?:hours?|days?)\s*(?:to|before|until|or)",
        r"deadline[:\s]*(\d+)\s*(?:hours?|days?)",
    ]
    for pattern in deadline_patterns:
        matches = re.findall(pattern, note_content, re.IGNORECASE)
        iocs["deadlines"].extend(matches)

    # Look for ransom amounts
    amount_patterns = [
        r"(\d+(?:\.\d+)?)\s*(?:BTC|bitcoin)",
        r"\$\s*([\d,]+)",
        r"([\d,]+)\s*(?:USD|dollars?)",
    ]
    for pattern in amount_patterns:
        match = re.search(pattern, note_content, re.IGNORECASE)
        if match:
            iocs["ransom_amount"] = match.group(1)
            break

    return iocs


# =============================================================================
# Task 4: Recovery Decision Framework - SOLUTION
# =============================================================================


@dataclass
class IncidentScenario:
    """Ransomware incident scenario for decision-making."""

    endpoints_encrypted: int
    total_endpoints: int
    backup_age_days: int
    backup_verified_clean: bool
    data_exfiltrated: bool
    exfil_data_types: List[str]
    ransom_demand_usd: int
    decryptor_available: bool
    critical_ops_down: bool
    regulatory_requirements: List[str]


def recommend_recovery_approach(scenario: IncidentScenario) -> Dict:
    """Recommend a recovery approach based on incident scenario."""
    result = {
        "primary_recommendation": "",
        "reasoning": "",
        "regulatory_actions": [],
        "estimated_recovery_time": "",
        "risk_assessment": "",
    }

    # Evaluate options
    encryption_percent = (scenario.endpoints_encrypted / scenario.total_endpoints) * 100

    # Option 1: Free decryptor
    if scenario.decryptor_available:
        result["primary_recommendation"] = "Use free decryptor from nomoreransom.org"
        result["reasoning"] = "Free decryptor available - lowest cost and risk option"
        result["estimated_recovery_time"] = "24-72 hours depending on volume"
        result["risk_assessment"] = "Low risk"

    # Option 2: Restore from backups
    elif scenario.backup_verified_clean and scenario.backup_age_days <= 7:
        result["primary_recommendation"] = "Restore from verified backups"
        result["reasoning"] = (
            f"Backups are {scenario.backup_age_days} days old and verified clean. "
            f"Accept {scenario.backup_age_days} days of data loss rather than paying ransom."
        )
        hours_estimate = scenario.endpoints_encrypted * 0.5  # ~30 min per endpoint
        if hours_estimate > 168:
            result["estimated_recovery_time"] = f"{hours_estimate/168:.0f} weeks"
        elif hours_estimate > 24:
            result["estimated_recovery_time"] = f"{hours_estimate/24:.0f} days"
        else:
            result["estimated_recovery_time"] = f"{hours_estimate:.0f} hours"
        result["risk_assessment"] = "Medium risk - verify backup integrity before restore"

    # Option 3: Partial recovery + rebuild
    elif scenario.backup_verified_clean:
        result["primary_recommendation"] = "Partial restore + rebuild critical systems"
        result["reasoning"] = (
            f"Backups are {scenario.backup_age_days} days old. "
            "Restore critical systems from backup, rebuild others."
        )
        result["estimated_recovery_time"] = "1-2 weeks"
        result["risk_assessment"] = "Medium-high risk - significant data loss possible"

    # Option 4: Consider negotiation (last resort)
    else:
        result["primary_recommendation"] = "Engage incident response firm for options"
        result["reasoning"] = (
            "No viable backup option. Engage professional IR firm to evaluate "
            "negotiation as last resort. Do NOT pay without professional guidance."
        )
        result["estimated_recovery_time"] = "Unknown - depends on chosen path"
        result["risk_assessment"] = "High risk in all scenarios"

    # Regulatory actions
    if "GDPR" in scenario.regulatory_requirements:
        result["regulatory_actions"].append("GDPR: Notify supervisory authority within 72 hours")
        if scenario.data_exfiltrated:
            result["regulatory_actions"].append(
                "GDPR: Notify affected individuals if high risk to rights"
            )

    if "HIPAA" in scenario.regulatory_requirements:
        result["regulatory_actions"].append("HIPAA: Report breach to HHS within 60 days")
        result["regulatory_actions"].append(
            "HIPAA: Notify affected individuals without unreasonable delay"
        )

    if "PCI-DSS" in scenario.regulatory_requirements:
        result["regulatory_actions"].append(
            "PCI-DSS: Notify card brands and acquiring bank immediately"
        )

    # Add exfiltration warning
    if scenario.data_exfiltrated:
        result["reasoning"] += (
            f" WARNING: Data exfiltrated ({', '.join(scenario.exfil_data_types)}). "
            "Even with recovery, data may be leaked. Consider legal and PR implications."
        )

    return result


# =============================================================================
# Main
# =============================================================================


def main():
    """Demonstrate ransomware analysis capabilities."""
    print("=" * 60)
    print("Lab 11a: Ransomware Fundamentals - Solution")
    print("=" * 60)

    # Task 1: Identify ransomware family
    print("\n📋 Task 1: Identify Ransomware Family")
    print("-" * 40)

    artifacts = RansomwareArtifacts(
        encrypted_extension=".lockbit",
        ransom_note_filename="Restore-My-Files.txt",
        ransom_note_content="""
        ~~~ LockBit 3.0 ~~~
        Your files have been encrypted!
        
        To decrypt your files, visit:
        http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion
        
        Your personal ID: A1B2C3D4E5F6
        
        Do not try to decrypt files yourself - you will damage them!
        """,
        suspicious_processes=["lockbit.exe", "psexec.exe"],
    )

    result = identify_ransomware_family(artifacts)
    print(f"✅ Family: {result['family'].value}")
    print(f"✅ Confidence: {result['confidence']:.1%}")
    print(f"✅ Matched indicators:")
    for indicator in result["matched_indicators"]:
        print(f"   • {indicator}")

    # Task 2: Map attack to MITRE
    print("\n📋 Task 2: Map Attack to MITRE ATT&CK")
    print("-" * 40)

    events = [
        AttackEvent("09:00", "Phishing email with macro document received"),
        AttackEvent("09:15", "PowerShell downloads beacon.exe from attacker server"),
        AttackEvent("09:30", "Scheduled task created for persistence"),
        AttackEvent("10:00", "AdFind.exe runs for Active Directory enumeration"),
        AttackEvent("11:00", "PsExec spreads malware to 5 other hosts"),
        AttackEvent("14:00", "Rclone uploads 50GB to cloud storage"),
        AttackEvent("15:00", "vssadmin deletes all shadow copies"),
        AttackEvent("15:05", "Files begin encrypting with .lockbit extension"),
    ]

    timeline = map_attack_timeline(events)
    for event in timeline:
        print(f"\n{event['timestamp']} - {event['description']}")
        if event["techniques"]:
            for tech in event["techniques"]:
                print(f"   → {tech['technique_id']}: {tech['technique_name']} ({tech['tactic']})")
        else:
            print("   → No technique mapped")

    # Task 3: Extract IOCs
    print("\n📋 Task 3: Extract IOCs from Ransom Note")
    print("-" * 40)

    ransom_note = """
    ALL YOUR FILES HAVE BEEN ENCRYPTED BY LOCKBIT 3.0
    
    Contact us:
    - TOR: http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion
    - Email: support@lockbit-decryptor.onion
    
    Your personal ID: VICTIM-A1B2C3D4E5
    
    Payment address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    Amount: 2.5 BTC
    
    Deadline: 72 hours or price doubles
    After 7 days, your data will be published on our leak site.
    """

    iocs = extract_iocs_from_note(ransom_note)
    print(f"✅ Onion URLs: {iocs['onion_urls']}")
    print(f"✅ Bitcoin addresses: {iocs['bitcoin_addresses']}")
    print(f"✅ Email addresses: {iocs['email_addresses']}")
    print(f"✅ Victim ID: {iocs['victim_id']}")
    print(f"✅ Deadlines: {iocs['deadlines']}")
    print(f"✅ Ransom amount: {iocs['ransom_amount']}")

    # Task 4: Recovery decision
    print("\n📋 Task 4: Recovery Decision")
    print("-" * 40)

    scenario = IncidentScenario(
        endpoints_encrypted=500,
        total_endpoints=1250,
        backup_age_days=3,
        backup_verified_clean=True,
        data_exfiltrated=True,
        exfil_data_types=["HR records", "financial data"],
        ransom_demand_usd=500000,
        decryptor_available=False,
        critical_ops_down=True,
        regulatory_requirements=["GDPR"],
    )

    recommendation = recommend_recovery_approach(scenario)
    print(f"\n✅ Primary Recommendation: {recommendation['primary_recommendation']}")
    print(f"\n✅ Reasoning: {recommendation['reasoning']}")
    print(f"\n✅ Estimated Recovery Time: {recommendation['estimated_recovery_time']}")
    print(f"\n✅ Risk Assessment: {recommendation['risk_assessment']}")
    print(f"\n✅ Regulatory Actions:")
    for action in recommendation["regulatory_actions"]:
        print(f"   • {action}")

    print("\n" + "=" * 60)
    print("✅ Lab complete! You now understand ransomware fundamentals.")
    print("=" * 60)


if __name__ == "__main__":
    main()

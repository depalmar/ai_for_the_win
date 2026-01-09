#!/usr/bin/env python3
"""
Lab 11a: Ransomware Fundamentals - Starter

Learn to identify ransomware families, map attacks to MITRE ATT&CK,
and make informed recovery decisions.

Complete the TODOs to build your ransomware analysis skills.
"""

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

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


# Family signatures for identification
FAMILY_SIGNATURES = {
    RansomwareFamily.LOCKBIT: {
        "extensions": [".lockbit", ".abcd", ".LockBit"],
        "note_patterns": ["lockbit", "restore-my-files", "LOCKBIT 3.0"],
        "note_files": ["Restore-My-Files.txt"],
    },
    RansomwareFamily.BLACKCAT: {
        "extensions": [".alphv", ".ALPHV"],
        "note_patterns": ["alphv", "blackcat", "RECOVER-FILES"],
        "note_files": ["RECOVER-[ID]-FILES.txt"],
    },
    RansomwareFamily.CONTI: {
        "extensions": [".CONTI", ".conti"],
        "note_patterns": ["conti", "CONTI_README"],
        "note_files": ["readme.txt", "CONTI_README.txt"],
    },
    RansomwareFamily.ROYAL: {
        "extensions": [".royal"],
        "note_patterns": ["royal", "README.TXT"],
        "note_files": ["README.TXT"],
    },
    RansomwareFamily.PLAY: {
        "extensions": [".play", ".PLAY"],
        "note_patterns": ["play", "ReadMe.txt"],
        "note_files": ["ReadMe.txt"],
    },
    RansomwareFamily.AKIRA: {
        "extensions": [".akira"],
        "note_patterns": ["akira", "akira_readme"],
        "note_files": ["akira_readme.txt"],
    },
}


# =============================================================================
# Task 1: Identify Ransomware Family
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

    TODO:
    1. Check file extension against known families
    2. Check ransom note filename patterns
    3. Search note content for family indicators
    4. Return family name with confidence score

    Args:
        artifacts: Collected ransomware artifacts

    Returns:
        {
            "family": RansomwareFamily,
            "confidence": float (0-1),
            "matched_indicators": List[str]
        }
    """
    matched_indicators = []
    family_scores = {family: 0 for family in RansomwareFamily}

    # TODO: Check extension matches
    # Hint: Loop through FAMILY_SIGNATURES and check if
    # artifacts.encrypted_extension matches any family's extensions

    # TODO: Check ransom note filename
    # Hint: Check if artifacts.ransom_note_filename matches
    # any family's note_files patterns

    # TODO: Check ransom note content
    # Hint: Search artifacts.ransom_note_content for
    # family-specific patterns (case-insensitive)

    # TODO: Calculate best match
    # Return the family with highest score

    return {
        "family": RansomwareFamily.UNKNOWN,
        "confidence": 0.0,
        "matched_indicators": matched_indicators,
    }


# =============================================================================
# Task 2: Map Attack to MITRE ATT&CK
# =============================================================================

MITRE_TECHNIQUES = {
    # Initial Access
    "phishing": {"id": "T1566", "tactic": "Initial Access"},
    "exploit_public": {"id": "T1190", "tactic": "Initial Access"},
    "valid_accounts": {"id": "T1078", "tactic": "Initial Access"},
    # Execution
    "powershell": {"id": "T1059.001", "tactic": "Execution"},
    "cmd": {"id": "T1059.003", "tactic": "Execution"},
    "macro": {"id": "T1204.002", "tactic": "Execution"},
    # Persistence
    "scheduled_task": {"id": "T1053.005", "tactic": "Persistence"},
    "registry_run": {"id": "T1547.001", "tactic": "Persistence"},
    "service": {"id": "T1543.003", "tactic": "Persistence"},
    # Discovery
    "ad_enum": {"id": "T1087.002", "tactic": "Discovery"},
    "network_scan": {"id": "T1046", "tactic": "Discovery"},
    "file_discovery": {"id": "T1083", "tactic": "Discovery"},
    # Lateral Movement
    "psexec": {"id": "T1569.002", "tactic": "Lateral Movement"},
    "wmi": {"id": "T1047", "tactic": "Lateral Movement"},
    "rdp": {"id": "T1021.001", "tactic": "Lateral Movement"},
    "smb": {"id": "T1021.002", "tactic": "Lateral Movement"},
    # Collection
    "archive": {"id": "T1560", "tactic": "Collection"},
    "data_staged": {"id": "T1074", "tactic": "Collection"},
    # Exfiltration
    "exfil_cloud": {"id": "T1567", "tactic": "Exfiltration"},
    "exfil_c2": {"id": "T1041", "tactic": "Exfiltration"},
    # Impact
    "encrypt": {"id": "T1486", "tactic": "Impact"},
    "inhibit_recovery": {"id": "T1490", "tactic": "Impact"},
    "service_stop": {"id": "T1489", "tactic": "Impact"},
    "data_destruction": {"id": "T1485", "tactic": "Impact"},
}


@dataclass
class AttackEvent:
    """A single event in an attack timeline."""

    timestamp: str
    description: str
    techniques: List[str] = None  # To be filled


def map_event_to_mitre(event_description: str) -> List[Dict]:
    """
    Map an attack event description to MITRE ATT&CK techniques.

    TODO:
    1. Parse the event description for keywords
    2. Match keywords to techniques in MITRE_TECHNIQUES
    3. Return list of matching techniques

    Args:
        event_description: Natural language description of event

    Returns:
        List of {
            "technique_id": "T1234",
            "technique_name": "...",
            "tactic": "...",
            "confidence": float
        }

    Example:
        "PowerShell downloads beacon.exe" -> T1059.001 (PowerShell)
    """
    matches = []
    description_lower = event_description.lower()

    # TODO: Define keyword mappings
    # Example: "powershell" -> "powershell" technique
    keyword_mappings = {
        "phishing": "phishing",
        "powershell": "powershell",
        # TODO: Add more mappings
    }

    # TODO: Search for keywords and add matches

    return matches


def map_attack_timeline(events: List[AttackEvent]) -> List[Dict]:
    """
    Map an entire attack timeline to MITRE ATT&CK.

    Returns enriched timeline with technique mappings.
    """
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
# Task 3: Extract IOCs from Ransom Note
# =============================================================================


def extract_iocs_from_note(note_content: str) -> Dict:
    """
    Extract Indicators of Compromise from a ransom note.

    TODO:
    1. Extract .onion URLs (Tor addresses)
    2. Extract Bitcoin/cryptocurrency addresses
    3. Extract email addresses
    4. Extract victim IDs
    5. Identify family-specific patterns

    Args:
        note_content: Full text of ransom note

    Returns:
        {
            "onion_urls": [...],
            "bitcoin_addresses": [...],
            "email_addresses": [...],
            "victim_id": "...",
            "deadlines": [...],
            "ransom_amount": "..."
        }
    """
    iocs = {
        "onion_urls": [],
        "bitcoin_addresses": [],
        "email_addresses": [],
        "victim_id": None,
        "deadlines": [],
        "ransom_amount": None,
    }

    # TODO: Extract .onion URLs
    # Pattern: [a-z2-7]{16,56}\.onion
    onion_pattern = r"[a-z2-7]{16,56}\.onion"
    # iocs["onion_urls"] = re.findall(onion_pattern, note_content)

    # TODO: Extract Bitcoin addresses
    # Pattern: (bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}
    btc_pattern = r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"
    # iocs["bitcoin_addresses"] = re.findall(btc_pattern, note_content)

    # TODO: Extract email addresses
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    # iocs["email_addresses"] = re.findall(email_pattern, note_content)

    # TODO: Look for victim IDs (often hex strings)

    # TODO: Look for deadlines/timers

    return iocs


# =============================================================================
# Task 4: Recovery Decision Framework
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
    """
    Recommend a recovery approach based on incident scenario.

    TODO:
    1. Evaluate backup viability
    2. Check for free decryptors
    3. Assess regulatory requirements
    4. Consider business impact
    5. Return prioritized recommendations

    Args:
        scenario: Incident details

    Returns:
        {
            "primary_recommendation": str,
            "reasoning": str,
            "regulatory_actions": List[str],
            "estimated_recovery_time": str,
            "risk_assessment": str
        }
    """
    result = {
        "primary_recommendation": "",
        "reasoning": "",
        "regulatory_actions": [],
        "estimated_recovery_time": "",
        "risk_assessment": "",
    }

    # TODO: Evaluate backup option
    # If backups exist, are recent, and verified clean -> recommend restore

    # TODO: Check decryptor availability
    # If free decryptor available -> recommend using it

    # TODO: Assess regulatory requirements
    # GDPR: 72-hour notification
    # HIPAA: Breach notification
    # etc.

    # TODO: Determine recommendation based on factors

    return result


# =============================================================================
# Main
# =============================================================================


def main():
    """Run the lab exercises."""
    print("=" * 60)
    print("Lab 11a: Ransomware Fundamentals - Starter")
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
    print(f"Family: {result['family']}")
    print(f"Confidence: {result['confidence']:.1%}")
    print(f"Indicators: {result['matched_indicators']}")
    print("\n⚠️  Complete the TODO in identify_ransomware_family()")

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

    for event in events[:3]:
        techniques = map_event_to_mitre(event.description)
        print(f"{event.timestamp} - {event.description}")
        print(f"  Techniques: {techniques}")
    print("...")
    print("\n⚠️  Complete the TODO in map_event_to_mitre()")

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
    print(f"Onion URLs: {iocs['onion_urls']}")
    print(f"Bitcoin addresses: {iocs['bitcoin_addresses']}")
    print(f"Victim ID: {iocs['victim_id']}")
    print("\n⚠️  Complete the TODO in extract_iocs_from_note()")

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
    print(f"Recommendation: {recommendation['primary_recommendation']}")
    print(f"Reasoning: {recommendation['reasoning']}")
    print("\n⚠️  Complete the TODO in recommend_recovery_approach()")

    print("\n" + "=" * 60)
    print("Complete the TODOs, then compare with solution/main.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

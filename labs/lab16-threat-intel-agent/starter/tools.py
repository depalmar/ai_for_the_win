#!/usr/bin/env python3
"""
Lab 05: Threat Intelligence Agent - Tools Module

Implement tools that the AI agent can use for threat intelligence gathering.
"""

import hashlib
import json
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

# For real implementations, you'd use these APIs:
# - VirusTotal: https://www.virustotal.com/api/
# - AbuseIPDB: https://www.abuseipdb.com/api
# - Shodan: https://shodan.io/
# - GreyNoise: https://www.greynoise.io/

# =============================================================================
# Tool Input Schemas
# =============================================================================


class IPLookupInput(BaseModel):
    """Input schema for IP lookup tool."""

    ip: str = Field(description="IPv4 or IPv6 address to look up")


class DomainAnalysisInput(BaseModel):
    """Input schema for domain analysis tool."""

    domain: str = Field(description="Domain name to analyze (e.g., 'evil.com')")


class HashCheckInput(BaseModel):
    """Input schema for hash lookup tool."""

    file_hash: str = Field(description="File hash (MD5, SHA1, or SHA256)")


class CVELookupInput(BaseModel):
    """Input schema for CVE lookup tool."""

    cve_id: str = Field(description="CVE identifier (e.g., 'CVE-2024-1234')")


class MITRELookupInput(BaseModel):
    """Input schema for MITRE ATT&CK lookup."""

    technique_id: str = Field(description="MITRE ATT&CK technique ID (e.g., 'T1059.001')")


# =============================================================================
# Mock Threat Intelligence Data
# =============================================================================

# This simulates real threat intelligence data
# In production, you'd query actual APIs

MOCK_IP_DATA = {
    "185.143.223.47": {
        "is_malicious": True,
        "abuse_score": 95,
        "country": "RU",
        "city": "Moscow",
        "asn": "AS48666",
        "isp": "Bulletproof Hosting Ltd",
        "threat_types": ["C2", "Malware Distribution"],
        "first_seen": "2023-06-15",
        "last_seen": "2024-01-15",
        "reports": 847,
        "tags": ["APT29", "CozyBear"],
    },
    "91.234.99.100": {
        "is_malicious": True,
        "abuse_score": 78,
        "country": "NL",
        "city": "Amsterdam",
        "asn": "AS12345",
        "isp": "VPS Provider",
        "threat_types": ["Botnet", "Scanner"],
        "first_seen": "2024-01-01",
        "last_seen": "2024-01-14",
        "reports": 156,
        "tags": [],
    },
}

MOCK_DOMAIN_DATA = {
    "evil-c2.com": {
        "is_malicious": True,
        "category": "C2",
        "registrar": "PrivacyGuard Inc",
        "creation_date": "2024-01-10",
        "dns_records": {
            "A": ["185.143.223.47"],
            "MX": [],
            "NS": ["ns1.privatedns.com"],
        },
        "ssl_info": {
            "issuer": "Let's Encrypt",
            "valid_from": "2024-01-10",
            "valid_to": "2024-04-10",
        },
        "threat_intel": {
            "malware_families": ["Cobalt Strike"],
            "campaigns": ["APT29-2024-01"],
        },
    },
    "malware-drop.net": {
        "is_malicious": True,
        "category": "Malware Distribution",
        "registrar": "Shady Registrar",
        "creation_date": "2023-12-20",
        "dns_records": {
            "A": ["91.234.99.100", "91.234.99.101"],
            "MX": [],
            "NS": ["ns1.shadydns.net"],
        },
        "ssl_info": None,
        "threat_intel": {"malware_families": ["Emotet", "TrickBot"], "campaigns": []},
    },
}

MOCK_HASH_DATA = {
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2": {
        "is_malicious": True,
        "detection_ratio": "52/72",
        "malware_family": "Cobalt Strike",
        "file_type": "PE32 executable",
        "file_size": 245760,
        "first_seen": "2024-01-12",
        "names": ["beacon.exe", "payload.exe"],
        "behavior": ["Creates scheduled task", "Contacts C2", "Injects into processes"],
    }
}

MOCK_CVE_DATA = {
    "CVE-2024-1234": {
        "description": "Remote code execution vulnerability in Example Software",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "affected_products": ["Example Software 1.0-2.5"],
        "exploited_in_wild": True,
        "exploit_available": True,
        "patch_available": True,
        "patch_url": "https://example.com/security/patch",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    }
}

MOCK_MITRE_DATA = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "platforms": ["Windows"],
        "detection": "Monitor for PowerShell execution, especially encoded commands and download cradles.",
        "mitigations": [
            "Disable PowerShell for non-admin users",
            "Enable PowerShell script block logging",
            "Use Constrained Language Mode",
        ],
        "related_groups": ["APT29", "APT28", "FIN7"],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse scheduled tasks to execute malicious code.",
        "platforms": ["Windows"],
        "detection": "Monitor for schtasks.exe and Task Scheduler events (4698, 4699).",
        "mitigations": [
            "Restrict task creation to administrators",
            "Monitor scheduled task changes",
        ],
        "related_groups": ["APT29", "Lazarus"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools from external systems into compromised environment.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for unusual outbound connections and file downloads.",
        "mitigations": ["Network intrusion prevention", "Web proxy filtering"],
        "related_groups": ["APT29", "APT28", "Turla"],
    },
}


# =============================================================================
# Tool Implementations
# =============================================================================


def lookup_ip(ip: str) -> dict:
    """
    Look up reputation and geolocation for an IP address.

    Args:
        ip: IPv4 or IPv6 address

    Returns:
        Threat intelligence data for the IP

    TODO:
    1. Validate IP format
    2. Check mock data (or real API in production)
    3. Return structured response
    4. Handle unknown IPs gracefully
    """
    # YOUR CODE HERE

    # Basic validation
    # if not is_valid_ip(ip):
    #     return {"error": f"Invalid IP format: {ip}"}

    # Check mock data
    # if ip in MOCK_IP_DATA:
    #     data = MOCK_IP_DATA[ip].copy()
    #     data["ip"] = ip
    #     return data

    # Unknown IP - return neutral response
    # return {
    #     "ip": ip,
    #     "is_malicious": False,
    #     "abuse_score": 0,
    #     "country": "Unknown",
    #     "message": "No threat intelligence found for this IP"
    # }

    pass


def analyze_domain(domain: str) -> dict:
    """
    Analyze a domain for threat indicators.

    Args:
        domain: Domain name to analyze

    Returns:
        Domain analysis results

    TODO:
    1. Normalize domain (lowercase, remove protocol)
    2. Check mock data (or real API)
    3. Return structured response
    """
    # YOUR CODE HERE
    pass


def check_hash(file_hash: str) -> dict:
    """
    Check file hash against threat intelligence.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash

    Returns:
        Hash analysis results

    TODO:
    1. Identify hash type by length
    2. Normalize to lowercase
    3. Check mock data (or real API)
    4. Return structured response
    """
    # YOUR CODE HERE
    pass


def search_cve(cve_id: str) -> dict:
    """
    Get details about a CVE.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)

    Returns:
        CVE details

    TODO:
    1. Validate CVE format
    2. Normalize to uppercase
    3. Check mock data (or real API)
    4. Return structured response
    """
    # YOUR CODE HERE
    pass


def get_attack_technique(technique_id: str) -> dict:
    """
    Get details about a MITRE ATT&CK technique.

    Args:
        technique_id: ATT&CK technique ID (e.g., T1059.001)

    Returns:
        Technique details

    TODO:
    1. Normalize technique ID format
    2. Check mock data (or real API)
    3. Return structured response
    """
    # YOUR CODE HERE
    pass


# =============================================================================
# Helper Functions
# =============================================================================


def is_valid_ip(ip: str) -> bool:
    """Validate IP address format."""
    import re

    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def identify_hash_type(hash_value: str) -> Optional[str]:
    """Identify hash type by length."""
    hash_len = len(hash_value)
    if hash_len == 32:
        return "md5"
    elif hash_len == 40:
        return "sha1"
    elif hash_len == 64:
        return "sha256"
    return None


def normalize_domain(domain: str) -> str:
    """Normalize domain name."""
    domain = domain.lower().strip()
    # Remove protocol if present
    for prefix in ["http://", "https://", "www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    # Remove trailing slash and path
    domain = domain.split("/")[0]
    return domain


# =============================================================================
# Tool Registration (for LangChain)
# =============================================================================


def get_tools():
    """
    Get list of tools configured for LangChain agent.

    TODO: Create StructuredTool instances for each function
    """
    from langchain.tools import StructuredTool

    tools = [
        # StructuredTool.from_function(
        #     func=lookup_ip,
        #     name="ip_lookup",
        #     description="Look up threat intelligence for an IP address. Returns reputation, geolocation, and threat data.",
        #     args_schema=IPLookupInput
        # ),
        # ... add other tools
    ]

    return tools


# =============================================================================
# Testing
# =============================================================================

if __name__ == "__main__":
    # Test the tools
    print("Testing IP Lookup:")
    result = lookup_ip("185.143.223.47")
    print(json.dumps(result, indent=2))

    print("\nTesting Domain Analysis:")
    result = analyze_domain("evil-c2.com")
    print(json.dumps(result, indent=2))

    print("\nTesting Hash Check:")
    result = check_hash("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    print(json.dumps(result, indent=2))

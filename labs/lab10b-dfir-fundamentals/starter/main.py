"""
Lab 10b: DFIR Fundamentals (Starter)

Build an artifact analysis toolkit for incident response.
Complete the TODOs to analyze processes, files, network, and map to ATT&CK.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class Severity(Enum):
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"


@dataclass
class Finding:
    """Represents a security finding."""
    severity: Severity
    category: str  # process, file, network, registry
    description: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    evidence: Optional[str] = None


# ============================================================================
# SAMPLE INCIDENT DATA
# ============================================================================

SAMPLE_PROCESSES = [
    {"pid": 4100, "name": "WINWORD.EXE", "parent": "explorer.exe", 
     "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
     "cmdline": "WINWORD.EXE /n Invoice.docm"},
    {"pid": 4200, "name": "powershell.exe", "parent": "WINWORD.EXE",
     "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "cmdline": "powershell.exe -enc JABjAGwAaQBlAG4="},
    {"pid": 4350, "name": "rundll32.exe", "parent": "powershell.exe",
     "path": "C:\\Windows\\System32\\rundll32.exe",
     "cmdline": "rundll32.exe"},
    {"pid": 5600, "name": "svchost.exe", "parent": "rundll32.exe",
     "path": "C:\\Users\\Public\\svchost.exe",
     "cmdline": "svchost.exe -k netsvcs"},
    {"pid": 7000, "name": "locker.exe", "parent": "rundll32.exe",
     "path": "C:\\Windows\\Temp\\locker.exe",
     "cmdline": "locker.exe -encrypt C:\\"},
    {"pid": 7100, "name": "vssadmin.exe", "parent": "locker.exe",
     "path": "C:\\Windows\\System32\\vssadmin.exe",
     "cmdline": "vssadmin delete shadows /all /quiet"},
    # Benign processes for comparison
    {"pid": 800, "name": "svchost.exe", "parent": "services.exe",
     "path": "C:\\Windows\\System32\\svchost.exe",
     "cmdline": "svchost.exe -k DcomLaunch"},
    {"pid": 2100, "name": "explorer.exe", "parent": "userinit.exe",
     "path": "C:\\Windows\\explorer.exe",
     "cmdline": "explorer.exe"},
]

SAMPLE_FILES = [
    {"path": "C:\\Windows\\Temp\\locker.exe", "size": 245760, "created": "2024-01-15 09:15"},
    {"path": "C:\\Users\\Public\\svchost.exe", "size": 102400, "created": "2024-01-15 09:20"},
    {"path": "C:\\Users\\jsmith\\Desktop\\README.txt", "size": 2048, "created": "2024-01-15 11:00"},
    {"path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice.docm", "size": 51200, "created": "2024-01-15 09:00"},
]

SAMPLE_CONNECTIONS = [
    {"pid": 4350, "local": "192.168.1.50:49667", "remote": "185.143.223.47:443", "state": "ESTABLISHED"},
    {"pid": 4350, "local": "192.168.1.50:49668", "remote": "185.143.223.47:8080", "state": "ESTABLISHED"},
    {"pid": 5600, "local": "192.168.1.50:49700", "remote": "45.33.32.156:4444", "state": "ESTABLISHED"},
    {"pid": 800, "local": "192.168.1.50:135", "remote": "0.0.0.0:0", "state": "LISTENING"},
]

# ATT&CK technique database (simplified)
ATTACK_TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1059.001": "Command and Scripting: PowerShell",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1055": "Process Injection",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1041": "Exfiltration Over C2 Channel",
}


# ============================================================================
# TODO 1: Process Anomaly Detection
# ============================================================================

def analyze_processes(processes: List[Dict]) -> List[Finding]:
    """
    Analyze process data for suspicious indicators.
    
    Look for:
    - Office apps spawning shells (powershell, cmd)
    - System binaries running from wrong paths
    - Encoded PowerShell commands
    - Processes with no arguments when they should have them
    
    Args:
        processes: List of process dictionaries
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    # Known suspicious parent-child relationships
    suspicious_parents = {
        "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"],
        "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    }
    
    # System binaries that should only be in System32
    system_binaries = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe"]
    
    for proc in processes:
        # TODO: Check for suspicious parent-child relationships
        # Hint: if proc["name"].lower() in suspicious_parents:
        #       check if proc["parent"].lower() in suspicious_parents[proc["name"].lower()]
        
        # TODO: Check for masquerading (system binary from wrong path)
        # Hint: Check if name is in system_binaries but path doesn't contain "System32"
        
        # TODO: Check for encoded PowerShell
        # Hint: Check if "-enc" or "-encoded" in cmdline
        
        # TODO: Check for rundll32 without arguments
        # Hint: cmdline.strip() == "rundll32.exe"
        
        pass  # Remove this and add your code
    
    return findings


# ============================================================================
# TODO 2: File Artifact Analysis
# ============================================================================

def analyze_files(files: List[Dict]) -> List[Finding]:
    """
    Analyze file artifacts for suspicious indicators.
    
    Look for:
    - Executables in temp folders
    - Executables in user-writable locations
    - Known malicious file patterns
    
    Args:
        files: List of file dictionaries
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    suspicious_locations = [
        "\\temp\\",
        "\\users\\public\\",
        "\\appdata\\local\\temp\\",
    ]
    
    suspicious_extensions = [".exe", ".dll", ".bat", ".ps1", ".vbs"]
    
    for file in files:
        # TODO: Check for executables in suspicious locations
        # Hint: Check if any suspicious_location is in file["path"].lower()
        #       AND file["path"].lower() ends with any suspicious_extension
        
        pass  # Remove this and add your code
    
    return findings


# ============================================================================
# TODO 3: Network Connection Analysis
# ============================================================================

def analyze_network(connections: List[Dict]) -> List[Finding]:
    """
    Analyze network connections for suspicious indicators.
    
    Look for:
    - Connections to known suspicious ports (4444, 8080, etc.)
    - Connections from suspicious processes
    - External connections from system processes
    
    Args:
        connections: List of connection dictionaries
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    suspicious_ports = [4444, 5555, 6666, 8080, 8443, 1337, 31337]
    
    for conn in connections:
        # TODO: Extract remote port from connection
        # Hint: int(conn["remote"].split(":")[1])
        
        # TODO: Check if port is suspicious
        # Hint: if remote_port in suspicious_ports:
        
        pass  # Remove this and add your code
    
    return findings


# ============================================================================
# TODO 4: ATT&CK Mapping
# ============================================================================

def map_to_attack(finding: Finding) -> Finding:
    """
    Map a finding to MITRE ATT&CK technique.
    
    Args:
        finding: Finding object to map
        
    Returns:
        Finding with technique_id and technique_name populated
    """
    # Mapping patterns to techniques
    patterns = {
        "T1566.001": ["office", "spawn", "macro", "attachment"],
        "T1059.001": ["powershell", "-enc", "encoded"],
        "T1036.005": ["masquerad", "wrong path", "impersonat"],
        "T1055": ["injection", "hollow", "writeprocess"],
        "T1490": ["shadow", "vssadmin", "recovery"],
        "T1486": ["encrypt", "ransom", "locker"],
        "T1071.001": ["c2", "beacon", "443", "http"],
    }
    
    # TODO: Search finding description for pattern matches
    # Hint: for technique, keywords in patterns.items():
    #       if any(kw in finding.description.lower() for kw in keywords):
    #           finding.technique_id = technique
    #           finding.technique_name = ATTACK_TECHNIQUES.get(technique)
    
    pass  # Remove this and add your code
    
    return finding


# ============================================================================
# TODO 5: Generate Report
# ============================================================================

def generate_report(findings: List[Finding]) -> str:
    """
    Generate a formatted incident report.
    
    Args:
        findings: List of all findings
        
    Returns:
        Formatted report string
    """
    # TODO: Group findings by category
    # TODO: Sort by severity
    # TODO: Format nicely with ASCII art borders
    
    report = "🔍 DFIR Artifact Analysis Report\n"
    report += "=" * 50 + "\n\n"
    
    # Your code here to build the report
    
    return report


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("🔍 DFIR Fundamentals - Artifact Analysis")
    print("=" * 50)
    
    all_findings = []
    
    # Analyze processes
    print("\n[1] Analyzing processes...")
    process_findings = analyze_processes(SAMPLE_PROCESSES)
    all_findings.extend(process_findings)
    print(f"    Found {len(process_findings)} process anomalies")
    
    # Analyze files
    print("\n[2] Analyzing files...")
    file_findings = analyze_files(SAMPLE_FILES)
    all_findings.extend(file_findings)
    print(f"    Found {len(file_findings)} file anomalies")
    
    # Analyze network
    print("\n[3] Analyzing network...")
    network_findings = analyze_network(SAMPLE_CONNECTIONS)
    all_findings.extend(network_findings)
    print(f"    Found {len(network_findings)} network anomalies")
    
    # Map to ATT&CK
    print("\n[4] Mapping to MITRE ATT&CK...")
    for finding in all_findings:
        map_to_attack(finding)
    
    # Generate report
    print("\n[5] Generating report...")
    report = generate_report(all_findings)
    
    print("\n" + "=" * 50)
    print(report)
    
    if len(all_findings) == 0:
        print("\n❌ No findings! Complete the TODOs to detect anomalies.")
    else:
        print(f"\n✅ Analysis complete! {len(all_findings)} findings identified.")


if __name__ == "__main__":
    main()

"""
Lab 07a: Binary Analysis Basics (Solution)

A complete binary analysis toolkit for malware hunting.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional

try:
    import pefile

    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False


@dataclass
class BinaryAnalysis:
    """Results of binary analysis."""

    filename: str
    size: int
    entropy: float
    strings: list
    suspicious_strings: list
    imports: dict
    suspicious_apis: list
    sections: list
    indicators: list


# PE Header Signatures for binary identification
PE_HEADER_SIGNATURES = {
    "MZ": b"MZ",  # DOS header
    "PE": b"PE\x00\x00",  # PE signature
}

SUSPICIOUS_APIS = {
    "injection": [
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
    ],
    "execution": [
        "CreateProcess",
        "CreateProcessW",
        "ShellExecute",
        "WinExec",
        "system",
    ],
    "persistence": [
        "RegSetValueEx",
        "RegSetValueExW",
        "RegCreateKeyEx",
    ],
    "network": [
        "InternetOpen",
        "InternetConnect",
        "HttpOpenRequest",
        "URLDownloadToFile",
        "connect",
        "send",
        "recv",
    ],
    "credential": [
        "CredRead",
        "CredEnumerate",
        "LsaRetrievePrivateData",
    ],
    "crypto": [
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContext",
    ],
}

SUSPICIOUS_PATTERNS = [
    (r"https?://[\w\.-]+[/\w\.-]*", "URL"),
    (r"HKEY_[\w_]+\\[\w\\]+", "Registry path"),
    (r"cmd\.exe|powershell\.exe", "Command interpreter"),
    (r"password|credential|login", "Credential-related"),
    (r"\\\\[\w\.]+\\[\w$]+", "UNC path"),
    (r"\.onion", "Tor address"),
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
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


def get_entropy_assessment(entropy: float) -> str:
    """Get human-readable entropy assessment."""
    if entropy < 1.0:
        return "Very low (repetitive data)"
    elif entropy < 4.0:
        return "Low (text/structured)"
    elif entropy < 6.0:
        return "Normal (executable code)"
    elif entropy < 7.0:
        return "High (compressed)"
    else:
        return "⚠️ Very high (packed/encrypted)"


def extract_strings(data: bytes, min_length: int = 4) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    matches = re.findall(pattern, data)
    return [m.decode("ascii", errors="ignore") for m in matches]


def find_suspicious_strings(strings: list) -> list:
    """Find strings matching suspicious patterns."""
    suspicious = []
    seen = set()

    for string in strings:
        for pattern, pattern_type in SUSPICIOUS_PATTERNS:
            if re.search(pattern, string, re.IGNORECASE):
                if string not in seen:
                    suspicious.append((string, pattern_type))
                    seen.add(string)
                break

    return suspicious


def parse_pe_imports(filepath: str) -> dict:
    """Parse imports from a PE file."""
    if not HAVE_PEFILE:
        return {"error": "pefile not installed"}

    try:
        pe = pefile.PE(filepath)
        imports = {}

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="ignore"))
                imports[dll_name] = functions

        return imports
    except Exception as e:
        return {"error": str(e)}


def find_suspicious_apis(imports: dict) -> list:
    """Find suspicious API imports."""
    suspicious = []

    all_functions = []
    for dll, functions in imports.items():
        if isinstance(functions, list):
            all_functions.extend(functions)

    for func in all_functions:
        for category, apis in SUSPICIOUS_APIS.items():
            if func in apis:
                suspicious.append((func, category))
                break

    return suspicious


def analyze_sections(filepath: str) -> list:
    """Analyze PE sections for anomalies."""
    if not HAVE_PEFILE:
        return []

    try:
        pe = pefile.PE(filepath)
        sections = []

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy = section.get_entropy()

            sections.append(
                {
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": entropy,
                    "executable": bool(section.Characteristics & 0x20000000),
                    "writable": bool(section.Characteristics & 0x80000000),
                }
            )

        return sections
    except Exception as e:
        return [{"error": str(e)}]


def analyze_pe_structure(headers: dict) -> dict:
    """
    Analyze PE structure from header information.

    Args:
        headers: Dict with machine, num_sections, timestamp, characteristics

    Returns:
        Analysis results with architecture and section info
    """
    machine_types = {
        "0x14c": "x86 (32-bit)",
        "0x8664": "x64 (64-bit)",
        "0x1c0": "ARM",
        "0xaa64": "ARM64",
    }

    machine = headers.get("machine", "unknown")
    arch = machine_types.get(machine, f"Unknown ({machine})")

    return {
        "architecture": arch,
        "sections": headers.get("num_sections", 0),
        "timestamp": headers.get("timestamp", "unknown"),
        "characteristics": headers.get("characteristics", []),
        "is_executable": "EXECUTABLE_IMAGE" in headers.get("characteristics", []),
        "is_dll": "DLL" in headers.get("characteristics", []),
    }


def check_suspicious_sections(sections: list) -> list:
    """
    Check sections for suspicious characteristics.

    Args:
        sections: List of section dicts with name and characteristics

    Returns:
        List of suspicious findings
    """
    suspicious = []

    # Known packer/suspicious section names
    suspicious_names = [
        ".UPX",
        "UPX0",
        "UPX1",
        "UPX2",  # UPX packer
        ".aspack",
        ".adata",  # ASPack
        ".nsp",
        ".nsp0",
        ".nsp1",  # NSPack
        ".packed",  # Generic packed
        ".themida",
        ".winlice",  # Themida
        ".vmp",
        ".vmp0",
        ".vmp1",  # VMProtect
        ".petite",  # Petite
    ]

    for section in sections:
        name = section.get("name", "")
        chars = section.get("characteristics", [])

        # Check for packer indicators
        for sus_name in suspicious_names:
            if sus_name.lower() in name.lower():
                suspicious.append(
                    {
                        "section": name,
                        "reason": f"Packer indicator: {sus_name}",
                        "severity": "high",
                    }
                )
                break

        # Check for executable + writable (common in packed/malicious)
        if "EXECUTE" in chars and "WRITE" in chars:
            suspicious.append(
                {
                    "section": name,
                    "reason": "Section is both executable and writable",
                    "severity": "medium",
                }
            )

    return suspicious


def detect_packers(sections: list) -> list:
    """
    Detect known packers from section names.

    Args:
        sections: List of section dicts with name field

    Returns:
        List of detected packer names
    """
    packers = []

    packer_signatures = {
        "UPX": [".UPX", "UPX0", "UPX1", "UPX2"],
        "ASPack": [".aspack", ".adata"],
        "NSPack": [".nsp", ".nsp0", ".nsp1"],
        "Themida": [".themida", ".winlice"],
        "VMProtect": [".vmp", ".vmp0", ".vmp1"],
        "Petite": [".petite"],
        "PECompact": [".pec", ".pec2"],
    }

    section_names = [s.get("name", "").lower() for s in sections]

    for packer, signatures in packer_signatures.items():
        for sig in signatures:
            if any(sig.lower() in name for name in section_names):
                if packer not in packers:
                    packers.append(packer)
                break

    return packers


def generate_indicators(analysis: BinaryAnalysis) -> list:
    """Generate list of suspicious indicators."""
    indicators = []

    # Entropy check
    if analysis.entropy > 7.0:
        indicators.append(f"High entropy ({analysis.entropy:.2f}) - possible packing/encryption")

    # Suspicious API combinations
    api_categories = set(cat for _, cat in analysis.suspicious_apis)

    if "injection" in api_categories:
        indicators.append("Process injection APIs detected (T1055)")

    if "injection" in api_categories and "execution" in api_categories:
        indicators.append("Code injection + execution - likely malicious")

    if "network" in api_categories:
        indicators.append("Network APIs - potential C2 capability (T1071)")

    if "persistence" in api_categories:
        indicators.append("Persistence APIs - registry modification (T1547)")

    if "crypto" in api_categories:
        indicators.append("Crypto APIs - possible ransomware (T1486)")

    # Suspicious strings
    has_url = any(stype == "URL" for _, stype in analysis.suspicious_strings)
    has_cmd = any(stype == "Command interpreter" for _, stype in analysis.suspicious_strings)

    if has_url:
        indicators.append("URL found - potential C2/download")

    if has_cmd:
        indicators.append("Command interpreter reference - execution capability")

    return indicators


def analyze_binary(filepath: str = None, data: bytes = None) -> BinaryAnalysis:
    """Perform complete binary analysis."""
    if data is None and filepath:
        with open(filepath, "rb") as f:
            data = f.read()

    filename = filepath or "memory_buffer"

    # Basic analysis
    entropy = calculate_entropy(data)
    strings = extract_strings(data)
    suspicious_strings = find_suspicious_strings(strings)

    # PE-specific analysis
    imports = {}
    sections = []
    if filepath and HAVE_PEFILE:
        try:
            imports = parse_pe_imports(filepath)
            sections = analyze_sections(filepath)
        except Exception:
            pass

    suspicious_apis = find_suspicious_apis(imports)

    analysis = BinaryAnalysis(
        filename=filename,
        size=len(data),
        entropy=entropy,
        strings=strings,
        suspicious_strings=suspicious_strings,
        imports=imports,
        suspicious_apis=suspicious_apis,
        sections=sections,
        indicators=[],
    )

    analysis.indicators = generate_indicators(analysis)

    return analysis


def print_report(analysis: BinaryAnalysis):
    """Print formatted analysis report."""
    print(f"\n🔬 Binary Analysis Report")
    print("=" * 60)
    print(f"📄 File: {analysis.filename}")
    print(f"   Size: {analysis.size:,} bytes")

    # Entropy
    print(f"\n📊 ENTROPY ANALYSIS")
    print("-" * 60)
    print(f"   Overall: {analysis.entropy:.2f}")
    print(f"   Assessment: {get_entropy_assessment(analysis.entropy)}")

    # Section entropy (if available)
    if analysis.sections:
        print("\n   Section Entropy:")
        for section in analysis.sections:
            if isinstance(section, dict) and "name" in section:
                ent = section.get("entropy", 0)
                bar = "█" * int(ent * 2) + "░" * (16 - int(ent * 2))
                flag = " ⚠️" if ent > 7.0 else ""
                print(f"   {section['name']:10s} {ent:.2f} {bar}{flag}")

    # Strings
    print(f"\n📝 STRINGS ANALYSIS")
    print("-" * 60)
    print(f"   Total strings: {len(analysis.strings)}")

    if analysis.suspicious_strings:
        print(f"\n   ⚠️ Suspicious strings ({len(analysis.suspicious_strings)}):")
        for string, stype in analysis.suspicious_strings[:10]:
            print(f"     [{stype:20s}] {string[:50]}")

    # Imports
    if analysis.imports and "error" not in analysis.imports:
        print(f"\n📦 IMPORTS ANALYSIS")
        print("-" * 60)
        for dll, funcs in list(analysis.imports.items())[:5]:
            print(f"   {dll}: {len(funcs)} imports")

        if analysis.suspicious_apis:
            print(f"\n   ⚠️ Suspicious APIs ({len(analysis.suspicious_apis)}):")
            for api, category in analysis.suspicious_apis:
                print(f"     [{category:12s}] {api}")

    # Indicators
    if analysis.indicators:
        print(f"\n🎯 THREAT INDICATORS")
        print("-" * 60)
        for indicator in analysis.indicators:
            print(f"   [!] {indicator}")

    # Risk assessment
    print(f"\n📊 RISK ASSESSMENT")
    print("-" * 60)
    risk_score = len(analysis.indicators) + len(analysis.suspicious_apis) // 2
    if risk_score >= 5:
        print("   Risk Level: 🔴 HIGH")
    elif risk_score >= 2:
        print("   Risk Level: 🟠 MEDIUM")
    else:
        print("   Risk Level: 🟢 LOW")


def create_sample_data() -> bytes:
    """Create sample binary-like data for testing."""
    data = b"MZ" + b"\x90" * 100
    data += b"PE\x00\x00"
    data += b"\x00" * 100
    data += b"push ebp\nmov ebp, esp\nsub esp, 0x20\n" * 50
    data += b"http://evil-c2.com/beacon\x00"
    data += b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    data += b"cmd.exe /c whoami\x00"
    data += b"password.txt\x00"
    data += b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"

    import random

    random.seed(42)
    data += bytes([random.randint(0, 255) for _ in range(500)])

    return data


def main():
    print("🔬 Binary Analysis Basics - Complete Toolkit")
    print("=" * 60)

    # Create and analyze sample data
    print("\n📦 Creating sample binary data...")
    sample_data = create_sample_data()

    analysis = analyze_binary(data=sample_data)
    print_report(analysis)

    # Key takeaways
    print("\n" + "=" * 60)
    print("📚 KEY TAKEAWAYS")
    print("=" * 60)
    print(
        """
   1. Entropy measures randomness - high = packed/encrypted
   2. String extraction reveals IOCs (URLs, paths, commands)
   3. API imports show capabilities (injection, C2, persistence)
   4. Section analysis finds anomalies in structure
   5. Combine indicators for confidence scoring

   Ready for Lab 07 (YARA Generator)!
    """
    )


if __name__ == "__main__":
    main()

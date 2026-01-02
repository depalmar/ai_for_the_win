"""
Lab 07a: Binary Analysis Basics (Starter)

Learn essential binary analysis concepts for malware hunting.
Complete the TODOs to build a binary analysis toolkit.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional

# Optional: pefile for PE parsing (pip install pefile)
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False
    print("⚠️ For full PE parsing: pip install pefile")


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class BinaryAnalysis:
    """Results of binary analysis."""
    filename: str
    size: int
    entropy: float
    strings: list
    suspicious_strings: list
    imports: dict  # DLL -> list of functions
    suspicious_apis: list
    sections: list  # List of section info dicts
    indicators: list  # List of suspicious findings


# Suspicious API categories
SUSPICIOUS_APIS = {
    "injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    ],
    "execution": [
        "CreateProcess", "CreateProcessW", "ShellExecute",
        "WinExec", "system",
    ],
    "persistence": [
        "RegSetValueEx", "RegSetValueExW", "RegCreateKeyEx",
    ],
    "network": [
        "InternetOpen", "InternetConnect", "HttpOpenRequest",
        "URLDownloadToFile", "connect", "send", "recv",
    ],
    "credential": [
        "CredRead", "CredEnumerate", "LsaRetrievePrivateData",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    ],
}

# Suspicious string patterns
SUSPICIOUS_PATTERNS = [
    (r'https?://[\w\.-]+[/\w\.-]*', "URL"),
    (r'HKEY_[\w_]+\\[\w\\]+', "Registry path"),
    (r'cmd\.exe|powershell\.exe', "Command interpreter"),
    (r'password|credential|login', "Credential-related"),
    (r'\\\\[\w\.]+\\[\w$]+', "UNC path"),
    (r'\.onion', "Tor address"),
]


# ============================================================================
# TODO 1: Calculate entropy
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    
    Entropy measures randomness (0-8 bits per byte):
    - 0-4: Structured data (text, code)
    - 4-6: Normal executable
    - 6-7: Compressed
    - 7-8: Encrypted/packed
    
    Args:
        data: Binary data to analyze
        
    Returns:
        Entropy value (0.0 to 8.0)
    """
    if not data:
        return 0.0
    
    # TODO: Calculate Shannon entropy
    # Formula: H = -Σ(p * log2(p)) for each byte value
    # Steps:
    # 1. Count occurrences of each byte value (0-255)
    # 2. Calculate probability of each: count / total_length
    # 3. Sum: -probability * log2(probability) for each
    
    # Hint: Use Counter from collections
    # Hint: Use math.log2()
    
    # Your code here:
    return 0.0


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


# ============================================================================
# TODO 2: Extract strings
# ============================================================================

def extract_strings(data: bytes, min_length: int = 4) -> list:
    """
    Extract printable ASCII strings from binary data.
    
    Args:
        data: Binary data
        min_length: Minimum string length to extract
        
    Returns:
        List of extracted strings
    """
    # TODO: Extract ASCII strings using regex
    # Pattern: printable ASCII characters (0x20-0x7E) repeated min_length+ times
    # Hint: pattern = rb'[\x20-\x7e]{4,}'
    
    # Your code here:
    return []


def find_suspicious_strings(strings: list) -> list:
    """
    Find strings matching suspicious patterns.
    
    Args:
        strings: List of extracted strings
        
    Returns:
        List of (string, pattern_type) tuples
    """
    suspicious = []
    
    # TODO: Check each string against SUSPICIOUS_PATTERNS
    # Hint: for string in strings:
    #           for pattern, pattern_type in SUSPICIOUS_PATTERNS:
    #               if re.search(pattern, string, re.IGNORECASE):
    #                   suspicious.append((string, pattern_type))
    
    # Your code here:
    return suspicious


# ============================================================================
# TODO 3: Parse PE imports
# ============================================================================

def parse_pe_imports(filepath: str) -> dict:
    """
    Parse imports from a PE file.
    
    Args:
        filepath: Path to PE file
        
    Returns:
        Dict of DLL name -> list of imported functions
    """
    if not HAVE_PEFILE:
        return {"error": "pefile not installed"}
    
    # TODO: Use pefile to parse imports
    # Hint:
    # pe = pefile.PE(filepath)
    # for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #     dll_name = entry.dll.decode()
    #     functions = [imp.name.decode() for imp in entry.imports if imp.name]
    
    # Your code here:
    return {}


def find_suspicious_apis(imports: dict) -> list:
    """
    Find suspicious API imports.
    
    Args:
        imports: Dict of DLL -> functions
        
    Returns:
        List of (function_name, category) tuples
    """
    suspicious = []
    
    # TODO: Check each import against SUSPICIOUS_APIS
    # Hint: Flatten all functions, check each against each category
    
    # Your code here:
    return suspicious


# ============================================================================
# TODO 4: Analyze sections
# ============================================================================

def analyze_sections(filepath: str) -> list:
    """
    Analyze PE sections for anomalies.
    
    Args:
        filepath: Path to PE file
        
    Returns:
        List of section info dicts
    """
    if not HAVE_PEFILE:
        return []
    
    # TODO: Parse sections using pefile
    # For each section, extract:
    # - Name
    # - Virtual size
    # - Raw size
    # - Entropy
    # - Characteristics (executable, writable, etc.)
    
    # Hint:
    # pe = pefile.PE(filepath)
    # for section in pe.sections:
    #     name = section.Name.decode().strip('\x00')
    #     entropy = section.get_entropy()
    
    # Your code here:
    return []


# ============================================================================
# TODO 5: Generate report
# ============================================================================

def analyze_binary(filepath: str) -> BinaryAnalysis:
    """
    Perform complete binary analysis.
    
    Args:
        filepath: Path to binary file
        
    Returns:
        BinaryAnalysis object with all findings
    """
    # TODO: Combine all analysis functions
    # 1. Read file and calculate entropy
    # 2. Extract and analyze strings
    # 3. Parse imports (if PE file)
    # 4. Analyze sections
    # 5. Generate indicators list
    
    # Your code here:
    return BinaryAnalysis(
        filename=filepath,
        size=0,
        entropy=0.0,
        strings=[],
        suspicious_strings=[],
        imports={},
        suspicious_apis=[],
        sections=[],
        indicators=[]
    )


def print_report(analysis: BinaryAnalysis):
    """Print formatted analysis report."""
    print(f"\n🔬 Binary Analysis Report")
    print("=" * 55)
    print(f"📄 File: {analysis.filename}")
    print(f"   Size: {analysis.size:,} bytes")
    
    print(f"\n📊 ENTROPY: {analysis.entropy:.2f}")
    print(f"   Assessment: {get_entropy_assessment(analysis.entropy)}")
    
    if analysis.suspicious_strings:
        print(f"\n📝 SUSPICIOUS STRINGS ({len(analysis.suspicious_strings)}):")
        for string, stype in analysis.suspicious_strings[:10]:
            print(f"   [{stype}] {string[:60]}")
    
    if analysis.suspicious_apis:
        print(f"\n⚠️ SUSPICIOUS APIs ({len(analysis.suspicious_apis)}):")
        for api, category in analysis.suspicious_apis[:10]:
            print(f"   [{category}] {api}")
    
    if analysis.indicators:
        print(f"\n🎯 INDICATORS:")
        for indicator in analysis.indicators:
            print(f"   • {indicator}")


# ============================================================================
# SAMPLE DATA (for testing without real malware)
# ============================================================================

def create_sample_data() -> bytes:
    """Create sample binary-like data for testing."""
    # Simulated PE-like data with various entropy levels
    data = b"MZ" + b"\x90" * 100  # DOS header stub
    data += b"PE\x00\x00"  # PE signature
    data += b"\x00" * 100  # Headers
    
    # Low entropy section (code-like)
    data += b"push ebp\nmov ebp, esp\nsub esp, 0x20\n" * 50
    
    # Medium entropy section (strings)
    data += b"http://evil-c2.com/beacon\x00"
    data += b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    data += b"cmd.exe /c whoami\x00"
    data += b"password.txt\x00"
    data += b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    
    # Some random-ish data
    import random
    random.seed(42)
    data += bytes([random.randint(0, 255) for _ in range(500)])
    
    return data


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("🔬 Binary Analysis Basics")
    print("=" * 55)
    
    # Create sample data for testing
    print("\n📦 Creating sample binary data...")
    sample_data = create_sample_data()
    print(f"   Sample size: {len(sample_data):,} bytes")
    
    # Test 1: Entropy
    print("\n" + "=" * 55)
    print("1. Entropy Calculation")
    print("-" * 55)
    
    entropy = calculate_entropy(sample_data)
    if entropy > 0:
        print(f"   Overall entropy: {entropy:.2f}")
        print(f"   Assessment: {get_entropy_assessment(entropy)}")
    else:
        print("   ❌ Complete TODO 1 to calculate entropy")
    
    # Test 2: String extraction
    print("\n" + "=" * 55)
    print("2. String Extraction")
    print("-" * 55)
    
    strings = extract_strings(sample_data)
    if strings:
        print(f"   Found {len(strings)} strings")
        print("   Sample strings:")
        for s in strings[:5]:
            print(f"     • {s[:50]}")
    else:
        print("   ❌ Complete TODO 2 to extract strings")
    
    # Test 3: Suspicious strings
    print("\n" + "=" * 55)
    print("3. Suspicious String Detection")
    print("-" * 55)
    
    suspicious = find_suspicious_strings(strings) if strings else []
    if suspicious:
        print(f"   Found {len(suspicious)} suspicious strings:")
        for string, stype in suspicious[:5]:
            print(f"     [{stype}] {string[:50]}")
    else:
        print("   ❌ Complete TODO 2 to find suspicious strings")
    
    # Summary
    print("\n" + "=" * 55)
    completed = sum([
        entropy > 0,
        len(strings) > 0,
        len(suspicious) > 0,
    ])
    print(f"Progress: {completed}/3 core TODOs complete")
    
    if completed >= 2:
        print("\n✅ You understand binary basics! Ready for Lab 07.")
    else:
        print("\n📝 Keep working on the TODOs!")


if __name__ == "__main__":
    main()

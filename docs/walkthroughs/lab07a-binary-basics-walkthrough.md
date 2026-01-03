# Lab 07a: Binary Analysis Basics Walkthrough

Step-by-step guide to understanding PE files and malware indicators.

## Overview

This walkthrough guides you through:
1. Understanding PE file structure
2. Calculating file entropy
3. Extracting strings and imports
4. Identifying suspicious indicators

**Difficulty:** Intermediate
**Time:** 45-60 minutes
**Prerequisites:** Basic Python (Lab 00a)

---

## Why Binary Analysis?

Before generating YARA rules (Lab 07), you need to understand what you're looking for:

| What to Analyze | What It Reveals |
|-----------------|-----------------|
| PE Structure | File validity, anomalies |
| Entropy | Packing/encryption |
| Imports | Capabilities |
| Strings | IOCs, commands |
| Sections | Obfuscation techniques |

---

## Exercise 1: Calculate Entropy (TODO 1)

### What is Entropy?

Entropy measures randomness (0-8 bits per byte):

```
0-1   Highly repetitive (all zeros)
1-4   Plain text, source code
4-6   Normal compiled code
6-7   Compressed data
7-8   Encrypted/packed ⚠️
```

### Implementation

```python
import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0

    # Count byte frequencies
    counter = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
```

### Testing It

```python
# Low entropy - repetitive
low = bytes([0] * 1000)
print(f"All zeros: {calculate_entropy(low):.2f}")  # ~0.0

# Medium entropy - text
text = b"This is normal ASCII text content" * 20
print(f"Text: {calculate_entropy(text):.2f}")  # ~4.5

# High entropy - random (encrypted)
import os
high = os.urandom(1000)
print(f"Random: {calculate_entropy(high):.2f}")  # ~7.9
```

### Interpreting Results

```python
def assess_entropy(entropy: float) -> str:
    """Assess entropy level."""
    if entropy < 1.0:
        return "Very low - repetitive data"
    elif entropy < 4.0:
        return "Low - plain text or code"
    elif entropy < 6.0:
        return "Normal - typical executable"
    elif entropy < 7.0:
        return "High - compressed data"
    else:
        return "Very high ⚠️ - likely packed/encrypted"
```

---

## Exercise 2: Extract Strings (TODO 2)

### Why Strings Matter

Malware strings reveal:
- C2 URLs and domains
- Registry persistence paths
- Commands and capabilities
- Mutex names for identification

### Implementation

```python
import re

def extract_strings(data: bytes, min_length: int = 4) -> list:
    """Extract printable strings from binary data."""
    strings = []

    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    for match in re.finditer(ascii_pattern, data):
        strings.append(("ASCII", match.group().decode('ascii')))

    # Unicode strings (UTF-16LE common in Windows)
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    for match in re.finditer(unicode_pattern, data):
        try:
            s = match.group().decode('utf-16-le').strip('\x00')
            strings.append(("Unicode", s))
        except:
            pass

    return strings
```

### Filtering Suspicious Strings

```python
SUSPICIOUS_PATTERNS = {
    "urls": r'https?://[\w\.-]+[/\w\.-]*',
    "ips": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "registry": r'HKEY_[\w\\]+',
    "commands": r'(cmd\.exe|powershell|whoami|net\s+user)',
    "credentials": r'(password|login|credential)',
    "crypto": r'(encrypt|decrypt|ransom|bitcoin)',
    "paths": r'C:\\[\w\\]+\.(exe|dll|bat|ps1)',
}

def filter_suspicious_strings(strings: list) -> dict:
    """Filter strings for suspicious indicators."""
    suspicious = {category: [] for category in SUSPICIOUS_PATTERNS}

    for string_type, string in strings:
        for category, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, string, re.IGNORECASE):
                suspicious[category].append(string)

    return {k: v for k, v in suspicious.items() if v}
```

---

## Exercise 3: Parse PE Imports (TODO 3)

### Why Imports Matter

Imports reveal what APIs the malware uses:

| API | Capability |
|-----|------------|
| `VirtualAlloc` + `WriteProcessMemory` | Code injection |
| `CreateRemoteThread` | Process injection |
| `RegSetValueEx` | Registry persistence |
| `InternetOpen` | Network/C2 |
| `CryptEncrypt` | Ransomware |

### Using pefile

```python
import pefile

def analyze_imports(pe_path: str) -> dict:
    """Analyze PE imports for suspicious APIs."""
    pe = pefile.PE(pe_path)

    imports = {}
    suspicious = []

    SUSPICIOUS_APIS = {
        # Injection
        "VirtualAlloc": "Memory allocation for code",
        "VirtualProtect": "Change memory protection",
        "WriteProcessMemory": "Write to other process",
        "CreateRemoteThread": "Execute in other process",
        "NtUnmapViewOfSection": "Process hollowing",

        # Execution
        "CreateProcess": "Process creation",
        "ShellExecute": "Shell command execution",
        "WinExec": "Execute command",

        # Persistence
        "RegSetValueEx": "Registry modification",
        "RegCreateKeyEx": "Registry key creation",

        # Network
        "InternetOpen": "HTTP client",
        "URLDownloadToFile": "Download file",
        "socket": "Raw socket",
        "connect": "Network connection",

        # Crypto
        "CryptEncrypt": "Encryption",
        "CryptDecrypt": "Decryption",
    }

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports[dll_name] = []

            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode()
                    imports[dll_name].append(api_name)

                    if api_name in SUSPICIOUS_APIS:
                        suspicious.append({
                            "api": api_name,
                            "dll": dll_name,
                            "description": SUSPICIOUS_APIS[api_name]
                        })

    return {
        "imports": imports,
        "suspicious": suspicious,
        "total_imports": sum(len(v) for v in imports.values())
    }
```

---

## Exercise 4: Analyze Sections (TODO 4)

### PE Section Basics

```
Normal PE:
├── .text    Code (executable)
├── .data    Initialized data
├── .rdata   Read-only data, imports
└── .rsrc    Resources

Suspicious:
├── UPX0, UPX1    UPX packer
├── .vmp          VMProtect
├── Random names  Custom packer
└── Very high entropy sections
```

### Implementation

```python
def analyze_sections(pe_path: str) -> dict:
    """Analyze PE sections for anomalies."""
    pe = pefile.PE(pe_path)

    sections = []
    anomalies = []

    NORMAL_SECTIONS = {'.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc'}
    PACKER_SECTIONS = {'UPX0', 'UPX1', '.vmp', 'MPRESS'}

    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        entropy = section.get_entropy()

        section_info = {
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            "characteristics": hex(section.Characteristics)
        }
        sections.append(section_info)

        # Check for anomalies
        if entropy > 7.0:
            anomalies.append(f"High entropy in {name}: {entropy:.2f}")

        if name in PACKER_SECTIONS:
            anomalies.append(f"Packer section detected: {name}")

        if name not in NORMAL_SECTIONS and not name.startswith('.'):
            anomalies.append(f"Unusual section name: {name}")

        # Writeable + Executable is suspicious
        if (section.Characteristics & 0x20000000) and \
           (section.Characteristics & 0x80000000):
            anomalies.append(f"Section {name} is both writable and executable")

    return {
        "sections": sections,
        "anomalies": anomalies,
        "count": len(sections)
    }
```

---

## Exercise 5: Generate Report (TODO 5)

### Complete Analysis Function

```python
def analyze_binary(file_path: str) -> dict:
    """Complete binary analysis."""
    with open(file_path, 'rb') as f:
        data = f.read()

    # Basic info
    file_entropy = calculate_entropy(data)

    # String analysis
    strings = extract_strings(data)
    suspicious_strings = filter_suspicious_strings(strings)

    # PE analysis
    try:
        import_analysis = analyze_imports(file_path)
        section_analysis = analyze_sections(file_path)
        is_pe = True
    except:
        import_analysis = {"error": "Not a valid PE file"}
        section_analysis = {"error": "Not a valid PE file"}
        is_pe = False

    # MITRE ATT&CK mapping
    techniques = map_to_mitre(
        suspicious_strings,
        import_analysis.get("suspicious", [])
    )

    return {
        "file": file_path,
        "size": len(data),
        "entropy": file_entropy,
        "is_pe": is_pe,
        "strings": {
            "total": len(strings),
            "suspicious": suspicious_strings
        },
        "imports": import_analysis,
        "sections": section_analysis,
        "mitre_techniques": techniques,
        "risk_level": assess_risk(file_entropy, suspicious_strings, import_analysis)
    }

def map_to_mitre(strings: dict, apis: list) -> list:
    """Map findings to MITRE ATT&CK."""
    techniques = []

    if "urls" in strings:
        techniques.append({"id": "T1071.001", "name": "Web Protocols"})
    if "registry" in strings:
        techniques.append({"id": "T1547.001", "name": "Registry Run Keys"})
    if "commands" in strings:
        techniques.append({"id": "T1059", "name": "Command and Scripting"})

    for api in apis:
        if "WriteProcessMemory" in api["api"] or "CreateRemoteThread" in api["api"]:
            techniques.append({"id": "T1055", "name": "Process Injection"})
        if "Crypt" in api["api"]:
            techniques.append({"id": "T1486", "name": "Data Encrypted"})

    return techniques

def assess_risk(entropy: float, strings: dict, imports: dict) -> str:
    """Assess overall risk level."""
    score = 0

    if entropy > 7.0:
        score += 2
    if strings:
        score += len(strings)
    if imports.get("suspicious"):
        score += len(imports["suspicious"])

    if score >= 5:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"
```

---

## Common Errors

### 1. Reading Binary as Text

```python
# WRONG
with open("file.exe", "r") as f:
    data = f.read()  # Unicode decode error!

# CORRECT
with open("file.exe", "rb") as f:  # Binary mode
    data = f.read()
```

### 2. Missing pefile

```python
# If pefile not installed
pip install pefile

# Or handle gracefully
try:
    import pefile
except ImportError:
    print("Install pefile: pip install pefile")
```

### 3. Assuming All Files Are PE

```python
# WRONG
pe = pefile.PE(path)  # Crashes on non-PE!

# CORRECT
try:
    pe = pefile.PE(path)
except pefile.PEFormatError:
    print("Not a valid PE file")
```

---

## Key Takeaways

1. **Entropy** - High entropy (>7) suggests packing/encryption
2. **Imports** - APIs reveal capabilities (injection, C2, crypto)
3. **Strings** - URLs, paths, commands are IOCs
4. **Sections** - Anomalies indicate obfuscation
5. **MITRE mapping** - Gives common language for findings

---

## Quick Reference: Suspicious Indicators

### High-Risk APIs
```
VirtualAlloc + WriteProcessMemory → Code injection
CreateRemoteThread → Process injection
CryptEncrypt → Ransomware
InternetOpen + URLDownloadToFile → Download & execute
```

### Red Flag Strings
```
http://[external-domain]/[path]
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
cmd.exe /c [command]
powershell -enc [base64]
```

### Section Anomalies
```
UPX0/UPX1 → UPX packed
.vmp → VMProtect
High entropy (.rsrc > 7.0) → Encrypted resources
W+X sections → Self-modifying code
```

---

## Next Steps

Now you can analyze binaries:

- **Lab 07**: Generate YARA rules from your analysis
- **Lab 11**: Apply to ransomware detection
- **Lab 13**: Analyze memory dumps

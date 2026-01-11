# Lab 19: Binary Analysis Basics [Bridge Lab]

**Difficulty:** 🟡 Intermediate | **Time:** 45-60 min | **Prerequisites:** Lab 01

> **Bridge Lab:** This lab covers PE file structure and binary analysis fundamentals before the YARA Generator in Lab 21.

Essential binary/malware analysis concepts before building YARA rules.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab19_binary_basics.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Understand PE (Portable Executable) file structure
- Extract strings, imports, and sections from binaries
- Calculate file entropy (detect packing/encryption)
- Identify suspicious indicators in executables
- Be prepared for Lab 21 (YARA Generator)

## Prerequisites

- Python basics (Lab 01)
- No special tools required (we'll use Python libraries)

## Time Required

⏱️ **45-60 minutes**

---

## 📋 Quick Reference Cheat Sheet

### PE File Structure

```
┌─────────────────────────────────────────────────────────────┐
│                  PE FILE STRUCTURE                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────────┐                                      │
│   │   DOS Header     │  "MZ" magic bytes                    │
│   ├──────────────────┤                                      │
│   │   PE Header      │  "PE\0\0" signature                  │
│   ├──────────────────┤                                      │
│   │   Optional Hdr   │  Entry point, image base             │
│   ├──────────────────┤                                      │
│   │   Section Table  │  .text, .data, .rsrc, etc.          │
│   ├──────────────────┤                                      │
│   │   .text section  │  Code (executable)                   │
│   ├──────────────────┤                                      │
│   │   .data section  │  Initialized data                    │
│   ├──────────────────┤                                      │
│   │   .rdata section │  Read-only data, imports             │
│   ├──────────────────┤                                      │
│   │   .rsrc section  │  Resources (icons, strings)          │
│   └──────────────────┘                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Indicators at a Glance

| Indicator | Normal | Suspicious | Why |
|-----------|--------|------------|-----|
| **Entropy** | 4.0-6.5 | >7.0 | Packed/encrypted |
| **.text section** | Exists | Missing/renamed | Obfuscation |
| **Imports** | Standard APIs | Suspicious APIs | Capabilities |
| **Strings** | Readable | Encoded/none | Obfuscation |
| **Sections** | 3-6 | Many or weird names | Packing |

### Suspicious API Imports

```
🔴 HIGH RISK APIs (potential malware):
   VirtualAlloc, VirtualProtect    → Code injection
   CreateRemoteThread              → Process injection
   WriteProcessMemory              → Memory manipulation
   NtUnmapViewOfSection            → Process hollowing
   RegSetValueEx                   → Persistence
   InternetOpen, URLDownloadToFile → C2/download
   CryptEncrypt, CryptDecrypt      → Ransomware

🟡 MEDIUM RISK APIs (context-dependent):
   CreateProcess, ShellExecute     → Execution
   GetProcAddress, LoadLibrary     → Dynamic loading
   SetWindowsHookEx                → Keylogging
   FindFirstFile, FindNextFile     → File enumeration
```

### Entropy Levels

```
ENTROPY SCALE (0-8 bits per byte):
───────────────────────────────────────────────────
0-1   │███░░░░░░░░░░░░░░░│  Highly repetitive
1-4   │██████░░░░░░░░░░░░│  Plain text, code
4-6   │█████████░░░░░░░░░│  Normal executable
6-7   │████████████░░░░░░│  Compressed data
7-8   │███████████████░░░│  Encrypted/packed ⚠️
───────────────────────────────────────────────────
```

---

## Why This Matters for Security

Before you can generate YARA rules, you need to understand:

| Concept | Why It Matters |
|---------|----------------|
| **PE Structure** | Know where to look for indicators |
| **Imports** | Reveal malware capabilities |
| **Strings** | URLs, commands, mutex names |
| **Entropy** | Detect packed/encrypted malware |
| **Sections** | Identify anomalies in structure |

---

## Understanding Entropy

**Entropy** measures randomness in data (0-8 bits per byte):

```python
import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
```

### What Entropy Tells You

| Entropy | Meaning | Example |
|---------|---------|---------|
| < 1.0 | Almost no variation | All zeros, repeated pattern |
| 1.0-4.0 | Structured text | Plain text, source code |
| 4.0-6.0 | Normal compiled code | Typical .exe |
| 6.0-7.0 | Compressed | ZIP, PNG data |
| > 7.0 | Encrypted/packed | UPX packed, encrypted |

---

## Extracting Strings

Strings reveal:
- URLs and domains (C2 servers)
- Registry paths (persistence)
- File paths (targets)
- Commands (capabilities)
- Mutex names (identification)

```python
import re

def extract_strings(data: bytes, min_length: int = 4) -> list:
    """Extract ASCII and Unicode strings from binary data."""
    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)

    # Unicode strings (simplified)
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)

    return [s.decode('ascii', errors='ignore') for s in ascii_strings]
```

---

## Your Task

Build a binary analysis toolkit that:
1. Parses PE headers
2. Extracts and analyzes imports
3. Calculates section entropy
4. Identifies suspicious indicators

### TODOs

1. **TODO 1**: Calculate file entropy
2. **TODO 2**: Extract strings from binary
3. **TODO 3**: Parse PE imports (using pefile)
4. **TODO 4**: Analyze section characteristics
5. **TODO 5**: Generate suspicious indicators report

---

## Hints

<details>
<summary>💡 Hint 1: Using pefile</summary>

```python
import pefile

pe = pefile.PE("sample.exe")

# Get imports
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"DLL: {entry.dll.decode()}")
    for imp in entry.imports:
        print(f"  - {imp.name.decode() if imp.name else 'ordinal'}")

# Get sections
for section in pe.sections:
    print(f"Section: {section.Name.decode().strip()}")
    print(f"  Entropy: {section.get_entropy():.2f}")
```

</details>

<details>
<summary>💡 Hint 2: Suspicious Strings Pattern</summary>

```python
SUSPICIOUS_PATTERNS = [
    r'https?://[\w\.-]+',           # URLs
    r'HKEY_[\w\\]+',                # Registry
    r'cmd\.exe|powershell',         # Execution
    r'password|credential|login',    # Credential theft
    r'encrypt|decrypt|ransom',       # Ransomware
]
```

</details>

---

## Expected Output

```
🔬 Binary Analysis Toolkit
===========================

📄 File: sample.exe
   Size: 245,760 bytes
   Type: PE32 executable

📊 ENTROPY ANALYSIS
───────────────────────────────────────────────
   Overall: 5.23 (Normal executable)

   Section Entropy:
   .text    5.89 ████████████░░░░ Normal code
   .rdata   4.12 ████████░░░░░░░░ Read-only data
   .data    2.34 █████░░░░░░░░░░░ Initialized data
   .rsrc    7.45 ██████████████░░ ⚠️ High entropy!

📦 IMPORTS ANALYSIS
───────────────────────────────────────────────
   kernel32.dll (15 imports)
     CreateProcessW, VirtualAlloc, WriteProcessMemory ⚠️

   ws2_32.dll (5 imports)
     connect, send, recv

   ⚠️ SUSPICIOUS APIs DETECTED:
     • VirtualAlloc + WriteProcessMemory → Code injection
     • connect + send → Network communication

📝 STRINGS ANALYSIS
───────────────────────────────────────────────
   Total strings: 234

   ⚠️ Suspicious strings found:
     • http://evil-c2.com/beacon
     • HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
     • cmd.exe /c whoami
     • password.txt

🎯 SUMMARY
───────────────────────────────────────────────
   Risk Level: HIGH

   Indicators:
   [!] High entropy section (.rsrc) - possible encryption
   [!] Process injection APIs (VirtualAlloc + WriteProcessMemory)
   [!] Network APIs with external URL
   [!] Registry persistence path found
   [!] Command execution strings

   MITRE ATT&CK Mapping:
   • T1055 - Process Injection
   • T1547.001 - Registry Run Keys
   • T1059.003 - Windows Command Shell
   • T1071.001 - Web Protocols (C2)
```

---

## Common Packing/Obfuscation

| Packer | Indicators |
|--------|------------|
| **UPX** | Sections: UPX0, UPX1; Entry in UPX1 |
| **Themida** | Very high entropy; Few imports |
| **VMProtect** | Virtualized code; .vmp sections |
| **Custom** | High entropy; Stub code |

### Detecting Packers

```python
def detect_packer(pe):
    """Simple packer detection heuristics."""
    indicators = []

    # Check for UPX
    section_names = [s.Name.decode().strip('\x00') for s in pe.sections]
    if 'UPX0' in section_names or 'UPX1' in section_names:
        indicators.append("UPX packer detected")

    # Check overall entropy
    with open(pe.path, 'rb') as f:
        entropy = calculate_entropy(f.read())
    if entropy > 7.0:
        indicators.append(f"High entropy ({entropy:.2f}) - likely packed")

    # Check import count
    import_count = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
    if import_count < 10:
        indicators.append(f"Few imports ({import_count}) - possible packing")

    return indicators
```

---

## Key Takeaways

1. **PE structure** - Know the header, sections, imports
2. **Entropy** - High entropy (>7) often means packed/encrypted
3. **Imports** - APIs reveal capabilities (injection, C2, persistence)
4. **Strings** - URLs, paths, commands are IOCs
5. **Sections** - Anomalies indicate packing/obfuscation

---

## What's Next?

Now that you understand binary analysis:

- **Lab 21**: Generate YARA rules from samples
- **Lab 31**: Apply to ransomware detection
- **Lab 13**: Analyze memory dumps

You're ready to hunt malware! 🎯

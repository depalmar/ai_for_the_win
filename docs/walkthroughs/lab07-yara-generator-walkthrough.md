# Lab 07: YARA Rule Generator - Solution Walkthrough

## Overview

Build an AI-powered YARA rule generator that analyzes malware samples and creates detection rules automatically.

**Time:** 2-3 hours
**Difficulty:** Intermediate

---

## Task 1: Static Analysis

### Extracting Features from Samples

```python
import hashlib
import magic
import pefile
import re
from pathlib import Path

class MalwareAnalyzer:
    def __init__(self):
        self.magic = magic.Magic(mime=True)

    def analyze_sample(self, file_path: str) -> dict:
        """Extract static features from a file."""
        path = Path(file_path)
        content = path.read_bytes()

        analysis = {
            'filename': path.name,
            'size': len(content),
            'md5': hashlib.md5(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
            'mime_type': self.magic.from_buffer(content),
            'strings': self._extract_strings(content),
            'imports': [],
            'sections': [],
            'entropy': self._calculate_entropy(content)
        }

        # PE-specific analysis
        if self._is_pe(content):
            analysis.update(self._analyze_pe(content))

        return analysis

    def _extract_strings(self, content: bytes, min_length: int = 6) -> list[str]:
        """Extract ASCII and Unicode strings."""
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, content)

        # Unicode strings
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
        unicode_strings = re.findall(unicode_pattern, content)
        unicode_strings = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings]

        return [s.decode('ascii', errors='ignore') for s in ascii_strings] + unicode_strings

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        import math
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)

        return round(entropy, 2)

    def _is_pe(self, content: bytes) -> bool:
        """Check if file is a PE executable."""
        return content[:2] == b'MZ'

    def _analyze_pe(self, content: bytes) -> dict:
        """Analyze PE file structure."""
        try:
            pe = pefile.PE(data=content)

            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll_name}:{imp.name.decode()}")

            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'entropy': round(section.get_entropy(), 2)
                })

            return {
                'imports': imports,
                'sections': sections,
                'is_packed': any(s['entropy'] > 7.0 for s in sections),
                'compile_time': pe.FILE_HEADER.TimeDateStamp
            }
        except Exception as e:
            return {'pe_error': str(e)}

# Analyze a sample
analyzer = MalwareAnalyzer()
analysis = analyzer.analyze_sample("samples/suspicious.exe")
print(f"MD5: {analysis['md5']}")
print(f"Entropy: {analysis['entropy']}")
print(f"Suspicious strings: {len(analysis['strings'])}")
```

---

## Task 2: Pattern Identification

### Finding Unique Indicators

```python
class PatternExtractor:
    def __init__(self):
        self.suspicious_patterns = {
            'urls': r'https?://[\w\-\.]+\.[a-zA-Z]{2,}[/\w\-\.\?\=\&]*',
            'ips': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'registry': r'(HKEY_[\w\\]+|Software\\[\w\\]+)',
            'files': r'[A-Za-z]:\\[\w\\\.]+\.(exe|dll|bat|ps1|vbs)',
            'commands': r'(cmd\.exe|powershell|wscript|cscript)',
            'base64': r'[A-Za-z0-9+/]{50,}={0,2}'
        }

    def extract_patterns(self, strings: list[str]) -> dict:
        """Extract suspicious patterns from strings."""
        findings = {key: [] for key in self.suspicious_patterns}

        for string in strings:
            for pattern_name, pattern in self.suspicious_patterns.items():
                matches = re.findall(pattern, string, re.IGNORECASE)
                findings[pattern_name].extend(matches)

        # Deduplicate
        return {k: list(set(v)) for k, v in findings.items()}

    def find_unique_sequences(self, content: bytes,
                              min_length: int = 8,
                              max_sequences: int = 10) -> list[bytes]:
        """Find unique byte sequences for YARA rules."""
        sequences = []

        # Look for interesting byte patterns
        patterns = [
            # Common packer signatures
            rb'\x55\x8B\xEC',  # push ebp; mov ebp, esp
            rb'\x60\xE8\x00\x00\x00\x00',  # pushad; call
            # XOR loops
            rb'\x80\x34[\x00-\xff]\x00',  # xor byte ptr
        ]

        for pattern in patterns:
            if pattern in content:
                # Find context around pattern
                idx = content.find(pattern)
                context = content[max(0, idx-4):idx+len(pattern)+4]
                sequences.append(context)

        # Find high-entropy regions (potential encrypted data)
        chunk_size = 256
        for i in range(0, len(content) - chunk_size, chunk_size):
            chunk = content[i:i+chunk_size]
            if self._calculate_entropy(chunk) > 7.5:
                # Take a sample from high-entropy region
                sequences.append(content[i:i+16])

        return sequences[:max_sequences]

    def _calculate_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy

# Extract patterns
extractor = PatternExtractor()
patterns = extractor.extract_patterns(analysis['strings'])

print("Found patterns:")
for pattern_type, matches in patterns.items():
    if matches:
        print(f"  {pattern_type}: {len(matches)} matches")
```

---

## Task 3: AI-Powered Rule Generation

### Using LLM to Generate YARA Rules

```python
import anthropic
import json

class YARAGenerator:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def generate_rule(self, analysis: dict, patterns: dict) -> str:
        """Generate YARA rule using Claude."""

        prompt = f"""You are a malware analyst creating YARA rules. Generate a YARA rule based on this analysis:

## File Analysis
- Filename: {analysis['filename']}
- SHA256: {analysis['sha256']}
- Size: {analysis['size']} bytes
- Entropy: {analysis['entropy']}
- MIME Type: {analysis['mime_type']}
- Is Packed: {analysis.get('is_packed', 'Unknown')}

## Imports (first 20)
{json.dumps(analysis.get('imports', [])[:20], indent=2)}

## Sections
{json.dumps(analysis.get('sections', []), indent=2)}

## Suspicious Patterns Found
- URLs: {patterns.get('urls', [])}
- IPs: {patterns.get('ips', [])}
- Registry Keys: {patterns.get('registry', [])}
- File Paths: {patterns.get('files', [])}
- Commands: {patterns.get('commands', [])}

## Notable Strings (first 30)
{json.dumps(analysis.get('strings', [])[:30], indent=2)}

Generate a YARA rule that:
1. Has a descriptive rule name based on observed behavior
2. Includes metadata (author, date, description, hash)
3. Uses string matches for unique indicators
4. Uses byte patterns where appropriate (hex strings)
5. Has a reasonable condition that balances detection and false positives
6. Includes comments explaining the detection logic

Return ONLY the YARA rule, no explanations."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

# Generate rule
generator = YARAGenerator()
yara_rule = generator.generate_rule(analysis, patterns)
print(yara_rule)
```

### Expected Output
```yara
rule Trojan_Downloader_GenericHTTP
{
    meta:
        author = "AI Security Lab"
        date = "2024-12-23"
        description = "Detects generic HTTP downloader trojan with C2 communication"
        hash = "a1b2c3d4e5f6..."
        reference = "Internal Analysis"

    strings:
        // C2 Communication
        $url1 = "http://malicious-domain.com/gate.php" ascii wide
        $url2 = "http://192.168.1.100:8080/beacon" ascii

        // Registry persistence
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

        // Command execution
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "powershell -enc" ascii nocase

        // Suspicious API imports
        $api1 = "URLDownloadToFileA" ascii
        $api2 = "ShellExecuteA" ascii
        $api3 = "VirtualAlloc" ascii

        // Byte patterns (decryption routine)
        $bytes1 = { 55 8B EC 83 EC ?? 53 56 57 }
        $bytes2 = { 80 34 ?? ?? 40 3B C1 72 F7 }

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize < 500KB and
        (
            (any of ($url*) and any of ($api*)) or
            (2 of ($cmd*, $reg*) and any of ($bytes*)) or
            (all of ($api*) and any of ($bytes*))
        )
}
```

---

## Task 4: Rule Validation

### Testing Generated Rules

```python
import yara
import tempfile
import os

class YARAValidator:
    def __init__(self):
        pass

    def validate_syntax(self, rule_text: str) -> dict:
        """Validate YARA rule syntax."""
        try:
            # Write rule to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(rule_text)
                temp_path = f.name

            # Compile rule
            rules = yara.compile(filepath=temp_path)
            os.unlink(temp_path)

            return {
                'valid': True,
                'rules_count': len(list(rules)),
                'error': None
            }
        except yara.SyntaxError as e:
            return {
                'valid': False,
                'rules_count': 0,
                'error': str(e)
            }

    def test_rule(self, rule_text: str, test_files: list[str]) -> dict:
        """Test rule against sample files."""
        results = {
            'matches': [],
            'no_matches': [],
            'errors': []
        }

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(rule_text)
                temp_path = f.name

            rules = yara.compile(filepath=temp_path)

            for file_path in test_files:
                try:
                    matches = rules.match(file_path)
                    if matches:
                        results['matches'].append({
                            'file': file_path,
                            'rules': [m.rule for m in matches]
                        })
                    else:
                        results['no_matches'].append(file_path)
                except Exception as e:
                    results['errors'].append({
                        'file': file_path,
                        'error': str(e)
                    })

            os.unlink(temp_path)
        except Exception as e:
            results['errors'].append({'compile_error': str(e)})

        return results

# Validate and test
validator = YARAValidator()

# Check syntax
syntax_check = validator.validate_syntax(yara_rule)
print(f"Syntax valid: {syntax_check['valid']}")

if syntax_check['valid']:
    # Test against samples
    test_results = validator.test_rule(yara_rule, [
        "samples/suspicious.exe",
        "samples/clean.exe",
        "samples/malware2.exe"
    ])

    print(f"Matches: {len(test_results['matches'])}")
    print(f"No matches: {len(test_results['no_matches'])}")
```

---

## Task 5: Rule Refinement

### Iterative Improvement with Feedback

```python
class YARARefinementLoop:
    def __init__(self):
        self.generator = YARAGenerator()
        self.validator = YARAValidator()
        self.client = anthropic.Anthropic()

    def refine_rule(self, original_rule: str,
                    validation_results: dict,
                    false_positives: list[str] = None) -> str:
        """Refine rule based on validation feedback."""

        prompt = f"""You are refining a YARA rule based on testing feedback.

## Original Rule
```yara
{original_rule}
```

## Validation Results
- Syntax Valid: {validation_results.get('valid', True)}
- Syntax Error: {validation_results.get('error', 'None')}

## Testing Results
- True Positives: {len(validation_results.get('matches', []))}
- Missed Samples: {len(validation_results.get('no_matches', []))}

## False Positives (if any)
{false_positives or 'None reported'}

Please refine the rule to:
1. Fix any syntax errors
2. Reduce false positives if reported
3. Improve detection coverage if samples were missed
4. Optimize conditions for performance

Return ONLY the refined YARA rule."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def auto_refine(self, analysis: dict, patterns: dict,
                    test_files: list[str], max_iterations: int = 3) -> str:
        """Automatically refine rule through multiple iterations."""

        rule = self.generator.generate_rule(analysis, patterns)

        for i in range(max_iterations):
            print(f"Iteration {i+1}/{max_iterations}")

            # Validate
            syntax = self.validator.validate_syntax(rule)
            if not syntax['valid']:
                rule = self.refine_rule(rule, syntax)
                continue

            # Test
            test_results = self.validator.test_rule(rule, test_files)

            # Check if good enough
            if (len(test_results['matches']) > 0 and
                len(test_results['errors']) == 0):
                print("Rule validated successfully!")
                break

            # Refine
            rule = self.refine_rule(rule, test_results)

        return rule

# Auto-refine rule
refiner = YARARefinementLoop()
final_rule = refiner.auto_refine(
    analysis,
    patterns,
    ["samples/suspicious.exe", "samples/malware2.exe"]
)
print(final_rule)
```

---

## Task 6: Batch Processing

### Processing Multiple Samples

```python
def generate_rules_batch(sample_paths: list[str],
                         output_dir: str = "rules/") -> list[str]:
    """Generate YARA rules for multiple samples."""

    analyzer = MalwareAnalyzer()
    extractor = PatternExtractor()
    generator = YARAGenerator()
    validator = YARAValidator()

    os.makedirs(output_dir, exist_ok=True)
    generated_rules = []

    for sample_path in sample_paths:
        print(f"\nProcessing: {sample_path}")

        try:
            # Analyze
            analysis = analyzer.analyze_sample(sample_path)
            patterns = extractor.extract_patterns(analysis['strings'])

            # Generate
            rule = generator.generate_rule(analysis, patterns)

            # Validate
            if validator.validate_syntax(rule)['valid']:
                # Save rule
                rule_name = Path(sample_path).stem
                rule_path = f"{output_dir}/{rule_name}.yar"

                with open(rule_path, 'w') as f:
                    f.write(rule)

                generated_rules.append(rule_path)
                print(f"  ✓ Rule saved: {rule_path}")
            else:
                print(f"  ✗ Invalid rule generated")

        except Exception as e:
            print(f"  ✗ Error: {e}")

    return generated_rules

# Process batch
rules = generate_rules_batch([
    "samples/sample1.exe",
    "samples/sample2.dll",
    "samples/sample3.exe"
])
print(f"\nGenerated {len(rules)} valid rules")
```

---

## Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Syntax errors | Use LLM to fix, common issues: missing quotes, bad hex |
| Too many false positives | Add more specific conditions, use PE structure checks |
| Missing detections | Add more string variants, use wildcards |
| Slow rules | Limit string count, use `filesize` condition first |
| Unicode issues | Use `ascii wide` modifier for strings |

---

## Next Steps

- Integrate with MISP for IOC sharing
- Build web interface for non-technical users
- Add Sigma rule generation
- Create rule testing framework with known malware families
- Implement rule deduplication for large rule sets

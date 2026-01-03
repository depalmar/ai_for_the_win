# Lab 07: AI-Powered YARA Rule Generator

Use LLMs to generate and optimize YARA rules from malware samples.

---

## 🎯 Learning Objectives

By completing this lab, you will:

1. Understand YARA rule structure and syntax
2. Extract meaningful strings and patterns from samples
3. Use LLMs to generate detection logic
4. Validate and test generated rules
5. Optimize rules for performance and accuracy

---

## ⏱️ Estimated Time

60-75 minutes (with AI assistance)

---

## 📋 Prerequisites

- Completed Labs 01-02 (malware analysis basics)
- YARA installed (`pip install yara-python`)
- LLM API access

### Required Libraries

```bash
pip install yara-python langchain langchain-anthropic pefile
pip install rich  # For pretty output
```

---

## 📖 Background

### YARA Rule Structure

```yara
rule Malware_Family_Variant
{
    meta:
        description = "Detects specific malware family"
        author = "Your Name"
        date = "2024-01-15"
        reference = "https://threat-report-url"
        hash = "sample_hash"
        
    strings:
        $mz = { 4D 5A }                    // Hex pattern
        $str1 = "malicious_string" ascii   // ASCII string
        $str2 = "unicode_string" wide      // Unicode
        $regex = /https?:\/\/[^\s]+/       // Regex
        
    condition:
        uint16(0) == 0x5A4D and            // PE file check
        filesize < 5MB and                  // Size limit
        ($mz at 0) and                      // MZ at offset 0
        2 of ($str*)                        // 2+ strings match
}
```

### String Selection Criteria

| Type | Good Indicators | Bad Indicators |
|------|-----------------|----------------|
| Strings | Unique function names, C2 domains | Common Windows APIs |
| Hex | Unique opcodes, encryption routines | Common PE structures |
| Regex | URL patterns, config formats | Overly broad patterns |

---

## 🔬 Lab Tasks

### Task 1: Sample Analysis (15 min)

```python
class SampleAnalyzer:
    """Extract features from malware samples."""
    
    def extract_strings(self, filepath: str, min_length: int = 6) -> List[str]:
        """
        Extract strings from binary file.
        
        TODO:
        1. Read binary content
        2. Extract ASCII strings (min_length chars)
        3. Extract Unicode strings
        4. Filter out common/noisy strings
        5. Return unique strings
        """
        pass
    
    def extract_pe_features(self, filepath: str) -> dict:
        """
        Extract PE file features.
        
        TODO:
        1. Parse PE headers
        2. Get imports/exports
        3. Get section names and entropy
        4. Get compile timestamp
        5. Return feature dict
        """
        pass
    
    def find_unique_patterns(self, filepath: str) -> List[dict]:
        """
        Find byte patterns unique to this sample.
        
        TODO:
        1. Identify high-entropy sections
        2. Find repeated patterns
        3. Look for encryption/encoding routines
        4. Return patterns with offsets
        """
        pass
```

### Task 2: LLM Rule Generator (20 min)

```python
class YARAGenerator:
    """Generate YARA rules using LLM."""
    
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = self._create_prompt()
    
    def _create_prompt(self) -> str:
        """
        Create system prompt for YARA generation.
        
        TODO:
        1. Define LLM role as YARA expert
        2. Include YARA syntax rules
        3. Add best practices
        4. Specify output format
        """
        pass
    
    def generate_rule(
        self,
        sample_info: dict,
        strings: List[str],
        pe_features: dict,
        malware_family: str = None
    ) -> str:
        """
        Generate YARA rule from sample features.
        
        TODO:
        1. Format sample info for LLM
        2. Include extracted strings
        3. Ask LLM to:
           - Select best strings for detection
           - Create appropriate conditions
           - Add metadata
        4. Return YARA rule text
        """
        pass
    
    def optimize_rule(self, rule: str, feedback: str = None) -> str:
        """
        Optimize/improve a YARA rule.
        
        TODO:
        1. Analyze current rule
        2. Apply LLM suggestions for:
           - Performance improvements
           - False positive reduction
           - Better string selection
        3. Return optimized rule
        """
        pass
```

### Task 3: Rule Validation (10 min)

```python
def validate_yara_rule(rule_text: str) -> dict:
    """
    Validate YARA rule syntax and logic.
    
    TODO:
    1. Attempt to compile rule
    2. Check for syntax errors
    3. Validate condition logic
    4. Return validation result
    """
    pass


def test_rule_on_samples(
    rule_text: str,
    positive_samples: List[str],
    negative_samples: List[str]
) -> dict:
    """
    Test rule against known samples.
    
    TODO:
    1. Compile rule
    2. Scan positive samples (should match)
    3. Scan negative samples (should not match)
    4. Calculate accuracy metrics
    """
    pass
```

### Task 4: Rule Refinement Loop (15 min)

```python
def refine_rule_iteratively(
    generator: YARAGenerator,
    initial_rule: str,
    test_results: dict,
    max_iterations: int = 3
) -> str:
    """
    Iteratively refine rule based on test results.
    
    TODO:
    1. Test current rule
    2. If false positives: make more specific
    3. If false negatives: make more general
    4. Ask LLM to adjust
    5. Repeat until satisfactory
    """
    pass
```

### Task 5: Batch Generation (10 min)

```python
def generate_rules_for_family(
    generator: YARAGenerator,
    samples: List[str],
    family_name: str
) -> str:
    """
    Generate YARA rule for malware family from multiple samples.
    
    TODO:
    1. Analyze all samples
    2. Find common strings/patterns
    3. Identify family-specific indicators
    4. Generate comprehensive rule
    5. Validate against all samples
    """
    pass
```

---

## 📁 Files

```
lab07-yara-generator/
├── README.md
├── starter/
│   ├── main.py
│   ├── analyzer.py
│   └── generator.py
├── solution/
│   └── main.py
├── samples/
│   ├── malware/          # Test malware samples (safe)
│   └── benign/           # Benign files for FP testing
├── rules/
│   └── generated/        # Output directory
└── tests/
    └── test_generator.py
```

---

## 🧪 Sample Output

```yara
rule Emotet_Loader_2024
{
    meta:
        description = "Detects Emotet loader variant from Jan 2024 campaign"
        author = "AI Security Training"
        date = "2024-01-15"
        reference = "https://example.com/emotet-analysis"
        hash = "abc123def456..."
        
    strings:
        // Unique strings from sample
        $s1 = "GetProcAddress" ascii
        $s2 = "VirtualAlloc" ascii
        
        // C2 communication patterns
        $c2_pattern = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[a-z]{8,12}/
        
        // Unique byte patterns
        $hex1 = { 4D 5A 90 00 03 00 00 00 }
        $hex2 = { 68 ?? ?? ?? ?? FF 15 }  // Push + call pattern
        
        // Decryption routine signature
        $decrypt = { 8B 45 ?? 33 45 ?? 89 45 ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            (2 of ($s*) and $c2_pattern) or
            ($decrypt and any of ($hex*))
        )
}
```

---

## ✅ Success Criteria

- [ ] String extraction works on PE files
- [ ] LLM generates valid YARA syntax
- [ ] Rules compile without errors
- [ ] Rules detect target samples
- [ ] False positive rate < 5%
- [ ] Rules are readable and documented

---

## 🚀 Bonus Challenges

1. **Multi-Family**: Generate rules for different malware families
2. **Sigma Integration**: Convert to Sigma for log detection
3. **Performance Profiling**: Optimize rule scan speed
4. **Version Tracking**: Detect variants across versions
5. **Auto-Hunt**: Integrate with VirusTotal hunting

---

## 💡 Hints

<details>
<summary>Hint: Good vs Bad Strings</summary>

```python
# Filter out common strings that cause false positives
BAD_STRINGS = [
    "Microsoft", "Windows", "kernel32.dll", "ntdll.dll",
    "GetLastError", "GetModuleHandle", "LoadLibrary",
    # Generic error messages
    "Error", "Warning", "Failed",
    # Common paths
    "C:\\Windows", "System32",
]

def is_good_string(s: str) -> bool:
    if len(s) < 6:
        return False
    if s in BAD_STRINGS:
        return False
    if s.startswith("http") and "microsoft" in s.lower():
        return False
    return True
```
</details>

<details>
<summary>Hint: YARA Generation Prompt</summary>

```python
YARA_PROMPT = """You are a YARA rule expert. Generate detection rules following these guidelines:

BEST PRACTICES:
1. Use specific strings that are unique to the malware
2. Avoid common Windows API names unless combined with other indicators
3. Include file size limits to improve performance
4. Use wildcards (??) sparingly in hex patterns
5. Add meaningful metadata

CONDITION LOGIC:
- Combine strings with AND/OR appropriately
- Use "X of ($strings*)" for flexibility
- Include PE header checks for executables
- Consider entropy checks for packed samples

OUTPUT FORMAT:
Return only the YARA rule, no explanation.
"""
```
</details>

---

## 📚 Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Performance Guidelines](https://yara.readthedocs.io/en/stable/writingrules.html#performance)
- [Florian Roth's YARA Rules](https://github.com/Neo23x0/signature-base)
- [YARA Rule Generator Tools](https://github.com/InQuest/yara-rules)

---

> **Stuck?** See the [Lab 07 Walkthrough](../../docs/walkthroughs/lab07-yara-generator-walkthrough.md) for step-by-step guidance.

**Next Lab**: [Lab 08 - Vulnerability Scanner AI](../lab08-vuln-scanner-ai/)


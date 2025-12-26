# Structured Output Parsing Guide

Getting reliable, structured data from LLMs for security automation.

---

## Table of Contents

1. [Why Structured Output Matters](#why-structured-output-matters)
2. [Output Format Strategies](#output-format-strategies)
3. [JSON Schema Validation](#json-schema-validation)
4. [Handling Malformed Responses](#handling-malformed-responses)
5. [Partial Parsing and Recovery](#partial-parsing-and-recovery)
6. [Security Considerations](#security-considerations)
7. [Production Patterns](#production-patterns)

---

## Why Structured Output Matters

In security automation, you need **reliable, parseable data** from LLMs:

```
Unstructured: "I found 3 suspicious IPs: 192.168.1.100, 10.0.0.50, and 172.16.0.1"

Structured: {
  "iocs": [
    {"type": "ip", "value": "192.168.1.100", "confidence": 0.95},
    {"type": "ip", "value": "10.0.0.50", "confidence": 0.87},
    {"type": "ip", "value": "172.16.0.1", "confidence": 0.92}
  ]
}
```

**Why this matters for security:**
- Automated SIEM integration requires structured data
- Alerting systems need consistent field names
- Downstream analysis depends on predictable formats
- Audit trails require machine-parseable logs

---

## Output Format Strategies

### Strategy 1: Explicit JSON Instructions

```python
prompt = """Analyze this log entry and extract IOCs.

Return ONLY valid JSON in this exact format:
{
  "severity": "critical|high|medium|low",
  "iocs": [
    {"type": "ip|domain|hash|email", "value": "string", "confidence": 0.0-1.0}
  ],
  "mitre_techniques": ["T1234"],
  "summary": "Brief description"
}

Log entry:
{log_entry}

JSON output:"""
```

**Key elements:**
- Specify "ONLY valid JSON"
- Show exact field names and types
- Include enum values where applicable
- End with "JSON output:" to prime the response

### Strategy 2: Few-Shot Examples

```python
prompt = """Extract security events from logs.

Example 1:
Log: "Failed SSH login for root from 192.168.1.100"
Output: {"event_type": "auth_failure", "source_ip": "192.168.1.100", "username": "root", "service": "ssh"}

Example 2:
Log: "Malware detected: trojan.exe (hash: abc123)"
Output: {"event_type": "malware_detection", "filename": "trojan.exe", "hash": "abc123", "hash_type": "unknown"}

Now analyze:
Log: "{log_entry}"
Output:"""
```

### Strategy 3: XML Tags for Complex Structures

```python
prompt = """Analyze the threat report and structure your findings.

<analysis>
  <summary>One paragraph overview</summary>
  <threat_actor>
    <name>Actor name or "Unknown"</name>
    <motivation>Financial/Espionage/Hacktivism/Unknown</motivation>
  </threat_actor>
  <iocs>
    <ioc type="ip|domain|hash">value</ioc>
  </iocs>
  <mitre_mapping>
    <technique id="T1234">Description</technique>
  </mitre_mapping>
</analysis>

Threat Report:
{report}

Analysis:"""
```

---

## JSON Schema Validation

### Using Pydantic for Validation

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Literal
from enum import Enum

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    EMAIL = "email"
    URL = "url"

class IOC(BaseModel):
    type: IOCType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)

    @validator('value')
    def validate_value(cls, v, values):
        if values.get('type') == IOCType.IP:
            # Basic IP validation
            parts = v.split('.')
            if len(parts) != 4:
                raise ValueError(f"Invalid IP format: {v}")
        return v

class SecurityAnalysis(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    iocs: List[IOC]
    mitre_techniques: List[str] = []
    summary: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

def parse_llm_response(response_text: str) -> SecurityAnalysis:
    """Parse and validate LLM response."""
    import json

    # Extract JSON from response
    json_str = extract_json(response_text)

    # Parse and validate
    data = json.loads(json_str)
    return SecurityAnalysis(**data)
```

### JSON Extraction Function

```python
import re
import json

def extract_json(text: str) -> str:
    """Extract JSON from LLM response, handling common issues."""

    # Try to find JSON block
    patterns = [
        r'```json\s*([\s\S]*?)\s*```',  # Markdown code block
        r'```\s*([\s\S]*?)\s*```',       # Generic code block
        r'(\{[\s\S]*\})',                 # Raw JSON object
        r'(\[[\s\S]*\])',                 # Raw JSON array
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            candidate = match.group(1).strip()
            try:
                json.loads(candidate)  # Validate it's parseable
                return candidate
            except json.JSONDecodeError:
                continue

    # If no valid JSON found, try the whole text
    text = text.strip()
    if text.startswith('{') or text.startswith('['):
        return text

    raise ValueError("No valid JSON found in response")
```

---

## Handling Malformed Responses

### Common LLM JSON Issues

| Issue | Example | Solution |
|-------|---------|----------|
| Trailing comma | `{"a": 1,}` | Regex cleanup |
| Single quotes | `{'a': 1}` | Replace quotes |
| Unquoted keys | `{a: 1}` | Use `demjson3` |
| Comments | `{"a": 1} // note` | Strip comments |
| Truncation | `{"a": 1, "b":` | Partial recovery |

### Robust JSON Parser

```python
import re
import json

def robust_json_parse(text: str) -> dict:
    """Parse JSON with common LLM error handling."""

    # Extract JSON portion
    text = extract_json(text)

    # Fix common issues
    fixes = [
        # Remove trailing commas
        (r',(\s*[}\]])', r'\1'),
        # Remove comments
        (r'//.*$', '', re.MULTILINE),
        (r'/\*.*?\*/', ''),
        # Fix single quotes to double quotes (careful with apostrophes)
        (r"(?<=[{,:\[])\s*'([^']*?)'\s*(?=[,}\]:])", r'"\1"'),
    ]

    for pattern, replacement, *flags in fixes:
        flag = flags[0] if flags else 0
        text = re.sub(pattern, replacement, text, flags=flag)

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Try with demjson3 for more lenient parsing
        try:
            import demjson3
            return demjson3.decode(text)
        except:
            raise ValueError(f"Could not parse JSON: {e}")
```

### Retry with Correction

```python
def parse_with_retry(
    client,
    initial_response: str,
    expected_schema: dict,
    max_retries: int = 2
) -> dict:
    """Retry parsing with LLM correction if needed."""

    for attempt in range(max_retries + 1):
        try:
            return robust_json_parse(initial_response)
        except ValueError as e:
            if attempt == max_retries:
                raise

            # Ask LLM to fix its response
            correction_prompt = f"""Your previous response was not valid JSON.

Error: {e}

Your response was:
{initial_response[:500]}...

Please provide ONLY the corrected JSON, no explanation:"""

            response = client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=1024,
                messages=[{"role": "user", "content": correction_prompt}]
            )
            initial_response = response.content[0].text

    return {}
```

---

## Partial Parsing and Recovery

### Extracting Partial Data

When JSON is truncated (due to token limits), extract what you can:

```python
def partial_json_recovery(text: str) -> dict:
    """Recover partial data from truncated JSON."""

    result = {}

    # Try to extract key-value pairs
    kv_pattern = r'"([^"]+)":\s*(?:"([^"]*?)"|(\d+(?:\.\d+)?)|(\[.*?\])|(\{.*?\})|(true|false|null))'

    for match in re.finditer(kv_pattern, text, re.DOTALL):
        key = match.group(1)
        # Find which group matched the value
        value = next((g for g in match.groups()[1:] if g is not None), None)

        if value is not None:
            # Try to parse the value
            try:
                result[key] = json.loads(value) if value not in ('true', 'false', 'null') else \
                             {'true': True, 'false': False, 'null': None}.get(value, value)
            except:
                result[key] = value

    return result
```

### Streaming JSON Parser

For long responses, parse as you receive:

```python
import ijson

def stream_parse_iocs(json_stream):
    """Parse IOCs from streaming JSON response."""

    iocs = []
    parser = ijson.parse(json_stream)

    current_ioc = {}
    in_ioc = False

    for prefix, event, value in parser:
        if prefix == 'iocs.item' and event == 'start_map':
            in_ioc = True
            current_ioc = {}
        elif prefix == 'iocs.item' and event == 'end_map':
            if current_ioc:
                iocs.append(current_ioc)
            in_ioc = False
        elif in_ioc and event in ('string', 'number'):
            field = prefix.split('.')[-1]
            current_ioc[field] = value

    return iocs
```

---

## Security Considerations

### Never Trust LLM Output Directly

```python
# BAD: Direct execution
command = llm_response["command"]
os.system(command)  # DANGEROUS!

# GOOD: Validate and allowlist
ALLOWED_COMMANDS = {"nmap", "whois", "dig", "curl"}

def safe_execute(llm_response: dict) -> str:
    command = llm_response.get("command", "").split()[0]

    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")

    # Additional validation...
    return subprocess.run(...)
```

### Sanitize Before Database Storage

```python
import bleach
from sqlalchemy import text

def store_analysis(analysis: SecurityAnalysis, db):
    """Safely store LLM analysis in database."""

    # Sanitize string fields
    safe_summary = bleach.clean(analysis.summary, strip=True)

    # Validate IOCs before storage
    validated_iocs = []
    for ioc in analysis.iocs:
        if validate_ioc(ioc):  # Your validation function
            validated_iocs.append({
                "type": ioc.type.value,
                "value": bleach.clean(ioc.value, strip=True),
                "confidence": min(max(ioc.confidence, 0), 1)
            })

    # Use parameterized queries
    db.execute(
        text("INSERT INTO analyses (summary, iocs) VALUES (:summary, :iocs)"),
        {"summary": safe_summary, "iocs": json.dumps(validated_iocs)}
    )
```

### Rate Limiting Parsed Actions

```python
from collections import defaultdict
from datetime import datetime, timedelta

class ActionRateLimiter:
    """Rate limit actions derived from LLM output."""

    def __init__(self, max_actions: int = 10, window_seconds: int = 60):
        self.max_actions = max_actions
        self.window = timedelta(seconds=window_seconds)
        self.action_times = defaultdict(list)

    def can_execute(self, action_type: str) -> bool:
        now = datetime.now()
        cutoff = now - self.window

        # Clean old entries
        self.action_times[action_type] = [
            t for t in self.action_times[action_type] if t > cutoff
        ]

        if len(self.action_times[action_type]) >= self.max_actions:
            return False

        self.action_times[action_type].append(now)
        return True
```

---

## Production Patterns

### Complete Parsing Pipeline

```python
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class ParseResult:
    success: bool
    data: Optional[dict]
    error: Optional[str]
    confidence: float
    raw_response: str

def production_parse_pipeline(
    llm_response: str,
    expected_schema: type,  # Pydantic model
    strict: bool = True
) -> ParseResult:
    """Production-ready parsing pipeline."""

    # Step 1: Extract JSON
    try:
        json_str = extract_json(llm_response)
    except ValueError as e:
        if strict:
            return ParseResult(False, None, f"No JSON found: {e}", 0.0, llm_response)
        # Try partial recovery
        data = partial_json_recovery(llm_response)
        if data:
            return ParseResult(True, data, "Partial recovery", 0.3, llm_response)
        return ParseResult(False, None, str(e), 0.0, llm_response)

    # Step 2: Parse JSON
    try:
        data = robust_json_parse(json_str)
    except ValueError as e:
        return ParseResult(False, None, f"Invalid JSON: {e}", 0.0, llm_response)

    # Step 3: Validate schema
    try:
        validated = expected_schema(**data)
        return ParseResult(True, validated.dict(), None, 0.95, llm_response)
    except Exception as e:
        if strict:
            return ParseResult(False, data, f"Schema validation failed: {e}", 0.5, llm_response)
        return ParseResult(True, data, f"Warning: {e}", 0.6, llm_response)
```

### Logging and Monitoring

```python
import logging
import json
from datetime import datetime

logger = logging.getLogger("llm_parsing")

def logged_parse(response: str, context: dict) -> ParseResult:
    """Parse with comprehensive logging."""

    start = datetime.now()
    result = production_parse_pipeline(response, SecurityAnalysis)
    duration = (datetime.now() - start).total_seconds()

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "success": result.success,
        "confidence": result.confidence,
        "duration_ms": duration * 1000,
        "response_length": len(response),
        "error": result.error,
        **context
    }

    if result.success:
        logger.info(json.dumps(log_entry))
    else:
        logger.warning(json.dumps(log_entry))

    return result
```

---

## Quick Reference

### Prompt Template

```python
STRUCTURED_OUTPUT_PROMPT = """You are a security analyst. Analyze the input and return ONLY valid JSON.

Schema:
{schema}

Rules:
1. Return ONLY the JSON object, no explanation
2. Use null for missing values, not empty strings
3. All strings must be properly escaped
4. Numbers should not be quoted

Input:
{input}

JSON:"""
```

### Validation Checklist

- [ ] JSON extracted from response
- [ ] Schema validation passed
- [ ] Required fields present
- [ ] Enum values valid
- [ ] Numeric ranges correct
- [ ] String lengths reasonable
- [ ] No injection payloads in strings
- [ ] Confidence scores between 0-1

---

## Next Steps

| If you want to... | Go to... |
|-------------------|----------|
| Learn prompt engineering | [Lab 00c](../../labs/lab00c-intro-prompt-engineering/) |
| Handle API errors | [Error Handling Guide](./error-handling-guide.md) |
| Apply to log analysis | [Lab 04](../../labs/lab04-llm-log-analysis/) |
| Understand LLM limitations | [Lab 00d](../../labs/lab00d-ai-in-security-operations/) |

---

*Last updated: January 2025*

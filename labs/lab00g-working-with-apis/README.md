# Lab 00g: Working with APIs

**Difficulty:** 🟢 Beginner | **Time:** 30-45 min | **Prerequisites:** Lab 00a

Learn to make HTTP requests, handle JSON responses, and work with security APIs.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab00g_working_with_apis.ipynb)

## Learning Objectives

By the end of this lab, you will:
- Make HTTP requests using Python's `requests` library
- Parse JSON responses into Python dictionaries
- Handle API errors gracefully
- Work with API keys securely
- Understand rate limiting and pagination

## Prerequisites

- Completed Lab 00a (Python basics)
- Basic understanding of web concepts (URLs, HTTP)

## Time Required

⏱️ **30-45 minutes**

---

## Why This Matters for Security

Modern security tools rely heavily on APIs:

| API Type | Use Case | Examples |
|----------|----------|----------|
| **Threat Intel** | Check IP/domain reputation | VirusTotal, AbuseIPDB, Shodan |
| **SIEM/SOAR** | Query logs and alerts | Splunk, Elastic, Microsoft Sentinel |
| **LLM** | AI-powered analysis | Anthropic, OpenAI, Google |
| **Ticketing** | Create/update incidents | ServiceNow, Jira |

---

## HTTP Basics

### The Request-Response Cycle

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP REQUEST/RESPONSE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Your Code                        API Server               │
│   ─────────                        ──────────               │
│                                                             │
│   1. Request ─────────────────────►                         │
│      GET /api/v1/ip/8.8.8.8                                 │
│      Headers: Authorization: Bearer xxx                     │
│                                                             │
│   2. Response ◄────────────────────                         │
│      Status: 200 OK                                         │
│      Body: {"ip": "8.8.8.8", "malicious": false}           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### HTTP Methods

| Method | Purpose | Example |
|--------|---------|---------|
| **GET** | Retrieve data | Get IP reputation |
| **POST** | Send data | Submit file for scanning |
| **PUT** | Update data | Update alert status |
| **DELETE** | Remove data | Delete old records |

### Status Codes

| Code | Meaning | What To Do |
|------|---------|------------|
| 200 | Success | Parse the response |
| 400 | Bad Request | Check your parameters |
| 401 | Unauthorized | Check your API key |
| 403 | Forbidden | You don't have permission |
| 404 | Not Found | Resource doesn't exist |
| 429 | Rate Limited | Slow down, wait and retry |
| 500 | Server Error | API is having issues |

---

## Making Requests with Python

### Basic GET Request

```python
import requests

response = requests.get("https://api.example.com/data")

if response.status_code == 200:
    data = response.json()  # Parse JSON
    print(data)
else:
    print(f"Error: {response.status_code}")
```

### Adding Headers (API Keys)

```python
headers = {
    "Authorization": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}

response = requests.get(
    "https://api.example.com/data",
    headers=headers
)
```

### Query Parameters

```python
# These two are equivalent:
# https://api.example.com/search?query=malware&limit=10

params = {"query": "malware", "limit": 10}
response = requests.get(
    "https://api.example.com/search",
    params=params
)
```

### POST Request with JSON Body

```python
payload = {
    "ip": "192.168.1.1",
    "action": "block"
}

response = requests.post(
    "https://api.example.com/block",
    json=payload,  # Automatically converts to JSON
    headers=headers
)
```

---

## Working with Nested JSON (Security APIs)

Security API responses are often deeply nested. Here's how to navigate them safely.

### The Challenge: Deeply Nested Responses

```python
# Typical VirusTotal response structure
vt_response = {
    "data": {
        "id": "abc123",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 45,
                "suspicious": 2,
                "harmless": 10,
                "undetected": 5
            },
            "sha256": "5d41402abc4b2a76b9719d911017c592",
            "names": ["malware.exe", "bad_file.exe"]
        }
    }
}

# BAD: Crashes if any key is missing
malicious_count = vt_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
# KeyError if "data" or "attributes" doesn't exist!
```

### Safe Navigation with `.get()`

```python
# GOOD: Use .get() with defaults - never crashes
def extract_vt_stats(response):
    """Safely extract stats from VirusTotal response."""
    data = response.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "sha256": attributes.get("sha256", "unknown")
    }

# Works even if response is empty or malformed
result = extract_vt_stats({})  # Returns defaults, no crash
print(result)  # {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'sha256': 'unknown'}
```

### Chaining `.get()` for Deep Access

```python
# One-liner for deep access with default
malicious = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)

# More readable version with intermediate variables
def get_nested(data, keys, default=None):
    """
    Safely get a nested value from a dict.
    
    Usage: get_nested(response, ["data", "attributes", "sha256"], "unknown")
    """
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data

# Usage
sha256 = get_nested(vt_response, ["data", "attributes", "sha256"], "not_found")
```

### Working with Lists in JSON

```python
# Response with lists
threat_report = {
    "indicators": [
        {"type": "ip", "value": "192.168.1.100", "malicious": True},
        {"type": "domain", "value": "evil.com", "malicious": True},
        {"type": "hash", "value": "abc123", "malicious": False}
    ],
    "tags": ["ransomware", "apt29", "cobalt-strike"]
}

# Safely get lists
indicators = threat_report.get("indicators", [])  # Empty list if missing
tags = threat_report.get("tags", [])

# Filter malicious indicators
malicious_iocs = [
    ioc for ioc in indicators 
    if ioc.get("malicious", False)  # Safe access inside list comprehension
]
print(malicious_iocs)
# [{'type': 'ip', 'value': '192.168.1.100', 'malicious': True}, ...]

# Extract just the values
malicious_values = [ioc.get("value") for ioc in malicious_iocs]
print(malicious_values)  # ['192.168.1.100', 'evil.com']
```

### Real-World Example: Parsing AbuseIPDB Response

```python
def parse_abuseipdb_response(response_json):
    """
    Parse AbuseIPDB API response safely.
    
    Example response:
    {
        "data": {
            "ipAddress": "185.220.101.5",
            "abuseConfidenceScore": 100,
            "countryCode": "DE",
            "reports": [
                {"reporterId": 123, "categories": [14, 15], "comment": "SSH brute force"},
                {"reporterId": 456, "categories": [21], "comment": "Port scan"}
            ]
        }
    }
    """
    data = response_json.get("data", {})
    
    # Basic info
    result = {
        "ip": data.get("ipAddress", "unknown"),
        "score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", "??"),
        "report_count": len(data.get("reports", []))
    }
    
    # Extract attack categories from all reports
    reports = data.get("reports", [])
    all_categories = []
    for report in reports:
        categories = report.get("categories", [])
        all_categories.extend(categories)
    
    result["attack_categories"] = list(set(all_categories))  # Unique categories
    
    return result

# Usage
api_response = {
    "data": {
        "ipAddress": "185.220.101.5",
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "reports": [
            {"categories": [14, 15]},
            {"categories": [21, 14]}
        ]
    }
}

parsed = parse_abuseipdb_response(api_response)
print(parsed)
# {'ip': '185.220.101.5', 'score': 100, 'country': 'DE', 'report_count': 2, 'attack_categories': [14, 15, 21]}
```

### Validating JSON Structure

```python
def validate_response(response, required_fields):
    """Check if response has required fields."""
    missing = []
    for field in required_fields:
        if field not in response:
            missing.append(field)
    
    if missing:
        raise ValueError(f"Response missing required fields: {missing}")
    
    return True

# Usage
try:
    validate_response(api_response, ["data"])
    data = api_response["data"]
    validate_response(data, ["ipAddress", "abuseConfidenceScore"])
    # Now safe to access
except ValueError as e:
    print(f"Invalid response: {e}")
```

### Quick Reference: JSON Navigation

```python
# Safe access patterns
data.get("key", default)              # Single key with default
data.get("key", {}).get("nested")     # Chained for nested
data.get("list_key", [])              # Empty list default for lists

# List comprehension with safe access
[item.get("value") for item in data.get("items", [])]

# Check before access
if "key" in data:
    value = data["key"]

# Try/except for critical paths
try:
    critical_value = data["must"]["exist"]["path"]
except KeyError as e:
    print(f"Missing required field: {e}")
    critical_value = None
```

---

## Handling Errors

### Try-Except Pattern

```python
import requests
from requests.exceptions import RequestException

def safe_api_call(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raises exception for 4xx/5xx
        return response.json()
    except requests.exceptions.Timeout:
        print("Request timed out")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
        return None
    except RequestException as e:
        print(f"Request failed: {e}")
        return None
```

---

## Working with API Keys Securely

### ❌ BAD: Hardcoded keys

```python
# NEVER do this!
API_KEY = "sk-12345abcdef"
```

### ✅ GOOD: Environment variables

```python
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env file

API_KEY = os.getenv("MY_API_KEY")
if not API_KEY:
    raise ValueError("MY_API_KEY not set!")
```

### .env file (never commit this!)

```
# .env
MY_API_KEY=sk-12345abcdef
VIRUSTOTAL_API_KEY=abc123
```

### .gitignore

```
# .gitignore
.env
*.env
.env.*
```

---

## Rate Limiting

APIs limit how many requests you can make:

```python
import time

def rate_limited_request(urls, requests_per_minute=60):
    """Make requests with rate limiting."""
    delay = 60 / requests_per_minute  # seconds between requests

    results = []
    for url in urls:
        response = requests.get(url)
        results.append(response.json())
        time.sleep(delay)  # Wait before next request

    return results
```

### Handling 429 (Rate Limited)

```python
def request_with_retry(url, max_retries=3):
    """Retry on rate limit."""
    for attempt in range(max_retries):
        response = requests.get(url)

        if response.status_code == 429:
            wait_time = int(response.headers.get("Retry-After", 60))
            print(f"Rate limited. Waiting {wait_time}s...")
            time.sleep(wait_time)
            continue

        return response

    raise Exception("Max retries exceeded")
```

---

## Your Task

Complete the starter code to build a security API client.

### File: `starter/main.py`

```bash
python labs/lab00g-working-with-apis/starter/main.py
```

### TODOs

1. **TODO 1**: Make a GET request to a public API
2. **TODO 2**: Parse the JSON response
3. **TODO 3**: Add error handling
4. **TODO 4**: Load API key from environment
5. **TODO 5**: Implement rate limiting

---

## Hints

<details>
<summary>💡 Hint 1: Basic GET</summary>

```python
response = requests.get(url)
```

</details>

<details>
<summary>💡 Hint 2: Parse JSON</summary>

```python
data = response.json()
# Now data is a Python dict
```

</details>

<details>
<summary>💡 Hint 3: Error Handling</summary>

```python
try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
```

</details>

---

## Practice APIs (No Key Required)

These free APIs are great for practice:

| API | URL | Description |
|-----|-----|-------------|
| **IP Info** | `https://ipinfo.io/8.8.8.8/json` | IP geolocation |
| **HTTPBin** | `https://httpbin.org/get` | Echo service |
| **JSON Placeholder** | `https://jsonplaceholder.typicode.com/posts/1` | Fake REST API |

---

## Expected Output

```
🌐 Working with APIs - Security API Client
==========================================

1. Basic GET Request
   URL: https://ipinfo.io/8.8.8.8/json
   Status: 200 OK
   Response: {'ip': '8.8.8.8', 'city': 'Mountain View', ...}

2. Error Handling
   Testing invalid URL...
   Caught error: HTTPSConnectionPool(host='invalid.url')...

3. API Key Loading
   ✅ API key loaded from environment (length: 32)

4. Rate Limiting Demo
   Making 5 requests with 1s delay...
   Request 1/5 - Status: 200
   Request 2/5 - Status: 200
   ...

✅ You're ready to work with security APIs!
```

---

## Security API Examples

### VirusTotal (with API key)

```python
def check_hash_virustotal(file_hash, api_key):
    """Check file hash on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
        }
    return None
```

### AbuseIPDB (with API key)

```python
def check_ip_abuseipdb(ip_address, api_key):
    """Check IP reputation on AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": data["ipAddress"],
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"]
        }
    return None
```

---

## Key Takeaways

1. **requests library** - Your go-to for HTTP calls in Python
2. **JSON parsing** - `response.json()` gives you a Python dict
3. **Error handling** - Always wrap API calls in try-except
4. **API keys** - Never hardcode, use environment variables
5. **Rate limiting** - Respect API limits with delays/retries

---

## What's Next?

Now that you can work with APIs:

- **Lab 04**: Use LLM APIs for log analysis
- **Lab 05**: Build an agent with threat intel API tools
- **Lab 06**: Implement RAG with embedding APIs

You're ready for LLM-powered security tools! 🚀

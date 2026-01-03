# Lab 00g: Working with APIs Walkthrough

Step-by-step guide to making HTTP requests and working with security APIs.

## Overview

This walkthrough guides you through:
1. Making GET and POST requests with Python
2. Parsing JSON responses
3. Handling errors gracefully
4. Working with API keys securely
5. Implementing rate limiting

**Difficulty:** Intro
**Time:** 30-45 minutes
**Prerequisites:** Basic Python (Lab 00a)

---

## The Big Picture

Every LLM and security tool uses APIs:

```
Your Script                     API Server
    │                               │
    │── GET /api/ip/8.8.8.8 ──────►│
    │                               │
    │◄── {"malicious": false} ─────│
    │                               │
    Process JSON response
```

---

## Exercise 1: Basic GET Request (TODO 1)

### The Problem

How do we fetch data from a web API?

### The Solution

```python
import requests

def make_get_request(url: str) -> dict:
    """Make a GET request and return JSON response."""
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None
```

### Testing It

```python
# Free API - no key required
result = make_get_request("https://ipinfo.io/8.8.8.8/json")
print(result)
# {'ip': '8.8.8.8', 'city': 'Mountain View', 'country': 'US', ...}
```

### Understanding the Response

| Attribute | Meaning |
|-----------|---------|
| `response.status_code` | HTTP status (200=OK, 404=Not Found) |
| `response.json()` | Parse JSON body to Python dict |
| `response.text` | Raw text body |
| `response.headers` | Response headers |

---

## Exercise 2: Parsing JSON (TODO 2)

### The Problem

API responses are JSON strings - we need Python objects.

### The Solution

```python
import json

def parse_json_safely(response) -> dict:
    """Safely parse JSON, handling errors."""
    try:
        return response.json()
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return None
```

### Working with Nested JSON

```python
# API returns nested structure
data = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "harmless": 60
            }
        }
    }
}

# Navigate safely with .get()
stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
malicious = stats.get("malicious", 0)
```

### Why `.get()` Instead of `[]`?

```python
# Risky: KeyError if key doesn't exist
malicious = data["data"]["attributes"]["malicious"]  # KeyError!

# Safe: Returns None (or default) if missing
malicious = data.get("data", {}).get("malicious", 0)  # Returns 0
```

---

## Exercise 3: Error Handling (TODO 3)

### The Problem

APIs can fail: network issues, rate limits, bad requests.

### The Solution

```python
from requests.exceptions import RequestException
import time

def safe_api_call(url: str, timeout: int = 10) -> dict:
    """Make API call with comprehensive error handling."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  # Raises exception for 4xx/5xx
        return response.json()

    except requests.exceptions.Timeout:
        print(f"Request timed out after {timeout}s")
        return None

    except requests.exceptions.ConnectionError:
        print("Connection failed - check network")
        return None

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 401:
            print("Unauthorized - check API key")
        elif status == 429:
            print("Rate limited - slow down")
        elif status == 404:
            print("Resource not found")
        else:
            print(f"HTTP error: {status}")
        return None

    except RequestException as e:
        print(f"Request failed: {e}")
        return None
```

### Common Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Parse response |
| 400 | Bad Request | Check parameters |
| 401 | Unauthorized | Check API key |
| 403 | Forbidden | No permission |
| 404 | Not Found | Check URL/ID |
| 429 | Rate Limited | Wait and retry |
| 500 | Server Error | Retry later |

---

## Exercise 4: API Keys (TODO 4)

### The Problem

API keys are secrets - never hardcode them!

### ❌ BAD (Never Do This!)

```python
API_KEY = "sk-abc123secret456"  # EXPOSED IN CODE!
```

### ✅ GOOD (Environment Variables)

```python
import os
from dotenv import load_dotenv

def get_api_key(key_name: str) -> str:
    """Load API key from environment."""
    load_dotenv()  # Load .env file

    key = os.getenv(key_name)
    if not key:
        raise ValueError(f"{key_name} not set in environment!")
    return key

# Usage
api_key = get_api_key("ANTHROPIC_API_KEY")
```

### Setting Up `.env`

```bash
# .env file (NEVER commit this!)
ANTHROPIC_API_KEY=sk-ant-api03-...
VIRUSTOTAL_API_KEY=abc123...
ABUSEIPDB_API_KEY=xyz789...
```

### Add to `.gitignore`

```
# .gitignore
.env
*.env
.env.*
```

### Using Keys in Requests

```python
def make_authenticated_request(url: str, api_key: str) -> dict:
    """Make request with API key in header."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    return response.json()
```

---

## Exercise 5: Rate Limiting (TODO 5)

### The Problem

APIs limit requests per minute/hour. Exceed limits = 429 error.

### Solution 1: Simple Delay

```python
import time

def rate_limited_requests(urls: list, requests_per_minute: int = 30) -> list:
    """Make requests with rate limiting."""
    delay = 60 / requests_per_minute  # Seconds between requests

    results = []
    for url in urls:
        result = safe_api_call(url)
        results.append(result)
        time.sleep(delay)  # Wait before next request

    return results
```

### Solution 2: Retry on 429

```python
def request_with_retry(url: str, max_retries: int = 3) -> dict:
    """Retry on rate limit with exponential backoff."""
    for attempt in range(max_retries):
        response = requests.get(url)

        if response.status_code == 429:
            # Get wait time from header, or default
            wait = int(response.headers.get("Retry-After", 2 ** attempt))
            print(f"Rate limited. Waiting {wait}s...")
            time.sleep(wait)
            continue

        response.raise_for_status()
        return response.json()

    raise Exception(f"Failed after {max_retries} retries")
```

### Exponential Backoff

```
Attempt 1: Wait 1 second
Attempt 2: Wait 2 seconds
Attempt 3: Wait 4 seconds
Attempt 4: Wait 8 seconds
```

---

## Complete Example: Security API Client

```python
import os
import time
import requests
from dotenv import load_dotenv

class SecurityAPIClient:
    """Client for security threat intel APIs."""

    def __init__(self):
        load_dotenv()
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    def check_ip_virustotal(self, ip: str) -> dict:
        """Check IP reputation on VirusTotal."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    def check_ip_abuseipdb(self, ip: str) -> dict:
        """Check IP reputation on AbuseIPDB."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()["data"]

            return {
                "ip": ip,
                "abuse_score": data["abuseConfidenceScore"],
                "country": data["countryCode"],
                "reports": data["totalReports"]
            }
        except Exception as e:
            return {"ip": ip, "error": str(e)}
```

---

## Common Errors

### 1. Missing Timeout

```python
# Problem: Request hangs forever
response = requests.get(url)  # Could hang!

# Solution: Always set timeout
response = requests.get(url, timeout=10)
```

### 2. Not Checking Status

```python
# Problem: Assume success
data = response.json()  # Could fail if 404/500!

# Solution: Check status first
response.raise_for_status()  # Raises exception if error
data = response.json()
```

### 3. Hardcoded Keys

```python
# Problem: Key in code = key in git = key exposed
headers = {"x-apikey": "abc123"}  # NO!

# Solution: Environment variables
headers = {"x-apikey": os.getenv("VT_KEY")}
```

### 4. No Rate Limiting

```python
# Problem: 1000 requests instantly = banned
for ip in thousand_ips:
    check_ip(ip)  # Banned!

# Solution: Add delays
for ip in thousand_ips:
    check_ip(ip)
    time.sleep(0.5)  # 2 requests/second
```

---

## Key Takeaways

1. **requests library** - Your tool for HTTP in Python
2. **Parse JSON safely** - Use `.get()` for missing keys
3. **Handle errors** - Always wrap in try/except
4. **Protect keys** - Environment variables, never hardcode
5. **Respect limits** - Rate limit to avoid bans

---

## Practice APIs (No Key Required)

Try these for practice:

| API | URL | Description |
|-----|-----|-------------|
| IP Info | `https://ipinfo.io/8.8.8.8/json` | IP geolocation |
| HTTPBin | `https://httpbin.org/get` | Echo service |
| JSON Placeholder | `https://jsonplaceholder.typicode.com/posts/1` | Fake REST |

---

## Next Steps

You can now work with APIs! Continue to:

- **Lab 04**: Use LLM APIs (Anthropic, OpenAI)
- **Lab 05**: Build agents with tool-calling APIs
- **Lab 06**: Work with embedding APIs for RAG

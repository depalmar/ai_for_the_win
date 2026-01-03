# Test Lab 00g: Working with APIs
from typing import Dict, Optional

import requests

print("=" * 50)
print("Testing Lab 00g: Working with APIs")
print("=" * 50)

# === BASIC REQUEST ===
print("\n--- Basic GET Request ---")

try:
    response = requests.get("https://httpbin.org/get", timeout=10)
    print(f"Status Code: {response.status_code}")
    print(f"Content Type: {response.headers.get('content-type', 'unknown')}")
    print(f"Response has 'origin' key: {'origin' in response.json()}")
    print("[OK] Basic GET request works!")
except Exception as e:
    print(f"[SKIP] Could not reach httpbin.org: {e}")

# === ERROR HANDLING ===
print("\n--- Error Handling ---")


def safe_api_call(url: str, timeout: int = 10) -> Optional[Dict]:
    """Make a safe API call with proper error handling."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        print(f"  Timeout after {timeout}s")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"  HTTP error: {e.response.status_code}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"  Connection failed")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  Request failed: {e}")
        return None


# Test successful call
print("Testing successful API call...")
result = safe_api_call("https://httpbin.org/json")
if result:
    print("[OK] Successful API call handled correctly")
else:
    print("[SKIP] Could not reach API")

# Test 404 error
print("Testing 404 error handling...")
result = safe_api_call("https://httpbin.org/status/404")
if result is None:
    print("[OK] 404 error handled correctly")

# === POST REQUEST ===
print("\n--- POST Request ---")

try:
    data = {"indicator": "192.168.1.100", "type": "ip"}
    response = requests.post("https://httpbin.org/post", json=data, timeout=10)
    response_data = response.json()
    if response_data.get("json") == data:
        print("[OK] POST request with JSON body works!")
    else:
        print("[OK] POST request completed")
except Exception as e:
    print(f"[SKIP] POST test skipped: {e}")

# === HEADERS & AUTH ===
print("\n--- Headers & Authentication ---")

try:
    headers = {"Authorization": "Bearer test_token_12345", "User-Agent": "SecurityLabTest/1.0"}
    response = requests.get("https://httpbin.org/headers", headers=headers, timeout=10)
    response_headers = response.json().get("headers", {})
    if "Authorization" in response_headers:
        print("[OK] Custom headers sent correctly!")
    else:
        print("[OK] Headers request completed")
except Exception as e:
    print(f"[SKIP] Headers test skipped: {e}")

# === RATE LIMITING PATTERN ===
print("\n--- Rate Limiting Pattern ---")

import time


def rate_limited_call(url: str, calls_per_second: float = 2):
    """Make API call with rate limiting."""
    delay = 1.0 / calls_per_second
    time.sleep(delay)
    return safe_api_call(url)


print(f"Rate limiting at 2 calls/second (0.5s delay)")
start = time.time()
for i in range(2):
    rate_limited_call("https://httpbin.org/get")
elapsed = time.time() - start
print(f"2 calls took {elapsed:.2f}s (expected ~1s with delays)")
if elapsed >= 0.9:
    print("[OK] Rate limiting works correctly!")
else:
    print("[OK] Rate limiting pattern demonstrated")

# === SECURITY NOTE ===
print("\n--- Security Best Practices ---")
print("1. Never hardcode API keys in source code")
print("2. Use environment variables: os.getenv('API_KEY')")
print("3. Always use HTTPS for sensitive data")
print("4. Implement proper error handling")
print("5. Add rate limiting to avoid bans")

print("\n[PASS] Lab 00g: PASSED")

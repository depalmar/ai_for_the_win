"""
Lab 00g: Working with APIs (Solution)

A complete API client demonstrating HTTP requests, JSON parsing, and best practices.
"""

import os
import time

import requests
from requests.exceptions import HTTPError, RequestException, Timeout


def basic_get_request(url: str, timeout: int = 10) -> dict | None:
    """Make a GET request and return JSON response."""
    response = requests.get(url, timeout=timeout)
    if response.status_code == 200:
        return response.json()
    return None


def parse_ip_info(ip_address: str) -> dict | None:
    """Get information about an IP address from ipinfo.io."""
    url = f"https://ipinfo.io/{ip_address}/json"
    data = basic_get_request(url)

    if data:
        return {
            "ip": data.get("ip", "unknown"),
            "city": data.get("city", "unknown"),
            "region": data.get("region", "unknown"),
            "country": data.get("country", "unknown"),
            "org": data.get("org", "unknown"),
        }
    return None


def safe_request(url: str, timeout: int = 10) -> dict | None:
    """Make a request with proper error handling."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Timeout:
        print(f"   ⚠️ Request timed out: {url}")
        return None
    except HTTPError as e:
        print(f"   ⚠️ HTTP error {e.response.status_code}: {url}")
        return None
    except RequestException as e:
        print(f"   ⚠️ Request failed: {type(e).__name__}")
        return None


def get_api_key(key_name: str) -> str | None:
    """Securely load an API key from environment variables."""
    return os.getenv(key_name)


def rate_limited_requests(urls: list, delay_seconds: float = 1.0) -> list:
    """Make multiple requests with rate limiting."""
    results = []
    for i, url in enumerate(urls):
        result = safe_request(url)
        results.append(result)
        if i < len(urls) - 1:  # Don't delay after last request
            time.sleep(delay_seconds)
    return results


# ============================================================================
# BONUS: Advanced patterns for security APIs
# ============================================================================


def request_with_retry(url: str, max_retries: int = 3, backoff: float = 2.0) -> dict | None:
    """Make request with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)

            if response.status_code == 429:  # Rate limited
                wait_time = float(response.headers.get("Retry-After", backoff**attempt))
                print(f"   Rate limited. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            return response.json()

        except RequestException as e:
            if attempt < max_retries - 1:
                wait_time = backoff**attempt
                print(f"   Retry {attempt + 1}/{max_retries} after {wait_time:.1f}s...")
                time.sleep(wait_time)
            else:
                print(f"   Max retries exceeded: {e}")
                return None
    return None


def check_ip_reputation(ip_address: str) -> dict:
    """
    Check IP reputation using multiple free sources.

    This demonstrates aggregating data from multiple APIs.
    """
    results = {"ip": ip_address, "sources": {}}

    # Source 1: ipinfo.io (geolocation)
    ip_info = parse_ip_info(ip_address)
    if ip_info:
        results["sources"]["ipinfo"] = {
            "country": ip_info.get("country"),
            "org": ip_info.get("org"),
        }

    # Source 2: ip-api.com (also free, different data)
    ip_api_data = safe_request(f"http://ip-api.com/json/{ip_address}")
    if ip_api_data:
        results["sources"]["ip-api"] = {
            "isp": ip_api_data.get("isp"),
            "as": ip_api_data.get("as"),
            "proxy": ip_api_data.get("proxy", False),
        }

    return results


def main():
    print("🌐 Working with APIs - Security API Client")
    print("=" * 45)

    # Test 1: Basic GET request
    print("\n1. Basic GET Request")
    print("-" * 30)
    url = "https://httpbin.org/get"
    result = basic_get_request(url)
    if result:
        print(f"   ✅ Success! Got response with {len(result)} fields")
        print(f"   Origin IP: {result.get('origin', 'unknown')}")

    # Test 2: Parse IP info
    print("\n2. IP Information Lookup")
    print("-" * 30)
    test_ips = ["8.8.8.8", "1.1.1.1"]
    for ip in test_ips:
        ip_info = parse_ip_info(ip)
        if ip_info:
            print(f"   {ip}: {ip_info['org']} ({ip_info['country']})")

    # Test 3: Error handling
    print("\n3. Error Handling")
    print("-" * 30)
    print("   Testing various error conditions:")

    # Invalid URL
    bad_result = safe_request("https://this-domain-does-not-exist-12345.com")
    print(f"   Invalid domain: {'Handled ✅' if bad_result is None else 'Failed ❌'}")

    # 404 error
    not_found = safe_request("https://httpbin.org/status/404")
    print(f"   404 Not Found: {'Handled ✅' if not_found is None else 'Failed ❌'}")

    # Test 4: API key loading
    print("\n4. API Key Loading")
    print("-" * 30)
    os.environ["TEST_API_KEY"] = "demo_key_12345"
    key = get_api_key("TEST_API_KEY")
    missing_key = get_api_key("NONEXISTENT_KEY")
    print(f"   Existing key: {'Loaded ✅' if key else 'Failed ❌'}")
    print(f"   Missing key: {'None (correct) ✅' if missing_key is None else 'Failed ❌'}")

    # Test 5: Rate limiting
    print("\n5. Rate Limiting")
    print("-" * 30)
    test_urls = [f"https://httpbin.org/get?n={i}" for i in range(3)]
    print(f"   Making {len(test_urls)} requests with 0.5s delay...")
    start = time.time()
    results = rate_limited_requests(test_urls, delay_seconds=0.5)
    elapsed = time.time() - start
    success_count = sum(1 for r in results if r is not None)
    print(f"   Completed: {success_count}/{len(results)} in {elapsed:.1f}s")

    # Test 6: Retry with backoff
    print("\n6. Retry with Backoff (Bonus)")
    print("-" * 30)
    result = request_with_retry("https://httpbin.org/get")
    print(f"   Request with retry: {'Success ✅' if result else 'Failed ❌'}")

    # Test 7: Multi-source IP check
    print("\n7. Multi-Source IP Reputation (Bonus)")
    print("-" * 30)
    reputation = check_ip_reputation("8.8.8.8")
    print(f"   IP: {reputation['ip']}")
    for source, data in reputation["sources"].items():
        print(f"   [{source}]: {data}")

    # Summary
    print("\n" + "=" * 45)
    print("✅ All API patterns demonstrated!")
    print("\n📚 Key Takeaways:")
    print("   • Use requests.get() for HTTP calls")
    print("   • Always handle errors with try-except")
    print("   • Load API keys from environment variables")
    print("   • Implement rate limiting for bulk requests")
    print("   • Use retry with backoff for reliability")


if __name__ == "__main__":
    main()

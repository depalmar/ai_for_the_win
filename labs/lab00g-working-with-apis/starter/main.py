"""
Lab 00g: Working with APIs (Starter)

Learn to make HTTP requests, parse JSON, and work with security APIs.
Complete the TODOs to build a working API client.
"""

import os
import time
import requests
from requests.exceptions import RequestException

# ============================================================================
# TODO 1: Make a basic GET request
# ============================================================================

def basic_get_request(url: str) -> dict | None:
    """
    Make a GET request to the given URL and return the JSON response.
    
    Args:
        url: The URL to request
        
    Returns:
        Parsed JSON as a dict, or None if request failed
    """
    # TODO: Use requests.get() to make a request
    # TODO: Check if status code is 200
    # TODO: Return response.json()
    
    # Your code here:
    pass


# ============================================================================
# TODO 2: Parse JSON response and extract specific fields
# ============================================================================

def parse_ip_info(ip_address: str) -> dict | None:
    """
    Get information about an IP address from ipinfo.io.
    
    Args:
        ip_address: The IP to look up (e.g., "8.8.8.8")
        
    Returns:
        Dict with ip, city, region, country, org
    """
    url = f"https://ipinfo.io/{ip_address}/json"
    
    # TODO: Call basic_get_request to get the data
    # TODO: Extract and return only: ip, city, region, country, org
    # Hint: data.get("field_name", "unknown") handles missing fields
    
    # Your code here:
    pass


# ============================================================================
# TODO 3: Add error handling
# ============================================================================

def safe_request(url: str, timeout: int = 10) -> dict | None:
    """
    Make a request with proper error handling.
    
    Args:
        url: The URL to request
        timeout: Seconds to wait before timeout
        
    Returns:
        Parsed JSON or None if any error occurred
    """
    # TODO: Wrap the request in try-except
    # TODO: Handle timeout errors
    # TODO: Handle HTTP errors (4xx, 5xx)
    # TODO: Handle connection errors
    # Hint: Use requests.exceptions.Timeout, HTTPError, RequestException
    
    # Your code here:
    pass


# ============================================================================
# TODO 4: Load API key from environment
# ============================================================================

def get_api_key(key_name: str) -> str | None:
    """
    Securely load an API key from environment variables.
    
    Args:
        key_name: Name of the environment variable
        
    Returns:
        The API key value, or None if not set
    """
    # TODO: Use os.getenv() to get the environment variable
    # TODO: Return None if not set (don't raise an error)
    
    # Your code here:
    pass


# ============================================================================
# TODO 5: Implement rate limiting
# ============================================================================

def rate_limited_requests(urls: list, delay_seconds: float = 1.0) -> list:
    """
    Make multiple requests with rate limiting.
    
    Args:
        urls: List of URLs to request
        delay_seconds: Seconds to wait between requests
        
    Returns:
        List of responses (or None for failed requests)
    """
    # TODO: Loop through URLs
    # TODO: Make request for each URL
    # TODO: Sleep between requests
    # TODO: Collect results
    
    # Your code here:
    pass


# ============================================================================
# MAIN - Test your implementations
# ============================================================================

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
    else:
        print("   ❌ Complete TODO 1 to make GET requests")
    
    # Test 2: Parse IP info
    print("\n2. IP Information Lookup")
    print("-" * 30)
    ip_info = parse_ip_info("8.8.8.8")
    if ip_info:
        print(f"   IP: {ip_info.get('ip')}")
        print(f"   City: {ip_info.get('city')}")
        print(f"   Country: {ip_info.get('country')}")
        print(f"   Org: {ip_info.get('org')}")
    else:
        print("   ❌ Complete TODO 2 to parse IP info")
    
    # Test 3: Error handling
    print("\n3. Error Handling")
    print("-" * 30)
    # Test with invalid URL
    bad_result = safe_request("https://this-domain-does-not-exist-12345.com")
    if bad_result is None:
        print("   ✅ Handled invalid URL gracefully")
    else:
        print("   ❌ Complete TODO 3 for error handling")
    
    # Test 4: API key loading
    print("\n4. API Key Loading")
    print("-" * 30)
    # Set a test key for demo purposes
    os.environ["TEST_API_KEY"] = "demo_key_12345"
    key = get_api_key("TEST_API_KEY")
    if key:
        print(f"   ✅ Loaded key: {key[:5]}... (length: {len(key)})")
    else:
        print("   ❌ Complete TODO 4 to load API keys")
    
    # Test 5: Rate limiting
    print("\n5. Rate Limiting")
    print("-" * 30)
    test_urls = [
        "https://httpbin.org/get?request=1",
        "https://httpbin.org/get?request=2",
        "https://httpbin.org/get?request=3",
    ]
    print(f"   Making {len(test_urls)} requests with rate limiting...")
    results = rate_limited_requests(test_urls, delay_seconds=0.5)
    if results and all(r is not None for r in results):
        print(f"   ✅ All {len(results)} requests succeeded")
    else:
        print("   ❌ Complete TODO 5 for rate limiting")
    
    # Summary
    print("\n" + "=" * 45)
    todos_complete = sum([
        result is not None,
        ip_info is not None,
        bad_result is None,  # Should be None (error handled)
        key is not None,
        results is not None and len(results) > 0
    ])
    print(f"Progress: {todos_complete}/5 TODOs complete")
    
    if todos_complete == 5:
        print("\n✅ You're ready to work with security APIs!")
    else:
        print("\n📝 Keep working on the TODOs!")


if __name__ == "__main__":
    main()
